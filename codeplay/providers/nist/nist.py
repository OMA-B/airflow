import csv
import logging
from typing import List
from datetime import datetime


from data.silver.schema.core import cpe, cve_problem, cvss, cwe
from providers.core import CoreTransform, ProcessResult
from providers.nist import defs
from utils import utils

LOGGER = logging.getLogger(__name__)


class NISTTransform(CoreTransform):
    def __init__(self, engine=None, immediately_raise_error: bool = False) -> None:
        super(NISTTransform, self).__init__(engine)
        self.source_tool_id = self.get_source_tool("NIST")
        self.__immediately_raise_error = immediately_raise_error

    @CoreTransform.record_process_history
    def process_cwe(self, run_id: int, cwe_fp: str) -> ProcessResult:
        cwe_data: List[defs.CWE] = self.parse_cwe_file(cwe_fp)

        exceptions_list, duplicate_count = [], 0
        with self.engine.connect() as conn:
            for data in cwe_data:
                try:
                    if self.existing_nist_cwe(data.id):
                        LOGGER.warning(f"Duplicated CWE found for {data.id}")
                        duplicate_count += 1
                        continue

                    self.insert_cwe(conn, run_id, data)
                except Exception as ex:
                    if self.__immediately_raise_error:
                        raise ex

                    LOGGER.exception(ex)
                    exceptions_list.append(ex)
        conn.commit()

        return ProcessResult(
            filename=cwe_fp,
            findings_count=len(cwe_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    @CoreTransform.record_process_history
    def process_cve(self, run_id: int, nvdcve_fp: str) -> dict:
        cve_data: List[defs.CVE] = self.parse_file(nvdcve_fp)
        exceptions_list, duplicate_count = [], 0
        for cve in cve_data:
            try:
                cve_id: str = cve.cve.CVE_data_meta.ID

                if self.existing_nist_cve(cve_id):
                    LOGGER.warning(f"Duplicated CVSS found for {cve_id}")
                    duplicate_count += 1
                    continue

                with self.engine.connect() as conn:
                    self.insert_cve(conn, run_id, cve)
                    self.insert_cve_problem(
                        conn,
                        cve=cve_id,
                        problem_type_data=cve.cve.problemtype.problemtype_data,
                    )
                    self.insert_cpe(conn, cve_id=cve_id, nodes=cve.configurations.nodes)
                    conn.commit()

            except Exception as ex:
                if self.__immediately_raise_error:
                    raise ex

                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            filename=nvdcve_fp,
            findings_count=len(cve_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    def existing_nist_cve(self, cve: str) -> bool:
        return self.exists(cvss.CVSSTable, CVE=cve)

    def existing_nist_cwe(self, cwe_id: str) -> bool:
        return self.exists(cwe.CWETable, CWE=cwe_id)

    def get_cpe(
        self,
        cve_id: str,
        nodes,
    ) -> dict:
        outputs = []
        for node in nodes:
            if isinstance(node, dict) and "cpe_match" in node:
                for match in node["cpe_match"]:
                    if "cpe23Uri" in match and "vulnerable" in match:
                        outputs.append(
                            dict(
                                FK_CVE=cve_id,
                                Vulnerable=bool(match["vulnerable"]),
                                CPE23URI=match["cpe23Uri"],
                            )
                        )

            for child in node["children"]:
                outputs.extend(self.get_cpe(cve_id, [child]))

        return outputs

    def insert_cpe(
        self,
        conn,
        cve_id: str,
        nodes,
    ) -> None:
        if cpes := self.get_cpe(cve_id, nodes):
            conn.execute(cpe.CPETable.__table__.insert(), cpes)

    def insert_cve_problem(
        self,
        conn,
        cve: str,
        problem_type_data: List[dict],
    ) -> List[cve_problem.CVEProblemsTable]:
        outputs = []
        for data in problem_type_data:
            for description in data["description"]:
                outputs.append({"FK_CVE": cve, "Problem": description["value"]})

        if outputs:
            conn.execute(cve_problem.CVEProblemsTable.__table__.insert(), outputs)

    def insert_cve(
        self,
        conn,
        run_id: int,
        cve: defs.CVE,
    ) -> None:
        inputs = {}
        inputs["FK_RunID"] = run_id
        inputs["CVE"] = cve.cve.CVE_data_meta.ID
        inputs["Description"] = str(
            cve.cve.description.description_data[0].value
        ).replace("\t\n\r", " ")
        inputs["PublishedDate"] = datetime.strptime(
            cve.publishedDate, "%Y-%m-%dT%H:%M%z"
        )
        inputs["LastModifiedDate"] = datetime.strptime(
            cve.lastModifiedDate, "%Y-%m-%dT%H:%M%z"
        )
        inputs["Dataclass"] = str(cve.model_dump(mode="json"))

        if cve.impact.baseMetricV3:
            cvssV3 = cve.impact.baseMetricV3.cvssV3
            inputs["AttackComplexity3"] = cvssV3.attackComplexity
            inputs["AttackVector3"] = cvssV3.attackVector
            inputs["AvailabilityImpact3"] = cvssV3.availabilityImpact
            inputs["ConfidentialityImpact3"] = cvssV3.confidentialityImpact
            inputs["IntegrityImpact3"] = cvssV3.integrityImpact
            inputs["PrivilegesRequired3"] = cvssV3.privilegesRequired
            inputs["scope3"] = cvssV3.scope
            inputs["UserInteraction_3"] = cvssV3.userInteraction
            inputs["VectorString3"] = cvssV3.vectorString
            inputs["BaseScore3"] = cvssV3.baseScore
            inputs["BaseSeverity3"] = cvssV3.baseSeverity
            inputs["ExploitabilityScore3"] = cve.impact.baseMetricV3.exploitabilityScore
            inputs["ImpactScore3"] = cve.impact.baseMetricV3.impactScore

        if cve.impact.baseMetricV2:
            base_metric_v2 = cve.impact.baseMetricV2
            cvssV2 = base_metric_v2.cvssV2
            inputs["AccessComplexity"] = cvssV2.accessComplexity
            inputs["AccessVector"] = cvssV2.accessVector
            inputs["Authentication"] = cvssV2.authentication
            inputs["AvailabilityImpact"] = cvssV2.availabilityImpact
            inputs["ConfidentialityImpact"] = cvssV2.confidentialityImpact
            inputs["IntegrityImpact"] = cvssV2.integrityImpact
            inputs["VectorString"] = cvssV2.vectorString
            inputs["BaseScore"] = cvssV2.baseScore

            inputs["ObtainAllPrivileges"] = base_metric_v2.obtainAllPrivilege
            inputs["ObtainOtherPrivileges"] = base_metric_v2.obtainOtherPrivilege
            inputs["ObtainUserPrivileges"] = base_metric_v2.obtainUserPrivilege
            inputs["UserInteractionRequired"] = base_metric_v2.userInteractionRequired
            inputs["ExploitabilityScore"] = base_metric_v2.exploitabilityScore
            inputs["ImpactScore"] = base_metric_v2.impactScore
            inputs["Severity"] = base_metric_v2.severity

        conn.execute(cvss.CVSSTable.__table__.insert(), [inputs])

    def insert_cwe(
        self,
        conn,
        run_id: int,
        cwe_def: defs.CWE,
    ) -> None:
        data = dict(
            FK_RunID=run_id,
            CWE=str(cwe_def.id),
            Name=cwe_def.name,
            Weakness=cwe_def.weakness,
            Abstraction=cwe_def.abstraction,
            Status=cwe_def.status,
            Description=cwe_def.description,
            ExtendedDescription=cwe_def.extended_description,
            RelatedWeaknesses=cwe_def.related_weaknesses,
            WeaknessOrdinalities=cwe_def.weakness,
            ApplicablePlatforms=cwe_def.applicable_platforms,
            BackgroundDetails=cwe_def.background_details,
            AlternateTerms=cwe_def.alternate_terms,
            ModesOfIntroduction=str(cwe_def.model_computed_fields),
            ExploitationFactors=cwe_def.exploitation_factors,
            LikelihoodOfExploit=cwe_def.likelihood_of_exploit,
            CommonConsequences=cwe_def.common_consequences,
            DetectionMethods=cwe_def.detection_methods,
            PotentialMitigations=cwe_def.potential_mitigations,
            ObservedExamples=cwe_def.observed_examples,
            FunctionalAreas=cwe_def.functional_areas,
            AffectedResources=cwe_def.affected_resources,
            TaxonomyMappings=cwe_def.taxonomy_mappings,
            RelatedAttackPatterns=cwe_def.related_attack_patterns,
            Notes=str(cwe_def.notes),
            Dataclass=str(cwe_def.model_dump(mode="json")),
        )

        conn.execute(cwe.CWETable.__table__.insert(), [data])
        conn.commit()

    def parse_file(self, fp: str) -> List[defs.CVE]:
        raw_data = utils.open_json_file(fp)
        return [defs.CVE(**d) for d in raw_data["CVE_Items"]]

    def parse_cwe_file(self, fp: str) -> List[defs.CWE]:
        data = []
        with open(fp, "r", newline="") as file:
            cvs_reader = csv.reader(file)
            next(cvs_reader)

            for row in cvs_reader:
                row = [None if x == "" else x for x in row]

                data.append(
                    defs.CWE(
                        id=f"CWE-{row[0]}",
                        name=row[1],
                        weakness=row[2],
                        abstraction=row[3],
                        status=row[4],
                        description=row[5],
                        extended_description=row[6],
                        related_weaknesses=row[7],
                        weakness_ordinalities=row[8],
                        applicable_platforms=row[9],
                        background_details=row[10],
                        alternate_terms=row[11],
                        modes_of_introduction=row[12],
                        exploitation_factors=row[13],
                        likelihood_of_exploit=row[14],
                        common_consequences=row[15],
                        detection_methods=row[16],
                        potential_mitigations=row[17],
                        observed_examples=row[18],
                        functional_areas=row[19],
                        affected_resources=row[20],
                        taxonomy_mappings=row[21],
                        related_attack_patterns=row[22],
                        notes=row[23],
                    )
                )

        return data
