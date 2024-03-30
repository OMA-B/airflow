import logging
from typing import List
from sqlalchemy import select

from data.silver.schema.providers import qualys
from providers.core import CoreTransform, ProcessResult
from providers.qualys import defs
from utils import utils

LOGGER = logging.getLogger(__name__)


class QualysTransform(CoreTransform):
    def __init__(self, engine=None, immediately_raise_error: bool = False) -> None:
        super(QualysTransform, self).__init__(engine)
        self.source_tool_id = self.get_source_tool("Qualys")
        self.__immediately_raise_error = immediately_raise_error

    @CoreTransform.record_process_history
    def process_knowledge_base(self, run_id: int, solution_fp: str) -> ProcessResult:
        vulnerability_data: List[defs.Vulnerability] = self.parse_knowledge_base_file(
            solution_fp
        )

        exceptions_list, duplicate_count = [], 0
        for vuln in vulnerability_data:
            try:
                if self.existing_knowledge_base(vuln.QID):
                    LOGGER.warning(f"Duplicated Qulays QID found {vuln.QID}")
                    duplicate_count += 1
                    continue

                self.insert_qualys_knowledge_base(run_id, vuln)
                self.insert_qualys_knowledge_base_vulnerability(
                    plugin_id=vuln.id,
                    type_vuln=self.VulnerabilityType.CVE,
                    vals=self.find_cves_in_knowledge_base(vuln),
                )

            except Exception as ex:
                if self.__immediately_raise_error:
                    raise ex

                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            findings_count=len(vulnerability_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    @CoreTransform.record_process_history
    def process_findings(self, run_id: int, findings_fp: str) -> ProcessResult:
        findings_data: List[defs.Host] = self.parse_detection_file(findings_fp)
        exceptions_list, duplicate_count = [], 0
        for host in findings_data:
            try:
                host_id = self.get_host_id(host)
                for finding in host.DETECTION_LIST.DETECTION:
                    try:
                        if self.existing_qualys_finding(finding.UNIQUE_VULN_ID):
                            LOGGER.warning(
                                f"Duplicated Finding found for Qualys UNIQUE_VULN_ID-{finding.UNIQUE_VULN_ID}"
                            )
                            duplicate_count += 1
                            continue

                        severity_id = self.insert_severity(
                            value=finding.SEVERITY, is_internal=False, max=5
                        )

                        finding_id = self.insert_finding(
                            name=finding.UNIQUE_VULN_ID,
                            description=finding.RESULTS,
                            severity_id=severity_id,
                            host_id=host_id,
                            run_id=run_id,
                        )

                        self.insert_qualys_finding(
                            findings_id=finding_id,
                            severity_id=severity_id,
                            host_id=host_id,
                            finding=finding,
                        )

                        if cve_ids := self.find_cve_ids(finding.QID):
                            self.insert_finding_cve_junction(
                                finding_id=finding_id,
                                cve_ids=cve_ids,
                            )

                    except Exception as ex:
                        if self.__immediately_raise_error:
                            raise ex
                        LOGGER.exception(ex)
                        exceptions_list.append(ex)

            except Exception as ex:
                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            filename=findings_fp,
            findings_count=len(host.DETECTION_LIST.DETECTION),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    def get_host_id(self, host: defs.Host):
        host_name, domain = None, None
        if hasattr(host.DNS_DATA, "DOMAIN"):
            host_name = host.DNS_DATA.HOSTNAME
            domain = host.DNS_DATA.DOMAIN

        host_id = self.insert_host(
            name=str(host.ID),
            host_name=host_name,
            ipv4_address=host.IP,
            dns=host.DNS if hasattr(host, "DNS") else None,
            domain=domain,
            source_tool_id=self.source_tool_id,
        )

        return host_id

    def get_vulnerability(self, qid: str) -> defs.Vulnerability:
        query = select(qualys.QualysKnowledgeBaseTable.qid).where(
            qualys.QualysKnowledgeBaseTable.QID == qid,
        )
        result = self.engine.execute(query).fetchone()

        if result is None:
            raise ValueError(f"Missing QID-{qid} from Qualys KnowledgeBase TB")

        return result

    def find_cve_ids(self, qid: str) -> List[int]:
        cves = self.find_knowledge_base_cves(qid)

        if cves is None:
            return None

        return self.find_cves_tb_ids(cves=cves)

    def find_knowledge_base_cves(self, qid: str) -> List[int]:
        vulnerabilities = self.get_knowledge_base_vulnerabilities(qid)

        outputs = []
        if vulnerabilities:
            for vuln in vulnerabilities:
                if vuln.FK_VulnerabilityID == self.get_vulnerability_name_id(
                    self.VulnerabilityType.CVE
                ):
                    outputs.append(vuln.Value)

        return outputs or None

    def get_knowledge_base_vulnerabilities(
        self, qid: str
    ) -> qualys.QualysKnowledgeBaseVulnerabilitiesTable | None:
        return self.select_all(qualys.QualysKnowledgeBaseVulnerabilitiesTable, QID=qid)

    def find_cves_in_knowledge_base(
        self, vulnerability: defs.Vulnerability
    ) -> List[str]:
        cves = set()

        fields_search = [
            vulnerability.CVE_LIST,
            vulnerability.CORRELATION,
        ]

        for field in fields_search:
            cves = self.search_cve(str(field))
            cves.add(cves)

        return list(cves)

    def insert_qualys_knowledge_base_vulnerability(
        self, plugin_id, type_vuln: str, vals: str | List[str]
    ) -> None:
        if isinstance(vals, str):
            vals = [vals]

        inputs = []
        vuln = self.get_vulnerability_name_id(type_vuln=type_vuln)
        for val in vals:
            if val is None:
                continue

            inputs.append(
                {"FK_PluginID": plugin_id, "FK_VulnerabilityID": vuln, "Value": val}
            )

        if inputs:
            with self.engine.connect() as conn:
                conn.execute(
                    qualys.QualysKnowledgeBaseVulnerabilitiesTable.__table__.insert(),
                    [inputs],
                )

    def insert_qualys_finding(
        self,
        findings_id: int,
        severity_id: int,
        host_id: int,
        finding: defs.Detection,
    ) -> None:
        self.single_insert(
            qualys.QualysFindingTable,
            check_exist=False,
            FK_FindingID=findings_id,
            FK_SeverityID=severity_id,
            FK_HostID=host_id,
            FK_QID=finding.QID,
            SSL=finding.SSL,
            Status=finding.STATUS,
            Results=finding.RESULTS,
            UniqueVulnID=finding.UNIQUE_VULN_ID,
            Dataclass=str(finding.model_dump(mode="json")),
        )

    def existing_qualys_finding(self, unique_vuln_id: int) -> bool:
        return self.exists(qualys.QualysFindingsTable, unique_vuln_id=unique_vuln_id)

    def existing_tenable_finding(self, qid: int) -> bool:
        return self.exists(qualys.QualysKnowledgeBaseTable, QID=qid)

    def insert_qualys_knowledge_base(
        self, run_id: int, vuln: defs.Vulnerability
    ) -> None:
        self.single_insert(
            qualys.QualysKnowledgeBaseTable,
            check_exist=False,
            RunID=run_id,
            QID=vuln.QID,
            VulnType=vuln.VULN_TYPE,
            SeverityLevel=vuln.SEVERITY_LEVEL,
            Title=vuln.TITLE,
            Category=vuln.CATEGORY,
            SoftwareList=str(vuln.SOFTWARE_LIST),
            Diagnosis=str(vuln.DIAGNOSIS),
            Consequence=vuln.CONSEQUENCE,
            Solution=vuln.SOLUTION,
            CVSS=str(vuln.CVSS),
            CVSSV3=str(vuln.CVSS_V3),
            PciFlag=vuln.PCI_FLAG,
            ThreatIntelligence=str(vuln.THREAT_INTELLIGENCE),
            Discovery=str(vuln.DISCOVERY),
            Dataclass=str(vuln.model_dump(mode="json")),
        )

    def parse_detection_file(self, fp: str) -> List[defs.Host]:
        raw_data = utils.open_xml_file(fp)
        return [
            defs.Host(**d)
            for d in raw_data["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"][
                "HOST"
            ]
        ]

    def parse_knowledge_base_file(self, fp: str) -> List[defs.Vulnerability]:
        raw_data = utils.open_xml_file(fp)
        return [
            defs.Vulnerability(**d)
            for d in raw_data["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"][
                "VULN_LIST"
            ]["VULN"]
        ]
