import logging
from typing import List

from data.silver.schema.providers import tenable
from providers.core import CoreTransform, ProcessResult
from providers.tenable import defs
from utils import utils

LOGGER = logging.getLogger(__name__)


class TenableTransform(CoreTransform):
    def __init__(self, engine=None, immediately_raise_error: bool = False) -> None:
        super(TenableTransform, self).__init__(engine)
        self.source_tool_id = self.get_source_tool("Tenable")
        self.__immediately_raise_error = immediately_raise_error

    @CoreTransform.record_process_history
    def process_plugins(self, run_id: int, plugins_fp: str) -> ProcessResult:
        plugins_data: List[defs.Plugins] = self.parse_plugins_file(plugins_fp)

        exceptions_list, duplicate_count = [], 0
        for plugin in plugins_data:
            try:
                if self.existing_tenable_plugin(plugin.id):
                    LOGGER.warning(f"Duplicated Tenable Plugin found {plugin.id}")
                    duplicate_count += 1
                    continue

                plugins: tenable.TenablePluginsTable = self.insert_tenable_plugin(
                    run_id, plugin
                )

                self.insert_tenable_plugin_vulnerability(
                    plugin_id=plugin.id,
                    type_vuln=self.VulnerabilityType.CVE,
                    vals=self.find_cves_in_plugin(plugins),
                )

            except Exception as ex:
                if self.__immediately_raise_error:
                    raise ex

                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            filename=plugins_fp,
            findings_count=len(plugins_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    @CoreTransform.record_process_history
    def process_solutions(self, run_id: int, solution_fp: str) -> ProcessResult:
        solutions_data: List[defs.Solutions] = self.parse_solutions_file(solution_fp)

        exceptions_list, duplicate_count = [], 0
        for solution in solutions_data:
            try:
                if self.existing_tenable_solution(solution.solutionID):
                    LOGGER.warning(
                        f"Duplicated Tenable Solution found {solution.solutionID}"
                    )
                    duplicate_count += 1
                    continue

                if self.existing_tenable_plugin(solution.pluginID):
                    self.insert_tenable_solution(run_id, solution)

                else:
                    LOGGER.warning(
                        f"Skipping Solution (Missing PluginID {solution.pluginID})"
                    )
            except Exception as ex:
                if self.__immediately_raise_error:
                    raise ex

                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            filename=solution_fp,
            findings_count=len(solutions_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    @CoreTransform.record_process_history
    def process_findings(self, run_id: int, findings_fp: str) -> ProcessResult:
        findings_data: List[defs.Finding] = self.parse_findings_file(findings_fp)

        exceptions_list, duplicate_count = [], 0
        for finding in findings_data:
            try:
                if self.existing_tenable_finding(finding.uuid, finding.pluginID):
                    LOGGER.warning(
                        f"Duplicated Finding found for Tenable uuid-{finding.uuid}"
                    )
                    duplicate_count += 1
                    continue

                host_id = self.insert_host(
                    ipv4_address=finding.ip,
                    mac_address=finding.macAddress,
                    net_bios=finding.netbiosName,
                    dns=finding.dnsName,
                    protocol=finding.protocol,
                )

                severity_id = self.get_severity(
                    value=self.translate_serverity_to_numberic(finding.severity.name),
                    is_internal=True,
                )

                finding_id = self.insert_finding(
                    name=finding.name,
                    description="",
                    severity_id=severity_id,
                    host_id=host_id,
                    run_id=run_id,
                )

                self.insert_tenable_finding(
                    finding_id=finding_id, host_id=host_id, tenable_finding=finding
                )

                if cve_ids := self.find_cve_ids(finding.pluginID):
                    self.insert_finding_cve_junction(
                        finding_id=finding_id, cve_ids=cve_ids
                    )

            except Exception as ex:
                if self.__immediately_raise_error:
                    raise ex
                LOGGER.exception(ex)
                exceptions_list.append(ex)

        return ProcessResult(
            filename=findings_fp,
            findings_count=len(findings_data),
            exceptions_list=exceptions_list,
            duplicate_count=duplicate_count,
        )

    def translate_serverity_to_numberic(self, name: str) -> int:
        values = {"low": 3, "medium": 5, "high": 7, "critical": 10}

        return values[name.lower()]

    def get_tenable_plugin(self, plugin_id: int) -> int | None:
        plugin: tenable.TenablePluginsTable = self.select_first(
            tenable.TenablePluginsTable, PluginID=plugin_id
        )

        if plugin:
            return plugin.PluginID

        return None

    def existing_tenable_plugin(self, plugin_id: int) -> bool:
        return self.exists(tenable.TenablePluginsTable, PluginID=plugin_id)

    def existing_tenable_finding(self, uuid: int, plugin_id: int) -> bool:
        return self.exists(tenable.TenableFindingsTable, UUID=uuid, FK_PluginID=plugin_id)

    def existing_tenable_plugin(self, plugin_id: int) -> bool:
        return self.exists(tenable.TenablePluginsTable, PluginID=plugin_id)

    def existing_tenable_solution(self, solution_id: int) -> bool:
        return self.exists(tenable.TenableSolutionsTable, SolutionID=solution_id)

    def find_cve_ids(self, plugin_id: str) -> List[int] | None:
        cves = self.find_plugin_cves(plugin_id)

        if cves is None:
            return None

        return self.find_cves_tb_ids(cves=cves)

    def find_plugin_cves(self, plugin_id: str) -> List[str] | None:
        vulnerabilities = self.get_plugin_vulnerabilities(plugin_id)

        outputs = []
        if vulnerabilities:
            vuln_id = self.get_vulnerability_name_id(self.VulnerabilityType.CVE)
            for vuln in vulnerabilities:
                if vuln.FK_VulnerabilityID == vuln_id:
                    outputs.append(vuln.Value)

        return outputs or None

    def find_cves_in_plugin(
        self, plugin: tenable.TenablePluginsTable
    ) -> List[str] | None:
        output = []

        for field in [plugin.Description, plugin.SeeAlso]:
            if cves := self.search_cve(str(field)):
                output.extend([v.upper() for v in cves])

        if output:
            output = list(set(output))

        return output or None

    def get_plugin(self, plugin_id: str) -> tenable.TenablePluginsTable:
        plugin = self.select_first(tenable.TenablePluginsTable, FK_PluginID=plugin_id)

        if plugin is None:
            raise RuntimeError(f"Missing Tenable plugin_id {plugin_id}")

        return plugin

    def get_plugin_vulnerabilities(
        self, plugin_id: str
    ) -> tenable.TenablePluginsVulnerabilityTable | None:
        return self.select_all(
            tenable.TenablePluginsVulnerabilityTable, FK_PluginID=plugin_id
        )

    def insert_tenable_plugin_vulnerability(
        self, plugin_id, type_vuln: str, vals: str | List[str]
    ) -> None:
        if vals is None:
            return

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
                    tenable.TenablePluginsVulnerabilityTable.__table__.insert(),
                    inputs,
                )
                conn.commit()

    def insert_tenable_finding(
        self, finding_id: int, host_id: int, tenable_finding: defs.Finding
    ) -> None:
        self.single_insert(
            tenable.TenableFindingsTable,
            check_exist=False,
            Name=tenable_finding.name,
            FK_FindingID=finding_id,
            FK_HostID=host_id,
            FK_PluginID=tenable_finding.pluginID,
            SeverityName=tenable_finding.severity.name,
            SeverityDescription=tenable_finding.severity.description,
            UUID=tenable_finding.uuid,
            Dataclass=str(tenable_finding.model_dump(mode="json")),
        )

    def insert_tenable_plugin(
        self, run_id: int, plugin: defs.Plugins
    ) -> tenable.TenablePluginsTable:
        plugin, _ = self.single_insert(
            tenable.TenablePluginsTable,
            check_exist=False,
            FK_RunID=run_id,
            PluginID=plugin.id,
            RequiredPorts=plugin.requiredPorts,
            RequiredUDPPorts=plugin.requiredUDPPorts,
            CPE=plugin.cpe,
            SRCPort=plugin.srcPort,
            DSTPort=plugin.dstPort,
            Protocol=plugin.protocol,
            Solution=plugin.solution,
            SeeAlso=plugin.seeAlso,
            Synopsis=plugin.synopsis,
            CheckType=plugin.checkType,
            ExploitEase=plugin.exploitEase,
            ExploitAvailable=plugin.exploitAvailable,
            ExploitFrameworks=plugin.exploitFrameworks,
            CVSSVector=plugin.cvssVector,
            CVSSVectorBf=plugin.cvssV3VectorBF or None,
            BaseScore=plugin.baseScore,
            TemporalScore=plugin.temporalScore,
            CVSSV3Vector=plugin.cvssV3Vector or None,
            CVSSV3VectorBf=plugin.cvssV3VectorBF,
            CVSSV3BaseScore=plugin.cvssV3BaseScore,
            CVSSV3TemporalScore=plugin.cvssV3TemporalScore,
            VprScore=plugin.vprScore,
            VprContext=plugin.vprContext,
            StigSeverity=plugin.stigSeverity,
            PluginPubDate=plugin.patchPubDate,
            PluginModDate=plugin.pluginModDate,
            PatchPubDate=plugin.patchPubDate,
            PatchModDate=plugin.patchModDate,
            VulnPubDate=plugin.vulnPubDate,
            Description=plugin.description,
            FamilyID=plugin.family.id,
            FamilyName=plugin.family.name,
            FamilyType=plugin.family.type,
            Dataclass=str(plugin.model_dump(mode="json")),
        )
        return plugin

    def insert_tenable_solution(self, run_id: int, solution: defs.Solutions) -> None:
        self.single_insert(
            tenable.TenableSolutionsTable,
            check_exist=False,
            FK_RunID=run_id,
            CPE=solution.cpe,
            SolutionID=solution.solutionID,
            Solution=solution.solution,
            RemediationList=solution.remediationList,
            Total=solution.total,
            TotalPctg=solution.totalPctg,
            ScorePctg=solution.scorePctg,
            HostTotal=solution.hostTotal,
            MSBulletInTotal=solution.msbulletinTotal,
            CVETotal=solution.cveTotal,
            VPRScore=solution.vprScore,
            CVSSV3BaseScore=solution.cvssV3BaseScore,
            FK_PluginID=solution.pluginID,
            Dataclass=str(solution.model_dump(mode="json")),
        )

    def parse_findings_file(
        self,
        findings_fp: str,
    ) -> List[defs.Finding]:
        raw_data = utils.open_json_file(findings_fp)
        return [defs.Finding(**d) for d in raw_data["response"]["results"]]

    def parse_plugins_file(
        self,
        plugins_fp: str,
    ) -> List[defs.Plugins]:
        raw_data = utils.open_json_file(plugins_fp)
        return [defs.Plugins(**d) for d in raw_data["response"]]

    def parse_solutions_file(
        self,
        solutions_fp: str,
    ) -> List[defs.Solutions]:
        raw_data = utils.open_json_file(solutions_fp)

        return [defs.Solutions(**d) for d in raw_data["response"]["results"]]
