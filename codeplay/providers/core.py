import logging
import math
import re
from functools import wraps
import time
from collections import defaultdict
import os
from enum import Enum

from sqlalchemy import select

from data.silver.schema.core import (
    application,
    enum,
    finding,
    host,
    location,
    cwe,
    cvss,
    severity,
)
from data.silver.schema.core.transform_history import TransformHistoryTable
from utils import db, utils
from typing import List
from datetime import datetime
from dataclasses import dataclass
import traceback

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class ProcessResult:
    filename: str
    findings_count: int
    exceptions_list: list = None
    duplicate_count: int = 0

    def __post_init__(self):
        self.error_count = len(self.exceptions_list)


class CoreTransform(db.DatabaseManager):
    class VulnerabilityType(str, Enum):
        CVE = "CVE"
        CWE = "CWE"

    def __init__(self, engine=None) -> None:
        super(CoreTransform, self).__init__(engine)

        self.source_tool_id = None
        self.__severity_cache = defaultdict()
        self.__vulnerability_enum_cache = defaultdict()
        self.__source_tool_cache = defaultdict()

    def insert_application(self, name: int, host_id: int) -> None:
        data = self.single_insert(
            application.ApplicationsTable, Name=name, HostID=host_id
        )

        return data.ID

    def insert_host(
        self,
        name: str = None,
        host_name: str = None,
        url: str = None,
        domain: str = None,
        ipv4_address: str = None,
        ipv6_address: str = None,
        mac_address: str = None,
        port: int = None,
        dns: str = None,
        protocol: str = None,
        net_bios: str = None,
        location_id: int = None,
        application_id: int = None,
    ) -> int | None:
        data, _ = self.single_insert(
            host.HostTable,
            Name=name,
            HostName=host_name,
            URL=url,
            Domain=domain,
            IPV4Address=ipv4_address,
            IPV6Address=ipv6_address,
            Port=port,
            MACAddress=mac_address,
            DNS=dns,
            Protocol=protocol,
            NetBios=net_bios,
            FK_SourceToolID=self.source_tool_id,
            FK_LocationID=location_id,
            FK_ApplicationID=application_id,
        )

        return data.ID

    def get_host(self, name: str, mac_address: str = None) -> host.HostTable:
        query = select(host.HostTable).where(
            host.HostTable.Name == name,
            host.HostTable.MACAddress == mac_address,
        )
        result = self.engine.execute(query)
        return result.fetchone()

    def insert_location(self, name: str, description: str) -> int | None:
        data = self.single_insert(
            location.LocationTable, name=name, description=description
        )

        return data.ID

    def find_cves_tb_ids(self, cves: str | List[str]) -> List[int]:
        if isinstance(cves, str):
            cves = [cves]
            
        results = (
            self.session.query(cvss.CVSSTable.ID, cvss.CVSSTable.CVE)
            .filter(cvss.CVSSTable.CVE.in_(cves))
            .all()
        )
        
        if len(results) != len(cves):
            raise ValueError("Missing CVE in CVSSTable!!! ()")

        return [int(row.ID) for row in results]

    def insert_finding(
        self,
        name: str,
        description: str,
        severity_id: int,
        host_id: int,
        run_id: int,
    ) -> int | None:
        data, _ = self.single_insert(
            finding.FindingTable,
            check_exist=False,
            Name=name,
            Description=description,
            FK_SeverityID=severity_id,
            FK_HostID=host_id,
            FK_RunID=run_id,
        )

        return data.ID

    @staticmethod
    def get_normalized_severity_name(
        value: float, is_internal: bool, min: int, max: int
    ) -> str:
        normalized_val = (value / (max - min)) * 10.0

        if is_internal:
            normalized_val += 2

        rankings = [
            ("CRITICAL", (9, 10.1)),
            ("HIGH", (7, 9)),
            ("MEDIUM", (4, 7)),
            ("LOW", (0, 4)),
        ]

        idx = 0
        for vals in rankings:
            lower, upper = vals[1]
            if lower <= normalized_val and normalized_val < upper:
                break
            idx += 1

        if is_internal:
            if idx == 0:
                idx = 0
            else:
                idx -= 1

        return rankings[idx][0], math.ceil(normalized_val)

    def insert_severity(
        self, name: str, normalized_val: float, is_internal: bool
    ) -> int:
        data, _ = self.single_insert(
            severity.SeverityTable,
            Name=name,
            Value=normalized_val,
            IsInternal=is_internal,
        )

        return data.ID

    def insert_vulnerability_enum(self, enum_name: str) -> int:
        data, _ = self.single_insert(enum.EnumVulnerability, EnumName=enum_name)

        return data.ID

    def get_severity(
        self, value: str, is_internal: bool, min: int = 0, max: int = 10
    ) -> int | None:
        name, normalized_val = CoreTransform.get_normalized_severity_name(
            value, is_internal, min, max
        )

        key = hash((name, normalized_val, is_internal))
        if key not in self.__severity_cache:
            self.__severity_cache[key] = self.insert_severity(
                name, normalized_val, is_internal
            )

        return self.__severity_cache[key]

    def get_vulnerability_name_id(self, type_vuln: str) -> int | None:
        if type_vuln not in self.__vulnerability_enum_cache:
            self.__vulnerability_enum_cache[type_vuln] = self.insert_vulnerability_enum(
                type_vuln
            )

        return self.__vulnerability_enum_cache[type_vuln]

    def get_source_tool(self, source_tool: str) -> int:
        if source_tool not in self.__source_tool_cache:
            self.__source_tool_cache[source_tool] = self.insert_source_tool(source_tool)
        return self.__source_tool_cache[source_tool]

    def insert_source_tool(self, source_tool: str) -> int | None:
        data, _ = self.single_insert(enum.EnumSourceTool, EnumName=source_tool)
        return data.ID

    def get_location(self, name: str) -> location.LocationTable | None:
        if name is None:
            return

        query = select(location.LocationTable).where(
            location.LocationTable.name == name
        )
        result = self.engine.execute(query)
        return result.fetchone()

    def parse_file(self, file_path: str) -> dict:
        data: dict = utils.open_json_file(file_path)

        return data.ID

    def select_cve_ids(self, cves: List[str] | str) -> List[int]:
        if isinstance(cves, list):
            cves = [cves]

        results = (
            self.session.query(cvss.CVSSTable.ID)
            .filter(cvss.CVSSTable.cve.in_(cves))
            .all()
        )

        if results is None or len(results) != len(cves):
            raise RuntimeError(f"Missing CVEs {cves} in CVETable table")

        return [row.ID for row in results]

    def select_cwe_ids(self, cwes: List[str] | str) -> List[int]:
        if isinstance(cwes, list):
            cwes = [cwes]

        results = (
            self.session.query(cwe.CWETable.id).filter(cwe.CWETable.cwe.in_(cwes)).all()
        )

        if results is None or len(results) != len(cwes):
            raise RuntimeError(f"Missing CVEs {cwes} in CWETable")

        return [row.ID for row in results]

    def insert_finding_cve_junction(
        self,
        finding_id: int,
        cve_ids: int | List[int],
    ) -> None:
        if cve_ids is None:
            return

        if isinstance(cve_ids, int):
            cve_ids = [cve_ids]

        for cve_id in cve_ids:
            self.single_insert(
                finding.FindingCVEJunctionTable,
                check_exist=False,
                FK_FindingID=finding_id,
                FK_CVEID=cve_id,
            )

    def insert_finding_cwe_junction(
        self,
        finding_id: int,
        cwe_ids: int | List[int],
    ) -> None:
        if cwe_ids is None:
            return

        if isinstance(cwe_ids, int):
            cwe_ids = [cwe_ids]

        for cwe_id in cwe_ids:
            self.insert(
                finding.FindingCWEJunctionTable,
                FK_FindingID=finding_id,
                CWEID=cwe_id,
            )

    def search_cve(self, input_string: str) -> None | List[str]:
        return self.search_str(input_string, r"(?i)CVE-\d{4}-\d+\b")

    def search_cwe(self, input_string: str) -> None | List[str]:
        return self.search_str(input_string, r"(?i)CWE-\d+\b")

    def search_str(self, input_string: str, pattern: str) -> None | List[str]:
        if matchs := re.findall(pattern, input_string):
            return matchs

        return None

    def insert_record_history(
        self, source_tool_id: int, proccess_name: str, start_datetime: datetime
    ) -> int:
        result, _ = self.single_insert(
            TransformHistoryTable,
            FK_SourceToolID=source_tool_id,
            ProccessName=proccess_name,
            StartDatetime=start_datetime,
        )

        return result.RunID

    def update_record_history(
        self,
        run_id: int,
        filename: str,
        end_datetime: datetime,
        findings_count: int = 0,
        error_count: int = 0,
        error_messages: list = None,
        duplicate_count: int = 0,
    ) -> int:
        self.session.query(TransformHistoryTable).filter(
            TransformHistoryTable.RunID == run_id
        ).update(
            {
                "Filename": filename,
                "EndDatetime": end_datetime,
                "FindingCount": findings_count,
                "ErrorCount": error_count,
                "ErrorMessages": str(error_messages),
                "DuplicateCount": duplicate_count,
            }
        )
        self.session.commit()

    def record_process_history(func):
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            run_id = self.insert_record_history(
                start_datetime=datetime.now(),
                source_tool_id=self.source_tool_id,
                proccess_name=func.__name__,
            )

            t0 = time.time()
            result: ProcessResult = func(self, run_id, *args, **kwargs)
            LOGGER.info(
                f"Proccess time for {func.__name__}: {str(time.time() - t0)} seconds"
            )

            exception_str = ""
            for e in result.exceptions_list:
                LOGGER.exception(e)
                formated_exception = traceback.format_exception(
                    type(e), e, e.__traceback__
                )
                exception_str += f"{formated_exception}, "

            self.update_record_history(
                run_id=run_id,
                end_datetime=datetime.now(),
                findings_count=result.findings_count,
                error_count=result.error_count,
                error_messages=result.exceptions_list or None,
                duplicate_count=result.duplicate_count,
                filename=str(os.path.basename(result.filename)),
            )

            if result.exceptions_list:
                raise RuntimeError(exception_str)

            return result

        return wrapped
