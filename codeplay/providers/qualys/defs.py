from typing import List

from pydantic import BaseModel


class DNSData(BaseModel):
    HOSTNAME: str
    DOMAIN: str
    FQDN: str


class Detection(BaseModel):
    UNIQUE_VULN_ID: int
    QID: int
    TYPE: str
    SEVERITY: int
    SSL: int
    RESULTS: str = None
    STATUS: str
    FIRST_FOUND_DATETIME: str = None
    LAST_FOUND_DATETIME: str = None
    SOURCE: str = None
    TIMES_FOUND: int = None
    LAST_TEST_DATETIME: str = None
    LAST_UPDATE_DATETIME: str = None
    IS_IGNORED: int = None
    IS_DISABLED: int = None
    LAST_PROCESSED_DATETIME: str = None


class DetectionList(BaseModel):
    DETECTION: List[Detection] | Detection


class Host(BaseModel):
    ID: int
    IP: str
    DNS: str = None
    TRACKING_METHOD: str
    DNS_DATA: DNSData = None
    LAST_SCAN_DATETIME: str
    LAST_VM_SCANNED_DATE: str
    LAST_VM_SCANNED_DURATION: int
    DETECTION_LIST: DetectionList


class Software(BaseModel):
    PRODUCT: str = None
    VENDOR: str = None


class SoftwareList(BaseModel):
    SOFTWARE: List[Software] | Software = None


class Access(BaseModel):
    VECTOR: int = None
    COMPLEXITY: int = None


class Attack(BaseModel):
    VECTOR: int = None
    COMPLEXITY: int = None


class Impact(BaseModel):
    CONFIDENTIALITY: int = None
    INTEGRITY: int = None
    AVAILABILITY: int = None


class Cvss(BaseModel):
    BASE: dict | str = None
    TEMPORAL: float = None
    VECTOR_STRING: str = None
    ACCESS: Access = None
    IMPACT: Impact = None
    AUTHENTICATION: int = None
    EXPLOITABILITY: int = None
    REMEDIATION_LEVEL: int = None
    REPORT_CONFIDENCE: int = None


class Cvss_v3(BaseModel):
    BASE: dict | str = None
    TEMPORAL: float = None
    VECTOR_STRING: str = None
    CVSS3_VERSION: float = None
    ATTACK: Attack = None
    IMPACT: Impact = None
    PRIVILEGES_REQUIRED: int = None
    USER_INTERACTION: int = None
    SCOPE: int = None
    EXPLOIT_CODE_MATURITY: int = None
    REMEDIATION_LEVEL: int = None
    REPORT_CONFIDENCE: int = None


class ThreatIntelligence(BaseModel):
    THREAT_INTEL: List[dict] | dict


class Discovery(BaseModel):
    REMOTE: int


class CVE(BaseModel):
    ID: str
    URL: str


class CVEList(BaseModel):
    CVE: List[CVE] | CVE


class Vulnerability(BaseModel):
    QID: int
    VULN_TYPE: str
    SEVERITY_LEVEL: int
    TITLE: str
    CATEGORY: str
    LAST_SERVICE_MODIFICATION_DATETIME: str
    PUBLISHED_DATETIME: str
    PATCHABLE: int
    BUGTRAQ_LIST: dict = None
    SOFTWARE_LIST: SoftwareList = None
    DIAGNOSIS: str
    CORRELATION: dict = None
    CONSEQUENCE: str = None
    SOLUTION: str
    CVSS: Cvss = None
    CVSS_V3: Cvss_v3 = None
    PCI_FLAG: int | None = None
    THREAT_INTELLIGENCE: ThreatIntelligence = None
    DISCOVERY: Discovery = None
    CVE_LIST: CVEList = None
