from pydantic import BaseModel
from typing_extensions import Annotated
from pydantic.functional_validators import BeforeValidator


def empty_to_zero(v: str) -> float | None:
    if v == "":
        return 0.0
    if v.isnumeric():
        return float(v)

    return v


class Severity(BaseModel):
    id: int
    name: str
    description: str = None


class Family(BaseModel):
    id: int
    name: str = None
    type: str = None


class Repository(BaseModel):
    id: int
    name: str
    description: str
    dataFormat: str


class Finding(BaseModel):
    pluginID: int
    severity: Severity
    vprScore: Annotated[float, BeforeValidator(empty_to_zero)]
    vprContext: str
    ip: str
    uuid: str
    port: int
    protocol: str
    name: str
    dnsName: str
    macAddress: str
    netbiosName: str
    recastRiskRuleComment: str
    acceptRiskRuleComment: str
    hostUniqueness: str
    hostUUID: str = None
    acrScore: str = None
    assetExposureScore: str = None
    uniqueness: str = None
    family: Family
    repository: Repository
    pluginInfo: str = None


class Plugins(BaseModel):
    requiredPorts: str = None
    requiredUDPPorts: str = None
    cpe: str | None = None
    srcPort: int | None = None
    dstPort: int | None = None
    protocol: str | None = None
    solution: str | None = None
    seeAlso: str | None = None
    synopsis: str | None = None
    checkType: str | None = None
    exploitEase: str | None = None
    exploitAvailable: bool | None = None
    exploitFrameworks: str | None = None
    cvssVector: str | None = None
    cvssVectorBF: int | None = None
    baseScore: float | None = None
    temporalScore: float | None = None
    cvssV3Vector: float | str | None = None
    cvssV3VectorBF: int | None = None
    cvssV3BaseScore: float | None = None
    cvssV3TemporalScore: float | None = None
    vprScore: float | None = None
    vprContext: str | None = None
    stigSeverity: str | None = None
    pluginPubDate: int = None
    pluginModDate: int = None
    patchPubDate: int = None
    patchModDate: int = None
    vulnPubDate: int = None
    name: str = None
    description: str = None
    id: int = None
    family: Family


class Solutions(BaseModel):
    solutionID: str
    cpe: str
    solution: str
    remediationList: str
    total: int | None
    totalPctg: str | None
    scorePctg: str | None
    hostTotal: int | None
    msbulletinTotal: int | None
    cveTotal: int | None
    vprScore: float | None
    cvssV3BaseScore: Annotated[float, BeforeValidator(empty_to_zero)]
    pluginID: int


class Respository(BaseModel):
    id: int
    name: str
    description: str
    type: str
    vulnCount: int
    remoteIP: str
    uuid: str


class Assets(BaseModel):
    id: int
    description: str
    name: str
    type: str
    ipCount: int
    uuid: str
