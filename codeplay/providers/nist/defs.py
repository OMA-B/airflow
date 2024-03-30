from typing import List

from pydantic import BaseModel


class ProblemType(BaseModel):
    problemtype_data: List[dict] | None


class CVEDataMeta(BaseModel):
    ID: str | None
    ASSIGNER: str | None


class ReferenceData(BaseModel):
    url: str | None
    name: str | None
    refsource: str | None
    tags: List[str] | None


class References(BaseModel):
    reference_data: List[ReferenceData]


class DescriptionData(BaseModel):
    lang: str | None
    value: str | None


class Description(BaseModel):
    description_data: List[DescriptionData]


class CvssV3(BaseModel):
    version: float | None = None
    vectorString: str | None = None
    attackVector: str | None = None
    attackComplexity: str | None = None
    privilegesRequired: str | None = None
    userInteraction: str | None = None
    scope: str | None = None
    confidentialityImpact: str | None = None
    integrityImpact: str | None = None
    availabilityImpact: str | None = None
    baseScore: float | None = None
    baseSeverity: str | None = None


class BaseMetricV3(BaseModel):
    cvssV3: CvssV3
    exploitabilityScore: float | None
    impactScore: float | None
    impactScore: float | None


class CvssV2(BaseModel):
    version: float | None
    vectorString: str | None = None
    accessVector: str | None = None
    accessComplexity: str | None = None
    authentication: str | None = None
    confidentialityImpact: str | None = None
    integrityImpact: str | None = None
    availabilityImpact: str | None = None
    baseScore: float | None = None


class BaseMetricV2(BaseModel):
    cvssV2: CvssV2
    severity: str | None = None
    exploitabilityScore: float | None = None
    impactScore: float | None = None
    obtainAllPrivilege: bool | None = None
    obtainUserPrivilege: bool | None = None
    obtainOtherPrivilege: bool | None = None
    userInteractionRequired: bool | None = None


class Impact(BaseModel):
    baseMetricV3: BaseMetricV3 = None
    baseMetricV2: BaseMetricV2 = None


class Configurations(BaseModel):
    CVE_data_version: float | None
    nodes: list


class CveBase(BaseModel):
    data_type: str | None
    data_format: str | None
    CVE_data_meta: CVEDataMeta
    problemtype: ProblemType
    references: References
    description: Description


class CVE(BaseModel):
    cve: CveBase
    configurations: Configurations
    impact: Impact
    publishedDate: str
    lastModifiedDate: str


class CWE(BaseModel):
    id: str
    name: str | None
    weakness: str | None
    abstraction: str | None
    status: str | None
    description: str | None
    extended_description: str | None
    related_weaknesses: str | None
    weakness_ordinalities: str | None
    applicable_platforms: str | None
    background_details: str | None
    alternate_terms: str | None
    modes_of_introduction: str | None
    exploitation_factors: str | None
    likelihood_of_exploit: str | None
    common_consequences: str | None
    detection_methods: str | None
    potential_mitigations: str | None
    observed_examples: str | None
    functional_areas: str | None
    affected_resources: str | None
    taxonomy_mappings: str | None
    related_attack_patterns: str | None
    notes: str | None
