from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from . import transform_history

Base = declarative_base()


class CVSSTable(Base):
    __tablename__ = "CVSS"

    ID = Column(Integer, primary_key=True)
    CVE = Column(String(60), index=True, unique=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)
    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )

    AttackComplexity3 = Column(String)
    AttackVector3 = Column(String)
    AvailabilityImpact3 = Column(String)
    ConfidentialityImpact3 = Column(String)
    IntegrityImpact3 = Column(String)
    PrivilegesRequired3 = Column(String)
    Scope3 = Column(String)
    UserInteraction3 = Column(String)
    VectorString3 = Column(String)
    ExloitabilityScore3 = Column(Float)
    ImpactScore3 = Column(Float)
    BaseScore3 = Column(Float)
    BaseSeverity3 = Column(String)
    AccessComplexity = Column(String)
    AccessVector = Column(String)
    Authentication = Column(String)
    AvailabilityImpact = Column(String)
    ConfidentialityImpact = Column(String)
    IntegrityImpact = Column(String)
    ObtainAllPrivileges = Column(Boolean)
    ObtainOtherPrivileges = Column(Boolean)
    ObtainUserPrivileges = Column(Boolean)
    UserInteractionRequired = Column(Boolean)
    VectorString = Column(String)
    ExploitabilityScore = Column(Float)
    ImpactScore = Column(Float)
    BaseScore = Column(Float)
    Severity = Column(String)
    Description = Column(Text)
    PublishedDate = Column(DateTime)
    LastModifiedDate = Column(DateTime)

    Dataclass = Column(Text)
