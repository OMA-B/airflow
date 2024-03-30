from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from . import transform_history

Base = declarative_base()


class CWETable(Base):
    __tablename__ = "CWE"

    ID = Column(Integer, primary_key=True)
    CWE = Column(String(60), index=True, unique=True)

    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)
    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )

    Name = Column(Text, nullable=False)
    Weakness = Column(Text)
    Abstraction = Column(Text)
    Status = Column(Text)
    Description = Column(Text)
    ExtendedDescription = Column(Text)
    RelatedWeaknesses = Column(Text)
    WeaknessOrdinalities = Column(Text)
    ApplicablePlatforms = Column(Text)
    BackgroundDetails = Column(Text)
    AlternateTerms = Column(Text)
    ModesOfIntroduction = Column(Text)
    ExploitationFactors = Column(Text)
    LikelihoodOfExploit = Column(Text)
    CommonConsequences = Column(Text)
    DetectionMethods = Column(Text)
    PotentialMitigations = Column(Text)
    ObservedExamples = Column(Text)
    FunctionalAreas = Column(Text)
    AffectedResources = Column(Text)
    TaxonomyMappings = Column(Text)
    RelatedAttackPatterns = Column(Text)
    Notes = Column(Text)

    Dataclass = Column(Text)
