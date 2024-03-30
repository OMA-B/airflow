from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from data.silver.schema.core import finding, host, enum, transform_history

Base = declarative_base()


class QualysKnowledgeBaseTable(Base):
    __tablename__ = "QualysKnowledgeBase"

    ID = Column(BigInteger, nullable=False, index=True)
    QID = Column(BigInteger, primary_key=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    VulnType = Column(String)
    SeverityLevel = Column(Integer)
    Title = Column(String)
    Category = Column(String)
    Software_list = Column(Text)
    Diagnosis = Column(Text)
    Consequence = Column(Text)
    Solution = Column(Text)
    CVSS = Column(Text)
    CVSSV3 = Column(Text)
    PciFlag = Column(Integer)
    ThreatIntelligence = Column(Text)
    Discovery = Column(Text)

    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )

    Dataclass = Column(Text)


class QualysKnowledgeBaseVulnerabilitiesTable(Base):
    __tablename__ = "QualysKnowledgeBaseVulnerability"

    ID = Column(BigInteger, primary_key=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    FK_QID = Column(BigInteger, ForeignKey(QualysKnowledgeBaseTable.QID))
    FK_VulnerabilityID = Column(Integer, ForeignKey(enum.EnumVulnerability.ID))
    Value = Column(String)


class QualysFindingTable(Base):
    __tablename__ = "QualysFinding"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    ## Foreign Keys
    FK_FindingsID = Column(
        BigInteger, ForeignKey(finding.FindingTable.ID), nullable=False
    )
    FK_HostID = Column(BigInteger, ForeignKey(host.HostTable.ID), nullable=False)
    FK_QID = Column(BigInteger, ForeignKey(QualysKnowledgeBaseTable.QID))

    SeverityLevel = Column(String)
    SSL = Column(Integer)
    Status = Column(String)
    Results = Column(String)
    UniqueVulnID = Column(Integer)

    Dataclass = Column(Text)
