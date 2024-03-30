from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
import uuid
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from data.silver.schema.core import finding, host, enum, transform_history

Base = declarative_base()


class TenablePluginsTable(Base):
    __tablename__ = "TenablePlugin"

    PluginID = Column(BigInteger, primary_key=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    RequiredPorts = Column(String)
    RequiredUDPPorts = Column(String)
    CPE = Column(String)
    SRCPort = Column(String)
    DSTPort = Column(String)
    Protocol = Column(String)
    Solution = Column(String)
    SeeAlso = Column(String)
    Synopsis = Column(String)
    CheckType = Column(String)
    ExploitEase = Column(String)
    ExploitAvailable = Column(Boolean)
    ExploitFrameworks = Column(String)
    CVSSVector = Column(String)
    CVSSVectorBf = Column(Float)
    BaseScore = Column(Float)
    TemporalScore = Column(Float)
    CVSSV3Vector = Column(String)
    CVSSV3VectorBf = Column(Float)
    CVSSV3BaseScore = Column(Float)
    CVSSV3TemporalScore = Column(Float)
    VprScore = Column(Float)
    VprContext = Column(Text)
    StigSeverity = Column(Text)
    PluginPubDate = Column(Integer)
    PluginModDate = Column(Integer)
    PatchPubDate = Column(Integer)
    PatchModDate = Column(Integer)
    VulnPubDate = Column(Integer)
    Description = Column(Text)
    FamilyID = Column(Integer)
    FamilyName = Column(String)
    FamilyType = Column(String)

    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )

    Dataclass = Column(Text)


class TenablePluginsVulnerabilityTable(Base):
    __tablename__ = "TenablePluginVulnerability"

    ID = Column(BigInteger, primary_key=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    FK_PluginID = Column(BigInteger, ForeignKey(TenablePluginsTable.PluginID))
    FK_VulnerabilityID = Column(Integer, ForeignKey(enum.EnumVulnerability.ID))
    Value = Column(String)


class TenableFindingsTable(Base):
    __tablename__ = "TenableFinding"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    ## Foreign Keys
    FK_FindingID = Column(
        BigInteger, ForeignKey(finding.FindingTable.ID), nullable=False
    )

    FK_HostID = Column(BigInteger, ForeignKey(host.HostTable.ID), nullable=False)
    FK_PluginID = Column(
        BigInteger, ForeignKey(TenablePluginsTable.PluginID), nullable=False
    )

    Name = Column(String)
    SeverityName = Column(String)
    SeverityDescription = Column(String)
    UUID = Column(
        "UUID", Text(length=36), default=lambda: str(uuid.uuid4()), primary_key=True
    )
    Dataclass = Column(Text)


class TenableSolutionsTable(Base):
    __tablename__ = "TenableSolution"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    SolutionID = Column(String)
    CPE = Column(String)
    Solution = Column(Text)
    RemediationList = Column(Text)
    Total = Column(Integer)
    TotalPctg = Column(String)
    ScorePctg = Column(String)
    HostTotal = Column(Integer)
    MSBulletInTotal = Column(Integer)
    CVETotal = Column(Integer)
    VPRScore = Column(Float)
    CVSSV3BaseScore = Column(Float)

    ## Foreign Keys
    FK_PluginID = Column(BigInteger, ForeignKey(TenablePluginsTable.PluginID))
    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )

    Dataclass = Column(Text)
