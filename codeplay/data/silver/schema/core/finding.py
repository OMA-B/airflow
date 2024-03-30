from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from data.silver.schema.core import cvss, cwe, host, severity, transform_history

Base = declarative_base()


class FindingTable(Base):
    __tablename__ = "Finding"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    Name = Column(String, nullable=False)
    Description = Column(String)

    ## Foreign Keys
    FK_SeverityID = Column(
        Integer, ForeignKey(severity.SeverityTable.ID), nullable=False
    )
    FK_HostID = Column(BigInteger, ForeignKey(host.HostTable.ID), nullable=False)
    FK_RunID = Column(
        Integer, ForeignKey(transform_history.TransformHistoryTable.RunID)
    )


class FindingCVEJunctionTable(Base):
    __tablename__ = "FindingCVE"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    modified_at = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    ## Foreign Keys
    FK_FindingID = Column(BigInteger, ForeignKey(FindingTable.ID))
    FK_CVEID = Column(Integer, ForeignKey(cvss.CVSSTable.ID))


class FindingCWEJunctionTable(Base):
    __tablename__ = "FindingCWE"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    ## Foreign Keys
    FK_FindingID = Column(BigInteger, ForeignKey(FindingTable.ID))
    FK_CWEID = Column(Integer, ForeignKey(cwe.CWETable.ID))
