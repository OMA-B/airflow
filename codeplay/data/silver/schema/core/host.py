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

from . import application, enum, location

Base = declarative_base()


# an example mapping using the base
class HostTable(Base):
    __tablename__ = "Host"

    ID = Column(BigInteger, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    FK_SourceToolID = Column(
        Integer, ForeignKey(enum.EnumSourceTool.ID), nullable=False
    )

    Name = Column(String)
    HostName = Column(String)
    URL = Column(String)
    Domain = Column(String)
    IPV4Address = Column(String(length=15))
    IPV6Address = Column(String(length=45))
    Port = Column(Integer)
    MACAddress = Column(String)
    DNS = Column(String)
    Protocol = Column(String)
    NetBios = Column(String)

    FK_LocationID = Column(Integer, ForeignKey(location.LocationTable.ID))
    FK_ApplicationID = Column(Integer, ForeignKey(application.ApplicationTable.ID))
