from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from . import cvss

Base = declarative_base()


class CPETable(Base):
    __tablename__ = "CPE"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    FK_CVE = Column(String(60), ForeignKey(cvss.CVSSTable.CVE), nullable=False)

    CPE23URI = Column(String)
    Vulnerable = Column(Boolean)
