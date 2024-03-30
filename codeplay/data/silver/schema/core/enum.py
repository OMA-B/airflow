from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class EnumSourceTool(Base):
    __tablename__ = "EnumSourceTool"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    EnumName = Column(String, nullable=False)


class EnumVulnerability(Base):
    __tablename__ = "EnumVulnerability"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    EnumName = Column(String, primary_key=True)
