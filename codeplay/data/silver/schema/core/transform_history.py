from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
from data.silver.schema.core import enum

Base = declarative_base()


class EnumTransformStatus(Base):
    __tablename__ = "EnumSourceTool"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    NAME = Column(String, nullable=False)


class TransformHistoryTable(Base):
    __tablename__ = "ProcessHistory"

    RunID = Column(Integer, primary_key=True, autoincrement=True)
    Tombstone = Column(Boolean)

    ## Foreign Keys
    FK_SourceToolID = Column(
        Integer, ForeignKey(enum.EnumSourceTool.ID), nullable=False
    )

    ProccessName = Column(String, nullable=False)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    StartDatetime = Column(DateTime)
    EndDatetime = Column(DateTime)
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    FindingCount = Column(Integer)
    ErrorCount = Column(Integer)
    ErrorMessages = Column(Text)
    DuplicateCount = Column(Integer)
    Filename = Column(String)
