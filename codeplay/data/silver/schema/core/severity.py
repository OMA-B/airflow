from sqlalchemy import Boolean, Column, Float, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class SeverityTable(Base):
    __tablename__ = "Severity"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    Name = Column(String, nullable=False)
    Value = Column(Float, nullable=False)
    Description = Column(String)
    IsInternal = Column(Boolean, nullable=False)
