from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class LocationTable(Base):
    __tablename__ = "Location"

    ID = Column(Integer, primary_key=True, autoincrement=True)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.now())
    ModifiedAt = Column(DateTime, nullable=False, server_default=func.now())
    Tombstone = Column(Boolean)

    Name = Column(String, nullable=False)
    Description = Column(String)
