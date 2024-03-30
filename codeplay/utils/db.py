from typing import Tuple
from dataclasses import dataclass

from sqlalchemy import insert, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession
import pandas as pd
import logging
import json


LOGGER = logging.getLogger(__name__)


@dataclass
class DataBaseConnection:
    host: str
    database: str
    user: str
    driver: str
    password: str


def build_db_connection(config: DataBaseConnection) -> str:
    base_str = ";".join(
        [
            f"DRIVER={{{config.driver}}}",
            f"SERVER={{{config.host}}}",
            f"DATABASE={{{config.database}}}",
            f"UID={{{config.user}}}",
            f"PWD={{{config.password}}}",
        ]
    )

    return base_str


def build_sqlalchemy_connection(config: DataBaseConnection) -> str:
    url_str = build_db_connection(config)
    return f"mssql+pyodbc:///?odbc_connect={url_str}"


class DatabaseManager:
    def __init__(self, engine=None, async_engine=None) -> None:
        self.engine = engine
        self.async_engine = async_engine

        if self.engine:
            self.session = sessionmaker(bind=self.engine)()
        elif self.async_engine:
            self.async_session = sessionmaker(
                async_engine, expire_on_commit=False, class_=AsyncSession
            )

    def single_insert(
        self, table: object, check_exist: True = True, debug: bool = False, **kwargs
    ) -> Tuple[None | int, bool]:
        if check_exist:
            existing_obj = self.session.query(table).filter_by(**kwargs).first()

            if existing_obj:
                return existing_obj, False

        orm_obj = table(**kwargs)

        if debug:
            LOGGER.warning(orm_obj.__table__.insert())
            LOGGER.warning(json.dumps(kwargs, indent=4))

        self.session.add(orm_obj)
        self.session.commit()
        return orm_obj, True

    def bulk_insert(self, table, data, return_data: bool = False):
        if isinstance(data, dict):
            data = [data]

        with self.engine.connect() as conn:
            if return_data:
                result = conn.execute(
                    insert(table).returning(table),
                    data,
                )
                conn.commit()
                return result
            else:
                result = conn.execute(
                    insert(table),
                    data,
                )
                conn.commit()
                return None

    def select_first(self, table, **kwargs) -> Tuple[None | object]:
        existing_obj = self.session.query(table).filter_by(**kwargs).first()
        return existing_obj or None

    def select_all(self, table, **kwargs) -> Tuple[None | object]:
        existing_obj = self.session.query(table).filter_by(**kwargs).all()
        return existing_obj or None

    def exists(self, table, **kwargs) -> bool:
        return self.select_first(table, **kwargs) is not None

    def query(
        self, query_text: str, no_return: bool = False, **params
    ) -> pd.DataFrame | None:
        if isinstance(query_text, str):
            query_text = text(query_text)

        with self.engine.connect() as conn:
            if no_return is False:
                data = pd.read_sql_query(sql=query_text, con=conn, params=params)
            else:
                conn.execute(sql=query_text, vars=params)
                data = None

            conn.commit()

        return data
