import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL


from utils.db import DataBaseConnection, build_sqlalchemy_connection


def get_url(port: int = 5432, host: str = "host.docker.internal") -> URL:
    connection_config = DataBaseConnection(
        host=host,
        database="master",
        user="SA",
        driver="ODBC Driver 17 for SQL Server",
        password="Secret1234",
    )

    url = build_sqlalchemy_connection(connection_config)

    return url


@pytest.fixture()
def engine():
    url = get_url()
    return create_engine(url)
