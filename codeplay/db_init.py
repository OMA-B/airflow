import logging

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL

from utils.db import DataBaseConnection, build_sqlalchemy_connection

logging.basicConfig()

LOGGER = logging.getLogger("aperture.deployment")
LOGGER.setLevel(logging.INFO)


def get_url(port: int = 1433, host: str = "host.docker.internal") -> URL:
    return URL.create(
        "mssql+pyodbc",
        username="sa",
        password="Secret1234",
        host=host,
        port=port,
        database="master",
    )


def upgrade_database() -> None:
    config = Config("/workspace/data/silver/alembic.ini")
    config.set_main_option("script_location", "/workspace/data/silver/alembic")

    connection_config = DataBaseConnection(
        host="host.docker.internal",
        database="master",
        user="SA",
        driver="ODBC Driver 17 for SQL Server",
        password="Secret1234",
    )

    url = build_sqlalchemy_connection(connection_config)
    config.set_main_option("sqlalchemy.url", url)
    engine = create_engine(url)

    LOGGER.info(f"Database Upgrading... {config}")
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        command.upgrade(config, "head", sql=False)


if __name__ == "__main__":
    upgrade_database()
