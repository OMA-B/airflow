"""create account table

Revision ID: 4c45804e3e8f
Revises:
Create Date: 2023-10-12 19:55:54.574391

"""
from typing import Sequence, Union

from alembic import op

from data.silver.schema.core import cpe, cve_problem, cvss, cwe
from data.silver.schema.core.application import ApplicationTable
from data.silver.schema.core.enum import EnumSourceTool, EnumVulnerability
from data.silver.schema.core.finding import (
    FindingTable,
    FindingCVEJunctionTable,
    FindingCWEJunctionTable,
)
from data.silver.schema.core.host import HostTable
from data.silver.schema.core.location import LocationTable
from data.silver.schema.core.severity import SeverityTable
from data.silver.schema.core.transform_history import TransformHistoryTable
from data.silver.schema.providers.qualys import (
    QualysFindingTable,
    QualysKnowledgeBaseTable,
    QualysKnowledgeBaseVulnerabilitiesTable,
)
from data.silver.schema.providers.tenable import (
    TenableFindingsTable,
    TenablePluginsTable,
    TenableSolutionsTable,
    TenablePluginsVulnerabilityTable,
)

# revision identifiers, used by Alembic.
revision: str = "4c45804e3e8f"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    engine = op.get_bind()

    # Add models to Session so they're tracked
    EnumSourceTool().__table__.create(engine)
    EnumVulnerability().__table__.create(engine)
    SeverityTable().__table__.create(engine)
    LocationTable().__table__.create(engine)

    ApplicationTable().__table__.create(engine)
    HostTable().__table__.create(engine)
    TransformHistoryTable().__table__.create(engine)

    cvss.CVSSTable().__table__.create(engine)
    cve_problem.CVEProblemsTable().__table__.create(engine)
    cpe.CPETable().__table__.create(engine)
    cwe.CWETable().__table__.create(engine)

    FindingTable().__table__.create(engine)

    QualysKnowledgeBaseTable().__table__.create(engine)
    QualysKnowledgeBaseVulnerabilitiesTable().__table__.create(engine)
    QualysFindingTable().__table__.create(engine)
    FindingCVEJunctionTable().__table__.create(engine)
    FindingCWEJunctionTable().__table__.create(engine)

    TenablePluginsTable().__table__.create(engine)
    TenablePluginsVulnerabilityTable.__table__.create(engine)
    TenableSolutionsTable().__table__.create(engine)
    TenableFindingsTable().__table__.create(engine)


def downgrade() -> None:
    engine = op.get_bind()

    # Perform ORM logic in downgrade (e.g. clear tables)
    TenableSolutionsTable().__table__.drop(engine)
    TenableFindingsTable().__table__.drop(engine)
    TenablePluginsVulnerabilityTable.__table__.drop(engine)
    TenablePluginsTable().__table__.drop(engine)

    cvss.CVSSTable().__table__.drop(engine)
    cve_problem.CVEProblemsTable().__table__.drop(engine)
    cpe.CPETable().__table__.drop(engine)
    cpe.CPETable().__table__.drop(engine)
    cwe.CWETable().__table__.drop(engine)

    FindingCVEJunctionTable().__table__.drop(engine)
    FindingCWEJunctionTable().__table__.drop(engine)
    QualysFindingTable().__table__.drop(engine)
    QualysKnowledgeBaseTable().__table__.drop(engine)
    QualysKnowledgeBaseVulnerabilitiesTable().__table__.drop(engine)

    FindingTable().__table__.drop(engine)
    TransformHistoryTable().__table__.drop(engine)
    HostTable().__table__.drop(engine)
    ApplicationTable().__table__.drop(engine)
    LocationTable().__table__.drop(engine)
    SeverityTable().__table__.drop(engine)
    EnumSourceTool().__table__.drop(engine)
    EnumVulnerability().__table__.create(engine)
