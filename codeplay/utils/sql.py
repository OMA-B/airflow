COLUMN_EXISTS = """
IF EXISTS (
	SELECT 1
	FROM sys.columns
	where object_id = object_id('{table}')
	and name = '{column}'
)
	SELECT 1 AS ColExists 
ELSE 
	SELECT 0 AS ColExists
"""


def query_exists(table: str, column: str) -> str:
    return COLUMN_EXISTS.format(table, column)
