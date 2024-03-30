## Data Model 


This project defines all SQL schemas as class with Object Relational Mapper provided by [SQLAlchemy ORM](https://docs.sqlalchemy.org/en/20/orm/). The advantage of this is the schemas are DB agnostic (Postgres, MSSQL, etc).   

[Alembic](https://alembic.sqlalchemy.org/en/latest/) is a lightweight database migration tool for usage with the SQLAlchemy Database Toolkit for Python. In order to keep track of changes to the database over time and update the schema it is going to be used to deploy changes with Azure pipelines to SQL.    
