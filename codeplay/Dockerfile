FROM python:3.10.8-slim AS base

RUN apt update && \
    apt install -y --no-install-recommends python3-pip && \
    apt install bash-completion && \
    apt install nano && \
    apt install -y --no-install-recommends libpq-dev python3-dev && \
    apt install -y build-essential curl gnupg libsasl2
    
# Microsoft ODBC 17 installation for Debian
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt update && ACCEPT_EULA=Y apt-get install -y msodbcsql17 \
    && apt install -y --no-install-recommends unixodbc-dev



RUN python3 -m pip install --upgrade pip
RUN pip3 install -U pip setuptools

RUN pip3 install poetry-core
RUN pip3 install poetry

RUN pip3 install appdirs==1.4.4

RUN pip3 config set global.timeout 600  

# Install git
RUN apt-get update --fix-missing
RUN apt-get install -y git

# Change ownership of files to solve container ID issue
# (https://stackoverflow.com/questions/60958053/bitbucket-pipeline-with-docker-compose-container-id-166535-cannot-be-mapped-to)
RUN chown -R root:root /usr/local/lib/python*

WORKDIR /workspace

COPY . .

RUN poetry install -vv # --no-dev
