# Python base (Debian 11 so MS ODBC repo matches)
FROM python:3.11-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps + PG 16 client + MS ODBC 17 + XML/SAML toolchain
#
# libxml2-dev / libxslt1-dev / libxmlsec1-dev / libxmlsec1-openssl / pkg-config
# / zlib1g-dev are required so that lxml and xmlsec (both used by
# python3-saml for SSO) are compiled from source against the SAME system
# libxml2 below -- see the PIP_NO_BINARY note further down for why.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl gnupg2 ca-certificates apt-transport-https lsb-release \
        unixodbc unixodbc-dev \
        pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl zlib1g-dev && \
    # MS ODBC repo (for pyodbc/MSSQL if you need it)
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl -fsSL https://packages.microsoft.com/config/debian/11/prod.list \
         > /etc/apt/sources.list.d/mssql-release.list && \
    # PostgreSQL PGDG repo for pg_dump 16
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt bullseye-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql17 postgresql-client-16 && \
    # Verify ODBC driver installation
    odbcinst -q -d && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# lxml publishes a manylinux wheel with its OWN statically bundled libxml2.
# xmlsec (pyxmlsec) builds against the system libxmlsec1, which links the
# system libxml2 installed above. Mixing the two ABIs is exactly the
# "lxml & xmlsec libxml2 library version mismatch" failure seen at SAML
# runtime -- installing lxml's prebuilt wheel silently sets that trap.
# Forcing both packages to build from source here makes them share the one
# system libxml2, so they are guaranteed ABI-compatible.
#
# requirements.txt pins xmlsec<1.3.14 deliberately: pyxmlsec >=1.3.14
# requires the xmlsec1 C library >=1.3.x, which is NOT available via apt on
# Debian bullseye (system libxmlsec1-dev is 1.2.31) or even bookworm
# (1.2.37) -- only Debian sid/experimental carry it. Building >=1.3.14 from
# source on this base image fails with
# "'xmlSecKeyDataFormatEngine' undeclared". python3-saml==1.16.0 only
# requires xmlsec>=1.3.9, so the older pin is fully compatible.
RUN pip install --upgrade pip && \
    PIP_NO_BINARY=lxml,xmlsec pip install --no-cache-dir -r requirements.txt

# Fail the build here, not at first login in production, if the XML/SAML
# stack ended up broken.
RUN python -c "import xmlsec; from lxml import etree; print('XML stack OK - libxml2', etree.LIBXML_VERSION, '- xmlsec', xmlsec.__version__)"

COPY . .

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Environment variables (can be overridden by Coolify)
ENV APP_ENV=development
EXPOSE 8001
CMD ["/app/entrypoint.sh"]
