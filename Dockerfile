# Python base (Debian 11 so MS ODBC repo matches)
FROM python:3.11-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps + PG 16 client + MS ODBC 17
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        gnupg2 \
        ca-certificates \
        apt-transport-https \
        lsb-release \
        unixodbc \
        unixodbc-dev \
        libxml2-dev \
        libxslt1-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        pkg-config \
        zlib1g-dev && \
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl -fsSL https://packages.microsoft.com/config/debian/11/prod.list \
         > /etc/apt/sources.list.d/mssql-release.list && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt bullseye-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql17 postgresql-client-16 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --no-binary=lxml,xmlsec -r requirements.txt

COPY . .

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Environment variables (can be overridden by Coolify)
ENV APP_ENV=development
EXPOSE 8001
CMD ["/app/entrypoint.sh"]
