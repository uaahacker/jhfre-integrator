import logging

import pyodbc
import pymysql
import psycopg2
import psycopg2.extras

from .models import DatabaseConnection, Integration, IntegrationCredential
from .integration_credentials import decrypt_credentials_for_runtime
from .query_execution import (
    configure_postgresql_statement_timeout,
    establish_mysql_read_only_transaction,
    establish_postgresql_read_only_transaction,
    fetch_limited_rows,
    get_external_query_limits,
    raise_timeout_if_applicable,
)
from .sql_policy import require_read_only_query


logger = logging.getLogger(__name__)


def _close_quietly(resource):
    if resource is not None:
        try:
            resource.close()
        except Exception:
            logger.debug('External database resource did not close cleanly.', exc_info=True)


def _rollback_quietly(connection):
    if connection is not None:
        try:
            connection.rollback()
        except Exception:
            logger.debug('External database transaction did not roll back cleanly.', exc_info=True)


def _warn_if_truncated(truncated, max_rows, execution_context):
    if truncated:
        logger.warning(
            'External query results were truncated for %s at %s rows.',
            execution_context,
            max_rows,
        )


def fetch_data_from_connection(user, connection_id, query, *, max_rows=None, execution_context='external query'):
    """Fetch bounded data from a saved connection using only approved SQL text."""
    require_read_only_query(query)
    limits = get_external_query_limits()
    row_limit = limits.admin_max_rows if max_rows is None else max_rows

    try:
        if user.is_superuser or user.is_staff:
            connection = DatabaseConnection.objects.get(id=connection_id, is_active=True)
        else:
            connection = DatabaseConnection.objects.get(id=connection_id, user=user)

        results = []
        if connection.connection_type == 'mssql':
            drivers_to_try = [
                'ODBC Driver 17 for SQL Server',
                'ODBC Driver 18 for SQL Server',
                'ODBC Driver 13 for SQL Server',
                'SQL Server Native Client 11.0',
                'SQL Server',
            ]
            connection_successful = False
            for driver in drivers_to_try:
                conn = cursor = None
                try:
                    conn_string = (
                        f'DRIVER={{{driver}}};SERVER={connection.server},{connection.port};'
                        f'DATABASE={connection.database_name};UID={connection.username};'
                        f'PWD={connection.get_password()};Connection Timeout={limits.connect_timeout};'
                    )
                    conn = pyodbc.connect(conn_string)
                    cursor = conn.cursor()
                    cursor.timeout = limits.query_timeout
                    cursor.execute(query)
                    columns = [column[0] for column in cursor.description]
                    rows, truncated = fetch_limited_rows(cursor, row_limit)
                    results = [dict(zip(columns, row)) for row in rows]
                    _warn_if_truncated(truncated, row_limit, execution_context)
                    connection_successful = True
                    break
                except Exception as driver_error:
                    raise_timeout_if_applicable(driver_error)
                finally:
                    _close_quietly(cursor)
                    _close_quietly(conn)

            if not connection_successful:
                raise Exception('No compatible ODBC driver found for SQL Server connection')

        elif connection.connection_type == 'mysql':
            conn = cursor = None
            read_only_transaction = False
            try:
                conn = pymysql.connect(
                    host=connection.server,
                    port=int(connection.port),
                    user=connection.username,
                    password=connection.get_password(),
                    database=connection.database_name,
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=limits.connect_timeout,
                    read_timeout=limits.query_timeout,
                    write_timeout=limits.query_timeout,
                    autocommit=False,
                )
                cursor = conn.cursor()
                establish_mysql_read_only_transaction(cursor)
                read_only_transaction = True
                cursor.execute(query)
                results, truncated = fetch_limited_rows(cursor, row_limit)
                _warn_if_truncated(truncated, row_limit, execution_context)
            except Exception as exc:
                raise_timeout_if_applicable(exc)
                raise
            finally:
                _close_quietly(cursor)
                if read_only_transaction:
                    _rollback_quietly(conn)
                _close_quietly(conn)

        elif connection.connection_type == 'postgresql':
            conn = cursor = None
            read_only_transaction = False
            try:
                conn = psycopg2.connect(
                    host=connection.server,
                    port=connection.port,
                    user=connection.username,
                    password=connection.get_password(),
                    dbname=connection.database_name,
                    connect_timeout=limits.connect_timeout,
                )
                establish_postgresql_read_only_transaction(conn)
                read_only_transaction = True
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                configure_postgresql_statement_timeout(cursor, limits.query_timeout)
                cursor.execute(query)
                result_tuples, truncated = fetch_limited_rows(cursor, row_limit)
                results = [dict(row) for row in result_tuples]
                _warn_if_truncated(truncated, row_limit, execution_context)
            except Exception as exc:
                raise_timeout_if_applicable(exc)
                raise
            finally:
                _close_quietly(cursor)
                if read_only_transaction:
                    _rollback_quietly(conn)
                _close_quietly(conn)

        return results
    except DatabaseConnection.DoesNotExist:
        raise Exception('Database connection not found or you do not have permission to use it.')


def fetch_data_from_integration(user, integration_id, query, *, max_rows=None, execution_context='external query'):
    """Fetch bounded data from an integration credential using approved SQL text."""
    require_read_only_query(query)
    limits = get_external_query_limits()
    row_limit = limits.admin_max_rows if max_rows is None else max_rows

    try:
        integration = Integration.objects.get(id=integration_id)
        if user.is_superuser or user.is_staff:
            credential = IntegrationCredential.objects.filter(
                integration=integration,
                enabled=True,
            ).first()
        else:
            credential = IntegrationCredential.objects.get(
                user=user,
                integration=integration,
                enabled=True,
            )

        if not credential or not credential.credentials:
            raise Exception('No enabled database credentials found for this integration.')

        from .db_config import get_available_odbc_driver, should_use_mssql

        if not should_use_mssql():
            return []

        creds = decrypt_credentials_for_runtime(integration.fields, credential.credentials)
        host = creds.get('host')
        database = creds.get('database')
        username = creds.get('username')
        password = creds.get('password')
        if not all([host, database, username, password]):
            raise Exception('Incomplete database credentials in integration.')

        driver = get_available_odbc_driver()
        if not driver:
            raise Exception('No compatible ODBC driver found.')

        import os
        trust_cert = 'yes' if os.environ.get('APP_ENV') in ['development', 'production'] else 'no'
        connection_string = (
            f'DRIVER={{{driver}}};SERVER={host},1433;DATABASE={database};UID={username};'
            f'PWD={password};TrustServerCertificate={trust_cert};'
            f'Connection Timeout={limits.connect_timeout};'
        )

        conn = cursor = None
        try:
            conn = pyodbc.connect(connection_string)
            cursor = conn.cursor()
            cursor.timeout = limits.query_timeout
            cursor.execute(query)
            columns = [column[0] for column in cursor.description]
            rows, truncated = fetch_limited_rows(cursor, row_limit)
            results = [dict(zip(columns, row)) for row in rows]
            _warn_if_truncated(truncated, row_limit, execution_context)
            return results
        except Exception as exc:
            raise_timeout_if_applicable(exc)
            raise
        finally:
            _close_quietly(cursor)
            _close_quietly(conn)
    except (Integration.DoesNotExist, IntegrationCredential.DoesNotExist):
        raise Exception('Integration not found or you do not have permission to use it.')
