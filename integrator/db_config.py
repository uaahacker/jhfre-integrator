import os
import pyodbc
import logging
from django.conf import settings
from .models import IntegrationCredential
from .integration_credentials import decrypt_credentials_for_runtime
from .query_execution import fetch_limited_rows, get_external_query_limits, raise_timeout_if_applicable
from .sql_policy import validate_read_only_query


logger = logging.getLogger(__name__)

def get_available_odbc_driver():
    """
    Get the best available ODBC driver for SQL Server.
    Returns the driver name or None if no compatible driver is found.
    """
    # Preferred drivers in order of preference
    preferred_drivers = [
        'ODBC Driver 18 for SQL Server',
        'ODBC Driver 17 for SQL Server', 
        'ODBC Driver 13 for SQL Server',
        'SQL Server'
    ]
    
    try:
        available_drivers = pyodbc.drivers()
        
        for driver in preferred_drivers:
            if driver in available_drivers:
                return driver
        
        # If no preferred driver is found, return the first SQL Server driver if any
        for driver in available_drivers:
            if 'SQL Server' in driver:
                return driver
        
        return None
    except Exception:
        logger.warning('ODBC driver detection failed.')
        return None

def should_use_mssql():
    """
    Determine if MSSQL should be used based on environment.
    Only use MSSQL in production or when explicitly configured.
    """
    # Check if we're in an environment that should use MSSQL
    app_env = os.environ.get('APP_ENV', 'local')
    
    # In local development with SQLite, skip MSSQL unless explicitly requested
    if app_env == 'local' and 'sqlite' in settings.DATABASES['default']['ENGINE']:
        return False
    
    # In development/production environments, use MSSQL if available
    return True

def get_mssql_connection(user):
    """
    Dynamically establish a connection to the MSSQL database.
    Returns None gracefully in environments where MSSQL is not available.
    """
    # Check if we should even attempt MSSQL connection
    if not should_use_mssql():
        logger.debug('MSSQL connection skipped in the local SQLite environment.')
        return None
    
    try:
        credential = IntegrationCredential.objects.filter(
            user=user,
            integration__name='Microsoft Database',
            enabled=True
        ).first()

        if not credential or not credential.credentials:
            logger.debug('MSSQL integration credentials are unavailable.')
            return None

        # Get the best available ODBC driver
        driver = get_available_odbc_driver()
        if not driver:
            available_drivers = pyodbc.drivers() if pyodbc else []
            logger.warning('No compatible ODBC driver was found.')
            # Don't raise exception - return None for graceful degradation
            return None

        limits = get_external_query_limits()
        # Build connection string with additional SSL/security options for different environments
        trust_cert = "yes" if os.environ.get('APP_ENV') in ['development', 'production'] else "no"
        
        credentials = decrypt_credentials_for_runtime(credential.integration.fields, credential.credentials)
        connection_string = (
            f"DRIVER={{{driver}}};"
            f"SERVER={credentials.get('host')},1433;"
            f"DATABASE={credentials.get('database', 'PMWEB')};"
            f"UID={credentials.get('username')};"
            f"PWD={credentials.get('password')};"
            f"TrustServerCertificate={trust_cert};"
            f"Connection Timeout={limits.connect_timeout};"
        )

        connection = pyodbc.connect(connection_string)
        logger.info('MSSQL connection established.')
        return connection

    except pyodbc.Error:
        logger.warning('MSSQL connection failed.')
        return None
    except Exception:
        logger.warning('Unexpected MSSQL connection failure.')
        return None


def fetch_mssql_data(user, query, *, max_rows=None, execution_context='administrative MSSQL browse'):
    """
    Fetch data from the MSSQL database using a provided query.
    Returns empty list gracefully if connection fails.
    """
    policy_result = validate_read_only_query(query)
    if not policy_result.allowed:
        logger.warning('Blocked MSSQL query by SQL policy (%s).', policy_result.code)
        return []

    limits = get_external_query_limits()
    row_limit = limits.admin_max_rows if max_rows is None else max_rows
    connection = get_mssql_connection(user)

    if connection:
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.timeout = limits.query_timeout
            cursor.execute(query)
            columns = [column[0] for column in cursor.description]
            rows, truncated = fetch_limited_rows(cursor, row_limit)
            data = [dict(zip(columns, row)) for row in rows]
            if truncated:
                logger.warning(
                    'External query results were truncated for %s at %s rows.',
                    execution_context,
                    row_limit,
                )
            connection.close()
            logger.info('MSSQL data fetched successfully (%s rows).', len(data))
            return data
        except Exception as e:
            try:
                raise_timeout_if_applicable(e)
            except Exception:
                logger.warning('MSSQL query timed out.')
            logger.warning('MSSQL data fetch failed.')
            if connection:
                connection.close()
            return []
        finally:
            if cursor:
                try:
                    cursor.close()
                except Exception:
                    logger.debug('MSSQL cursor did not close cleanly.')
    else:
        logger.warning('Unable to establish an MSSQL connection for the requested data.')
        # Return empty list instead of None for consistency
        return []


def test_mssql_connection(user):
    """
    Test MSSQL connection and return diagnostics.
    Useful for debugging connection issues.
    """
    diagnostics = {
        'environment': os.environ.get('APP_ENV', 'unknown'),
        'should_use_mssql': should_use_mssql(),
        'available_drivers': [],
        'selected_driver': None,
        'connection_successful': False,
        'error_message': None
    }
    
    try:
        diagnostics['available_drivers'] = list(pyodbc.drivers())
        diagnostics['selected_driver'] = get_available_odbc_driver()
        
        connection = get_mssql_connection(user)
        if connection:
            diagnostics['connection_successful'] = True
            connection.close()
        
    except Exception:
        diagnostics['error_message'] = 'MSSQL diagnostics failed.'
    
    return diagnostics
