"""Bounded external SQL execution settings and small driver-agnostic helpers."""

from dataclasses import dataclass
import os
import re


DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_QUERY_TIMEOUT = 30
DEFAULT_ADMIN_MAX_ROWS = 500
DEFAULT_DYNAMIC_DROPDOWN_MAX_ROWS = 100
DEFAULT_PROCEDURE_MAX_ROWS_PER_RESULT_SET = 100
DEFAULT_PROCEDURE_MAX_RESULT_SETS = 5
DEFAULT_PROCEDURE_MAX_TOTAL_ROWS = 500

APPLICATION_POLICY_ONLY = 'APPLICATION_POLICY_ONLY'
TRANSACTION_READ_ONLY_ENFORCED = 'TRANSACTION_READ_ONLY_ENFORCED'
UNSUPPORTED = 'UNSUPPORTED'


class ExternalQueryConfigurationError(ValueError):
    """Raised when an external-query environment setting is unsafe or malformed."""


class ExternalQueryTimeoutError(RuntimeError):
    """A redacted application exception for a driver-reported timeout."""


class ReadOnlyEnforcementError(RuntimeError):
    """Raised when a supported database cannot enter read-only mode safely."""


@dataclass(frozen=True)
class ExternalQueryLimits:
    connect_timeout: int
    query_timeout: int
    admin_max_rows: int
    dynamic_dropdown_max_rows: int


@dataclass(frozen=True)
class ProcedureExecutionLimits:
    connect_timeout: int
    procedure_timeout: int
    max_rows_per_result_set: int
    max_result_sets: int
    max_total_rows: int


def read_only_enforcement_status(connection_type: str) -> str:
    """Describe the actual protection available for the active connector type."""
    if connection_type in {'postgresql', 'mysql'}:
        return TRANSACTION_READ_ONLY_ENFORCED
    if connection_type == 'mssql':
        return APPLICATION_POLICY_ONLY
    return UNSUPPORTED


def establish_postgresql_read_only_transaction(connection) -> None:
    """Configure the next psycopg2 transaction as read-only before any SQL runs."""
    try:
        connection.set_session(readonly=True, autocommit=False)
    except Exception as exc:
        raise ReadOnlyEnforcementError('PostgreSQL read-only setup failed.') from exc


def establish_mysql_read_only_transaction(cursor) -> None:
    """Apply MySQL's next-transaction read-only mode before the application query."""
    try:
        cursor.execute('SET TRANSACTION READ ONLY')
    except Exception as exc:
        raise ReadOnlyEnforcementError('MySQL read-only setup failed.') from exc


def configure_postgresql_statement_timeout(cursor, query_timeout: int) -> None:
    """Set the current read-only PostgreSQL transaction's statement timeout."""
    cursor.execute('SET LOCAL statement_timeout = %s', (query_timeout * 1000,))


def parse_positive_int(value: str | None, *, default: int, name: str) -> int:
    """Accept only positive base-10 integer settings, falling back when unset."""
    if value is None:
        return default
    normalized = value.strip()
    if not re.fullmatch(r"[1-9][0-9]*", normalized):
        raise ExternalQueryConfigurationError(f"{name} must be a positive integer.")
    return int(normalized)


def get_external_query_limits(environ=None) -> ExternalQueryLimits:
    """Return fresh, strictly parsed limits so environment changes are never ignored."""
    environment = os.environ if environ is None else environ
    return ExternalQueryLimits(
        connect_timeout=parse_positive_int(
            environment.get('EXTERNAL_DB_CONNECT_TIMEOUT'),
            default=DEFAULT_CONNECT_TIMEOUT,
            name='EXTERNAL_DB_CONNECT_TIMEOUT',
        ),
        query_timeout=parse_positive_int(
            environment.get('EXTERNAL_DB_QUERY_TIMEOUT'),
            default=DEFAULT_QUERY_TIMEOUT,
            name='EXTERNAL_DB_QUERY_TIMEOUT',
        ),
        admin_max_rows=parse_positive_int(
            environment.get('EXTERNAL_DB_MAX_ROWS'),
            default=DEFAULT_ADMIN_MAX_ROWS,
            name='EXTERNAL_DB_MAX_ROWS',
        ),
        dynamic_dropdown_max_rows=parse_positive_int(
            environment.get('DYNAMIC_DROPDOWN_MAX_ROWS'),
            default=DEFAULT_DYNAMIC_DROPDOWN_MAX_ROWS,
            name='DYNAMIC_DROPDOWN_MAX_ROWS',
        ),
    )


def get_procedure_execution_limits(environ=None) -> ProcedureExecutionLimits:
    """Return fail-closed limits for approved procedure execution."""
    environment = os.environ if environ is None else environ
    query_limits = get_external_query_limits(environment)
    return ProcedureExecutionLimits(
        connect_timeout=query_limits.connect_timeout,
        procedure_timeout=parse_positive_int(
            environment.get('EXTERNAL_DB_PROCEDURE_TIMEOUT'),
            default=query_limits.query_timeout,
            name='EXTERNAL_DB_PROCEDURE_TIMEOUT',
        ),
        max_rows_per_result_set=parse_positive_int(
            environment.get('EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET'),
            default=DEFAULT_PROCEDURE_MAX_ROWS_PER_RESULT_SET,
            name='EXTERNAL_DB_PROCEDURE_MAX_ROWS_PER_RESULT_SET',
        ),
        max_result_sets=parse_positive_int(
            environment.get('EXTERNAL_DB_PROCEDURE_MAX_RESULT_SETS'),
            default=DEFAULT_PROCEDURE_MAX_RESULT_SETS,
            name='EXTERNAL_DB_PROCEDURE_MAX_RESULT_SETS',
        ),
        max_total_rows=parse_positive_int(
            environment.get('EXTERNAL_DB_PROCEDURE_MAX_TOTAL_ROWS'),
            default=DEFAULT_PROCEDURE_MAX_TOTAL_ROWS,
            name='EXTERNAL_DB_PROCEDURE_MAX_TOTAL_ROWS',
        ),
    )


def fetch_limited_rows(cursor, max_rows: int):
    """Fetch at most ``max_rows`` rows plus one sentinel without using fetchall()."""
    if max_rows <= 0:
        raise ValueError('max_rows must be positive.')
    rows = cursor.fetchmany(max_rows + 1)
    return rows[:max_rows], len(rows) > max_rows


def is_timeout_error(exc: Exception) -> bool:
    """Recognize common driver timeout signals without returning them to callers."""
    details = ' '.join(str(item) for item in getattr(exc, 'args', (exc,))).lower()
    return any(marker in details for marker in (
        'timeout', 'timed out', 'hyt00', 'hyt01', '57014', 'query_canceled',
    ))


def raise_timeout_if_applicable(exc: Exception) -> None:
    if is_timeout_error(exc):
        raise ExternalQueryTimeoutError('Database query timed out.') from exc
