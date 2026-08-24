"""Server-side validation and invocation helpers for approved stored procedures."""

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import re

from .models import ApprovedProcedure, ApprovedProcedureParameter


class ProcedureExecutionValidationError(ValueError):
    """Raised when an approved procedure request is not safe to execute."""


_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_$#]*$')

_INTEGER_TYPES = {'int', 'integer', 'smallint', 'bigint', 'tinyint', 'int2', 'int4', 'int8'}
_DECIMAL_TYPES = {'decimal', 'numeric', 'number', 'money', 'smallmoney'}
_STRING_TYPES = {
    'char', 'nchar', 'varchar', 'nvarchar', 'text', 'ntext', 'tinytext', 'mediumtext',
    'longtext', 'character varying', 'character', 'string',
}
_BOOLEAN_TYPES = {'bool', 'boolean', 'bit'}
_DATE_TYPES = {'date'}
_DATETIME_TYPES = {
    'datetime', 'datetime2', 'smalldatetime', 'timestamp', 'timestamp without time zone',
    'timestamp with time zone', 'timestamptz',
}


def _normalized_type(database_type):
    return ' '.join(database_type.lower().strip().split()).split('(', 1)[0].strip()


def parameter_type_category(database_type):
    """Return the conservative, supported binding category for an approved DB type."""
    normalized = _normalized_type(database_type)
    if normalized in _INTEGER_TYPES:
        return 'integer'
    if normalized in _DECIMAL_TYPES:
        return 'decimal'
    if normalized in _STRING_TYPES:
        return 'string'
    if normalized in _BOOLEAN_TYPES:
        return 'boolean'
    if normalized in _DATE_TYPES:
        return 'date'
    if normalized in _DATETIME_TYPES:
        return 'datetime'
    raise ProcedureExecutionValidationError('Unsupported approved parameter type.')


def require_safe_identifier(identifier):
    if not isinstance(identifier, str) or not _IDENTIFIER_RE.fullmatch(identifier):
        raise ProcedureExecutionValidationError('Approved procedure identity is invalid.')
    return identifier


def quote_identifier(engine, identifier):
    """Quote a previously validated server-side identifier for the target engine."""
    identifier = require_safe_identifier(identifier)
    if engine == 'mssql':
        return f'[{identifier}]'
    if engine == 'mysql':
        return f'`{identifier}`'
    if engine == 'postgresql':
        return f'"{identifier}"'
    raise ProcedureExecutionValidationError('Unsupported approved procedure engine.')


def validate_approved_procedure(approved_procedure):
    """Confirm an approval remains bound to its saved connection identity."""
    connection = approved_procedure.connection
    if not connection.is_active:
        raise ProcedureExecutionValidationError('Approved procedure is unavailable.')
    if approved_procedure.engine != connection.connection_type:
        raise ProcedureExecutionValidationError('Approved procedure identity no longer matches its connection.')
    if approved_procedure.database_name != connection.database_name:
        raise ProcedureExecutionValidationError('Approved procedure identity no longer matches its connection.')
    if approved_procedure.engine == 'postgresql' and approved_procedure.signature:
        raise ProcedureExecutionValidationError('PostgreSQL overload approvals are not supported yet.')
    quote_identifier(approved_procedure.engine, approved_procedure.schema)
    quote_identifier(approved_procedure.engine, approved_procedure.procedure_name)


def _coerce_value(parameter, value):
    if value is None:
        if parameter.nullable:
            return None
        raise ProcedureExecutionValidationError('A required procedure value is invalid.')

    category = parameter_type_category(parameter.database_type)
    if category == 'integer':
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        return value
    if category == 'decimal':
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        try:
            result = Decimal(str(value))
        except (InvalidOperation, ValueError):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.') from None
        if not result.is_finite():
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        return result
    if category == 'string':
        if not isinstance(value, str):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        if parameter.max_length is not None and len(value) > parameter.max_length:
            raise ProcedureExecutionValidationError('A procedure string value is too long.')
        return value
    if category == 'boolean':
        if not isinstance(value, bool):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        return value
    if category == 'date':
        if not isinstance(value, str):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.') from None
    if category == 'datetime':
        if not isinstance(value, str):
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.')
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise ProcedureExecutionValidationError('A procedure value has an invalid type.') from None
    raise ProcedureExecutionValidationError('Unsupported approved parameter type.')


def validate_parameter_values(approved_parameters, submitted_parameters):
    """Validate JSON values against the complete server-side contract."""
    if not isinstance(submitted_parameters, dict):
        raise ProcedureExecutionValidationError('Procedure parameters must be an object.')

    parameters = list(approved_parameters)
    expected_names = {parameter.name for parameter in parameters}
    if set(submitted_parameters) - expected_names:
        raise ProcedureExecutionValidationError('Unknown procedure parameter.')

    values = []
    for parameter in parameters:
        if parameter.direction != ApprovedProcedureParameter.INPUT:
            if parameter.name in submitted_parameters:
                raise ProcedureExecutionValidationError('Output procedure parameters are server controlled.')
            # OUT and INOUT binding is intentionally deferred until driver-specific semantics are verified.
            raise ProcedureExecutionValidationError('Approved procedure parameter direction is not supported.')
        if parameter.name not in submitted_parameters:
            if parameter.required:
                raise ProcedureExecutionValidationError('A required procedure parameter is missing.')
            raise ProcedureExecutionValidationError('Optional procedure parameters are not supported yet.')
        values.append(_coerce_value(parameter, submitted_parameters[parameter.name]))
    return values


def build_procedure_call(approved_procedure, approved_parameters):
    """Build SQL only from validated, server-side approval data; values stay bound."""
    engine = approved_procedure.engine
    schema = quote_identifier(engine, approved_procedure.schema)
    procedure_name = quote_identifier(engine, approved_procedure.procedure_name)
    parameters = list(approved_parameters)

    if engine == 'mssql':
        assignments = ', '.join(
            f'@{require_safe_identifier(parameter.name)}=?' for parameter in parameters
        )
        return f'EXEC {schema}.{procedure_name}' + (f' {assignments}' if assignments else '')
    if engine == 'mysql':
        return f'CALL {schema}.{procedure_name}(' + ', '.join('%s' for _ in parameters) + ')'
    if engine == 'postgresql':
        return f'CALL {schema}.{procedure_name}(' + ', '.join('%s' for _ in parameters) + ')'
    raise ProcedureExecutionValidationError('Unsupported approved procedure engine.')


def fetch_bounded_procedure_result_sets(cursor, limits, *, supports_multiple_result_sets):
    """Fetch procedure results without loading an unbounded result set into memory."""
    result_sets = []
    total_rows = 0
    result_set_count = 0
    truncated = False
    has_current_result_set = True

    while has_current_result_set:
        if cursor.description:
            if result_set_count >= limits.max_result_sets:
                truncated = True
                break
            remaining_total = limits.max_total_rows - total_rows
            if remaining_total <= 0:
                truncated = True
                break
            row_limit = min(limits.max_rows_per_result_set, remaining_total)
            rows = cursor.fetchmany(row_limit + 1)
            row_truncated = len(rows) > row_limit
            rows = rows[:row_limit]
            total_rows += len(rows)
            if rows and isinstance(rows[0], dict):
                columns = list(rows[0].keys())
            else:
                columns = [column[0] for column in cursor.description]
            result_sets.append({
                'columns': columns,
                'rows': [dict(row) if isinstance(row, dict) else dict(zip(columns, row)) for row in rows],
            })
            result_set_count += 1
            if row_truncated or total_rows >= limits.max_total_rows:
                truncated = True
                break

        if not supports_multiple_result_sets:
            break
        has_current_result_set = cursor.nextset()

    return result_sets, truncated, result_set_count, total_rows
