"""Conservative application-layer containment for externally executed SQL text."""

from dataclasses import dataclass

import sqlparse
from sqlparse import tokens as T


USER_FACING_ERROR = 'Only a single read-only query is permitted.'


@dataclass(frozen=True)
class SqlPolicyResult:
    allowed: bool
    code: str


class SqlPolicyViolation(ValueError):
    """Raised when SQL text is not permitted to reach an external connector."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(USER_FACING_ERROR)


_FORBIDDEN_KEYWORDS = {
    'ALTER', 'ANALYZE', 'BEGIN', 'CALL', 'COMMIT', 'COPY', 'CREATE', 'DECLARE',
    'DELETE', 'DO', 'DROP', 'EXEC', 'EXECUTE', 'GRANT', 'INSERT', 'INTO', 'LOAD',
    'LOCK', 'MERGE', 'PRAGMA', 'REINDEX', 'RENAME', 'REPLACE', 'REVOKE', 'ROLLBACK',
    'SAVEPOINT', 'SET', 'TRUNCATE', 'UPDATE', 'UPSERT', 'USE', 'VACUUM',
}


def _is_executable_token(token) -> bool:
    return not (
        token.is_whitespace
        or token.ttype in T.Whitespace
        or token.ttype in T.Comment
        or token.value == ';'
    )


def _contains_forbidden_keyword(statement) -> bool:
    for token in statement.flatten():
        if token.ttype in T.Comment or token.ttype in T.Whitespace:
            continue
        if token.ttype in T.Keyword and token.normalized.upper() in _FORBIDDEN_KEYWORDS:
            return True
    return False


def validate_read_only_query(query) -> SqlPolicyResult:
    """Allow one syntactically SELECT-oriented statement with no write/control tokens.

    This is intentionally conservative. It is containment only and cannot establish
    database-level read-only behavior.
    """
    if not isinstance(query, str) or not query.strip():
        return SqlPolicyResult(False, 'missing_query')

    statements = [
        statement
        for statement in sqlparse.parse(query)
        if any(_is_executable_token(token) for token in statement.flatten())
    ]
    if len(statements) != 1:
        return SqlPolicyResult(False, 'multiple_or_empty_statements')

    statement = statements[0]
    if statement.get_type().upper() != 'SELECT':
        return SqlPolicyResult(False, 'not_select')
    if _contains_forbidden_keyword(statement):
        return SqlPolicyResult(False, 'write_or_control_keyword')

    return SqlPolicyResult(True, 'allowed')


def require_read_only_query(query) -> None:
    result = validate_read_only_query(query)
    if not result.allowed:
        raise SqlPolicyViolation(result.code)
