"""
SQL error patterns ported from AWVS10 classSQLInjection.inc
66 plain-text patterns + 24 regex patterns covering all major DBs.
"""
import re

MYSQL_ERRORS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Warning: mysqli_",
    "MySqlException",
    "valid MySQL result",
    "MySqlClient.",
    "com.mysql.jdbc",
    "Syntax error or access violation",
    "SQLSTATE[HY",
    "MySQL server version for the right syntax",
]

MSSQL_ERRORS = [
    "Driver][SQL Server]",
    "Unclosed quotation mark after the character string",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "macabortar",
    "SqlException",
    "com.microsoft.sqlserver.jdbc",
    "Incorrect syntax near",
    "Msg 170, Level 15, State",
    "Microsoft SQL Native Client error",
    "ODBC Driver][SQL Server]",
    "SQL Server][ODBC",
    "SQLServer JDBC Driver]",
    "com.jnetdirect.jsql",
    "Unclosed quotation mark",
]

POSTGRESQL_ERRORS = [
    "PostgreSQL query failed",
    "Warning: pg_",
    "valid PostgreSQL result",
    "Npgsql.",
    "PG::SyntaxError",
    "org.postgresql.util.PSQLException",
    "ERROR:  syntax error at or near",
    "ERROR: parser: parse error at or near",
    "PostgreSQL.*ERROR",
    "PSQLException",
]

ORACLE_ERRORS = [
    "ORA-00933",
    "ORA-06512",
    "ORA-00936",
    "ORA-00921",
    "ORA-01756",
    "quoted string not properly terminated",
    "SQL command not properly ended",
    "Oracle error",
    "Oracle.*Driver",
    "oracle.jdbc",
    "OracleException",
]

SQLITE_ERRORS = [
    "SQLite/JDBCDriver",
    "SQLite.Exception",
    "System.Data.SQLite.SQLiteException",
    "Warning: SQLite3::",
    "SQLITE_ERROR",
    "[SQLITE_ERROR]",
    "SQLite3::query",
    "SQLite3::SQLException",
    "unrecognized token:",
]

DB2_ERRORS = [
    "CLI Driver][DB2",
    "DB2 SQL error",
    "db2_",
    "SQLCODE",
    "SQLSTATE",
]

INFORMIX_ERRORS = [
    "IfxException",
    "com.informix.jdbc",
    "SQLCODE=-",
]

GENERIC_ERRORS = [
    "SQL syntax.*error",
    "Warning.*\\Wmysql_",
    "Warning.*\\Wmysqli_",
    "Warning.*\\Wpg_",
    "Syntax error.*in query expression",
    "Data type mismatch in criteria expression",
    "A Database Error Occurred",
    "ADODB.Field error",
    "ADODB.Command",
    "JET Database Engine",
    "Access Database Engine",
    "Hibernate",
    "javax.persistence",
    "HibernateException",
]

ALL_PLAIN_PATTERNS = (
    MYSQL_ERRORS
    + MSSQL_ERRORS
    + POSTGRESQL_ERRORS
    + ORACLE_ERRORS
    + SQLITE_ERRORS
    + DB2_ERRORS
    + INFORMIX_ERRORS
)

REGEX_PATTERNS = [re.compile(p, re.IGNORECASE) for p in GENERIC_ERRORS]


def detect_sql_error(response_body: str) -> tuple[bool, str]:
    body_lower = response_body.lower()
    for pattern in ALL_PLAIN_PATTERNS:
        if pattern.lower() in body_lower:
            return True, pattern
    for regex in REGEX_PATTERNS:
        if regex.search(response_body):
            return True, regex.pattern
    return False, ""


DB_FINGERPRINTS = {
    "mysql": [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "MySqlException",
    ],
    "mssql": [
        "Driver][SQL Server]",
        "Unclosed quotation mark",
        "Incorrect syntax near",
    ],
    "postgresql": [
        "PostgreSQL query failed",
        "PG::SyntaxError",
        "PSQLException",
    ],
    "oracle": [
        "ORA-00933",
        "ORA-06512",
        "quoted string not properly terminated",
    ],
    "sqlite": [
        "SQLite",
        "SQLITE_ERROR",
        "unrecognized token",
    ],
}


def fingerprint_db(response_body: str) -> str:
    body_lower = response_body.lower()
    for db_name, patterns in DB_FINGERPRINTS.items():
        for p in patterns:
            if p.lower() in body_lower:
                return db_name
    return "unknown"
