import json
import os
import sys

import pyodbc


def _get_bool_env(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _build_connection_string():
    required_vars = ["DB_SERVER", "DB_USER", "DB_PASSWORD"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise RuntimeError(
            "Missing required database environment variables: "
            + ", ".join(missing_vars)
        )

    driver = os.getenv("DB_DRIVER", "ODBC Driver 17 for SQL Server")
    server = os.getenv("DB_SERVER")
    port = os.getenv("DB_PORT", "1433")
    database = os.getenv("DB_NAME", "master")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    login_timeout = os.getenv("DB_LOGIN_TIMEOUT", "30")
    encrypt = "yes" if _get_bool_env("DB_ENCRYPT", True) else "no"
    trust_server_cert = (
        "yes" if _get_bool_env("DB_TRUST_SERVER_CERTIFICATE", True) else "no"
    )

    return (
        f"DRIVER={{{driver}}};"
        f"SERVER={server},{port};"
        f"DATABASE={database};"
        f"UID={user};"
        f"PWD={password};"
        f"Encrypt={encrypt};"
        f"TrustServerCertificate={trust_server_cert};"
        f"Connection Timeout={login_timeout};"
    )


def _load_sql_commands(rollback_sql_path):
    with open(rollback_sql_path, "r", encoding="utf-8") as file_handle:
        lines = []
        for raw_line in file_handle:
            stripped_line = raw_line.strip()
            if not stripped_line or stripped_line.startswith("--"):
                continue
            if stripped_line.upper() == "GO":
                continue
            lines.append(raw_line)

    normalized_sql = "".join(lines)
    return [command.strip() for command in normalized_sql.split(";") if command.strip()]


def run_rollback(rollback_sql_path):
    if not os.path.exists(rollback_sql_path):
        print(
            json.dumps(
                {
                    "status": "Error",
                    "details": f"Rollback file not found: {rollback_sql_path}",
                },
                indent=4,
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    commands = _load_sql_commands(rollback_sql_path)
    conn = None

    try:
        conn_str = _build_connection_string()
        conn = pyodbc.connect(conn_str, autocommit=True)
        cursor = conn.cursor()

        executed_commands = []
        for command in commands:
            cursor.execute(command)
            executed_commands.append(command)

        print(
            json.dumps(
                {
                    "status": "Success",
                    "rollback_sql_path": rollback_sql_path,
                    "executed_commands": len(executed_commands),
                },
                indent=4,
                ensure_ascii=False,
            )
        )

    except Exception as exception:
        print(
            json.dumps(
                {
                    "status": "Error",
                    "rollback_sql_path": rollback_sql_path,
                    "details": f"Rollback failed: {exception}",
                },
                indent=4,
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        run_rollback(sys.argv[1])
    else:
        print("Usage: python3 rollback.py <rollback_sql_path>")
        sys.exit(1)