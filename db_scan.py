import json
import os
import sys

import pyodbc

from scanner import (
    scan_auth_and_authz,
    scan_auditing_logging,
    scan_encryption,
    scan_password_policies,
    scan_surface_area,
    scan_application_development,
)


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


# ==============================================================================
# HAM MAIN: KET NOI VA GOI CAC MODULES
# ==============================================================================
def run_full_automated_scan():
    final_report = []
    conn = None

    try:
        conn_str = _build_connection_string()
        # Thực hiện kết nối
        conn = pyodbc.connect(conn_str, autocommit=True)
        cursor = conn.cursor()

        # Gọi tuần tự từng module (Đảm bảo bạn đã có các hàm scan này ở trên)
        final_report.extend(scan_surface_area(cursor))
        final_report.extend(scan_auth_and_authz(cursor))
        final_report.extend(scan_application_development(cursor))
        # Nếu bạn đã viết các module khác (password, audit, encryption) thì gỡ comment ở dưới
        final_report.extend(scan_password_policies(cursor))
        final_report.extend(scan_auditing_logging(cursor))
        final_report.extend(scan_encryption(cursor))

    except Exception as e:
        final_report.append({
            "status": "Error",
            "details": f"Không thể kết nối đến Database: {e}"
        })
        print(json.dumps(final_report, indent=4, ensure_ascii=False))
        sys.exit(1)
    finally:
        if conn is not None:
            conn.close()

    # Xuất kết quả phân tích
    print(json.dumps(final_report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    run_full_automated_scan()
