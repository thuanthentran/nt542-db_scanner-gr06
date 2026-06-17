import sys
import os
import json
import pyodbc
from datetime import datetime

from remediator import REMEDIATION_REGISTRY


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

def run_remediation(audit_json_path, rollback_sql_path):
    # 1. Đọc file Audit Results
    if not os.path.exists(audit_json_path):
        print(f"LỖI: Không tìm thấy file {audit_json_path}")
        sys.exit(1) # <--- CẦN THÊM DÒNG NÀY

        
    with open(audit_json_path, 'r', encoding='utf-8') as f:
        audit_results = json.load(f)

    conn_str = _build_connection_string()
    conn = pyodbc.connect(conn_str, autocommit=True)
    cursor = conn.cursor()

    remediation_logs = []
    full_rollback_script = f"-- ROLLBACK SCRIPT GENERATED ON {datetime.now()}\n-- Chạy script này để khôi phục trạng thái trước khi Remediation\n\n"

    # 3. Quét các Rule Vi phạm và Kích hoạt Fix
    for finding in audit_results:
        if finding.get("status") == "Violate":
            rule_id = finding.get("rule_id")
            
            # Kiểm tra xem rule này có nằm trong Registry để fix không
            if rule_id in REMEDIATION_REGISTRY:
                fix_func = REMEDIATION_REGISTRY[rule_id]
                status, details, rollback_sql = fix_func(cursor)
                
                remediation_logs.append({
                    "rule_id": rule_id,
                    "action": "Auto-Remediate",
                    "status": status,
                    "details": details
                })
                
                if rollback_sql:
                    full_rollback_script += f"-- Rollback for Rule {rule_id}\n{rollback_sql}\n"
            else:
                remediation_logs.append({
                    "rule_id": rule_id,
                    "action": "Manual",
                    "status": "Requires DBA",
                    "details": "Rule này yêu cầu can thiệp thủ công hoặc khai báo tham số động."
                })

    conn.close()

    # 4. Ghi file Rollback Script
    with open(rollback_sql_path, 'w', encoding='utf-8') as f:
        f.write(full_rollback_script)

    # Xuất Log ra màn hình (hoặc lưu file tuỳ bạn)
    print(json.dumps(remediation_logs, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    import sys
    # Nhận đường dẫn từ Ansible truyền vào
    if len(sys.argv) == 3:
        audit_json_path = sys.argv[1]
        rollback_sql_path = sys.argv[2]
        run_remediation(audit_json_path, rollback_sql_path)
    else:
        print("Usage: python3 remediate.py <audit_json_path> <rollback_sql_path>")
        # Chạy local test nếu không có tham số
        run_remediation("audit_results.json", "rollback_script.sql")