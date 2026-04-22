import json
import pyodbc

from scanner import (
    scan_auth_and_authz,
    scan_auditing_logging,
    scan_encryption,
    scan_password_policies,
    scan_surface_area,
    scan_application_development,
)


# ==============================================================================
# HAM MAIN: KET NOI VA GOI CAC MODULES
# ==============================================================================
def run_full_automated_scan():
    # Chuỗi kết nối ODBC đã được chuyển đổi từ cấu hình SSMS của bạn
    conn_str = (
        r'DRIVER={ODBC Driver 17 for SQL Server};'
        r'SERVER=localhost\SQLEXPRESS01;'
        r'DATABASE=master;'
        r'Trusted_Connection=yes;'          # Tương đương Integrated Security=True
        r'Encrypt=yes;'                     # Tương đương Encrypt=True
        r'TrustServerCertificate=yes;'      # Tương đương TrustServerCertificate=True
        r'Timeout=0;'                       # Tương đương Command Timeout=0
    )

    final_report = []

    try:
        # Thực hiện kết nối
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()

        # Gọi tuần tự từng module (Đảm bảo bạn đã có các hàm scan này ở trên)
        final_report.extend(scan_surface_area(cursor))
        final_report.extend(scan_auth_and_authz(cursor))
        final_report.extend(scan_application_development(cursor))
        # Nếu bạn đã viết các module khác (password, audit, encryption) thì gỡ comment ở dưới
        final_report.extend(scan_password_policies(cursor))
        final_report.extend(scan_auditing_logging(cursor))
        final_report.extend(scan_encryption(cursor))


        conn.close()

    except Exception as e:
        final_report.append({
            "status": "Error",
            "details": f"Không thể kết nối đến Database: {e}"
        })

    # Xuất kết quả phân tích
    print(json.dumps(final_report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    run_full_automated_scan()
