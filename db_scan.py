import mariadb
import json

def scan_mariadb_port():
    # 1. Thông tin kết nối môi trường Lab của bạn
    # Hãy thay đổi 'MẬT_KHẨU_BẠN_ĐÃ_ĐẶT' bằng mật khẩu root bạn vừa cài
    config = {
        'user': 'root',
        'password': 'Thu4n@th3n',
        'host': '127.0.0.1',
        'port': 3306
    }

    # 2. Khởi tạo dictionary chứa kết quả (theo đúng sơ đồ thiết kế của bạn)
    scan_result = {
        "policy": "Ensure MariaDB is configured to use non-standard ports",
        "status": "",
        "details": ""
    }

    try:
        # Kết nối vào database
        conn = mariadb.connect(**config)
        cursor = conn.cursor()

        # 3. Quét (Scan): Chạy lệnh SQL của MariaDB để lấy thông tin port
        cursor.execute("SHOW VARIABLES LIKE 'port';")
        result = cursor.fetchone() # Kết quả trả về sẽ có dạng tuple, ví dụ: ('port', '3306')

        if result:
            current_port = result[1]
            
            # 4. So sánh (Compliance/Violate): Kiểm tra xem có phải port mặc định không
            if current_port == '3306':
                scan_result["status"] = "Violate"
                scan_result["details"] = f"Cảnh báo: MariaDB đang chạy trên port mặc định ({current_port})."
            else:
                scan_result["status"] = "Compliance"
                scan_result["details"] = f"An toàn: MariaDB đã đổi sang port ({current_port})."

        conn.close()

    except mariadb.Error as e:
        scan_result["status"] = "Error"
        scan_result["details"] = f"Không thể kết nối đến Database: {e}"

    # 5. Xuất kết quả ra chuẩn JSON
    print(json.dumps(scan_result, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    scan_mariadb_port()