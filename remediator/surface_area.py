def fix_sys_config(cursor, rule_id, config_name, expected_int):
    """Hàm dùng chung để fix các cấu hình hệ thống (sp_configure)"""
    # Lấy giá trị hiện tại để làm rollback
    cursor.execute(f"SELECT CAST(value_in_use as int) FROM sys.configurations WHERE name = '{config_name}';")
    row = cursor.fetchone()
    if not row:
        return "Error", f"Không tìm thấy cấu hình {config_name}", ""
    
    current_value = int(row[0])
    if current_value == expected_int:
        return "Skipped", f"{config_name} đã đạt chuẩn, không cần fix", ""

    # Lệnh Rollback (đưa về giá trị cũ)
    rollback_sql = f"EXEC sp_configure '{config_name}', {current_value}; RECONFIGURE;\n"
    
    # Lệnh Remediation (áp dụng giá trị chuẩn)
    try:
        # Bật show advanced options nếu cần
        cursor.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        cursor.execute(f"EXEC sp_configure '{config_name}', {expected_int}; RECONFIGURE;")
        cursor.execute("EXEC sp_configure 'show advanced options', 0; RECONFIGURE;")
        return "Success", f"Đã cấu hình {config_name} thành {expected_int}", rollback_sql
    except Exception as e:
        return "Error", f"Lỗi khi fix {config_name}: {e}", ""

def fix_rule_2_9(cursor):
    """Tắt Trustworthy cho các DB vi phạm"""
    cursor.execute("SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';")
    violating_dbs = [r[0] for r in cursor.fetchall()]
    
    if not violating_dbs:
        return "Skipped", "Không có DB nào vi phạm Trustworthy", ""

    rollback_sql = ""
    remediated_dbs = []
    for db in violating_dbs:
        try:
            cursor.execute(f"ALTER DATABASE [{db}] SET TRUSTWORTHY OFF;")
            rollback_sql += f"ALTER DATABASE [{db}] SET TRUSTWORTHY ON;\n"
            remediated_dbs.append(db)
        except Exception as e:
            pass

    return "Success", f"Đã tắt Trustworthy cho: {remediated_dbs}", rollback_sql

def fix_rule_2_13(cursor):
    """Vô hiệu hóa tài khoản sa"""
    cursor.execute("SELECT name FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;")
    if not cursor.fetchone():
        return "Skipped", "Tài khoản gốc đã bị disable sẵn", ""

    try:
        cursor.execute("ALTER LOGIN sa DISABLE;")
        rollback_sql = "ALTER LOGIN sa ENABLE;\n"
        return "Success", "Đã vô hiệu hóa tài khoản sa", rollback_sql
    except Exception as e:
        return "Error", f"Lỗi khi vô hiệu hóa sa: {e}", ""