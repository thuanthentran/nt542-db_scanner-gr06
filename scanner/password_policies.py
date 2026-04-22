def scan_password_policies(cursor):
    results = []

    # Rule 4.2: Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All Sysadmin Logins
    query_4_2 = """
    SELECT l.[name] FROM sys.sql_logins AS l
    WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1 AND l.is_expiration_checked <> 1
    UNION ALL
    SELECT l.[name] FROM sys.sql_logins AS l JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id
    WHERE p.type = 'CL' AND p.state IN ('G', 'W') AND l.is_expiration_checked <> 1;
    """
    cursor.execute(query_4_2)
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    # FIX: Thêm r để lấy chuỗi thay vì tuple
    violators_4_2 = [r for r in rows]
    results.append({
        "group": "Password Policies", "rule_id": "4.2",
        "policy": "Ensure 'CHECK_EXPIRATION' is 'ON' for Sysadmin/CONTROL SERVER",
        "status": status, "details": f"Các tài khoản vi phạm: {violators_4_2}" if violators_4_2 else "Tất cả tài khoản đều tuân thủ"
    })

    # Rule 4.3: Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins
    cursor.execute("SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;")
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    # FIX: Thêm row
    violators = [row for row in rows]
    results.append({
        "group": "Password Policies", "rule_id": "4.3",
        "policy": "Ensure 'CHECK_POLICY' Option is set to 'ON'",
        "status": status, "details": f"Các tài khoản vi phạm CHECK_POLICY: {violators}" if violators else "Tất cả tài khoản đều tuân thủ"
    })

    return results
