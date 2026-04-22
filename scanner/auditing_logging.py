def scan_auditing_logging(cursor):
    results = []

    # Rule 5.1: Ensure 'Maximum number of error log files' is >= 12
    query_5_1 = """
    SELECT TOP 1 ISNULL(TRY_CAST(value_data AS int), -1) AS [NumberOfLogFiles]
    FROM sys.dm_server_registry
    WHERE value_name = 'NumErrorLogs';
    """
    cursor.execute(query_5_1)
    row = cursor.fetchone()
    if row:
        num_error_logs = int(row[0])
        status = "Compliance" if num_error_logs == -1 or num_error_logs >= 12 else "Violate"
        results.append({
            "group": "Auditing and Logging", "rule_id": "5.1",
            "policy": "Ensure 'Maximum number of error log files' is >= 12",
            "status": status, "details": f"Số lượng Error Logs giữ lại: {'Không giới hạn' if num_error_logs == -1 else num_error_logs}"
        })

    # Rule 5.2: Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'
    cursor.execute("SELECT CAST(value_in_use as int) FROM sys.configurations WHERE name = 'default trace enabled';")
    row = cursor.fetchone()
    if row:
        default_trace_enabled = int(row[0])
        status = "Compliance" if default_trace_enabled == 1 else "Violate"
        results.append({
            "group": "Auditing and Logging", "rule_id": "5.2",
            "policy": "Ensure 'Default Trace Enabled' is set to '1'",
            "status": status, "details": f"Giá trị Default Trace hiện tại: {default_trace_enabled}"
        })

    # Rule 5.3: Ensure 'Login Auditing' is set to 'failed logins'
    cursor.execute("EXEC xp_loginconfig 'audit level';")
    row = cursor.fetchone()
    if row:
        audit_level = str(row[1])
        status = "Compliance" if audit_level.lower() in ['failure', 'all'] else "Violate"
        results.append({
            "group": "Auditing and Logging", "rule_id": "5.3",
            "policy": "Ensure 'Login Auditing' is set to 'failed logins'",
            "status": status, "details": f"Cấu hình Audit level hiện hành: {audit_level}"
        })

    return results