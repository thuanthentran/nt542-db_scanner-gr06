def fix_rule_4_2(cursor):
    """Bật CHECK_EXPIRATION cho Sysadmin"""
    query = """
    SELECT l.[name] FROM sys.sql_logins AS l WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1 AND l.is_expiration_checked <> 1
    """
    cursor.execute(query)
    violators = [r[0] for r in cursor.fetchall()]
    
    rollback_sql = ""
    fixed = []
    for user in violators:
        try:
            cursor.execute(f"ALTER LOGIN [{user}] WITH CHECK_EXPIRATION = ON;")
            rollback_sql += f"ALTER LOGIN [{user}] WITH CHECK_EXPIRATION = OFF;\n"
            fixed.append(user)
        except Exception:
            pass
            
    return "Success", f"Đã bật CHECK_EXPIRATION cho: {fixed}", rollback_sql

def fix_rule_4_3(cursor):
    """Bật CHECK_POLICY cho tài khoản SQL Auth"""
    cursor.execute("SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;")
    violators = [r[0] for r in cursor.fetchall()]
    
    rollback_sql = ""
    fixed = []
    for user in violators:
        try:
            cursor.execute(f"ALTER LOGIN [{user}] WITH CHECK_POLICY = ON;")
            rollback_sql += f"ALTER LOGIN [{user}] WITH CHECK_POLICY = OFF;\n"
            fixed.append(user)
        except Exception:
            pass
            
    return "Success", f"Đã bật CHECK_POLICY cho: {fixed}", rollback_sql