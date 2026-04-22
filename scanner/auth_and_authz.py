def scan_auth_and_authz(cursor):
    results = []
    
    cursor.execute("SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) as [login_mode];")
    row = cursor.fetchone()
    if row:
        login_mode = int(row[0])
        status = "Compliance" if login_mode == 1 else "Violate"
        results.append({
            "group": "Authentication & Authorization", "rule_id": "3.1",
            "policy": "Ensure 'Server Authentication' is set to 'Windows Authentication Mode'",
            "status": status, "details": "Đang dùng Windows Authentication (An toàn)" if login_mode == 1 else "Đang dùng Mixed Mode (Violate)"
        })

    query_3_8 = """
    SELECT COUNT(1) 
    FROM master.sys.server_permissions 
    WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%') 
    AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') 
    AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2) 
    AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3) 
    AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4) 
    AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);
    """
    cursor.execute(query_3_8)
    row = cursor.fetchone()
    extra_public_permissions = int(row[0]) if row else 0
    status = "Violate" if extra_public_permissions > 0 else "Compliance"
    results.append({
        "group": "Authentication & Authorization", "rule_id": "3.8",
        "policy": "Ensure only default permissions are granted to the public server role",
        "status": status, "details": f"Phát hiện {extra_public_permissions} quyền dư thừa được cấp cho role public"
    })

    cursor.execute("SELECT pr.[name] FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name like 'BUILTIN%';")
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Authentication & Authorization", "rule_id": "3.9",
        "policy": "Ensure Windows BUILTIN groups are not SQL Logins",
        "status": status, "details": f"Phát hiện {len(rows)} nhóm BUILTIN đang làm SQL Login"
    })

    query_3_10 = """
    SELECT pr.[name] FROM sys.server_principals pr 
    JOIN sys.server_permissions pe ON pr.[principal_id] = pe.[grantee_principal_id] 
    WHERE pr.[type_desc] = 'WINDOWS_GROUP' AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';
    """
    cursor.execute(query_3_10)
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Authentication & Authorization", "rule_id": "3.10",
        "policy": "Ensure Windows local groups are not SQL Logins",
        "status": status, "details": f"Phát hiện {len(rows)} nhóm Local được cấu hình làm SQL Login"
    })

    cursor.execute("USE [msdb];")
    query_3_11 = """
    SELECT sp.name AS proxyname FROM dbo.sysproxylogin spl 
    JOIN sys.database_principals dp ON dp.sid = spl.sid 
    JOIN sysproxies sp ON sp.proxy_id = spl.proxy_id 
    WHERE principal_id = USER_ID('public');
    """
    cursor.execute(query_3_11)
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Authentication & Authorization", "rule_id": "3.11",
        "policy": "Ensure public role in msdb is not granted access to SQL Agent proxies",
        "status": status, "details": "An toàn" if len(rows) == 0 else "Role public đang có quyền truy cập proxy"
    })

    cursor.execute("USE [msdb];")
    query_3_13 = """
    SELECT m.name FROM sys.database_role_members AS drm 
    INNER JOIN sys.database_principals AS r ON drm.role_principal_id = r.principal_id 
    INNER JOIN sys.database_principals AS m ON drm.member_principal_id = m.principal_id 
    WHERE r.name in ('db_owner', 'db_securityadmin', 'db_ddladmin', 'db_datawriter') and m.name <>'dbo';
    """
    cursor.execute(query_3_13)
    rows = cursor.fetchall()
    status = "Violate" if len(rows) > 0 else "Compliance"
    results.append({
        "group": "Authentication & Authorization", "rule_id": "3.13",
        "policy": "Ensure no admin role membership in MSDB database",
        "status": status, "details": "An toàn" if len(rows) == 0 else "Phát hiện tài khoản có quyền admin trong msdb"
    })
    
    # Lấy danh sách các database để chạy vòng lặp
    cursor.execute("SELECT name FROM sys.databases WHERE state = 0;")
    databases = [r[0] for r in cursor.fetchall()]

    for db in databases:
        if db not in ('master', 'tempdb', 'msdb'):
            cursor.execute(f"USE [{db}];")
            query_3_2 = f"""
            SELECT DB_NAME() AS DatabaseName FROM sys.database_permissions 
            WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest') 
            AND [state_desc] LIKE 'GRANT%' AND [permission_name] = 'CONNECT';
            """
            cursor.execute(query_3_2)
            if cursor.fetchall():
                results.append({
                    "group": "Authentication & Authorization", "rule_id": "3.2",
                    "policy": f"Ensure CONNECT permissions on 'guest' is Revoked (DB: {db})",
                    "status": "Violate", "details": f"Tài khoản guest đang có quyền CONNECT trên DB {db}"
                })

        cursor.execute(f"USE [{db}];")
        query_3_3 = f"""
        SELECT dp.name FROM sys.database_principals AS dp 
        LEFT JOIN sys.server_principals as sp ON dp.sid=sp.sid 
        WHERE sp.sid IS NULL AND dp.authentication_type_desc = 'INSTANCE';
        """
        cursor.execute(query_3_3)
        orphans = [r[0] for r in cursor.fetchall()]
        if orphans:
            results.append({
                "group": "Authentication & Authorization", "rule_id": "3.3",
                "policy": f"Ensure 'Orphaned Users' are Dropped (DB: {db})",
                "status": "Violate", "details": f"Phát hiện Orphaned Users: {orphans}"
            })

        cursor.execute(f"USE [{db}];")
        query_3_4 = f"""
        SELECT name FROM sys.database_principals 
        WHERE name NOT IN ('dbo','Information_Schema','sys','guest') 
        AND type IN ('U','S','G') AND authentication_type = 2;
        """
        cursor.execute(query_3_4)
        sql_auth_users = [r[0] for r in cursor.fetchall()]
        if sql_auth_users:
            results.append({
                "group": "Authentication & Authorization", "rule_id": "3.4",
                "policy": f"Ensure SQL Authentication is not used in contained DB (DB: {db})",
                "status": "Violate", "details": f"Phát hiện User dùng SQL Auth: {sql_auth_users}"
            })

    return results