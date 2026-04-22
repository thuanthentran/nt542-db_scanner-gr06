def scan_encryption(cursor):
    results = []

    # Lấy danh sách các User Database để quét Rule 7.1 và 7.2
    cursor.execute("SELECT name FROM sys.databases WHERE state = 0 AND database_id > 4;")
    databases = [r[0] for r in cursor.fetchall()]

    for db in databases:
        # Rule 7.1: Symmetric Key encryption algorithm
        cursor.execute(f"USE [{db}];")
        cursor.execute("SELECT name FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND db_id() > 4;")
        violating_sym = [r[0] for r in cursor.fetchall()]
        if violating_sym:
            results.append({
                "group": "Encryption", "rule_id": "7.1",
                "policy": f"Ensure Symmetric Key is AES_128 or higher (DB: {db})",
                "status": "Violate", "details": f"Phát hiện thuật toán yếu: {violating_sym}"
            })
            
        # Rule 7.2: Asymmetric Key Size >= 2048
        cursor.execute(f"USE [{db}];")
        cursor.execute("SELECT name FROM sys.asymmetric_keys WHERE key_length < 2048 AND db_id() > 4;")
        violating_asym = [r[0] for r in cursor.fetchall()]
        if violating_asym:
            results.append({
                "group": "Encryption", "rule_id": "7.2",
                "policy": f"Ensure Asymmetric Key Size >= 2048 (DB: {db})",
                "status": "Violate", "details": f"Phát hiện Asymmetric key < 2048 bit: {violating_asym}"
            })

    # Chuyển context lại về master
    cursor.execute("USE [master];")

    # Rule 7.3: Ensure Database Backups are Encrypted
    query_7_3 = """
    SELECT b.database_name FROM msdb.dbo.backupset b
    INNER JOIN sys.databases d ON b.database_name = d.name
    WHERE b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted = 0;
    """
    cursor.execute(query_7_3)
    unencrypted_backups = sorted(set(r[0] for r in cursor.fetchall()))
    status = "Violate" if len(unencrypted_backups) > 0 else "Compliance"
    results.append({
        "group": "Encryption", "rule_id": "7.3",
        "policy": "Ensure Database Backups are Encrypted",
        "status": status, "details": f"Các database có backup chưa mã hóa: {unencrypted_backups}" if unencrypted_backups else "Tất cả backup đều an toàn"
    })

    # Rule 7.4: Ensure Network Encryption is Configured and Enabled
    query_7_4 = """
    SELECT DISTINCT encrypt_option FROM sys.dm_exec_connections c
    WHERE net_transport <> 'Shared memory' AND c.endpoint_id NOT IN (
        SELECT endpoint_id FROM sys.database_mirroring_endpoints WHERE encryption_algorithm IS NOT NULL
    );
    """
    cursor.execute(query_7_4)
    rows = cursor.fetchall()
    status = "Compliance" if any(str(r[0]).upper() == "TRUE" for r in rows) else "Violate"
    results.append({
        "group": "Encryption", "rule_id": "7.4",
        "policy": "Ensure Network Encryption is Configured and Enabled",
        "status": status, "details": "Network encryption được bật" if status == "Compliance" else "Chưa cấu hình Network Encryption"
    })

    # Rule 7.5: Ensure Databases are Encrypted with TDE
    cursor.execute("SELECT name FROM sys.databases WHERE database_id > 4 AND is_encrypted != 1;")
    tde_violating = [r[0] for r in cursor.fetchall()]
    status = "Violate" if len(tde_violating) > 0 else "Compliance"
    results.append({
        "group": "Encryption", "rule_id": "7.5",
        "policy": "Ensure Databases are Encrypted with TDE",
        "status": status, "details": f"Các Database chưa mã hóa TDE: {tde_violating}" if tde_violating else "Tất cả User DB đều mã hóa TDE"
    })

    return results