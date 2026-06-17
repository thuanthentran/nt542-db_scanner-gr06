# nt542-db_scanner-gr06

DB Scanner Ansible project for deploying the scanner, running audit checks, executing remediation, and rolling back remediation changes on SQL Server hosts.

## Mục Tiêu

Repository này chạy theo mô hình 3 luồng độc lập:

1. `site.yml` để deploy scanner, chạy audit và thu thập báo cáo.
2. `remediate.yml` để áp dụng remediation sau khi đã có kết quả audit.
3. `rollback.yml` để hoàn nguyên từ `rollback_script.sql` do remediation sinh ra.

Audit và remediation dùng 2 bộ tài khoản SQL riêng để tách quyền:

- Audit: chỉ cần quyền đọc/quan sát dữ liệu hệ thống.
- Remediation: cần quyền thay đổi cấu hình SQL Server.

## Điều Kiện Để Chạy Được Tới SQL Server Đích

Trước khi chạy playbook, cần đủ 3 lớp truy cập sau:

### 1. Truy cập SSH đến máy đích

Ansible kết nối vào host đích qua SSH để cài đặt file, virtualenv, script và chạy task. Tài khoản SSH phải có quyền sudo trên máy đích.

### 2. Kết nối từ máy đích tới SQL Server

Script `db_scan.py` và `remediate.py` không dùng Windows Integrated Authentication. Hai script này đọc biến môi trường do Ansible truyền vào:

- `DB_SERVER`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_DRIVER`
- `DB_ENCRYPT`
- `DB_TRUST_SERVER_CERTIFICATE`
- `DB_LOGIN_TIMEOUT`

### 3. Tài khoản SQL tách riêng

Nên chuẩn bị sẵn 2 login SQL:

- `audit_login`: dùng cho audit
- `remediation_login`: dùng cho remediation

Ví dụ logic phân quyền:

- `audit_login`: quyền đọc các catalog/view cần thiết cho scan.
- `remediation_login`: quyền đủ cao để chỉnh cấu hình, tạo hoặc xóa login, và áp dụng rollback nếu cần.

## Inventory Và Biến Môi Trường

Inventory đang dùng trong repo là:

`playbook/inventory/inventory.ini`

Ví dụ host trong inventory:

```ini
[db_servers]
dev-db-01 ansible_host=192.168.142.164 db_instance="MSSQLSERVER"
```

Biến môi trường khuyên dùng:

- `environment=dev` cho lab/dev
- `environment=prod` cho production
- `audit_db_user` và `audit_db_password` cho playbook audit
- `remediation_db_user` và `remediation_db_password` cho playbook remediation
- `rollback_db_user` và `rollback_db_password` cho playbook rollback

## Lệnh Chạy Playbook Chính Xác

### 1. Chạy deploy + audit + reporting

```bash
ansible-playbook playbook/site.yml -i playbook/inventory/inventory.ini -K \
	-e "environment=dev" \
	-e "audit_db_user=audit_login" \
	-e "audit_db_password=YOUR_AUDIT_PASSWORD"
```

Nếu muốn chạy production, đổi `environment=prod` và dùng credential tương ứng.

### 2. Chạy remediation riêng

```bash
ansible-playbook playbook/remediate.yml -i playbook/inventory/inventory.ini -K \
	-e "environment=dev" \
	-e "remediation_db_user=remediation_login" \
	-e "remediation_db_password=YOUR_REMEDIATION_PASSWORD"
```

Nếu muốn chỉ định đúng thư mục audit đã tạo trước đó, thêm:

```bash
	-e "audit_results_path=/var/reports/db_scanner/audit_YYYY-MM-DDTHH-MM-SSZ"
```

Nếu không truyền `audit_results_path`, playbook remediation sẽ tự tìm file `audit_results.json` mới nhất trên host đích.

### 3. Chạy audit only

```bash
ansible-playbook playbook/audit-only.yml -i playbook/inventory/inventory.ini -K \
	-e "environment=dev" \
	-e "audit_db_user=audit_login" \
	-e "audit_db_password=YOUR_AUDIT_PASSWORD"
```

## Trình Tự Vận Hành Khuyến Nghị

1. Cấu hình inventory và SSH access tới host đích.
2. Tạo 2 SQL login riêng cho audit và remediation.
3. Chạy `playbook/site.yml` để audit và sinh report.
4. Chạy `playbook/remediate.yml` để áp remediation.
5. Chạy `playbook/rollback.yml` nếu muốn quay lại trạng thái trước remediation.
6. Chạy lại `playbook/site.yml` sau rollback để xác nhận kết quả.

## Ghi Chú

- File này là tài liệu tóm tắt chạy thực tế.
- Nếu cần hướng dẫn nhanh hơn cho người mới, xem thêm `QUICKSTART.md`.