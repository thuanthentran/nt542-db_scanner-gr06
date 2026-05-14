# DB Scanner Ansible Playbook

Playbook này dùng để triển khai, audit, remediate và thu thập báo cáo từ nhiều SQL Server instance bằng Ansible.

## 📋 Yêu cầu

- **Ansible**: >= 2.9
- **Python**: >= 3.6
- **SSH Access**: Đến tất cả target servers
- **Sudo**: Quyền sudo trên target servers (không cần password nếu được config)

### Cài đặt Ansible

```bash
# Trên Ubuntu/Debian
sudo apt-get install ansible

# Trên macOS (brew)
brew install ansible

# Hoặc dùng pip
pip install ansible>=2.9
```

## 📁 Cấu trúc Thư mục

```
playbook/
├── site.yml                      # Playbook chính
├── audit-only.yml               # Playbook chỉ audit
├── remediate.yml                # Playbook remediation
├── rollback.yml                 # Playbook rollback
├── inventory/
│   ├── hosts.ini               # Inventory file với danh sách servers
│   └── hosts.yml               # Định dạng YAML (tùy chọn)
├── vars/
│   ├── main.yml                # Biến chung cho tất cả môi trường
│   ├── dev.yml                 # Biến riêng cho DEV
│   ├── staging.yml             # Biến riêng cho STAGING
│   └── prod.yml                # Biến riêng cho PROD
├── roles/
│   ├── common/                 # Các task chung
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   └── vars/main.yml
│   ├── deploy/                 # Tasks triển khai ứng dụng
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   └── vars/main.yml
│   ├── audit/                  # Tasks chạy audit
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   └── vars/main.yml
│   ├── remediation/            # Tasks remediation
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   ├── vars/
│   │   │   └── remediation_rules.yml
│   │   └── handlers/main.yml
│   └── reporting/              # Tasks thu thập báo cáo
│       ├── tasks/main.yml
│       ├── templates/
│       └── vars/main.yml
└── README.md                   # File này
```

## 🚀 Sử dụng Nhanh

### 1. Cấu hình Inventory

Chỉnh sửa `playbook/inventory/hosts.ini`:

```ini
[db_servers]
db-server-01 ansible_host=192.168.1.10 db_instance="SQLEXPRESS01"
db-server-02 ansible_host=192.168.1.11 db_instance="SQLEXPRESS02"
db-server-03 ansible_host=192.168.1.12 db_instance="SQLEXPRESS03"

[production]
db-server-03
```

### 2. Thiết lập SSH Key (nếu cần)

```bash
# Tạo SSH key nếu chưa có
ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa

# Sao chép key đến target servers
ssh-copy-id -i ~/.ssh/id_rsa.pub ansible@db-server-01
ssh-copy-id -i ~/.ssh/id_rsa.pub ansible@db-server-02
```

### 3. Kiểm tra Kết nối

```bash
# Kiểm tra tất cả hosts
ansible all -i playbook/inventory/hosts.ini -m ping

# Hoặc dùng script helper
./manage_playbook.sh test
```

### 4. Chạy Playbook

#### Triển khai ứng dụng

```bash
# Triển khai lên DEV
ansible-playbook playbook/site.yml -i playbook/inventory/host.ini \
  -e "environment=dev" \
  --tags=deploy

# Hoặc dùng script helper
./manage_playbook.sh deploy dev
```

#### Chạy Audit

```bash
# Audit trên PRODUCTION (không remediate)
ansible-playbook playbook/audit-only.yml -i playbook/inventory/host.ini \
  -e "environment=prod"

# Hoặc dùng script helper
./manage_playbook.sh audit prod
```

#### Chạy Remediation

```bash
# Remediate trên DEV (có backup trước)
ansible-playbook playbook/remediate.yml -i playbook/inventory/host.ini \
  -e "environment=dev" \
  -e "skip_remediation_prompt=true"

# Hoặc dùng script helper (sẽ confirm)
./manage_playbook.sh remediate dev
```

#### Chạy Đầy Đủ (Deploy + Audit + Remediate + Report)

```bash
ansible-playbook playbook/site.yml -i playbook/inventory/host.ini \
  -e "environment=dev"
```

## 📊 Output và Báo cáo

### Vị trí Báo cáo

```
/var/reports/db_scanner/
├── audit_[timestamp]/
│   ├── audit_results.json
│   ├── audit_report.html
│   └── audit_results.tar.gz
├── remediation_[date]/
│   ├── remediation_log.json
│   └── remediation_report.html
└── aggregated_[date]/
    ├── CONSOLIDATED_REPORT.html
    ├── CONSOLIDATED_REPORT.csv
    ├── CONSOLIDATED_REPORT.json
    └── reports_[date].tar.gz
```

### Định dạng Báo cáo

- **HTML**: Báo cáo visual với formatting đẹp
- **JSON**: Dữ liệu cấu trúc để integrate với tools khác
- **CSV**: Dữ liệu dạng bảng cho Excel

## 🔧 Cấu hình Nâng cao

### Thay đổi Tần suất Audit

Edit `playbook/vars/main.yml`:

```yaml
# Chạy lúc 2h sáng mỗi ngày (UTC)
audit_schedule: "0 2 * * *"
```

### Bật/Tắt Remediation

Dev (cho phép remediation):
```yaml
# playbook/vars/dev.yml
remediation_enabled: true
```

Production (tắt remediation):
```yaml
# playbook/vars/prod.yml
remediation_enabled: false  # Cần approval manual
```

### Tùy chỉnh Remediation Rules

Edit `playbook/roles/remediation/vars/remediation_rules.yml`:

```yaml
remediation_rules:
  - name: "Enable Audit Logging"
    description: "Enable SQL Server audit logging"
    action: "enable"
    enabled: true
    # ... thêm rule mới ở đây
```

### Gửi Báo cáo qua Email

Edit `playbook/vars/main.yml`:

```yaml
send_report_email: true
email_recipients:
  - "admin@company.com"
  - "dba@company.com"
smtp_server: "smtp.company.com"
smtp_port: 587
```

## 🔐 Bảo mật - Sử dụng Ansible Vault

### Tạo Vault Password

```bash
# Tạo file chứa password
echo "your_vault_password" > .vault_pass

# Hoặc nhập khi chạy
ansible-playbook playbook/site.yml --ask-vault-pass
```

### Mã hóa Biến Nhạy Cảm

```bash
# Tạo file biến mã hóa
ansible-vault create playbook/vars/vault.yml

# Chỉnh sửa file mã hóa
ansible-vault edit playbook/vars/vault.yml

# Sử dụng trong playbook
ansible-playbook playbook/site.yml --vault-password-file .vault_pass
```

## 📝 Một số Ví dụ

### 1. Triển khai lên Staging, chạy audit, không remediate

```bash
ansible-playbook playbook/audit-only.yml \
  -i playbook/inventory/hosts.ini \
  -e "environment=staging"
```

### 2. Remediate DEV với verbose output

```bash
ansible-playbook playbook/remediate.yml \
  -i playbook/inventory/hosts.ini \
  -e "environment=dev" \
  -e "skip_remediation_prompt=true" \
  -vvv
```

### 3. Chạy trên một server cụ thể

```bash
ansible-playbook playbook/site.yml \
  -i playbook/inventory/hosts.ini \
  -e "environment=prod" \
  --limit db-server-01
```

### 4. Rollback thay đổi từ một ngày cụ thể

```bash
ansible-playbook playbook/rollback.yml \
  -i playbook/inventory/hosts.ini \
  -e "backup_date=2026-05-14"
```

## 🛠️ Troubleshooting

### SSH Connection Timeout

```bash
# Tăng timeout
ansible-playbook playbook/site.yml \
  -i playbook/inventory/hosts.ini \
  -e "ansible_connection_timeout=60"
```

### Sudo Password Required

```bash
# Nhập password khi chạy
ansible-playbook playbook/site.yml \
  -i playbook/inventory/hosts.ini \
  -K
```

### Kiểm tra Syntax

```bash
# Kiểm tra playbook syntax
ansible-playbook playbook/site.yml --syntax-check

# Chế độ dry-run
ansible-playbook playbook/site.yml --check
```

### Xem Debug Output

```bash
# Verbose level 1
ansible-playbook playbook/site.yml -v

# Verbose level 2
ansible-playbook playbook/site.yml -vv

# Verbose level 3 (rất chi tiết)
ansible-playbook playbook/site.yml -vvv
```

## 📅 Scheduling Tự động

### Crontab Example

```bash
# Thêm vào crontab: crontab -e

# Chạy audit mỗi ngày lúc 2h sáng
0 2 * * * cd /opt/db_scanner && ansible-playbook playbook/audit-only.yml \
  -i playbook/inventory/hosts.ini -e "environment=prod" \
  >> /var/log/playbook_audit.log 2>&1

# Chạy remediation dev mỗi thứ 2 lúc 3h sáng
0 3 * * 1 cd /opt/db_scanner && ansible-playbook playbook/remediate.yml \
  -i playbook/inventory/hosts.ini -e "environment=dev" \
  -e "skip_remediation_prompt=true" \
  >> /var/log/playbook_remediate.log 2>&1
```

### Systemd Timer (Tùy chọn)

```bash
# Tạo service file
/etc/systemd/system/db-scanner-audit.service

# Tạo timer file
/etc/systemd/system/db-scanner-audit.timer
```

## 📚 Tài liệu Thêm

- [Ansible Documentation](https://docs.ansible.com/)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/tips_tricks/index.html)
- [Jinja2 Template Documentation](https://jinja.palletsprojects.com/)

## 🤝 Hỗ trợ

Nếu gặp vấn đề, vui lòng:

1. Kiểm tra logs: `tail -f /var/log/db_scanner/*.log`
2. Chạy playbook với verbose: `ansible-playbook ... -vvv`
3. Kiểm tra syntax: `ansible-playbook ... --syntax-check`
4. Test connectivity: `./manage_playbook.sh test`

## 📄 License

[Thêm thông tin License của bạn]
