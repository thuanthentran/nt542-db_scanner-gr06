# DB Scanner Ansible Playbook - Quick Start Guide

## 🚀 Khởi Động Nhanh

### Bước 1: Chuẩn bị Môi trường (5 phút)

```bash
# 1a. Cài đặt Ansible
pip install -r playbook/requirements.txt

# 1b. Cài đặt Collections
ansible-galaxy install -r playbook/requirements.yml

# 1c. Thiết lập SSH key (nếu chưa có)
ssh-keygen -t rsa -f ~/.ssh/ansible_key
```

### Bước 2: Cấu hình Inventory (10 phút)

```bash
# Chỉnh sửa file inventory
nano playbook/inventory/hosts.ini

# Thêm servers của bạn:
[db_servers]
my-db-server-01 ansible_host=192.168.x.x db_instance="SQLEXPRESS"
```

### Bước 3: Kiểm tra Kết nối (5 phút)

```bash
# Kiểm tra ping tất cả hosts
./manage_playbook.sh test

# Output mong đợi:
# my-db-server-01 | SUCCESS => {
#     "ping": "pong"
# }
```

### Bước 4: Chạy Playbook Đầu tiên (15-30 phút)

```bash
# Triển khai lên Dev (bao gồm cả remediation)
./manage_playbook.sh deploy dev

# Hoặc chỉ chạy audit (không remediate)
./manage_playbook.sh audit prod
```

## 📋 Các Lệnh Thường Dùng

### Thực thi từng phần

```bash
# Chỉ triển khai (deploy only)
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini \
  -e environment=dev --tags=deploy

# Chỉ audit (audit only)
ansible-playbook playbook/audit-only.yml -i playbook/inventory/hosts.ini \
  -e environment=prod

# Chỉ remediate (remediation only)
ansible-playbook playbook/remediate.yml -i playbook/inventory/hosts.ini \
  -e environment=dev -e skip_remediation_prompt=true

# Chỉ report (reporting only)
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini \
  -e environment=prod --tags=reporting
```

### Chạy trên một server cụ thể

```bash
# Chỉ trên db-server-01
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini \
  -e environment=dev --limit db-server-01

# Trên tất cả server trong nhóm "production"
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini \
  -e environment=prod --limit production
```

### Debug và Troubleshooting

```bash
# Chế độ dry-run (không thay đổi gì)
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini --check

# Kiểm tra syntax
ansible-playbook playbook/site.yml --syntax-check

# Verbose output (chi tiết hơn)
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini -vvv

# Liệt kê tất cả tasks
ansible-playbook playbook/site.yml --list-tasks

# Liệt kê tất cả hosts
ansible-inventory -i playbook/inventory/hosts.ini --list
```

## 📊 Báo cáo Kết quả

### Xem Báo cáo

```bash
# Liệt kê tất cả báo cáo
ls -la /var/reports/db_scanner/

# Xem báo cáo HTML (trên server)
firefox /var/reports/db_scanner/aggregated_YYYY-MM-DD/CONSOLIDATED_REPORT.html

# Xem báo cáo JSON
cat /var/reports/db_scanner/aggregated_YYYY-MM-DD/CONSOLIDATED_REPORT.json | jq .

# Xem báo cáo CSV
cat /var/reports/db_scanner/aggregated_YYYY-MM-DD/CONSOLIDATED_REPORT.csv
```

### Download Báo cáo về Local

```bash
# Sao chép báo cáo về máy local
scp -r ansible@db-server-01:/var/reports/db_scanner/aggregated_* ./local_reports/
```

## 🔐 Bảo mật

### Sử dụng Vault để Bảo mật Mật khẩu

```bash
# Tạo encrypted vault file
ansible-vault create playbook/vars/vault.yml

# Thêm credentials của bạn vào vault:
# db_user_password: "your_secure_password"
# email_password: "your_email_password"

# Chạy playbook với vault
ansible-playbook playbook/site.yml -i playbook/inventory/hosts.ini \
  --vault-password-file ~/.vault_pass
```

## ⚙️ Tùy chỉnh Cấu hình

### Thay đổi Tần suất Audit

```bash
# Sửa playbook/vars/main.yml
audit_schedule: "0 2 * * *"  # Cron format: 2h sáng mỗi ngày
```

### Bật Remediation cho Environment Cụ thể

```bash
# playbook/vars/dev.yml
remediation_enabled: true

# playbook/vars/prod.yml
remediation_enabled: false  # Tắt mặc định cho PROD
```

### Thêm Quy tắc Remediation Mới

```bash
# Chỉnh sửa playbook/roles/remediation/vars/remediation_rules.yml
remediation_rules:
  - name: "New Rule"
    description: "Description của rule"
    target: "Target"
    action: "enable|disable|configure"
    enabled: true
```

## 📅 Lên Lịch Tự Động

### Crontab

```bash
# Thêm vào crontab: crontab -e

# Audit hàng ngày lúc 2h sáng
0 2 * * * cd /path/to/playbook && \
  ansible-playbook playbook/audit-only.yml \
  -i playbook/inventory/hosts.ini \
  -e environment=prod >> /var/log/audit.log 2>&1
```

## 📞 Cần Giúp?

### Kiểm tra Logs

```bash
# Logs từ playbook execution
tail -f /var/log/playbook_audit.log

# Logs từ scanner application
tail -f /var/log/db_scanner/scanner.log

# Ansible debug logs
export ANSIBLE_DEBUG=1
```

### Xác Thực Vấn Đề

```bash
# Ping test
ansible all -i playbook/inventory/hosts.ini -m ping

# Gather facts
ansible all -i playbook/inventory/hosts.ini -m setup

# Run ad-hoc command
ansible all -i playbook/inventory/hosts.ini -m command -a "uname -a"
```

## 🎯 Tiếp Theo

1. **Production Deployment**: Xem [playbook/README.md](README.md) để chi tiết
2. **Advanced Configuration**: Tùy chỉnh remediation rules cho environment của bạn
3. **Monitoring Integration**: Intergrate với monitoring tools (Nagios, Prometheus, etc.)
4. **Backup Strategy**: Thiết lập backup automaticly cho database

---

**Chúc mừng!** Bạn đã sẵn sàng sử dụng DB Scanner Ansible Playbook. 🎉
