#!/bin/bash

# Script hỗ trợ để quản lý Ansible Playbook cho DB Scanner
# Sử dụng: ./manage_playbook.sh [command] [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAYBOOK_DIR="$SCRIPT_DIR/playbook"
INVENTORY="$PLAYBOOK_DIR/inventory/hosts.ini"
LOG_DIR="./logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
}

# Create log directory
mkdir -p "$LOG_DIR"

# Verify Ansible installation
check_ansible() {
    if ! command -v ansible-playbook &> /dev/null; then
        log_error "Ansible is not installed. Please install Ansible first."
        exit 1
    fi
    log_success "Ansible $(ansible-playbook --version | head -n1)"
}

# Validate inventory
check_inventory() {
    if [ ! -f "$INVENTORY" ]; then
        log_error "Inventory file not found: $INVENTORY"
        exit 1
    fi
    log_info "Using inventory: $INVENTORY"
}

# Run deployment
run_deploy() {
    local environment=${1:-dev}
    log_info "Deploying DB Scanner to $environment environment..."
    
    ansible-playbook "$PLAYBOOK_DIR/site.yml" \
        -i "$INVENTORY" \
        -e "environment=$environment" \
        --tags=deploy \
        2>&1 | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
    
    if [ $? -eq 0 ]; then
        log_success "Deployment completed"
    else
        log_error "Deployment failed"
        return 1
    fi
}

# Run audit only
run_audit() {
    local environment=${1:-prod}
    log_info "Running audit for $environment environment..."
    
    ansible-playbook "$PLAYBOOK_DIR/audit-only.yml" \
        -i "$INVENTORY" \
        -e "environment=$environment" \
        2>&1 | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
    
    if [ $? -eq 0 ]; then
        log_success "Audit completed"
    else
        log_error "Audit failed"
        return 1
    fi
}

# Run remediation
run_remediation() {
    local environment=${1:-dev}
    log_warning "Remediation will make changes to database configurations!"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        log_info "Remediation cancelled"
        return 0
    fi
    
    log_info "Running remediation for $environment environment..."
    
    ansible-playbook "$PLAYBOOK_DIR/remediate.yml" \
        -i "$INVENTORY" \
        -e "environment=$environment" \
        -e "skip_remediation_prompt=true" \
        2>&1 | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
    
    if [ $? -eq 0 ]; then
        log_success "Remediation completed"
    else
        log_error "Remediation failed"
        return 1
    fi
}

# Run full scan
run_full() {
    local environment=${1:-dev}
    log_info "Running full scan for $environment environment..."
    
    ansible-playbook "$PLAYBOOK_DIR/site.yml" \
        -i "$INVENTORY" \
        -e "environment=$environment" \
        2>&1 | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
    
    if [ $? -eq 0 ]; then
        log_success "Full scan completed"
    else
        log_error "Full scan failed"
        return 1
    fi
}

# List hosts
list_hosts() {
    log_info "Available hosts in inventory:"
    ansible-inventory -i "$INVENTORY" --list | grep '"name"' || true
}

# Test connectivity
test_connectivity() {
    log_info "Testing connectivity to all hosts..."
    ansible all -i "$INVENTORY" -m ping 2>&1 | tee -a "$LOG_DIR/playbook_$TIMESTAMP.log"
}

# Display help
show_help() {
    cat << EOF
${BLUE}DB Scanner Ansible Playbook Manager${NC}

Usage: $0 [command] [options]

Commands:
  deploy [env]         Deploy scanner to environment (default: dev)
  audit [env]          Run audit only (default: prod)
  remediate [env]      Run remediation (default: dev)
  full [env]           Run full scan - deploy + audit + remediate
  list                 List all available hosts
  test                 Test connectivity to all hosts
  help                 Show this help message

Environments:
  dev                  Development environment
  staging              Staging environment
  prod                 Production environment

Examples:
  $0 deploy prod
  $0 audit prod
  $0 remediate dev
  $0 full staging
  $0 test

EOF
}

# Main
main() {
    check_ansible
    check_inventory
    
    case "${1:-help}" in
        deploy)
            run_deploy "${2:-dev}"
            ;;
        audit)
            run_audit "${2:-prod}"
            ;;
        remediate)
            run_remediation "${2:-dev}"
            ;;
        full)
            run_full "${2:-dev}"
            ;;
        list)
            list_hosts
            ;;
        test)
            test_connectivity
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
