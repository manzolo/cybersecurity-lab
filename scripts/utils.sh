#!/bin/bash
# Basic utility functions

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

print_banner() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                ${BLUE}CYBERSECURITY LAB v3.0${NC}                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}            ${YELLOW}Enhanced Testing Environment${NC}                 ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
}

check_dependencies() {
    local deps=("multipass")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Multipass is not installed. Install it from: https://multipass.run/"
        fi
    done
}

get_vm_ip() {
    local vm_name="$1"
    multipass info "$vm_name" | grep IPv4 | awk '{print $2}'
}

save_vm_ips() {
    local target_ip="$1"
    local attacker_ip="$2"
    
    cat > "config/vm_ips.conf" << EOF
TARGET_IP=$target_ip
ATTACKER_IP=$attacker_ip
EOF
}
