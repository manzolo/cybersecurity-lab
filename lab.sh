#!/bin/bash
# =============================================================================
# CYBERSECURITY LAB - Main Script (FIXED VERSION)
# =============================================================================

set -euo pipefail

# Global configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"
readonly LOGS_DIR="${SCRIPT_DIR}/logs"
readonly TEMPLATES_DIR="${SCRIPT_DIR}/templates"
readonly SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
readonly VM_ATTACKER="attacker"
readonly VM_TARGET="target"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Source modular components (with error checking)
if [[ -f "${SCRIPTS_DIR}/utils.sh" ]]; then
    source "${SCRIPTS_DIR}/utils.sh"
fi

if [[ -f "${SCRIPTS_DIR}/vm_management.sh" ]]; then
    source "${SCRIPTS_DIR}/vm_management.sh"
fi

if [[ -f "${SCRIPTS_DIR}/testing.sh" ]]; then
    source "${SCRIPTS_DIR}/testing.sh"
fi

if [[ -f "${SCRIPTS_DIR}/menu.sh" ]]; then
    source "${SCRIPTS_DIR}/menu.sh"
fi

# =============================================================================
# MAIN FUNCTIONS
# =============================================================================

create_environment() {
    log "Creating enhanced lab environment..."
    
    # Create directory structure
    mkdir -p "$CONFIG_DIR" "$LOGS_DIR"
    
    # Check if templates exist
    if [[ ! -f "${TEMPLATES_DIR}/target-cloud-init.yaml" ]]; then
        error "Template files not found. Please copy the cloud-init templates to ${TEMPLATES_DIR}/"
    fi
    
    # Copy templates to config (no envsubst needed since we don't have variables)
    log "Preparing configuration files..."
    cp "${TEMPLATES_DIR}/target-cloud-init.yaml" "${CONFIG_DIR}/target-cloud-init.yaml"
    cp "${TEMPLATES_DIR}/attacker-cloud-init.yaml" "${CONFIG_DIR}/attacker-cloud-init.yaml"
    
    # Create VMs
    create_vms
    
    # Configure environment
    configure_environment_post_create
    
    # Show summary
    show_environment_summary
}

create_vms() {
    log "Creating virtual machines..."
    
    # Create attacker VM
    log "Creating attacker VM..."
    multipass launch --name "$VM_ATTACKER" \
        --cpus 2 --memory 2G --disk 10G \
        --cloud-init "${CONFIG_DIR}/attacker-cloud-init.yaml" || error "Error creating attacker VM"
    
    # Create target VM
    log "Creating target VM..."
    multipass launch --name "$VM_TARGET" \
        --cpus 2 --memory 2G --disk 10G \
        --cloud-init "${CONFIG_DIR}/target-cloud-init.yaml" || error "Error creating target VM"
    
    # Wait for initialization
    log "Waiting for VMs to initialize..."
    sleep 20
}

configure_environment_post_create() {
    # Get IPs and save them
    local target_ip=$(get_vm_ip "$VM_TARGET")
    local attacker_ip=$(get_vm_ip "$VM_ATTACKER")
    
    log "Target IP: $target_ip"
    log "Attacker IP: $attacker_ip"
    
    # Save IPs for later use
    save_vm_ips "$target_ip" "$attacker_ip"
    
    # Configure attacker with target IP (if function exists)
    if type configure_attacker_scripts >/dev/null 2>&1; then
        configure_attacker_scripts "$target_ip"
    else
        configure_attacker_basic "$target_ip"
    fi
    
    # Verify services (if function exists)
    if type verify_services >/dev/null 2>&1; then
        verify_services
    else
        log "Skipping service verification (function not available)"
        sleep 10
    fi
}

configure_attacker_basic() {
    local target_ip="$1"
    log "Configuring attacker with target IP: $target_ip"

    multipass exec "$VM_ATTACKER" -- bash -c "
        # Create directories with proper permissions
        sudo mkdir -p /home/ubuntu/logs
        sudo chown ubuntu:ubuntu /home/ubuntu/logs
        sudo chmod 755 /home/ubuntu/logs
        
        # Create convenience aliases
        sudo bash -c 'cat > /home/ubuntu/.bash_aliases' << 'EOF'
alias lab-test=\"echo 'Running tests against $target_ip...' && python3 /opt/attack-scripts/port-scanner.py $target_ip && python3 /opt/attack-scripts/connection-tester.py $target_ip -t both -c 3 && python3 /opt/attack-scripts/web-fuzzer.py $target_ip\"
alias lab-connect=\"echo 'Connecting to $target_ip:9000...' && python3 /opt/attack-scripts/interactive-client.py $target_ip -p 9000\"
alias lab-scan=\"python3 /opt/attack-scripts/port-scanner.py\"
alias lab-web=\"python3 /opt/attack-scripts/web-fuzzer.py\"
alias lab-logs=\"ls -la ~/logs && tail -20 ~/logs/attacker.log 2>/dev/null || echo 'No logs yet - run lab-test first'\"
EOF

        sudo chown ubuntu:ubuntu /home/ubuntu/.bash_aliases
    " || warn "Failed to configure some attacker settings"

    success "Attacker VM configured with target IP: $target_ip"
    info "Available commands in attacker VM:"
    info "  lab-test      - Run full test suite"
    info "  lab-connect   - Interactive TCP client"
    info "  lab-scan <ip> - Port scanner"
    info "  lab-web <ip>  - Web vulnerability tests"
    info "  lab-logs      - Show recent logs"
}

show_environment_summary() {
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        source "${CONFIG_DIR}/vm_ips.conf"
    else
        error "VM IP configuration not found"
    fi
    
    success "Environment successfully created!"
    echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${BLUE}Lab Environment Details${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Target IP:    ${GREEN}${TARGET_IP}${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Attacker IP:  ${YELLOW}${ATTACKER_IP}${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}Services Running:${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   TCP Server:  ${GREEN}${TARGET_IP}:9000${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   HTTP Server: ${GREEN}${TARGET_IP}:8080${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
    
    show_quick_commands
}

show_quick_commands() {
    echo -e "\n${BLUE}Quick Start Commands:${NC}"
    echo -e "  ${YELLOW}$0 test${NC}                    # Run automated tests"
    echo -e "  ${YELLOW}$0 client${NC}                  # Interactive TCP client"
    echo -e "  ${YELLOW}$0 status${NC}                  # Check status"
    echo -e "  ${YELLOW}multipass shell $VM_ATTACKER${NC}  # Connect to attacker"
    echo -e "  ${YELLOW}multipass shell $VM_TARGET${NC}    # Connect to target"
    
    echo -e "\n${BLUE}In attacker VM, use these shortcuts:${NC}"
    echo -e "  ${CYAN}lab-test${NC}      - Full test suite"
    echo -e "  ${CYAN}lab-connect${NC}   - Interactive client"
    echo -e "  ${CYAN}lab-logs${NC}      - View logs"
}

# Basic functions if modules aren't available
basic_destroy_environment() {
    log "Destroying lab environment..."
    
    for vm in "$VM_ATTACKER" "$VM_TARGET"; do
        if multipass list | grep -q "$vm"; then
            multipass stop "$vm" 2>/dev/null || true
            multipass delete "$vm" 2>/dev/null || true
        fi
    done
    
    multipass purge 2>/dev/null || true
    rm -f "${CONFIG_DIR}/vm_ips.conf"
    
    success "Environment destroyed successfully"
}

basic_show_status() {
    echo -e "${BLUE}=== LAB ENVIRONMENT STATUS ===${NC}"
    multipass list
    
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        echo -e "\n${BLUE}=== IP ADDRESSES ===${NC}"
        source "${CONFIG_DIR}/vm_ips.conf"
        echo -e "Target:   ${GREEN}$TARGET_IP${NC}"
        echo -e "Attacker: ${YELLOW}$ATTACKER_IP${NC}"
    fi
}

basic_run_tests() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    log "Running basic automated tests..."
    
    echo -e "\n${PURPLE}=== PORT SCAN ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p common 2>/dev/null || echo "Port scanner not available"
    
    echo -e "\n${PURPLE}=== CONNECTION TESTS ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" -t both -c 3 2>/dev/null || echo "Connection tester not available"
    
    echo -e "\n${PURPLE}=== WEB TESTS ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/web-fuzzer.py "$TARGET_IP" 2>/dev/null || echo "Web fuzzer not available"
    
    success "Tests completed (some tools may not be available yet)"
}

basic_run_interactive_client() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    log "Starting interactive client session..."
    info "Connecting to vulnerable server at $TARGET_IP:9000"
    
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/interactive-client.py "$TARGET_IP" -p 9000 2>/dev/null || {
        info "Interactive client not available, using netcat instead:"
        multipass exec "$VM_ATTACKER" -- nc "$TARGET_IP" 9000
    }
}

show_basic_help() {
    echo -e "${BLUE}USAGE:${NC} $0 [OPTION]"
    echo
    echo -e "${BLUE}OPTIONS:${NC}"
    echo -e "  ${YELLOW}create${NC}        Create the lab environment (2 VMs)"
    echo -e "  ${YELLOW}destroy${NC}       Destroy the lab environment completely"
    echo -e "  ${YELLOW}status${NC}        Show detailed VM and service status"
    echo -e "  ${YELLOW}test${NC}          Run comprehensive automated tests"
    echo -e "  ${YELLOW}client${NC}        Run interactive client to TCP server"
    echo -e "  ${YELLOW}help${NC}          Show this help message"
    echo
    echo -e "${BLUE}SERVICES DEPLOYED:${NC}"
    echo -e "  • ${GREEN}TCP Server${NC}     Port 9000  (Vulnerable command server)"
    echo -e "  • ${GREEN}HTTP Server${NC}    Port 8080  (Web app with XSS, traversal)"
    echo -e "  • ${GREEN}SSH Access${NC}     Port 22    (Remote access)"
    echo
    echo -e "${BLUE}EXAMPLES:${NC}"
    echo -e "  ${CYAN}$0 create${NC}                    # Create complete environment"
    echo -e "  ${CYAN}$0 test${NC}                      # Run all automated tests"
    echo -e "  ${CYAN}$0 client${NC}                    # Connect to TCP server interactively"
    echo -e "  ${CYAN}$0 status${NC}                    # Check status"
    echo -e "  ${CYAN}$0 destroy${NC}                   # Clean up everything"
    echo
    echo -e "  ${CYAN}multipass shell attacker${NC}     # Direct shell access"
    echo -e "  ${CYAN}multipass shell target${NC}       # Direct shell access"
    echo
    echo -e "${YELLOW}SETUP:${NC}"
    echo -e "If this is your first time, make sure you have the template files:"
    echo -e "  • templates/attacker-cloud-init.yaml"
    echo -e "  • templates/target-cloud-init.yaml"
    echo
    echo -e "${GREEN}TIP:${NC} Run without arguments to see this help"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Print banner if function exists
    if type print_banner >/dev/null 2>&1; then
        print_banner
    else
        echo -e "${CYAN}=== CYBERSECURITY LAB v3.0 ===${NC}"
    fi
    
    # Check dependencies if function exists
    if type check_dependencies >/dev/null 2>&1; then
        check_dependencies
    fi
    
    # Handle command line arguments
    case "${1:-menu}" in
        create)
            create_environment
            ;;
        destroy)
            if type destroy_environment >/dev/null 2>&1; then
                destroy_environment
            else
                basic_destroy_environment
            fi
            ;;
        status)
            if type show_status >/dev/null 2>&1; then
                show_status
            else
                basic_show_status
            fi
            ;;
        test)
            if type run_tests >/dev/null 2>&1; then
                run_tests
            else
                basic_run_tests
            fi
            ;;
        client)
            if type run_interactive_client >/dev/null 2>&1; then
                run_interactive_client
            else
                basic_run_interactive_client
            fi
            ;;
        menu|connect)
            if type interactive_menu >/dev/null 2>&1; then
                interactive_menu
            else
                warn "Interactive menu not available. Use individual commands."
                show_basic_help
            fi
            ;;
        help|--help|-h|"")
            if type show_help >/dev/null 2>&1; then
                show_help
            else
                show_basic_help
            fi
            ;;
        *)
            error "Unknown option: $1. Use 'help' to see available options."
            ;;
    esac
}

# Trap cleanup on script exit
trap 'echo -e "\n${YELLOW}Script interrupted. Environment preserved.${NC}"' INT

# Start the script
main "$@"