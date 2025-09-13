#!/bin/bash
# =============================================================================
# CYBERSECURITY LAB - Main Script with Separated Python Scripts
# =============================================================================

set -euo pipefail

# Global configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"
readonly LOGS_DIR="${SCRIPT_DIR}/logs"
readonly TEMPLATES_DIR="${SCRIPT_DIR}/templates"
readonly SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
readonly TARGET_SCRIPTS_DIR="${SCRIPT_DIR}/target-scripts"
readonly ATTACKER_SCRIPTS_DIR="${SCRIPT_DIR}/attacker-scripts"
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
# NEW FUNCTIONS FOR SEPARATED SCRIPTS
# =============================================================================

check_script_directories() {
    """Check if all required script directories exist"""
    local missing_dirs=()
    
    if [[ ! -d "$TARGET_SCRIPTS_DIR" ]]; then
        missing_dirs+=("target-scripts")
    fi
    
    if [[ ! -d "$ATTACKER_SCRIPTS_DIR" ]]; then
        missing_dirs+=("attacker-scripts")
    fi
    
    if [[ ! -d "$TEMPLATES_DIR" ]]; then
        missing_dirs+=("templates")
    fi
    
    if [[ ${#missing_dirs[@]} -gt 0 ]]; then
        error "Missing required directories: ${missing_dirs[*]}"
        echo -e "${YELLOW}Expected project structure:${NC}"
        echo "cybersecurity-lab/"
        echo "├── target-scripts/     # Python scripts for target VM"
        echo "├── attacker-scripts/   # Python scripts for attacker VM"
        echo "├── templates/          # Cloud-init templates"
        echo "└── scripts/            # Bash utility scripts"
        exit 1
    fi
}

deploy_target_scripts() {
    """Deploy Python scripts to target VM"""
    log "Deploying target scripts..."
    
    local scripts=(
        "vulnerable-server.py"
        "web-server.py"
        "monitor.sh"
    )
    
    for script in "${scripts[@]}"; do
        local script_path="${TARGET_SCRIPTS_DIR}/${script}"
        
        if [[ ! -f "$script_path" ]]; then
            warn "Script not found: $script_path"
            continue
        fi
        
        log "Transferring $script to target VM..."
        multipass transfer "$script_path" "$VM_TARGET:/tmp/$script"
        
        # Install with proper permissions
        multipass exec "$VM_TARGET" -- bash -c "
            sudo mv /tmp/$script /opt/
            sudo chmod +x /opt/$script
            sudo chown root:root /opt/$script
        "
    done
    
    success "Target scripts deployed successfully"
}

deploy_attacker_scripts() {
    """Deploy Python scripts to attacker VM"""
    log "Deploying attacker scripts..."
    
    local scripts=(
        "port-scanner.py"
        "connection-tester.py"
        "interactive-client.py"
        "web-fuzzer.py"
    )
    
    # Create attack scripts directory
    multipass exec "$VM_ATTACKER" -- bash -c "
        sudo mkdir -p /opt/attack-scripts
        sudo chown ubuntu:ubuntu /opt/attack-scripts
        chmod 755 /opt/attack-scripts
    "
    
    for script in "${scripts[@]}"; do
        local script_path="${ATTACKER_SCRIPTS_DIR}/${script}"
        
        if [[ ! -f "$script_path" ]]; then
            warn "Script not found: $script_path"
            continue
        fi
        
        log "Transferring $script to attacker VM..."
        multipass transfer "$script_path" "$VM_ATTACKER:/tmp/$script"
        
        # Install with proper permissions
        multipass exec "$VM_ATTACKER" -- bash -c "
            mv /tmp/$script /opt/attack-scripts/
            chmod +x /opt/attack-scripts/$script
            chown ubuntu:ubuntu /opt/attack-scripts/$script
        "
    done
    
    success "Attacker scripts deployed successfully"
}

configure_target_services() {
    """Configure systemd services for target VM"""
    log "Configuring target services..."
    
    # Create systemd service files
    multipass exec "$VM_TARGET" -- bash -c "
        # Vulnerable TCP Server Service
        sudo tee /etc/systemd/system/vulnerable-server.service > /dev/null << 'EOF'
[Unit]
Description=Vulnerable TCP Server for Cybersecurity Lab
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vulnerable-server.py
Restart=always
RestartSec=5
User=root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=vulnerable-server

[Install]
WantedBy=multi-user.target
EOF

        # Vulnerable Web Server Service
        sudo tee /etc/systemd/system/vulnerable-web.service > /dev/null << 'EOF'
[Unit]
Description=Vulnerable Web Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/web-server.py
Restart=always
RestartSec=5
User=root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=vulnerable-web

[Install]
WantedBy=multi-user.target
EOF

        # Target Monitor Service
        sudo tee /etc/systemd/system/target-monitor.service > /dev/null << 'EOF'
[Unit]
Description=Target Monitor
After=network.target

[Service]
ExecStart=/opt/monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

        # Create log files with proper permissions
        sudo touch /var/log/vulnerable-server.log
        sudo touch /var/log/vulnerable-web.log
        sudo touch /var/log/target-monitor.log
        sudo chmod 664 /var/log/vulnerable-*.log /var/log/target-monitor.log
        
        # Enable and start services
        sudo systemctl daemon-reload
        sudo systemctl enable vulnerable-server.service vulnerable-web.service target-monitor.service
        sudo systemctl start vulnerable-server.service vulnerable-web.service target-monitor.service
    "
    
    success "Target services configured and started"
}

configure_attacker_aliases() {
    """Configure convenient aliases in attacker VM"""
    local target_ip="$1"
    log "Configuring attacker aliases for target: $target_ip"
    
    multipass exec "$VM_ATTACKER" -- bash -c "
        # Create logs directory
        mkdir -p /home/ubuntu/logs
        chmod 755 /home/ubuntu/logs
        
        # Create convenience aliases
        cat > /home/ubuntu/.bash_aliases << 'EOF'
# Cybersecurity Lab Aliases
alias lab-test='echo \"Running comprehensive tests...\" && python3 /opt/attack-scripts/port-scanner.py $target_ip && python3 /opt/attack-scripts/connection-tester.py $target_ip -t both -c 3 && python3 /opt/attack-scripts/web-fuzzer.py $target_ip'
alias lab-connect='echo \"Connecting to vulnerable TCP server...\" && python3 /opt/attack-scripts/interactive-client.py $target_ip -p 9000'
alias lab-scan='python3 /opt/attack-scripts/port-scanner.py'
alias lab-web='python3 /opt/attack-scripts/web-fuzzer.py'
alias lab-conn='python3 /opt/attack-scripts/connection-tester.py'
alias lab-interactive='python3 /opt/attack-scripts/interactive-client.py'
alias lab-logs='ls -la ~/logs && echo && tail -20 ~/logs/attacker.log 2>/dev/null || echo \"No logs yet - run lab-test first\"'
alias lab-help='echo \"Available lab commands:\" && echo \"  lab-test      - Run full vulnerability test suite\" && echo \"  lab-connect   - Interactive TCP client\" && echo \"  lab-scan <ip> - Port scanner\" && echo \"  lab-web <ip>  - Web vulnerability fuzzer\" && echo \"  lab-logs      - Show recent activity logs\"'
EOF
        
        chown ubuntu:ubuntu /home/ubuntu/.bash_aliases
        
        # Install Python dependencies
        pip3 install requests >/dev/null 2>&1 || sudo apt-get install -y python3-requests >/dev/null 2>&1
    "
    
    success "Attacker VM configured with aliases and dependencies"
}

update_scripts_only() {
    """Update scripts on existing VMs without recreating them"""
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    log "Updating scripts on existing VMs..."
    
    # Check if VMs are running
    if ! multipass list | grep -q "$VM_TARGET.*Running"; then
        error "Target VM is not running"
    fi
    
    if ! multipass list | grep -q "$VM_ATTACKER.*Running"; then
        error "Attacker VM is not running"
    fi
    
    # Deploy updated scripts
    deploy_target_scripts
    deploy_attacker_scripts
    
    # Restart target services
    log "Restarting target services..."
    multipass exec "$VM_TARGET" -- bash -c "
        sudo systemctl restart vulnerable-server.service vulnerable-web.service
        sudo systemctl status vulnerable-server.service vulnerable-web.service --no-pager
    "
    
    success "Scripts updated successfully"
}

# =============================================================================
# UPDATED MAIN FUNCTIONS
# =============================================================================

create_environment() {
    log "Creating enhanced lab environment with separated scripts..."
    
    # Check prerequisites
    check_script_directories
    
    # Create directory structure
    mkdir -p "$CONFIG_DIR" "$LOGS_DIR"
    
    # Check if templates exist
    if [[ ! -f "${TEMPLATES_DIR}/target-cloud-init.yaml" ]]; then
        error "Template files not found. Please ensure templates are in ${TEMPLATES_DIR}/"
    fi
    
    # Copy templates to config
    log "Preparing configuration files..."
    cp "${TEMPLATES_DIR}/target-cloud-init.yaml" "${CONFIG_DIR}/target-cloud-init.yaml"
    cp "${TEMPLATES_DIR}/attacker-cloud-init.yaml" "${CONFIG_DIR}/attacker-cloud-init.yaml"
    
    # Create VMs with basic configuration
    create_vms_basic
    
    # Deploy scripts to VMs
    deploy_target_scripts
    deploy_attacker_scripts
    
    # Configure services
    configure_target_services
    
    # Configure environment
    configure_environment_post_create
    
    # Show summary
    show_environment_summary
}

create_vms_basic() {
    log "Creating virtual machines with basic configuration..."
    
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
    sleep 30
    
    success "VMs created successfully"
}

configure_environment_post_create() {
    # Get IPs and save them
    local target_ip=$(get_vm_ip "$VM_TARGET")
    local attacker_ip=$(get_vm_ip "$VM_ATTACKER")
    
    log "Target IP: $target_ip"
    log "Attacker IP: $attacker_ip"
    
    # Save IPs for later use
    save_vm_ips "$target_ip" "$attacker_ip"
    
    # Configure attacker with target IP
    configure_attacker_aliases "$target_ip"
    
    # Verify services are running
    sleep 10
    verify_services || warn "Some services may not be ready yet"
}

verify_services() {
    log "Verifying deployed services..."
    
    local services_ok=true
    
    # Check target services
    if multipass exec "$VM_TARGET" -- systemctl is-active --quiet vulnerable-server.service; then
        log "✓ TCP Server service is running"
    else
        warn "✗ TCP Server service not running"
        services_ok=false
    fi
    
    if multipass exec "$VM_TARGET" -- systemctl is-active --quiet vulnerable-web.service; then
        log "✓ Web Server service is running"
    else
        warn "✗ Web Server service not running"
        services_ok=false
    fi
    
    # Check attacker scripts
    if multipass exec "$VM_ATTACKER" -- test -x /opt/attack-scripts/port-scanner.py; then
        log "✓ Attacker scripts deployed"
    else
        warn "✗ Attacker scripts missing"
        services_ok=false
    fi
    
    if $services_ok; then
        success "All services verified successfully"
    else
        warn "Some services need attention - check with '$0 status'"
    fi
    
    return $services_ok
}

show_environment_summary() {
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        source "${CONFIG_DIR}/vm_ips.conf"
    else
        error "VM IP configuration not found"
    fi
    
    success "Environment successfully created with separated scripts!"
    echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${BLUE}Lab Environment Details${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Target IP:    ${GREEN}${TARGET_IP}${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Attacker IP:  ${YELLOW}${ATTACKER_IP}${NC}              ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}Services Running:${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   TCP Server:  ${GREEN}${TARGET_IP}:9000${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   HTTP Server: ${GREEN}${TARGET_IP}:8080${NC}       ${CYAN}│${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${PURPLE}Scripts Deployed:${NC}                       ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Target: 3 scripts                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Attacker: 4 scripts                  ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
    
    show_quick_commands
}

show_quick_commands() {
    echo -e "\n${BLUE}Quick Start Commands:${NC}"
    echo -e "  ${YELLOW}$0 test${NC}                    # Run automated tests"
    echo -e "  ${YELLOW}$0 client${NC}                  # Interactive TCP client"
    echo -e "  ${YELLOW}$0 status${NC}                  # Check status"
    echo -e "  ${YELLOW}$0 update-scripts${NC}          # Update scripts only"
    echo -e "  ${YELLOW}multipass shell $VM_ATTACKER${NC}  # Connect to attacker"
    echo -e "  ${YELLOW}multipass shell $VM_TARGET${NC}    # Connect to target"
    
    echo -e "\n${BLUE}In attacker VM, use these shortcuts:${NC}"
    echo -e "  ${CYAN}lab-help${NC}      - Show all available commands"
    echo -e "  ${CYAN}lab-test${NC}      - Full vulnerability test suite"
    echo -e "  ${CYAN}lab-connect${NC}   - Interactive client"
    echo -e "  ${CYAN}lab-web <ip>${NC}  - Web vulnerability fuzzer"
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
    rm -rf "${CONFIG_DIR}"
    
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
        
        echo -e "\n${BLUE}=== SERVICES STATUS ===${NC}"
        if multipass list | grep -q "$VM_TARGET.*Running"; then
            # Check services
            if multipass exec "$VM_TARGET" -- systemctl is-active vulnerable-server.service >/dev/null 2>&1; then
                echo -e "TCP Server (9000):  ${GREEN}RUNNING${NC}"
            else
                echo -e "TCP Server (9000):  ${RED}STOPPED${NC}"
            fi
            
            if multipass exec "$VM_TARGET" -- systemctl is-active vulnerable-web.service >/dev/null 2>&1; then
                echo -e "HTTP Server (8080): ${GREEN}RUNNING${NC}"
            else
                echo -e "HTTP Server (8080): ${RED}STOPPED${NC}"
            fi
        else
            echo -e "Target VM: ${RED}NOT RUNNING${NC}"
        fi
        
        echo -e "\n${BLUE}=== SCRIPTS STATUS ===${NC}"
        if multipass list | grep -q "$VM_ATTACKER.*Running"; then
            if multipass exec "$VM_ATTACKER" -- test -f /opt/attack-scripts/port-scanner.py; then
                echo -e "Attack Scripts: ${GREEN}DEPLOYED${NC}"
            else
                echo -e "Attack Scripts: ${RED}MISSING${NC}"
            fi
        else
            echo -e "Attacker VM: ${RED}NOT RUNNING${NC}"
        fi
    fi
}

basic_run_tests() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    log "Running automated tests with separated scripts..."
    
    echo -e "\n${PURPLE}=== ENHANCED PORT SCAN ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p common 2>/dev/null || echo "Port scanner not available"
    
    echo -e "\n${PURPLE}=== CONNECTION TESTS ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" -t both -c 3 2>/dev/null || echo "Connection tester not available"
    
    echo -e "\n${PURPLE}=== WEB VULNERABILITY SCAN ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/web-fuzzer.py "$TARGET_IP" 2>/dev/null || echo "Web fuzzer not available"
    
    success "Enhanced tests completed"
}

basic_run_interactive_client() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    log "Starting enhanced interactive client..."
    info "Connecting to vulnerable server at $TARGET_IP:9000"
    
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/interactive-client.py "$TARGET_IP" -p 9000 2>/dev/null || {
        info "Enhanced client not available, using netcat fallback:"
        multipass exec "$VM_ATTACKER" -- nc "$TARGET_IP" 9000
    }
}

show_enhanced_help() {
    echo -e "${BLUE}USAGE:${NC} $0 [OPTION]"
    echo
    echo -e "${BLUE}OPTIONS:${NC}"
    echo -e "  ${YELLOW}create${NC}        Create the lab environment (2 VMs + scripts)"
    echo -e "  ${YELLOW}destroy${NC}       Destroy the lab environment completely"
    echo -e "  ${YELLOW}status${NC}        Show detailed VM and service status"
    echo -e "  ${YELLOW}test${NC}          Run comprehensive automated tests"
    echo -e "  ${YELLOW}client${NC}        Run enhanced interactive client"
    echo -e "  ${YELLOW}update-scripts${NC} Update Python scripts on existing VMs"
    echo -e "  ${YELLOW}help${NC}          Show this help message"
    echo
    echo -e "${BLUE}NEW FEATURES:${NC}"
    echo -e "  • ${GREEN}Separated Python scripts${NC} for better maintainability"
    echo -e "  • ${GREEN}Enhanced vulnerability testing${NC} with detailed reporting"
    echo -e "  • ${GREEN}Interactive exploitation client${NC} with command completion"
    echo -e "  • ${GREEN}Comprehensive web fuzzing${NC} (XSS, traversal, endpoints)"
    echo -e "  • ${GREEN}Script update capability${NC} without VM recreation"
    echo
    echo -e "${BLUE}SCRIPT ORGANIZATION:${NC}"
    echo -e "  target-scripts/       ${GREEN}# Scripts deployed to target VM${NC}"
    echo -e "  attacker-scripts/     ${GREEN}# Scripts deployed to attacker VM${NC}"
    echo -e "  templates/            ${GREEN}# Cloud-init configuration templates${NC}"
    echo -e "  scripts/              ${GREEN}# Modular bash components${NC}"
    echo
    echo -e "${BLUE}SERVICES DEPLOYED:${NC}"
    echo -e "  • ${GREEN}Enhanced TCP Server${NC}     Port 9000  (Command injection, file access)"
    echo -e "  • ${GREEN}Vulnerable Web App${NC}      Port 8080  (XSS, traversal, info disclosure)"
    echo -e "  • ${GREEN}System Monitor${NC}          Background (Activity logging)"
    echo -e "  • ${GREEN}SSH Access${NC}              Port 22    (Remote access)"
    echo
    echo -e "${BLUE}EXAMPLES:${NC}"
    echo -e "  ${CYAN}$0 create${NC}                    # Create complete environment"
    echo -e "  ${CYAN}$0 test${NC}                      # Run all automated tests"
    echo -e "  ${CYAN}$0 client${NC}                    # Interactive exploitation session"
    echo -e "  ${CYAN}$0 update-scripts${NC}            # Update scripts without recreating VMs"
    echo -e "  ${CYAN}$0 status${NC}                    # Detailed status check"
    echo -e "  ${CYAN}$0 destroy${NC}                   # Clean up everything"
    echo
    echo -e "  ${CYAN}multipass shell attacker${NC}     # Direct shell access"
    echo -e "  ${CYAN}multipass shell target${NC}       # Direct shell access"
    echo
    echo -e "${GREEN}NEW:${NC} In attacker VM, use ${CYAN}lab-help${NC} to see all available testing commands"
}

# =============================================================================
# MAIN FUNCTION UPDATED
# =============================================================================

main() {
    # Print banner if function exists
    if type print_banner >/dev/null 2>&1; then
        print_banner
    else
        echo -e "${CYAN}=== CYBERSECURITY LAB v3.1 - Enhanced with Separated Scripts ===${NC}"
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
        update-scripts)
            update_scripts_only
            ;;
        menu|connect)
            if type interactive_menu >/dev/null 2>&1; then
                interactive_menu
            else
                warn "Interactive menu not available. Use individual commands."
                show_enhanced_help
            fi
            ;;
        help|--help|-h|"")
            if type show_help >/dev/null 2>&1; then
                show_help
            else
                show_enhanced_help
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