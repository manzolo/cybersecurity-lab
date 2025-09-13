#!/bin/bash
# =============================================================================
# CYBERSECURITY LAB - Complete Script with Separated Services
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
readonly SERVICES_DIR="${SCRIPT_DIR}/services"
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

# Source modular components
for module in utils vm_management testing menu motd aliases; do
    if [[ -f "${SCRIPTS_DIR}/${module}.sh" ]]; then
        source "${SCRIPTS_DIR}/${module}.sh"
    fi
done

# =============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# =============================================================================

check_service_files() {
    local missing_services=()
    local services=(
        "vulnerable-server.service"
        "vulnerable-web.service" 
        "target-monitor.service"
    )
    
    if [[ ! -d "$SERVICES_DIR" ]]; then
        error "Services directory not found: $SERVICES_DIR"
        return 1
    fi
    
    for service in "${services[@]}"; do
        if [[ ! -f "${SERVICES_DIR}/${service}" ]]; then
            missing_services+=("$service")
        fi
    done
    
    if [[ ${#missing_services[@]} -gt 0 ]]; then
        error "Missing service files: ${missing_services[*]}"
        return 1
    fi
    
    return 0
}

deploy_systemd_services() {
    log "Deploying systemd service files..."
    
    local services=(
        "vulnerable-server.service"
        "vulnerable-web.service"
        "target-monitor.service"
    )
    
    for service in "${services[@]}"; do
        local service_path="${SERVICES_DIR}/${service}"
        
        log "Deploying service: $service"
        multipass transfer "$service_path" "$VM_TARGET:/tmp/$service"
        
        multipass exec "$VM_TARGET" -- bash -c "
            sudo mv /tmp/$service /etc/systemd/system/$service
            sudo chown root:root /etc/systemd/system/$service
            sudo chmod 644 /etc/systemd/system/$service
        "
    done
    
    success "Systemd service files deployed successfully"
}

configure_target_services() {
    log "Configuring target services from separated files..."
    
    check_service_files || return 1
    deploy_systemd_services
    
    multipass exec "$VM_TARGET" -- bash -c "
        # Create log files with proper permissions
        sudo touch /var/log/vulnerable-server.log
        sudo touch /var/log/vulnerable-web.log  
        sudo touch /var/log/target-monitor.log
        sudo chmod 664 /var/log/vulnerable-*.log /var/log/target-monitor.log
        
        # Create dedicated lab log directory
        sudo mkdir -p /var/log/cybersecurity-lab
        sudo chmod 755 /var/log/cybersecurity-lab
        
        # Reload systemd and enable services
        sudo systemctl daemon-reload
        sudo systemctl enable vulnerable-server.service vulnerable-web.service target-monitor.service
        sudo systemctl start vulnerable-server.service vulnerable-web.service target-monitor.service
        
        # Wait and check status
        sleep 3
        echo 'Service Status Check:'
        systemctl is-active vulnerable-server.service && echo '✓ TCP Server: ACTIVE' || echo '✗ TCP Server: FAILED'
        systemctl is-active vulnerable-web.service && echo '✓ Web Server: ACTIVE' || echo '✗ Web Server: FAILED' 
        systemctl is-active target-monitor.service && echo '✓ Monitor: ACTIVE' || echo '✗ Monitor: FAILED'
    "
    
    success "Target services configured and started"
}

show_service_status() {
    if ! multipass list | grep -q "$VM_TARGET.*Running"; then
        warn "Target VM is not running"
        return 1
    fi
    
    echo -e "${BLUE}=== SYSTEMD SERVICES STATUS ===${NC}"
    
    multipass exec "$VM_TARGET" -- bash -c '
        services=("vulnerable-server.service" "vulnerable-web.service" "target-monitor.service")
        
        for service in "${services[@]}"; do
            echo "----------------------------------------"
            echo "Service: $service"
            echo "----------------------------------------"
            
            if systemctl is-active --quiet "$service"; then
                echo "Status: ✓ ACTIVE"
                uptime=$(systemctl show "$service" --property=ActiveEnterTimestamp --value)
                echo "Started: $uptime"
                echo "Recent logs:"
                journalctl -u "$service" --no-pager -n 3 --output=short 2>/dev/null || echo "No logs available"
            else
                echo "Status: ✗ INACTIVE"
                echo "Error logs:"
                journalctl -u "$service" --no-pager -n 3 --output=short 2>/dev/null || echo "No logs available"
            fi
            echo
        done
        
        echo "----------------------------------------"
        echo "Listening Ports:"
        echo "----------------------------------------"
        ss -tlnp | grep -E ":(9000|8080|22)" || echo "No lab services listening"
    '
}

restart_services() {
    if ! multipass list | grep -q "$VM_TARGET.*Running"; then
        error "Target VM is not running"
        return 1
    fi
    
    log "Restarting lab services..."
    
    multipass exec "$VM_TARGET" -- bash -c '
        services=("vulnerable-server.service" "vulnerable-web.service" "target-monitor.service")
        
        for service in "${services[@]}"; do
            echo "Restarting $service..."
            sudo systemctl restart "$service"
            
            if systemctl is-active --quiet "$service"; then
                echo "✓ $service restarted successfully"
            else
                echo "✗ $service failed to restart"
                journalctl -u "$service" --no-pager -n 5 2>/dev/null || true
            fi
        done
    '
    
    success "Service restart completed"
}

update_services_only() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    log "Updating systemd service files..."
    
    if ! multipass list | grep -q "$VM_TARGET.*Running"; then
        error "Target VM is not running"
    fi
    
    deploy_systemd_services
    
    multipass exec "$VM_TARGET" -- bash -c "
        sudo systemctl daemon-reload
        echo 'Systemd configuration reloaded'
    "
    
    info "Service files updated. Use 'restart-services' to apply changes."
    success "Service update completed"
}

# =============================================================================
# UPDATED MAIN FUNCTIONS
# =============================================================================

check_script_directories() {
    local missing_dirs=()
    
    local required_dirs=(
        "$TARGET_SCRIPTS_DIR:target-scripts"
        "$ATTACKER_SCRIPTS_DIR:attacker-scripts" 
        "$TEMPLATES_DIR:templates"
        "$SERVICES_DIR:services"
    )
    
    for dir_info in "${required_dirs[@]}"; do
        IFS=':' read -r dir_path dir_name <<< "$dir_info"
        if [[ ! -d "$dir_path" ]]; then
            missing_dirs+=("$dir_name")
        fi
    done
    
    if [[ ${#missing_dirs[@]} -gt 0 ]]; then
        error "Missing required directories: ${missing_dirs[*]}"
        echo -e "${YELLOW}Expected project structure:${NC}"
        echo "cybersecurity-lab/"
        echo "├── target-scripts/     # Python scripts for target VM"
        echo "├── attacker-scripts/   # Python scripts for attacker VM"  
        echo "├── templates/          # Cloud-init templates"
        echo "├── services/           # Systemd service files"
        echo "└── scripts/            # Bash utility scripts"
        return 1
    fi
    
    return 0
}

create_environment() {
    log "Creating enhanced lab environment with separated scripts and services..."
    
    check_script_directories
    mkdir -p "$CONFIG_DIR" "$LOGS_DIR"
    
    if [[ ! -f "${TEMPLATES_DIR}/target-cloud-init.yaml" ]]; then
        error "Template files not found in ${TEMPLATES_DIR}/"
    fi
    
    log "Preparing configuration files..."
    cp "${TEMPLATES_DIR}/target-cloud-init.yaml" "${CONFIG_DIR}/target-cloud-init.yaml"
    cp "${TEMPLATES_DIR}/attacker-cloud-init.yaml" "${CONFIG_DIR}/attacker-cloud-init.yaml"
    
    create_vms_basic
    deploy_target_scripts
    deploy_attacker_scripts  
    configure_target_services
    configure_environment_post_create
    show_environment_summary
}

deploy_target_scripts() {
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
        
        multipass exec "$VM_TARGET" -- bash -c "
            sudo mv /tmp/$script /opt/
            sudo chmod +x /opt/$script
            sudo chown root:root /opt/$script
        "
    done
    
    success "Target scripts deployed successfully"
}

deploy_attacker_scripts() {
    log "Deploying attacker scripts..."
    
    local scripts=(
        "port-scanner.py"
        "connection-tester.py"
        "interactive-client.py"
        "web-fuzzer.py"
    )
    
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
        
        multipass exec "$VM_ATTACKER" -- bash -c "
            mv /tmp/$script /opt/attack-scripts/
            chmod +x /opt/attack-scripts/$script
            chown ubuntu:ubuntu /opt/attack-scripts/$script
        "
    done
    
    success "Attacker scripts deployed successfully"
}

create_vms_basic() {
    log "Creating virtual machines with basic configuration..."
    
    log "Creating attacker VM..."
    multipass launch --name "$VM_ATTACKER" \
        --cpus 2 --memory 2G --disk 10G \
        --cloud-init "${CONFIG_DIR}/attacker-cloud-init.yaml" || error "Error creating attacker VM"
    
    log "Creating target VM..."
    multipass launch --name "$VM_TARGET" \
        --cpus 2 --memory 2G --disk 10G \
        --cloud-init "${CONFIG_DIR}/target-cloud-init.yaml" || error "Error creating target VM"
    
    log "Waiting for VMs to initialize..."
    sleep 30
    
    success "VMs created successfully"
}

configure_environment_post_create() {
    local target_ip=$(get_vm_ip "$VM_TARGET")
    local attacker_ip=$(get_vm_ip "$VM_ATTACKER")
    
    log "Target IP: $target_ip"
    log "Attacker IP: $attacker_ip"
    
    save_vm_ips "$target_ip" "$attacker_ip"
    configure_attacker_aliases "$target_ip"
    
    sleep 10
    verify_services || warn "Some services may not be ready yet"
}

verify_services() {
    log "Verifying deployed services..."
    
    local services_ok=true
    
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
    
    if multipass exec "$VM_TARGET" -- test -x /opt/attack-scripts/port-scanner.py; then
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
    
    success "Environment successfully created with separated scripts and services!"
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
    echo -e "${CYAN}│${NC} ${PURPLE}Components Deployed:${NC}                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Target scripts: 3                    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Attacker scripts: 4                  ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   Systemd services: 3                  ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
    
    show_quick_commands
}

show_quick_commands() {
    echo -e "\n${BLUE}Quick Start Commands:${NC}"
    echo -e "  ${YELLOW}$0 test${NC}                    # Run automated tests"
    echo -e "  ${YELLOW}$0 client${NC}                  # Interactive TCP client"
    echo -e "  ${YELLOW}$0 status${NC}                  # Check status"
    echo -e "  ${YELLOW}$0 service-status${NC}          # Detailed service status"
    
    echo -e "\n${BLUE}In attacker VM, use these shortcuts:${NC}"
    echo -e "  ${CYAN}lab-help${NC}      - Show all available commands"
    echo -e "  ${CYAN}lab-test${NC}      - Full vulnerability test suite"
    echo -e "  ${CYAN}lab-connect${NC}   - Interactive client"
    echo -e "  ${CYAN}lab-web <ip>${NC}  - Web vulnerability fuzzer"
    echo -e "  ${CYAN}lab-logs${NC}      - View logs"
}

update_scripts_only() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    log "Updating scripts on existing VMs..."
    
    if ! multipass list | grep -q "$VM_TARGET.*Running"; then
        error "Target VM is not running"
    fi
    
    if ! multipass list | grep -q "$VM_ATTACKER.*Running"; then
        error "Attacker VM is not running"
    fi
    
    deploy_target_scripts
    deploy_attacker_scripts
    
    log "Restarting target services..."
    multipass exec "$VM_TARGET" -- bash -c "
        sudo systemctl restart vulnerable-server.service vulnerable-web.service
        sudo systemctl status vulnerable-server.service vulnerable-web.service --no-pager
    "
    
    success "Scripts updated successfully"
}

# Basic functions for fallback
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
        
        echo -e "\n${BLUE}=== COMPONENTS STATUS ===${NC}"
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

show_enhanced_help() {
    echo -e "${BLUE}USAGE:${NC} $0 [OPTION]"
    echo
    echo -e "${BLUE}MAIN OPTIONS:${NC}"
    echo -e "  ${YELLOW}create${NC}          Create the lab environment (VMs + scripts + services)"
    echo -e "  ${YELLOW}destroy${NC}         Destroy the lab environment completely"
    echo -e "  ${YELLOW}status${NC}          Show detailed VM and service status"
    echo -e "  ${YELLOW}test${NC}            Run comprehensive automated tests"
    echo -e "  ${YELLOW}client${NC}          Run enhanced interactive client"
    echo -e "  ${YELLOW}help${NC}            Show this help message"
    echo
    echo -e "${BLUE}MANAGEMENT OPTIONS:${NC}"
    echo -e "  ${YELLOW}restart-services${NC} Restart all lab services"
    echo -e "  ${YELLOW}service-status${NC}  Show detailed service status"
    echo -e "  ${YELLOW}preview-motd${NC}    Preview MOTD for both VMs"
    echo
    echo -e "${BLUE}VISUAL ENHANCEMENTS:${NC}"
    echo -e "  • ${GREEN}Dynamic MOTD system${NC} with real-time system information"
    echo -e "  • ${GREEN}ASCII art banners${NC} for immersive experience"
    echo -e "  • ${GREEN}Color-coded status${NC} indicators for quick assessment"
    echo -e "  • ${GREEN}Attack statistics${NC} and connection monitoring"
    echo
    echo -e "${BLUE}PROJECT STRUCTURE:${NC}"
    echo -e "  target-scripts/       ${GREEN}# Python scripts for target VM${NC}"
    echo -e "  attacker-scripts/     ${GREEN}# Python scripts for attacker VM${NC}"
    echo -e "  services/             ${GREEN}# Systemd service files${NC}"
    echo -e "  templates/            ${GREEN}# Cloud-init templates${NC}"
    echo -e "  scripts/              ${GREEN}# Bash utility modules${NC}"
    echo
    echo -e "${BLUE}MOTD FEATURES:${NC}"
    echo -e "  • ${CYAN}Real-time system stats${NC}: Load, memory, uptime, connections"
    echo -e "  • ${CYAN}Target information${NC}: IP addresses, available services"
    echo -e "  • ${CYAN}Quick command reference${NC}: Most used commands at login"
    echo -e "  • ${CYAN}Attack statistics${NC}: Daily connection counts and activity"
    echo -e "  • ${CYAN}Security reminders${NC}: Educational use warnings"
    echo
    echo -e "${BLUE}EXAMPLES:${NC}"
    echo -e "  ${CYAN}$0 create${NC}                    # Create complete environment with MOTD"
    echo -e "  ${CYAN}$0 preview-motd${NC}              # Preview both VM welcome screens"
    echo -e "  ${CYAN}$0 update-motd${NC}               # Update MOTD with current system info"
    echo -e "  ${CYAN}multipass shell attacker${NC}     # See custom attacker MOTD"
    echo -e "  ${CYAN}multipass shell target${NC}       # See custom target MOTD"
    echo
    echo -e "${BLUE}MOTD COMMANDS IN VMs:${NC}"
    echo -e "  ${GREEN}lab-motd${NC}         Show welcome message again (attacker VM)"
    echo -e "  ${GREEN}lab-help${NC}         Show all lab commands with descriptions"
    echo
    echo -e "${GREEN}TIP:${NC} The MOTD system provides an immersive cybersecurity lab experience"
    echo -e "with real-time information and visual appeal for educational engagement."
}


# =============================================================================
# MAIN FUNCTION
# =============================================================================

main() {
    if type print_banner >/dev/null 2>&1; then
        print_banner
    else
        echo -e "${CYAN}=== CYBERSECURITY LAB v3.3 - Enhanced with Dynamic MOTD ===${NC}"
    fi
    
    if type check_dependencies >/dev/null 2>&1; then
        check_dependencies
    fi
    
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
        restart-services)
            restart_services
            ;;
        service-status)
            show_service_status
            ;;
        preview-motd)
            preview_motd
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
            show_enhanced_help
            ;;
        *)
            error "Unknown option: $1. Use 'help' to see available options."
            ;;
    esac
}

trap 'echo -e "\n${YELLOW}Script interrupted. Environment preserved.${NC}"' INT

main "$@"