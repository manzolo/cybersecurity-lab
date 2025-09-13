#!/bin/bash
# =============================================================================
# VM MANAGEMENT MODULE
# =============================================================================

configure_attacker_scripts() {
    local target_ip="$1"
    log "Configuring attacker with target IP: $target_ip"

    # Create comprehensive auto-test script with proper permissions
    multipass exec "$VM_ATTACKER" -- bash -c "
        # Create directories with proper permissions
        sudo mkdir -p /opt/lab-tools
        sudo mkdir -p /home/ubuntu/logs
        sudo chown ubuntu:ubuntu /home/ubuntu/logs
        sudo chmod 755 /home/ubuntu/logs
        
        # Create auto-test script
        sudo bash -c 'cat > /opt/lab-tools/auto-test.sh' << 'EOF'
#!/bin/bash
TARGET_IP=\"$target_ip\"
LOG_DIR=\"/home/ubuntu/logs\"

# Ensure log directory exists with correct permissions
mkdir -p \"\$LOG_DIR\"

echo \"=== CYBERSECURITY LAB - AUTOMATED TESTING ===\" | tee \"\$LOG_DIR/test-\$(date +%Y%m%d-%H%M%S).log\"
echo \"Target: \$TARGET_IP\" | tee -a \"\$LOG_DIR/test-\$(date +%Y%m%d-%H%M%S).log\"
echo \"\"

echo \"1. Port Scanning...\"
python3 /opt/attack-scripts/port-scanner.py \"\$TARGET_IP\"
echo \"\"

echo \"2. Connection Testing...\"
python3 /opt/attack-scripts/connection-tester.py \"\$TARGET_IP\" -t both -c 3
echo \"\"

echo \"3. Web Vulnerability Testing...\"
python3 /opt/attack-scripts/web-fuzzer.py \"\$TARGET_IP\"
echo \"\"

echo \"=== Testing Complete ===\" | tee -a \"\$LOG_DIR/test-\$(date +%Y%m%d-%H%M%S).log\"
EOF

        sudo chmod +x /opt/lab-tools/auto-test.sh
        
        # Create quick-connect script
        sudo bash -c 'cat > /opt/lab-tools/quick-connect.sh' << 'EOF'
#!/bin/bash
TARGET_IP=\"$target_ip\"
echo \"Connecting to vulnerable server at \$TARGET_IP:9000\"
echo \"Use commands: help, info, time, status, whoami, uptime, echo <msg>, quit\"
echo \"\"
python3 /opt/attack-scripts/interactive-client.py \"\$TARGET_IP\" -p 9000
EOF

        sudo chmod +x /opt/lab-tools/quick-connect.sh
        
        # Create convenience aliases
        sudo bash -c 'cat > /home/ubuntu/.bash_aliases' << 'EOF'
alias lab-test=\"/opt/lab-tools/auto-test.sh\"
alias lab-connect=\"/opt/lab-tools/quick-connect.sh\"
alias lab-scan=\"python3 /opt/attack-scripts/port-scanner.py\"
alias lab-web=\"python3 /opt/attack-scripts/web-fuzzer.py\"
alias lab-logs=\"ls -la /home/ubuntu/logs && tail -20 /home/ubuntu/logs/attacker.log 2>/dev/null || echo 'No logs yet'\"
EOF

        sudo chown ubuntu:ubuntu /home/ubuntu/.bash_aliases
    "

    # Verify scripts were created
    if multipass exec "$VM_ATTACKER" -- test -x /opt/lab-tools/auto-test.sh; then
        success "Auto-test scripts configured successfully"
        info "Available commands in attacker VM:"
        info "  lab-test      - Run full test suite"
        info "  lab-connect   - Interactive TCP client"
        info "  lab-scan <ip> - Port scanner"
        info "  lab-web <ip>  - Web vulnerability tests"
        info "  lab-logs      - Show recent logs"
    else
        error "Failed to create auto-test scripts"
    fi
}

destroy_environment() {
    log "Destroying lab environment..."
    
    # Stop and remove VMs
    for vm in "$VM_ATTACKER" "$VM_TARGET"; do
        if multipass list | grep -q "$vm"; then
            multipass stop "$vm" 2>/dev/null || true
            multipass delete "$vm" 2>/dev/null || true
        fi
    done
    
    multipass purge 2>/dev/null || true
    
    # Clean configuration files
    rm -f "${CONFIG_DIR}/vm_ips.conf"
    rm -rf "${CONFIG_DIR}"
    rm -rf "$LOGS_DIR"
    
    success "Environment destroyed successfully"
}

show_status() {
    echo -e "${BLUE}=== LAB ENVIRONMENT STATUS ===${NC}"
    multipass list
    
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        echo -e "\n${BLUE}=== IP ADDRESSES ===${NC}"
        source "${CONFIG_DIR}/vm_ips.conf"
        echo -e "Target:   ${GREEN}$TARGET_IP${NC}"
        echo -e "Attacker: ${YELLOW}$ATTACKER_IP${NC}"
    fi
    
    echo -e "\n${BLUE}=== ACTIVE SERVICES ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        echo "Checking target services..."
        
        # Check TCP server
        if multipass exec "$VM_TARGET" -- systemctl is-active vulnerable-server.service >/dev/null 2>&1; then
            echo -e "TCP Server (9000):  ${GREEN}RUNNING${NC}"
        else
            echo -e "TCP Server (9000):  ${RED}STOPPED${NC}"
        fi
        
        # Check HTTP server
        if multipass exec "$VM_TARGET" -- systemctl is-active vulnerable-web.service >/dev/null 2>&1; then
            echo -e "HTTP Server (8080): ${GREEN}RUNNING${NC}"
        else
            echo -e "HTTP Server (8080): ${RED}STOPPED${NC}"
        fi
        
        # Check monitor
        if multipass exec "$VM_TARGET" -- systemctl is-active target-monitor.service >/dev/null 2>&1; then
            echo -e "Monitor Service:    ${GREEN}RUNNING${NC}"
        else
            echo -e "Monitor Service:    ${RED}STOPPED${NC}"
        fi
    else
        echo -e "Target VM: ${RED}NOT RUNNING${NC}"
    fi
    
    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
        echo -e "Attacker VM: ${GREEN}RUNNING${NC}"
    else
        echo -e "Attacker VM: ${RED}NOT RUNNING${NC}"
    fi
    
    # Show quick access info
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        echo -e "\n${BLUE}=== QUICK ACCESS ===${NC}"
        echo -e "Attacker shell:     ${CYAN}multipass shell $VM_ATTACKER${NC}"
        echo -e "Target shell:       ${CYAN}multipass shell $VM_TARGET${NC}"
        echo -e "Run tests:          ${CYAN}$0 test${NC}"
        echo -e "Interactive client: ${CYAN}$0 client${NC}"
    fi
}

show_logs() {
    echo -e "${BLUE}=== LAB LOGS VIEWER ===${NC}"
    
    echo -e "\n${PURPLE}=== ATTACKER LOG ===${NC}"
    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
        # Try both possible log locations
        multipass exec "$VM_ATTACKER" -- bash -c "
            if [ -f /home/ubuntu/logs/attacker.log ]; then
                tail -n 15 /home/ubuntu/logs/attacker.log
            elif [ -f /home/ubuntu/logs/*.log ]; then
                tail -n 15 /home/ubuntu/logs/*.log
            else
                echo 'No attacker logs available yet'
                echo 'Logs will be created after running tests'
            fi
        " 2>/dev/null
    else
        warn "Attacker VM not running"
    fi
    
    echo -e "\n${PURPLE}=== TARGET TCP SERVER LOG ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- tail -n 15 /var/log/vulnerable-server.log 2>/dev/null || echo "No TCP server logs available"
    else
        warn "Target VM not running"
    fi
    
    echo -e "\n${PURPLE}=== TARGET HTTP SERVER LOG ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- tail -n 15 /var/log/vulnerable-web.log 2>/dev/null || echo "No HTTP server logs available"
    else
        warn "Target VM not running"
    fi
    
    echo -e "\n${PURPLE}=== TARGET MONITOR LOG ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- tail -n 10 /var/log/target-monitor.log 2>/dev/null || echo "No monitor logs available"
    else
        warn "Target VM not running"
    fi
}