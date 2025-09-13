#!/bin/bash
# =============================================================================
# TESTING MODULE
# =============================================================================

run_tests() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    log "Running comprehensive automated tests..."
    
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}         ${BLUE}AUTOMATED TESTING SUITE${NC}          ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    
    echo -e "\n${PURPLE}=== TEST 1: Enhanced Port Scan ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p common
    
    echo -e "\n${PURPLE}=== TEST 2: TCP Connection Test ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" -p 9000 -t tcp -c 3
    
    echo -e "\n${PURPLE}=== TEST 3: HTTP Connection Test ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" -t http
    
    echo -e "\n${PURPLE}=== TEST 4: Web Vulnerability Scan ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/web-fuzzer.py "$TARGET_IP"
    
    success "All tests completed successfully"
    
    echo -e "\n${BLUE}=== TEST SUMMARY ===${NC}"
    echo -e "• Port 9000 (TCP Server) should be ${GREEN}OPEN${NC}"
    echo -e "• Port 8080 (HTTP Server) should be ${GREEN}OPEN${NC}"
    echo -e "• Port 22 (SSH) should be ${GREEN}OPEN${NC}"
    echo -e "• XSS vulnerabilities should be ${YELLOW}DETECTED${NC}"
    echo -e "• Directory traversal should be ${YELLOW}DETECTED${NC}"
    
    info "Check logs with: $0 logs"
}

run_interactive_client() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    log "Starting interactive client session..."
    info "Connecting to vulnerable server at $TARGET_IP:9000"
    
    echo -e "${BLUE}Available commands in the vulnerable server:${NC}"
    echo -e "  help     - Show available commands"
    echo -e "  info     - Server information"
    echo -e "  time     - Current server time"
    echo -e "  status   - System status"
    echo -e "  whoami   - Current user info"
    echo -e "  uptime   - System uptime"
    echo -e "  echo <msg> - Echo a message"
    echo -e "  quit     - Disconnect"
    echo ""
    
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/interactive-client.py "$TARGET_IP" -p 9000
}

run_web_tests() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    log "Running web vulnerability tests..."
    
    echo -e "${PURPLE}=== Web Vulnerability Testing ===${NC}"
    echo -e "Testing HTTP server at ${GREEN}$TARGET_IP:8080${NC}"
    echo ""
    
    echo -e "${BLUE}Testing endpoints:${NC}"
    echo -e "• /             - Main page"
    echo -e "• /info         - Server info"
    echo -e "• /echo?msg=... - Echo endpoint (XSS testing)"
    echo -e "• /file?name=.. - File access (Path traversal testing)"
    echo ""
    
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/web-fuzzer.py "$TARGET_IP" -t all
    
    success "Web vulnerability tests completed"
    
    echo -e "\n${BLUE}=== EXPECTED FINDINGS ===${NC}"
    echo -e "• ${YELLOW}XSS${NC}: The /echo endpoint should reflect input without filtering"
    echo -e "• ${YELLOW}Path Traversal${NC}: The /file endpoint should allow ../../../etc/passwd"
    echo -e "• ${GREEN}Directory Listing${NC}: Some endpoints may reveal sensitive info"
    
    info "Try manual testing with: curl http://$TARGET_IP:8080/echo?msg=<script>alert('XSS')</script>"
}

run_port_scan() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    log "Running port scan against $TARGET_IP..."
    
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p common
}

run_custom_test() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    echo -e "${BLUE}=== CUSTOM TEST MENU ===${NC}"
    echo "1) Full port scan (1-65535)"
    echo "2) Common ports only"
    echo "3) TCP connection stress test"
    echo "4) HTTP endpoint enumeration"
    echo "5) Custom command"
    echo "0) Back to main menu"
    
    read -p "Choice: " choice
    
    case $choice in
        1)
            multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p all
            ;;
        2)
            multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP" -p common
            ;;
        3)
            multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" -p 9000 -t tcp -c 20
            ;;
        4)
            multipass exec "$VM_ATTACKER" -- bash -c "
                echo 'Testing HTTP endpoints:'
                for endpoint in / /info /echo /file /admin /config /status; do
                    echo \"Testing \$endpoint...\"
                    curl -s -o /dev/null -w \"Status: %{http_code} Size: %{size_download}\\n\" http://$TARGET_IP:8080\$endpoint || true
                done
            "
            ;;
        5)
            echo "Enter custom command to run on attacker VM:"
            read -p "> " custom_cmd
            multipass exec "$VM_ATTACKER" -- bash -c "$custom_cmd"
            ;;
        0)
            return 0
            ;;
        *)
            warn "Invalid choice"
            ;;
    esac
}