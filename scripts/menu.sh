#!/bin/bash
# =============================================================================
# MENU INTERFACE MODULE
# =============================================================================

interactive_menu() {
    while true; do
        if ! command -v dialog &> /dev/null; then
            # Enhanced simple menu without dialog
            echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
            echo -e "${CYAN}║${NC}    ${BLUE}CYBERSECURITY LAB - MAIN MENU${NC}        ${CYAN}║${NC}"
            echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}1)${NC} Create lab environment               ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}2)${NC} Open shell to attacker VM            ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}3)${NC} Open shell to target VM              ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}4)${NC} Show detailed status                 ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}5)${NC} Run automated tests                  ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}6)${NC} Run interactive client               ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}7)${NC} Run web vulnerability tests          ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}8)${NC} Run port scan only                   ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}9)${NC} Custom tests menu                    ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}10)${NC} Show logs                           ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}11)${NC} Destroy environment                 ${CYAN}║${NC}"
            echo -e "${CYAN}║${NC} ${YELLOW}0)${NC} Exit                                 ${CYAN}║${NC}"
            echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
            
            if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
                source "${CONFIG_DIR}/vm_ips.conf"
                echo -e "${BLUE}Current environment:${NC} Target=${GREEN}$TARGET_IP${NC}, Attacker=${YELLOW}$ATTACKER_IP${NC}"
            else
                echo -e "${RED}No environment configured. Use option 1 to create.${NC}"
            fi
            echo ""
            
            read -p "Choice: " choice
            
            case $choice in
                1) create_environment ;;
                2) 
                    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
                        echo -e "${BLUE}Connecting to attacker VM...${NC}"
                        echo -e "${YELLOW}Tip: Use 'lab-test' to run tests, 'lab-connect' for interactive client${NC}"
                        multipass shell "$VM_ATTACKER"
                    else
                        error "Attacker VM not running. Create environment first."
                    fi
                    ;;
                3) 
                    if multipass list | grep -q "$VM_TARGET.*Running"; then
                        echo -e "${BLUE}Connecting to target VM...${NC}"
                        multipass shell "$VM_TARGET"
                    else
                        error "Target VM not running. Create environment first."
                    fi
                    ;;
                4) show_status ;;
                5) run_tests ;;
                6) run_interactive_client ;;
                7) run_web_tests ;;
                8) run_port_scan ;;
                9) run_custom_test ;;
                10) show_logs ;;
                11) destroy_environment ;;
                0) exit 0 ;;
                *) warn "Invalid choice" ;;
            esac
        else
            # Enhanced dialog-based menu
            choice=$(dialog --clear \
                --backtitle "Cybersecurity Lab v3.0" \
                --title "Main Menu" \
                --menu "Select an option:" \
                25 70 15 \
                1 "Create lab environment" \
                2 "Open shell to attacker VM" \
                3 "Open shell to target VM" \
                4 "Show detailed status" \
                5 "Run automated tests" \
                6 "Run interactive client" \
                7 "Run web vulnerability tests" \
                8 "Run port scan only" \
                9 "Custom tests menu" \
                10 "Show logs" \
                11 "Destroy environment" \
                0 "Exit" \
                2>&1 >/dev/tty)
            
            clear
            
            case $choice in
                1) create_environment ;;
                2) 
                    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
                        echo -e "${BLUE}Connecting to attacker VM...${NC}"
                        echo -e "${YELLOW}Available aliases:${NC}"
                        echo -e "  lab-test      - Run full test suite"
                        echo -e "  lab-connect   - Interactive TCP client"
                        echo -e "  lab-scan <ip> - Port scanner"
                        echo -e "  lab-web <ip>  - Web vulnerability tests"
                        echo -e "  lab-logs      - Show recent logs"
                        echo ""
                        multipass shell "$VM_ATTACKER"
                    else
                        error "Attacker VM not running. Create environment first."
                    fi
                    ;;
                3) 
                    if multipass list | grep -q "$VM_TARGET.*Running"; then
                        multipass shell "$VM_TARGET"
                    else
                        error "Target VM not running. Create environment first."
                    fi
                    ;;
                4) show_status ;;
                5) run_tests ;;
                6) run_interactive_client ;;
                7) run_web_tests ;;
                8) run_port_scan ;;
                9) run_custom_test ;;
                10) show_logs ;;
                11) destroy_environment ;;
                0) exit 0 ;;
                *) break ;;
            esac
        fi
        
        if [[ $choice != "0" ]]; then
            echo -e "\n${YELLOW}Press ENTER to continue...${NC}"
            read
        fi
    done
}

show_connection_info() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        warn "Environment not configured. Create it first."
        return 1
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        ${BLUE}CONNECTION INFORMATION${NC}            ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Target VM: ${GREEN}$TARGET_IP${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} Attacker VM: ${YELLOW}$ATTACKER_IP${NC}                ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${PURPLE}Available Services:${NC}                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   TCP Server: ${GREEN}$TARGET_IP:9000${NC}          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   HTTP Server: ${GREEN}$TARGET_IP:8080${NC}         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   SSH Access: ${GREEN}$TARGET_IP:22${NC}            ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    
    echo -e "\n${BLUE}Quick Test Commands:${NC}"
    echo -e "  ${CYAN}nc $TARGET_IP 9000${NC}                    # Netcat to TCP server"
    echo -e "  ${CYAN}curl http://$TARGET_IP:8080${NC}           # Test HTTP server"
    echo -e "  ${CYAN}nmap -sV $TARGET_IP${NC}                   # Port scan"
    
    echo -e "\n${BLUE}Vulnerability Testing:${NC}"
    echo -e "  ${CYAN}curl 'http://$TARGET_IP:8080/echo?msg=<script>alert(1)</script>'${NC}"
    echo -e "  ${CYAN}curl 'http://$TARGET_IP:8080/file?name=../../../etc/passwd'${NC}"
}

show_lab_tips() {
    cat << EOF
${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}
${CYAN}║${NC}                    ${BLUE}LAB USAGE TIPS${NC}                        ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}

${BLUE}GETTING STARTED:${NC}
1. Run "${YELLOW}$0 create${NC}" to set up the environment
2. Use "${YELLOW}$0 test${NC}" to run automated vulnerability scans
3. Use "${YELLOW}$0 client${NC}" for interactive testing

${BLUE}ATTACKER VM SHORTCUTS:${NC}
Once connected to the attacker VM, use these aliases:
• ${GREEN}lab-test${NC}      - Run comprehensive test suite
• ${GREEN}lab-connect${NC}   - Interactive TCP client
• ${GREEN}lab-scan <ip>${NC} - Port scanner
• ${GREEN}lab-web <ip>${NC}  - Web vulnerability tests
• ${GREEN}lab-logs${NC}      - View recent logs

${BLUE}MANUAL TESTING:${NC}
• ${YELLOW}TCP Server${NC}: Connect to port 9000 for command injection testing
• ${YELLOW}HTTP Server${NC}: Port 8080 has XSS and path traversal vulns
• ${YELLOW}SSH Access${NC}: Standard SSH on port 22

${BLUE}EXPECTED VULNERABILITIES:${NC}
• ${RED}Command Injection${NC}: TCP server executes system commands
• ${RED}Cross-Site Scripting${NC}: /echo endpoint reflects input
• ${RED}Path Traversal${NC}: /file endpoint allows directory navigation
• ${RED}Information Disclosure${NC}: Various endpoints leak system info

${BLUE}LEARNING OBJECTIVES:${NC}
• Network reconnaissance and port scanning
• Vulnerability identification and exploitation
• Log analysis and monitoring
• Secure coding practices (by seeing what NOT to do)

${GREEN}TIP:${NC} This is a controlled environment for learning. Always get 
permission before testing on real systems!
EOF
}