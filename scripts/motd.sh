create_attacker_motd() {
    local target_ip="$1"
    log "Creating dynamic MOTD for attacker VM..."
    
    multipass exec "$VM_ATTACKER" -- bash -c "
        sudo tee /etc/update-motd.d/01-cybersec-lab > /dev/null << 'EOF'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'

HOSTNAME=\$(hostname); UPTIME=\$(uptime -p); USERS=\$(who | wc -l)
LOAD=\$(cat /proc/loadavg | awk '{print \$1, \$2, \$3}')
MEMORY=\$(free -h | grep '^Mem:' | awk '{print \$3\"/\"\$2}')
IP=\$(hostname -I | awk '{print \$1}'); TARGET_IP=\"$target_ip\"

if [ -f /opt/attack-scripts/port-scanner.py ]; then
    TOOLS_STATUS=\"\${GREEN}Available\${NC}\"
else
    TOOLS_STATUS=\"\${RED}Not Found\${NC}\"
fi

echo -e \"\${CYAN}\"
cat << 'BANNER'
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          🎯 CYBER ATTACK STATION 🎯                          ║
║   ░█████╗░██╗░░░██╗██████╗░███████╗██████╗░  ░█████╗░████████╗████████╗░█████╗░ ║
║   ██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗  ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗ ║
║   ██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝  ███████║░░░██║░░░░░░██║░░░███████║ ║
║   ██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗  ██╔══██║░░░██║░░░░░░██║░░░██╔══██║ ║
║   ╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║  ██║░░██║░░░██║░░░░░░██║░░░██║░░██║ ║
║   ░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝  ╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚═╝ ║
╚═══════════════════════════════════════════════════════════════════════════════╝
BANNER
echo -e \"\${NC}\"

echo -e \"\${WHITE}╔══════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${BLUE}SYSTEM STATUS\${NC} - Host: \${GREEN}\$HOSTNAME\${NC} | IP: \${GREEN}\$IP\${NC} | Uptime: \${CYAN}\$UPTIME\${NC}    \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC} Load: \${PURPLE}\$LOAD\${NC} | Memory: \${CYAN}\$MEMORY\${NC} | Tools: \$TOOLS_STATUS        \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚══════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${WHITE}╔══════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${RED}TARGET: \$TARGET_IP\${NC} | TCP:9000 (Command Server) | HTTP:8080 (Web App)     \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚══════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${WHITE}╔══════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${YELLOW}QUICK COMMANDS:\${NC}                                                             \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC}  \${CYAN}lab-test\${NC}      Full vulnerability test suite                                \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC}  \${CYAN}lab-connect\${NC}   Interactive TCP client                                      \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC}  \${CYAN}lab-scan \$TARGET_IP\${NC}  Advanced port scanner                                     \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC}  \${CYAN}lab-web \$TARGET_IP\${NC}   Web fuzzer (XSS, traversal)                              \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC}  \${CYAN}lab-help\${NC}      Show all available commands                                 \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚══════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${RED}⚠️  Educational Use Only - Authorized Testing Environment\${NC}\"
echo -e \"\${GREEN}Ready for penetration testing! Type \${CYAN}lab-help\${GREEN} to get started.\${NC}\"
echo
EOF

        sudo chmod +x /etc/update-motd.d/01-cybersec-lab
        sudo chmod -x /etc/update-motd.d/10-help-text 2>/dev/null || true
        sudo chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null || true
    "
}

create_target_motd() {
    log "Creating dynamic MOTD for target VM..."
    
    multipass exec "$VM_TARGET" -- bash -c "
        sudo tee /etc/update-motd.d/01-target-lab > /dev/null << 'EOF'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

HOSTNAME=\$(hostname); IP=\$(hostname -I | awk '{print \$1}')
UPTIME=\$(uptime -p); MEMORY=\$(free -h | grep '^Mem:' | awk '{print \$3\"/\"\$2}')

TCP_STATUS=\"\${RED}DOWN\${NC}\"; HTTP_STATUS=\"\${RED}DOWN\${NC}\"; MONITOR_STATUS=\"\${RED}DOWN\${NC}\"

systemctl is-active --quiet vulnerable-server.service && TCP_STATUS=\"\${GREEN}UP\${NC}\"
systemctl is-active --quiet vulnerable-web.service && HTTP_STATUS=\"\${GREEN}UP\${NC}\"
systemctl is-active --quiet target-monitor.service && MONITOR_STATUS=\"\${GREEN}UP\${NC}\"

CONNECTIONS=0
[ -f /var/log/vulnerable-server.log ] && CONNECTIONS=\$(grep \"\$(date '+%Y-%m-%d')\" /var/log/vulnerable-server.log 2>/dev/null | grep \"New connection\" | wc -l)

echo -e \"\${RED}\"
cat << 'BANNER'
╔════════════════════════════════════════════════════════════════════════════════╗
║                          🎯 VULNERABLE TARGET 🎯                              ║
║   ████████╗░█████╗░██████╗░░██████╗░███████╗████████╗  ░██████╗██╗░░░██╗░██████╗ ║
║   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝░██╔════╝╚══██╔══╝  ██╔════╝╚██╗░██╔╝██╔════╝ ║
║   ░░░██║░░░███████║██████╔╝██║░░██╗░█████╗░░░░░██║░░░  ╚█████╗░░╚████╔╝░╚█████╗░ ║
║   ░░░██║░░░██╔══██║██╔══██╗██║░░╚██╗██╔══╝░░░░░██║░░░  ░╚═══██╗░░╚██╔╝░░░╚═══██╗ ║
║   ░░░██║░░░██║░░██║██║░░██║╚██████╔╝███████╗░░░██║░░░  ██████╔╝░░░██║░░░██████╔╝ ║
║   ░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚══════╝░░░╚═╝░░░  ╚═════╝░░░░╚═╝░░░╚═════╝░ ║
╚════════════════════════════════════════════════════════════════════════════════╝
BANNER
echo -e \"\${NC}\"

echo -e \"\${WHITE}╔═════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${BLUE}SYSTEM:\${NC} \${GREEN}\$HOSTNAME\${NC} (\${GREEN}\$IP\${NC}) | Up: \${CYAN}\$UPTIME\${NC} | Mem: \${CYAN}\$MEMORY\${NC}       \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚═════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${WHITE}╔═════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${RED}VULNERABLE SERVICES\${NC} - TCP: \$TCP_STATUS | Web: \$HTTP_STATUS | Monitor: \$MONITOR_STATUS    \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC} Today's Attacks: \${YELLOW}\$CONNECTIONS\${NC} connections                                            \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚═════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${WHITE}╔═════════════════════════════════════════════════════════════════════════════════╗\${NC}\"
echo -e \"\${WHITE}║\${NC} \${YELLOW}ATTACK VECTORS:\${NC}                                                             \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC} • Port 9000: Command injection, file access (exec, file commands)           \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC} • Port 8080: XSS, directory traversal, RCE (/echo, /file, /exec)            \${WHITE}║\${NC}\"
echo -e \"\${WHITE}║\${NC} • Port 22: SSH access with standard authentication                           \${WHITE}║\${NC}\"
echo -e \"\${WHITE}╚═════════════════════════════════════════════════════════════════════════════════╝\${NC}\"

echo -e \"\${RED}⚠️  INTENTIONALLY VULNERABLE - Educational Lab Environment Only\${NC}\"
echo -e \"\${RED}All activities monitored and logged for training purposes.\${NC}\"
echo
EOF

        sudo chmod +x /etc/update-motd.d/01-target-lab
        sudo chmod -x /etc/update-motd.d/10-help-text 2>/dev/null || true
        sudo chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null || true
    "
}

# Nuove funzioni per gestire il MOTD
update_motd_system() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    log "Updating MOTD system..."
    
    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
        create_attacker_motd "$TARGET_IP"
    fi
    
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        create_target_motd
    fi
    
    success "MOTD system updated"
}

preview_motd() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    echo -e "${BLUE}=== ATTACKER VM MOTD PREVIEW ===${NC}"
    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
        multipass exec "$VM_ATTACKER" -- sudo /etc/update-motd.d/01-cybersec-lab 2>/dev/null
    else
        warn "Attacker VM not running"
    fi
    
    echo -e "\n${BLUE}=== TARGET VM MOTD PREVIEW ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- sudo /etc/update-motd.d/01-target-lab 2>/dev/null
    else
        warn "Target VM not running"
    fi
}

