# Aggiornare la funzione configure_attacker_aliases esistente
configure_attacker_aliases() {
    local target_ip="$1"
    log "Configuring attacker with custom MOTD and aliases for target: $target_ip"
    
    multipass exec "$VM_ATTACKER" -- bash -c "
        mkdir -p /home/ubuntu/logs
        chmod 755 /home/ubuntu/logs
        
        cat > /home/ubuntu/.bash_aliases << EOF
# Cybersecurity Lab Aliases
alias lab-test='echo \"Running comprehensive tests...\" && python3 /opt/attack-scripts/port-scanner.py $target_ip && python3 /opt/attack-scripts/connection-tester.py $target_ip -t both -c 3 && python3 /opt/attack-scripts/web-fuzzer.py $target_ip'
alias lab-connect='echo \"Connecting to vulnerable TCP server...\" && python3 /opt/attack-scripts/interactive-client.py $target_ip -p 9000'
alias lab-scan='python3 /opt/attack-scripts/port-scanner.py'
alias lab-web='python3 /opt/attack-scripts/web-fuzzer.py'
alias lab-conn='python3 /opt/attack-scripts/connection-tester.py'
alias lab-logs='ls -la ~/logs && echo && tail -20 ~/logs/attacker.log 2>/dev/null || echo \"No logs yet - run lab-test first\"'
alias lab-help='echo \"Available lab commands:\" && echo \"  lab-test      - Run full vulnerability test suite\" && echo \"  lab-connect   - Interactive TCP client\" && echo \"  lab-scan <ip> - Port scanner\" && echo \"  lab-web <ip>  - Web vulnerability fuzzer\" && echo \"  lab-logs      - Show recent activity logs\" && echo \"  lab-motd      - Show welcome message again\"'
alias lab-motd='sudo /etc/update-motd.d/01-cybersec-lab'
EOF
        
        chown ubuntu:ubuntu /home/ubuntu/.bash_aliases
        pip3 install requests >/dev/null 2>&1 || sudo apt-get install -y python3-requests >/dev/null 2>&1
    "
    
    # Create the MOTD
    create_attacker_motd "$target_ip"
    create_target_motd
    
    success "Enhanced MOTD system and aliases configured"
}

