#!/bin/bash
# =============================================================================
# CYBERSECURITY LAB - Environment Setup and Management (FIXED)
# =============================================================================
# This script manages a cybersecurity lab environment composed of two VMs:
# attacker and target
# =============================================================================

set -euo pipefail

# Global configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"
readonly LOGS_DIR="${SCRIPT_DIR}/logs"
readonly VM_ATTACKER="attacker"
readonly VM_TARGET="target"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

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

check_dependencies() {
    local deps=("multipass" "dialog")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            case "$dep" in
                "multipass")
                    error "Multipass is not installed. Install it from: https://multipass.run/"
                    ;;
                "dialog")
                    log "Installing dialog..."
                    sudo apt-get update && sudo apt-get install -y dialog
                    ;;
            esac
        fi
    done
}

create_directories() {
    mkdir -p "$CONFIG_DIR" "$LOGS_DIR"
}

# =============================================================================
# CONFIG FILE GENERATION
# =============================================================================

generate_target_config() {
    cat > "${CONFIG_DIR}/target-cloud-init.yaml" << 'EOF'
#cloud-config
package_update: true
package_upgrade: true
packages:
  - python3
  - python3-pip
  - python3-venv
  - ufw
  - htop
  - net-tools
  - tcpdump

users:
  - name: labuser
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... # Replace with your SSH key

write_files:
  - path: /opt/vulnerable-server.py
    content: |
      #!/usr/bin/env python3
      """
      Vulnerable TCP Server for cybersecurity testing
      """
      import socket
      import threading
      import time
      import logging
      from datetime import datetime
      
      # Logging configuration
      logging.basicConfig(
          level=logging.INFO,
          format='%(asctime)s - %(levelname)s - %(message)s',
          handlers=[
              logging.FileHandler('/var/log/vulnerable-server.log'),
              logging.StreamHandler()
          ]
      )
      logger = logging.getLogger(__name__)
      
      class VulnerableServer:
          def __init__(self, host="0.0.0.0", port=9000):
              self.host = host
              self.port = port
              self.running = False
              self.connections = []
          
          def handle_client(self, conn, addr):
              logger.info(f"New connection from {addr}")
              try:
                  while self.running:
                      data = conn.recv(1024).decode('utf-8').strip()
                      if not data:
                          break
                      
                      logger.info(f"Received command from {addr}: {data}")
                      
                      if data.lower() == "help":
                          response = "Available commands: help, info, time, echo <msg>, quit\\n"
                      elif data.lower() == "info":
                          response = f"Server info: {datetime.now()}\\n"
                      elif data.lower() == "time":
                          response = f"Server time: {time.ctime()}\\n"
                      elif data.lower().startswith("echo "):
                          msg = data[5:]
                          response = f"Echo: {msg}\\n"
                      elif data.lower() == "quit":
                          response = "Disconnecting...\\n"
                          conn.sendall(response.encode())
                          break
                      else:
                          response = f"Unknown command: {data}. Use 'help' for available commands\\n"
                      
                      conn.sendall(response.encode())
                      
              except Exception as e:
                  logger.error(f"Error handling client {addr}: {e}")
              finally:
                  conn.close()
                  logger.info(f"Connection closed with {addr}")
          
          def start(self):
              self.running = True
              with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                  server_socket.bind((self.host, self.port))
                  server_socket.listen(5)
                  
                  logger.info(f"Vulnerable server listening on {self.host}:{self.port}")
                  
                  try:
                      while self.running:
                          conn, addr = server_socket.accept()
                          client_thread = threading.Thread(
                              target=self.handle_client, 
                              args=(conn, addr)
                          )
                          client_thread.daemon = True
                          client_thread.start()
                  except KeyboardInterrupt:
                      logger.info("Server stopped by user")
                  finally:
                      self.running = False
      
      if __name__ == "__main__":
          server = VulnerableServer()
          server.start()
    permissions: '0755'

  - path: /etc/systemd/system/vulnerable-server.service
    content: |
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

  - path: /opt/monitor.sh
    content: |
      #!/bin/bash
      # Monitoring script for the target
      LOG_FILE="/var/log/target-monitor.log"
      
      while true; do
          echo "$(date -Is) - Active connections:" >> "$LOG_FILE"
          ss -tuln >> "$LOG_FILE"
          echo "$(date -Is) - Network processes:" >> "$LOG_FILE"
          lsof -i >> "$LOG_FILE"
          echo "---" >> "$LOG_FILE"
          sleep 10
      done
    permissions: '0755'

  - path: /etc/systemd/system/target-monitor.service
    content: |
      [Unit]
      Description=Target Monitor
      After=network.target

      [Service]
      ExecStart=/opt/monitor.sh
      Restart=always
      User=root

      [Install]
      WantedBy=multi-user.target

runcmd:
  # System setup
  - [systemctl, daemon-reload]
  - [systemctl, enable, vulnerable-server.service]
  - [systemctl, start, vulnerable-server.service]
  
  # Firewall configuration
  - [ufw, --force, reset]
  - [ufw, default, deny, incoming]
  - [ufw, default, allow, outgoing]
  - [ufw, allow, OpenSSH]
  - [ufw, allow, 9000/tcp]
  - [ufw, --force, enable]
  
  # Enable and start the monitor via systemd (non-blocking for cloud-init)
  - [systemctl, enable, target-monitor.service]
  - [systemctl, start, target-monitor.service]

final_message: "TARGET VM configured: vulnerable server on port 9000, firewall active"
EOF
}

generate_attacker_config() {
    cat > "${CONFIG_DIR}/attacker-cloud-init.yaml" << 'EOF'
#cloud-config
package_update: true
package_upgrade: true
packages:
  - netcat-openbsd
  - nmap
  - curl
  - wget
  - python3
  - python3-pip
  - git
  - htop
  - net-tools

users:
  - name: labuser
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... # Replace with your SSH key

write_files:
  - path: /opt/attack-scripts/port-scanner.py
    content: |
      #!/usr/bin/env python3
      """
      Simple Port Scanner for testing
      """
      import socket
      import sys
      import threading
      from datetime import datetime
      
      def scan_port(target, port, results):
          try:
              sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              sock.settimeout(1)
              result = sock.connect_ex((target, port))
              sock.close()
              
              if result == 0:
                  results.append(port)
                  print(f"Port {port}: OPEN")
          except socket.gaierror:
              pass
      
      def main():
          if len(sys.argv) != 2:
              print("Usage: python3 port-scanner.py <target_ip>")
              sys.exit(1)
          
          target = sys.argv[1]
          print(f"Scanning {target}...")
          print(f"Start time: {datetime.now()}")
          
          results = []
          threads = []
          
          # Scan common ports
          common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 9000]
          
          for port in common_ports:
              thread = threading.Thread(target=scan_port, args=(target, port, results))
              threads.append(thread)
              thread.start()
          
          for thread in threads:
              thread.join()
          
          print(f"\\nScan complete. Open ports: {sorted(results)}")
      
      if __name__ == "__main__":
          main()
    permissions: '0755'

  - path: /opt/attack-scripts/connection-tester.py
    content: |
      #!/usr/bin/env python3
      """
      Connection Tester - continuously tests connections to the target
      """
      import socket
      import time
      import sys
      import logging
      import os
      from datetime import datetime
      
      # Create logs directory if it doesn't exist
      log_dir = "/home/ubuntu/logs"
      os.makedirs(log_dir, exist_ok=True)
      log_file = os.path.join(log_dir, "attacker.log")
      
      # Logging setup - using user-writable directory
      logging.basicConfig(
          level=logging.INFO,
          format='%(asctime)s - %(message)s',
          handlers=[
              logging.FileHandler(log_file),
              logging.StreamHandler()
          ]
      )
      logger = logging.getLogger(__name__)
      
      def test_connection(target, port, interval=5):
          logger.info(f"Starting connection tests to {target}:{port}")
          
          success_count = 0
          fail_count = 0
          
          try:
              while True:
                  try:
                      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                          sock.settimeout(3)
                          sock.connect((target, port))
                          
                          # Send a test command
                          sock.send(b"info\\n")
                          response = sock.recv(1024).decode('utf-8')
                          
                          success_count += 1
                          logger.info(f"SUCCESS #{success_count}: Connected. Response: {response.strip()}")
                          
                  except Exception as e:
                      fail_count += 1
                      logger.warning(f"FAIL #{fail_count}: {e}")
                  
                  time.sleep(interval)
                  
          except KeyboardInterrupt:
              logger.info(f"Test finished. Successes: {success_count}, Failures: {fail_count}")
      
      if __name__ == "__main__":
          if len(sys.argv) != 3:
              print("Usage: python3 connection-tester.py <target_ip> <port>")
              sys.exit(1)
          
          target_ip = sys.argv[1]
          target_port = int(sys.argv[2])
          
          test_connection(target_ip, target_port)
    permissions: '0755'

  - path: /opt/attack-scripts/interactive-client.py
    content: |
      #!/usr/bin/env python3
      """
      Interactive client to talk to the vulnerable server
      """
      import socket
      import sys
      
      def interactive_client(target, port):
          try:
              with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                  sock.connect((target, port))
                  print(f"Connected to {target}:{port}")
                  print("Type 'quit' to exit")
                  
                  while True:
                      command = input("> ")
                      if command.lower() == 'quit':
                          sock.send(b"quit\\n")
                          break
                      
                      sock.send(f"{command}\\n".encode())
                      response = sock.recv(1024).decode('utf-8')
                      print(response.strip())
                      
          except Exception as e:
              print(f"Error: {e}")
      
      if __name__ == "__main__":
          if len(sys.argv) != 3:
              print("Usage: python3 interactive-client.py <target_ip> <port>")
              sys.exit(1)
          
          target_ip = sys.argv[1]
          target_port = int(sys.argv[2])
          
          interactive_client(target_ip, target_port)
    permissions: '0755'

runcmd:
  - [mkdir, -p, /opt/attack-scripts]
  - [mkdir, -p, /home/ubuntu/logs]
  - [chown, -R, ubuntu:ubuntu, /home/ubuntu/logs]
  - [chmod, +x, /opt/attack-scripts/*.py]

final_message: "ATTACKER VM configured with testing scripts"
EOF
}

# =============================================================================
# VIRTUAL ENVIRONMENT MANAGEMENT
# =============================================================================

create_environment() {
    mkdir -p ${PWD}/logs
    mkdir -p ${CONFIG_DIR}
    log "Creating lab environment..."
    
    # Generate configuration files
    generate_target_config
    generate_attacker_config
    
    # Create VMs
    log "Creating attacker VM..."
    multipass launch --name "$VM_ATTACKER" \
        --cpus 1 --memory 1G --disk 5G \
        --cloud-init "${CONFIG_DIR}/attacker-cloud-init.yaml" || error "Error creating attacker VM"
    
    log "Creating target VM..."
    multipass launch --name "$VM_TARGET" \
        --cpus 1 --memory 1G --disk 8G \
        --cloud-init "${CONFIG_DIR}/target-cloud-init.yaml" || error "Error creating target VM"
    
    # Wait initial provisioning
    log "Waiting for VMs to initialize..."
    sleep 10
    
    # Get and show IPs
    local target_ip=$(multipass info "$VM_TARGET" | grep IPv4 | awk '{print $2}')
    local attacker_ip=$(multipass info "$VM_ATTACKER" | grep IPv4 | awk '{print $2}')
    
    log "Environment successfully created!"
    echo -e "${BLUE}Target IP:${NC} $target_ip"
    echo -e "${BLUE}Attacker IP:${NC} $attacker_ip"
    
    # Save IPs for later use
    echo "TARGET_IP=$target_ip" > "${CONFIG_DIR}/vm_ips.conf"
    echo "ATTACKER_IP=$attacker_ip" >> "${CONFIG_DIR}/vm_ips.conf"
    
    # Configure attacker with the correct target IP
    configure_attacker_target "$target_ip"
}

configure_attacker_target() {
    local target_ip="$1"
    log "Configuring attacker with target IP: $target_ip"

    # Ensure /opt directory exists and create auto-test.sh with sudo
    multipass exec "$VM_ATTACKER" -- bash -c "
        sudo mkdir -p /opt &&
        sudo bash -c 'cat > /opt/auto-test.sh' << 'EOF'
#!/bin/bash
TARGET_IP=\"$target_ip\"
echo \"Starting connection test to \$TARGET_IP:9000\"
python3 /opt/attack-scripts/connection-tester.py \"\$TARGET_IP\" 9000
EOF
        sudo chmod +x /opt/auto-test.sh
    "

    # Verify the file was created and is executable
    if multipass exec "$VM_ATTACKER" -- test -x /opt/auto-test.sh; then
        log "Auto-test script configured successfully"
        log "Script content:"
        multipass exec "$VM_ATTACKER" -- cat /opt/auto-test.sh | head -5
    else
        error "Failed to create or make executable the auto-test script"
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
    rm -rf "logs"
    
    log "Environment destroyed successfully"
}

show_status() {
    echo -e "${BLUE}=== LAB ENVIRONMENT STATUS ===${NC}"
    multipass list
    
    if [[ -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        echo -e "\\n${BLUE}=== IP ADDRESSES ===${NC}"
        cat "${CONFIG_DIR}/vm_ips.conf"
    fi
    
    echo -e "\\n${BLUE}=== ACTIVE SERVICES ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        echo "Checking target services..."
        multipass exec "$VM_TARGET" -- systemctl is-active vulnerable-server.service 2>/dev/null || echo "vulnerable-server service: Not active"
    fi
}

show_help() {
    cat << EOF
${BLUE}CYBERSECURITY LAB - Testing Environment${NC}

Usage: $0 [OPTION]

OPTIONS:
  create     Create the lab environment (2 VMs)
  destroy    Destroy the lab environment
  status     Show VM and service status
  connect    Show interactive connection menu
  test       Run automated tests
  logs       Show lab logs
  help       Show this help message

EXAMPLES:
  $0 create          # Create environment
  $0 connect         # Interactive menu to connect to VMs
  $0 status          # Current status
  $0 destroy         # Remove everything

${YELLOW}NOTE:${NC} Make sure Multipass is installed and configured.
EOF
}

interactive_menu() {
    while true; do
        if ! command -v dialog &> /dev/null; then
            # Simple menu without dialog
            echo -e "\\n${BLUE}=== CYBERSECURITY LAB MENU ===${NC}"
            echo "1) Create lab environment"
            echo "2) Open shell to attacker VM"
            echo "3) Open shell to target VM"
            echo "4) Show status"
            echo "5) Run automated tests"
            echo "6) Show logs"
            echo "7) Destroy environment"
            echo "0) Exit"
            
            read -p "Choice: " choice
            
            case $choice in
                1) create_environment ;;
                2) multipass shell "$VM_ATTACKER" ;;
                3) multipass shell "$VM_TARGET" ;;
                4) show_status ;;
                5) run_tests ;;
                6) show_logs ;;
                7) destroy_environment ;;
                0) exit 0 ;;
                *) warn "Invalid choice" ;;
            esac
        else
            # Dialog-based menu
            choice=$(dialog --clear \
                --backtitle "Cybersecurity Lab" \
                --title "Main Menu" \
                --menu "Select an option:" \
                20 60 10 \
                1 "Create lab environment" \
                2 "Open shell to attacker VM" \
                3 "Open shell to target VM" \
                4 "Show status" \
                5 "Run automated tests" \
                6 "Show logs" \
                7 "Destroy environment" \
                0 "Exit" \
                2>&1 >/dev/tty)
            
            clear
            
            case $choice in
                1) create_environment ;;
                2) multipass shell "$VM_ATTACKER" ;;
                3) multipass shell "$VM_TARGET" ;;
                4) show_status ;;
                5) run_tests ;;
                6) show_logs ;;
                7) destroy_environment ;;
                0) exit 0 ;;
                *) break ;;
            esac
        fi
        
        read -p "Press ENTER to continue..."
    done
}

run_tests() {
    if [[ ! -f "${CONFIG_DIR}/vm_ips.conf" ]]; then
        error "Environment not configured. Run 'create' first."
    fi
    
    source "${CONFIG_DIR}/vm_ips.conf"
    
    log "Running automated tests..."
    
    echo -e "${BLUE}=== TEST 1: Port Scan ===${NC}"
    multipass exec "$VM_ATTACKER" -- python3 /opt/attack-scripts/port-scanner.py "$TARGET_IP"
    
    echo -e "\\n${BLUE}=== TEST 2: Connection Test (10 attempts) ===${NC}"
    multipass exec "$VM_ATTACKER" -- timeout 30 python3 /opt/attack-scripts/connection-tester.py "$TARGET_IP" 9000 || true
    
    log "Tests completed"
}

show_logs() {
    echo -e "${BLUE}=== ATTACKER LOG ===${NC}"
    if multipass list | grep -q "$VM_ATTACKER.*Running"; then
        multipass exec "$VM_ATTACKER" -- tail -n 20 /home/ubuntu/logs/attacker.log 2>/dev/null || echo "No logs available"
    fi
    
    echo -e "\\n${BLUE}=== TARGET LOG ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- tail -n 20 /var/log/vulnerable-server.log 2>/dev/null || echo "No logs available"
    fi
    
    echo -e "\\n${BLUE}=== TARGET MONITOR LOG ===${NC}"
    if multipass list | grep -q "$VM_TARGET.*Running"; then
        multipass exec "$VM_TARGET" -- tail -n 10 /var/log/target-monitor.log 2>/dev/null || echo "No logs available"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    check_dependencies
    create_directories
    
    case "${1:-}" in
        create)
            create_environment
            ;;
        destroy)
            destroy_environment
            ;;
        status)
            show_status
            ;;
        connect|menu)
            interactive_menu
            ;;
        test)
            run_tests
            ;;
        logs)
            show_logs
            ;;
        help|--help|-h)
            show_help
            ;;
        "")
            interactive_menu
            ;;
        *)
            error "Unknown option: $1. Use 'help' to see available options."
            ;;
    esac
}

# Start the script
main "$@"