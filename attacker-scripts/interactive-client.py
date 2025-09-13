#!/usr/bin/env python3
"""
Interactive TCP Client for connecting to vulnerable servers
Supports command history, logging, and exploitation features
"""
import socket
import sys
import readline
import argparse
import time
import threading
import logging
import os
from datetime import datetime

class InteractiveClient:
    def __init__(self, target, port, log_file=None):
        self.target = target
        self.port = port
        self.sock = None
        self.connected = False
        self.command_history = []
        self.session_log = []
        self.setup_logging(log_file)
        
        # Setup readline for command history
        try:
            readline.set_history_length(1000)
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self.command_completer)
        except ImportError:
            pass  # readline not available
    
    def setup_logging(self, log_file):
        """Setup session logging"""
        if log_file is None:
            log_dir = os.path.expanduser("~/logs")
            try:
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, f"interactive_session_{int(time.time())}.log")
            except:
                log_file = f"/tmp/interactive_session_{int(time.time())}.log"
        
        self.log_file = log_file
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def command_completer(self, text, state):
        """Command completion for readline"""
        commands = [
            'help', 'info', 'time', 'status', 'whoami', 'uptime', 'echo ', 
            'exec ', 'file ', 'test', 'quit', 'exit',
            # Common exploitation commands
            'exec whoami', 'exec id', 'exec uname -a', 'exec ps aux',
            'exec cat /etc/passwd', 'exec ls -la', 'exec pwd',
            'file /etc/passwd', 'file /etc/shadow', 'file ~/.bashrc'
        ]
        
        matches = [cmd for cmd in commands if cmd.startswith(text)]
        try:
            return matches[state]
        except IndexError:
            return None
    
    def connect(self):
        """Establish connection to the target"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            
            print(f"Connecting to {self.target}:{self.port}...")
            self.sock.connect((self.target, self.port))
            self.connected = True
            
            print(f"✓ Connected to {self.target}:{self.port}")
            self.logger.info(f"Connected to {self.target}:{self.port}")
            
            # Get initial response
            try:
                initial_response = self.sock.recv(2048).decode('utf-8', errors='ignore')
                if initial_response:
                    print(initial_response, end='')
                    self.log_interaction("SERVER", initial_response.strip())
            except socket.timeout:
                pass
            
            return True
            
        except ConnectionRefusedError:
            print(f"✗ Connection refused to {self.target}:{self.port}")
            print("  Make sure the target service is running")
            return False
        except socket.timeout:
            print(f"✗ Connection timeout to {self.target}:{self.port}")
            print("  Target may be unreachable or service may be down")
            return False
        except Exception as e:
            print(f"✗ Connection error: {e}")
            return False
    
    def log_interaction(self, source, message):
        """Log interaction to session log"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'source': source,
            'message': message
        }
        self.session_log.append(log_entry)
        
        # Also log to file
        self.logger.info(f"{source}: {message}")
    
    def send_command(self, command):
        """Send command and receive response"""
        if not self.connected or not self.sock:
            return False
        
        try:
            # Send command
            self.sock.send(f"{command}\n".encode())
            self.log_interaction("CLIENT", command)
            
            # Receive response
            response = self.sock.recv(4096).decode('utf-8', errors='ignore')
            if response:
                print(response, end='')
                self.log_interaction("SERVER", response.strip())
                return True
            else:
                print("✗ No response from server")
                return False
                
        except socket.timeout:
            print("✗ Response timeout")
            return False
        except Exception as e:
            print(f"✗ Communication error: {e}")
            return False
    
    def show_help(self):
        """Show client help information"""
        help_text = """
╔════════════════════════════════════════════════════════════════╗
║                    INTERACTIVE CLIENT HELP                     ║
╠════════════════════════════════════════════════════════════════╣
║ CLIENT COMMANDS:                                               ║
║   .help         - Show this help                               ║
║   .status       - Show connection status                       ║
║   .log          - Show session log summary                     ║
║   .history      - Show command history                         ║
║   .exploit      - Show exploitation hints                      ║
║   .quit/.exit   - Disconnect and exit                          ║
║                                                                ║
║ SERVER COMMANDS (sent to target):                              ║
║   help          - Server help                                  ║
║   info          - Server information                           ║
║   time          - Current server time                          ║
║   status        - System status                                ║
║   whoami        - Current user                                 ║
║   uptime        - System uptime                                ║
║   echo <msg>    - Echo message                                 ║
║   exec <cmd>    - Execute system command (DANGEROUS)           ║
║   file <path>   - Read file (VULNERABLE)                       ║
║   quit          - Disconnect from server                       ║
║                                                                ║
║ EXPLOITATION EXAMPLES:                                         ║
║   exec whoami                 - Get current user               ║
║   exec id                     - Get user/group info            ║
║   exec uname -a               - Get system info                ║
║   exec cat /etc/passwd        - Read user database             ║
║   exec ps aux                 - List running processes         ║
║   file /etc/passwd            - Directory traversal attack     ║
║   file ../../../etc/shadow    - Access shadow passwords        ║
╚════════════════════════════════════════════════════════════════╝
"""
        print(help_text)
    
    def show_exploitation_hints(self):
        """Show common exploitation techniques"""
        hints = """
╔════════════════════════════════════════════════════════════════╗
║                    EXPLOITATION TECHNIQUES                     ║
╠════════════════════════════════════════════════════════════════╣
║ 1. INFORMATION GATHERING:                                      ║
║    exec whoami           # Current user                        ║
║    exec id               # User privileges                     ║
║    exec uname -a         # System information                  ║
║    exec pwd              # Current directory                   ║
║    exec env              # Environment variables               ║
║                                                                ║
║ 2. FILE SYSTEM EXPLORATION:                                    ║
║    exec ls -la           # List files                          ║
║    exec find / -name "*.txt" 2>/dev/null  # Find files         ║
║    file /etc/passwd      # Read sensitive files               ║
║    file ~/.bashrc        # User configuration                 ║
║                                                                ║
║ 3. PRIVILEGE ESCALATION:                                       ║
║    exec sudo -l          # Check sudo permissions             ║
║    exec cat /etc/sudoers # Check sudo configuration           ║
║    exec find / -perm -4000 2>/dev/null  # Find SUID files     ║
║                                                                ║
║ 4. NETWORK RECONNAISSANCE:                                     ║
║    exec netstat -tulpn   # Network connections                ║
║    exec ss -tulpn        # Modern network tool                ║
║    exec ps aux          # Running processes                   ║
║                                                                ║
║ 5. PERSISTENCE:                                                ║
║    exec crontab -l       # Check scheduled tasks              ║
║    exec cat ~/.ssh/authorized_keys  # SSH keys                ║
║                                                                ║
║ WARNING: This is for educational purposes in controlled        ║
║          environments only!                                    ║
╚════════════════════════════════════════════════════════════════╝
"""
        print(hints)
    
    def show_session_stats(self):
        """Show session statistics"""
        if not self.session_log:
            print("No session data available")
            return
        
        client_commands = len([log for log in self.session_log if log['source'] == 'CLIENT'])
        server_responses = len([log for log in self.session_log if log['source'] == 'SERVER'])
        
        print(f"""
Session Statistics:
────────────────────
Connected to: {self.target}:{self.port}
Commands sent: {client_commands}
Responses received: {server_responses}
Log file: {self.log_file}
Session start: {self.session_log[0]['timestamp'] if self.session_log else 'N/A'}
""")
    
    def interactive_session(self):
        """Main interactive session loop"""
        print(f"""
╔════════════════════════════════════════════════════════════════╗
║                 INTERACTIVE TCP CLIENT SESSION                 ║
║                                                                ║
║ Connected to: {self.target}:{self.port}                        
║ Session log: {os.path.basename(self.log_file)}                 
║                                                                ║
║ Type '.help' for client help or 'help' for server commands    ║
║ Use '.quit' or Ctrl+C to exit                                 ║
╚════════════════════════════════════════════════════════════════╝
""")
        
        try:
            while self.connected:
                try:
                    # Get user input with prompt
                    command = input("client> ").strip()
                    
                    if not command:
                        continue
                    
                    # Handle client-side commands
                    if command.startswith('.'):
                        self.handle_client_command(command)
                        continue
                    
                    # Add to history
                    self.command_history.append(command)
                    
                    # Handle quit commands
                    if command.lower() in ['quit', 'exit']:
                        self.send_command(command)
                        break
                    
                    # Send command to server
                    if not self.send_command(command):
                        print("Communication failed. Attempting to reconnect...")
                        if not self.reconnect():
                            break
                    
                except EOFError:
                    print("\nEOF received. Exiting...")
                    break
                except KeyboardInterrupt:
                    print("\n\nSession interrupted by user")
                    break
                    
        finally:
            self.disconnect()
    
    def handle_client_command(self, command):
        """Handle client-side commands"""
        cmd = command[1:].lower()  # Remove the dot prefix
        
        if cmd == 'help':
            self.show_help()
        elif cmd == 'status':
            print(f"Connection: {'ACTIVE' if self.connected else 'DISCONNECTED'}")
            self.show_session_stats()
        elif cmd == 'log':
            self.show_session_stats()
        elif cmd == 'history':
            print("Command History:")
            for i, cmd in enumerate(self.command_history[-10:], 1):
                print(f"  {i:2d}: {cmd}")
        elif cmd == 'exploit':
            self.show_exploitation_hints()
        elif cmd in ['quit', 'exit']:
            self.connected = False
        else:
            print(f"Unknown client command: {command}")
            print("Type '.help' for available commands")
    
    def reconnect(self):
        """Attempt to reconnect"""
        print("Attempting to reconnect...")
        self.disconnect()
        time.sleep(2)
        return self.connect()
    
    def disconnect(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        self.connected = False
        print(f"\nDisconnected from {self.target}:{self.port}")
        self.logger.info("Session ended")
        
        # Save session summary
        if self.session_log:
            print(f"Session log saved to: {self.log_file}")

def main():
    parser = argparse.ArgumentParser(description='Interactive TCP Client for Vulnerability Testing')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=9000, help='Target port')
    parser.add_argument('-l', '--log', help='Log file path')
    
    args = parser.parse_args()
    
    client = InteractiveClient(args.target, args.port, args.log)
    
    try:
        if client.connect():
            client.interactive_session()
        else:
            print("Failed to connect. Exiting...")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nClient terminated by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()