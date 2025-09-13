#!/usr/bin/env python3
"""
Vulnerable TCP Server for cybersecurity testing
This server intentionally contains vulnerabilities for educational purposes.
WARNING: Do not use in production environments!
"""
import socket
import threading
import time
import logging
import os
import subprocess
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
        self.connection_count = 0
    
    def handle_client(self, conn, addr):
        """Handle individual client connections with intentional vulnerabilities"""
        self.connection_count += 1
        conn_id = self.connection_count
        logger.info(f"[Connection {conn_id}] New connection from {addr}")
        
        try:
            # Send welcome message
            welcome = f"Welcome to Vulnerable Server v1.0\nConnection ID: {conn_id}\nType 'help' for commands\n> "
            conn.sendall(welcome.encode())
            
            while self.running:
                data = conn.recv(1024).decode('utf-8').strip()
                if not data:
                    break
                
                logger.info(f"[Connection {conn_id}] Command: {data}")
                response = self.process_command(data)
                
                conn.sendall(response.encode())
                
                if data.lower() == "quit":
                    break
                    
        except Exception as e:
            logger.error(f"[Connection {conn_id}] Error: {e}")
        finally:
            conn.close()
            if conn in self.connections:
                self.connections.remove(conn)
            logger.info(f"[Connection {conn_id}] Disconnected")
    
    def process_command(self, command):
        """Process client commands - INTENTIONALLY VULNERABLE"""
        cmd = command.lower().strip()
        
        if cmd == "help":
            return """Available commands:
- help: Show this message
- info: Server information
- time: Current time
- status: System status (VULNERABLE - executes system commands)
- whoami: Current user
- uptime: System uptime
- echo <msg>: Echo message (VULNERABLE - no input validation)
- exec <cmd>: Execute system command (EXTREMELY VULNERABLE)
- file <path>: Read file (VULNERABLE - directory traversal)
- quit: Disconnect
> """
        
        elif cmd == "info":
            return f"Server: Vulnerable Test Server v1.0\nTime: {datetime.now()}\nConnections: {len(self.connections)}\nPID: {os.getpid()}\n> "
        
        elif cmd == "time":
            return f"Server time: {time.ctime()}\n> "
        
        elif cmd == "status":
            # VULNERABILITY: Command injection via system calls
            try:
                uptime = subprocess.check_output(['uptime'], text=True).strip()
                load = os.getloadavg()
                return f"System load: {load}\nUptime: {uptime}\nMemory: {subprocess.check_output(['free', '-h'], text=True)}\n> "
            except Exception as e:
                return f"Status error: {e}\n> "
        
        elif cmd == "whoami":
            try:
                user = subprocess.check_output(['whoami'], text=True).strip()
                return f"Current user: {user}\nUID: {os.getuid()}\nGID: {os.getgid()}\n> "
            except Exception as e:
                return f"Whoami error: {e}\n> "
        
        elif cmd == "uptime":
            try:
                uptime = subprocess.check_output(['uptime'], text=True).strip()
                return f"Uptime: {uptime}\n> "
            except Exception as e:
                return f"Uptime error: {e}\n> "
        
        elif cmd.startswith("echo "):
            # VULNERABILITY: No input validation - potential for injection
            msg = command[5:]  # Get everything after "echo "
            return f"Echo: {msg}\nLength: {len(msg)} chars\n> "
        
        elif cmd.startswith("exec "):
            # CRITICAL VULNERABILITY: Direct command execution
            exec_cmd = command[5:]  # Get everything after "exec "
            logger.warning(f"DANGEROUS: Executing command: {exec_cmd}")
            try:
                result = subprocess.check_output(exec_cmd, shell=True, text=True, stderr=subprocess.STDOUT)
                return f"Command output:\n{result}\n> "
            except subprocess.CalledProcessError as e:
                return f"Command failed (exit {e.returncode}):\n{e.output}\n> "
            except Exception as e:
                return f"Execution error: {e}\n> "
        
        elif cmd.startswith("file "):
            # VULNERABILITY: Directory traversal
            file_path = command[5:]  # Get everything after "file "
            logger.warning(f"File access attempt: {file_path}")
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                return f"File content ({file_path}):\n{content}\n> "
            except FileNotFoundError:
                return f"File not found: {file_path}\n> "
            except PermissionError:
                return f"Permission denied: {file_path}\n> "
            except Exception as e:
                return f"File error: {e}\n> "
        
        elif cmd == "quit":
            return "Goodbye!\n"
        
        elif cmd.startswith("test"):
            # Hidden test command for advanced exploitation
            return f"Test mode: Server is vulnerable to command injection, directory traversal, and buffer overflows\nTry: exec ls, file /etc/passwd\n> "
        
        else:
            return f"Unknown command: '{command}'. Use 'help' for available commands\n> "
    
    def start(self):
        """Start the vulnerable server"""
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            
            logger.info(f"Vulnerable server listening on {self.host}:{self.port}")
            logger.warning("WARNING: This server contains intentional vulnerabilities!")
            
            try:
                while self.running:
                    conn, addr = server_socket.accept()
                    self.connections.append(conn)
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
                logger.info("Server shutdown complete")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerable TCP Server for Security Testing')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=9000, help='Port to bind to')
    
    args = parser.parse_args()
    
    server = VulnerableServer(args.host, args.port)
    server.start()