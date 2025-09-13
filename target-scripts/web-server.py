#!/usr/bin/env python3
"""
Vulnerable HTTP Server for cybersecurity testing
Contains intentional vulnerabilities for educational purposes.
WARNING: Do not use in production environments!
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import os
import logging
import json
import subprocess
from datetime import datetime

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vulnerable-web.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VulnerableHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional vulnerabilities for security testing"""
    
    def do_GET(self):
        """Handle GET requests - contains multiple vulnerabilities"""
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)
        
        logger.info(f"GET request: {self.path} from {self.client_address[0]}")
        
        # Route handling
        if parsed_path.path == '/':
            self.serve_main_page()
        elif parsed_path.path == '/info':
            self.serve_info_page()
        elif parsed_path.path == '/echo':
            self.serve_echo_page(query)
        elif parsed_path.path == '/file':
            self.serve_file_page(query)
        elif parsed_path.path == '/admin':
            self.serve_admin_page(query)
        elif parsed_path.path == '/config':
            self.serve_config_page()
        elif parsed_path.path == '/logs':
            self.serve_logs_page()
        elif parsed_path.path == '/exec':
            self.serve_exec_page(query)
        elif parsed_path.path == '/status':
            self.serve_status_page()
        elif parsed_path.path == '/debug':
            self.serve_debug_page(query)
        else:
            self.serve_404()
    
    def serve_main_page(self):
        """Serve the main vulnerability showcase page"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerable Web Server - Security Testing Lab</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .warning { color: red; font-weight: bold; }
                .endpoint { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
                .vuln { color: #d9534f; }
            </style>
        </head>
        <body>
            <h1>🚨 Vulnerable Web Server</h1>
            <p class="warning">⚠️ This server contains intentional security vulnerabilities for educational purposes!</p>
            
            <h2>Available Test Endpoints:</h2>
            
            <div class="endpoint">
                <h3><a href="/info">📋 /info</a></h3>
                <p>Server information disclosure</p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/echo?msg=hello">💬 /echo?msg=...</a></h3>
                <p class="vuln">🔓 XSS Vulnerability: Reflects user input without sanitization</p>
                <p>Try: <code>/echo?msg=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/file?name=test.txt">📁 /file?name=...</a></h3>
                <p class="vuln">🔓 Directory Traversal: Reads arbitrary files</p>
                <p>Try: <code>/file?name=../../../etc/passwd</code></p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/admin?user=admin">🔒 /admin?user=...</a></h3>
                <p class="vuln">🔓 Authorization Bypass: No real authentication</p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/config">⚙️ /config</a></h3>
                <p class="vuln">🔓 Information Disclosure: Exposes configuration</p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/exec?cmd=whoami">💻 /exec?cmd=...</a></h3>
                <p class="vuln">🔓 CRITICAL: Remote Command Execution</p>
                <p>Try: <code>/exec?cmd=ls -la</code></p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/status">📊 /status</a></h3>
                <p>System status information</p>
            </div>
            
            <div class="endpoint">
                <h3><a href="/debug?action=test">🐛 /debug?action=...</a></h3>
                <p class="vuln">🔓 Debug Information Disclosure</p>
            </div>
            
            <hr>
            <p><strong>Learning Objectives:</strong></p>
            <ul>
                <li>Cross-Site Scripting (XSS) detection and exploitation</li>
                <li>Directory traversal / Path traversal attacks</li>
                <li>Information disclosure vulnerabilities</li>
                <li>Remote command execution</li>
                <li>Authorization bypass techniques</li>
            </ul>
            
            <p class="warning">⚠️ Remember: This is for educational use in controlled environments only!</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def serve_info_page(self):
        """Serve server info - potential information disclosure"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        info = {
            "server": "VulnWeb v1.0",
            "timestamp": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "system": f"{os.uname().sysname} {os.uname().release}",
            "user": os.getenv('USER', 'unknown'),
            "pid": os.getpid(),
            "cwd": os.getcwd(),
            "python_version": os.sys.version
        }
        
        self.wfile.write(json.dumps(info, indent=2).encode())
    
    def serve_echo_page(self, query):
        """VULNERABILITY: XSS - reflects user input without sanitization"""
        msg = query.get('msg', ['No message'])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # INTENTIONALLY VULNERABLE: No XSS protection
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Echo Test</title></head>
        <body>
            <h1>Echo Response</h1>
            <p>Your message: {msg}</p>
            <p>Message length: {len(msg)} characters</p>
            <hr>
            <p>Try XSS payloads like: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def serve_file_page(self, query):
        """VULNERABILITY: Directory traversal - reads arbitrary files"""
        filename = query.get('name', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        if not filename:
            self.wfile.write(b"No filename specified. Try: ?name=test.txt or ?name=../../../etc/passwd")
            return
        
        # INTENTIONALLY VULNERABLE: No path validation
        logger.warning(f"File access attempt: {filename}")
        
        try:
            # Try relative to /tmp first, then absolute path
            file_paths = [f"/tmp/{filename}", filename]
            
            content_found = False
            for file_path in file_paths:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    self.wfile.write(f"File: {file_path}\n{'='*50}\n{content}".encode())
                    content_found = True
                    break
                except (FileNotFoundError, PermissionError):
                    continue
            
            if not content_found:
                self.wfile.write(f"File not found or permission denied: {filename}".encode())
                
        except Exception as e:
            self.wfile.write(f"Error reading file: {e}".encode())
    
    def serve_admin_page(self, query):
        """VULNERABILITY: Authorization bypass - no real authentication"""
        user = query.get('user', ['guest'])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # INTENTIONALLY VULNERABLE: No real authentication
        if user.lower() in ['admin', 'administrator', 'root']:
            html = f"""
            <html><body>
            <h1>🔒 Admin Panel</h1>
            <p>Welcome, {user}!</p>
            <p><strong>CRITICAL VULNERABILITY:</strong> No real authentication!</p>
            <ul>
                <li>User database: 1000+ users</li>
                <li>Admin privileges: GRANTED</li>
                <li>Secret key: FLAG{{auth_bypass_success}}</li>
            </ul>
            <p>This demonstrates authorization bypass vulnerabilities.</p>
            </body></html>
            """
        else:
            html = f"""
            <html><body>
            <h1>🚫 Access Denied</h1>
            <p>User '{user}' does not have admin privileges.</p>
            <p>Hint: Try ?user=admin</p>
            </body></html>
            """
        
        self.wfile.write(html.encode())
    
    def serve_config_page(self):
        """VULNERABILITY: Information disclosure - exposes configuration"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        # INTENTIONALLY VULNERABLE: Exposes sensitive information
        config = {
            "database": {
                "host": "localhost",
                "username": "db_user",
                "password": "secret123",
                "database": "vuln_db"
            },
            "api_keys": {
                "secret_key": "super_secret_key_123",
                "jwt_secret": "jwt_signing_key_456"
            },
            "debug": True,
            "version": "1.0.0",
            "environment": "production"  # Lying about environment
        }
        
        self.wfile.write(json.dumps(config, indent=2).encode())
    
    def serve_logs_page(self):
        """VULNERABILITY: Information disclosure - exposes log files"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        try:
            with open('/var/log/vulnerable-web.log', 'r') as f:
                logs = f.readlines()[-50:]  # Last 50 lines
            
            content = "=== RECENT WEB SERVER LOGS ===\n" + "".join(logs)
            self.wfile.write(content.encode())
        except Exception as e:
            self.wfile.write(f"Could not read logs: {e}".encode())
    
    def serve_exec_page(self, query):
        """CRITICAL VULNERABILITY: Remote Command Execution"""
        cmd = query.get('cmd', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        if not cmd:
            self.wfile.write(b"No command specified. Try: ?cmd=whoami")
            return
        
        # CRITICAL VULNERABILITY: Direct command execution
        logger.error(f"CRITICAL: Remote command execution attempt: {cmd}")
        
        try:
            result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            response = f"Command: {cmd}\n{'='*50}\n{result}"
            self.wfile.write(response.encode())
        except subprocess.CalledProcessError as e:
            response = f"Command failed (exit {e.returncode}): {cmd}\n{e.output}"
            self.wfile.write(response.encode())
        except Exception as e:
            self.wfile.write(f"Execution error: {e}".encode())
    
    def serve_status_page(self):
        """Serve system status information"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        try:
            status = {
                "timestamp": datetime.now().isoformat(),
                "uptime": subprocess.check_output(['uptime'], text=True).strip(),
                "memory": subprocess.check_output(['free', '-h'], text=True),
                "disk": subprocess.check_output(['df', '-h'], text=True),
                "processes": len(subprocess.check_output(['ps', 'aux'], text=True).split('\n')),
                "network": subprocess.check_output(['ss', '-tuln'], text=True)
            }
            self.wfile.write(json.dumps(status, indent=2).encode())
        except Exception as e:
            error_msg = {"error": f"Status check failed: {e}"}
            self.wfile.write(json.dumps(error_msg).encode())
    
    def serve_debug_page(self, query):
        """VULNERABILITY: Debug information disclosure"""
        action = query.get('action', ['info'])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        if action == 'env':
            # VULNERABILITY: Exposes environment variables
            env_vars = dict(os.environ)
            content = "=== ENVIRONMENT VARIABLES ===\n"
            for key, value in env_vars.items():
                content += f"{key}={value}\n"
            self.wfile.write(content.encode())
        
        elif action == 'headers':
            # Show all request headers
            content = "=== REQUEST HEADERS ===\n"
            for header, value in self.headers.items():
                content += f"{header}: {value}\n"
            self.wfile.write(content.encode())
        
        elif action == 'stack':
            # VULNERABILITY: Stack trace exposure
            try:
                # Intentionally cause an error for stack trace
                1/0
            except Exception as e:
                import traceback
                content = f"=== STACK TRACE ===\n{traceback.format_exc()}"
                self.wfile.write(content.encode())
        
        else:
            content = f"""=== DEBUG INFO ===
Action: {action}
Timestamp: {datetime.now()}
Process ID: {os.getpid()}
Working Directory: {os.getcwd()}
Python Path: {os.sys.executable}

Available debug actions:
- ?action=env (environment variables)
- ?action=headers (request headers)  
- ?action=stack (stack trace)
"""
            self.wfile.write(content.encode())
    
    def serve_404(self):
        """Serve 404 with information disclosure"""
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # VULNERABILITY: Information disclosure in error pages
        html = f"""
        <html><body>
        <h1>404 - Not Found</h1>
        <p>The requested path <code>{self.path}</code> was not found.</p>
        <p><strong>Server Debug Info:</strong></p>
        <ul>
            <li>Server: VulnWeb v1.0</li>
            <li>Time: {datetime.now()}</li>
            <li>Your IP: {self.client_address[0]}</li>
            <li>Server Path: {os.getcwd()}</li>
        </ul>
        <p>Available endpoints: /, /info, /echo, /file, /admin, /config, /exec, /status, /debug</p>
        </body></html>
        """
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        """Override log message to use our logger"""
        logger.info(f"{self.client_address[0]} - {format % args}")

def main():
    """Main function with command line argument support"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerable Web Server for Security Testing')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    
    args = parser.parse_args()
    
    server = HTTPServer((args.host, args.port), VulnerableHTTPHandler)
    logger.info(f"Starting vulnerable HTTP server on {args.host}:{args.port}")
    logger.warning("WARNING: This server contains intentional vulnerabilities!")
    logger.warning("Do not use in production environments!")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        server.server_close()

if __name__ == "__main__":
    main()