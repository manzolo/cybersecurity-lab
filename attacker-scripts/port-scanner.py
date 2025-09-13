#!/usr/bin/env python3
"""
Enhanced Port Scanner for cybersecurity testing
Supports multiple scan types and detailed service detection
"""
import socket
import sys
import threading
import time
from datetime import datetime
import argparse
import subprocess
import json

class PortScanner:
    def __init__(self, timeout=1, threads=100):
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.service_info = {}
        self.scan_start = None
        self.scan_end = None
    
    def scan_port(self, target, port, results, service_detection=False):
        """Scan a single port with optional service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                results.append(port)
                print(f"Port {port}: OPEN", end="")
                
                if service_detection:
                    service = self.detect_service(target, port, sock)
                    if service:
                        self.service_info[port] = service
                        print(f" - {service}")
                    else:
                        print()
                else:
                    print()
            
            sock.close()
        except Exception:
            pass
    
    def detect_service(self, target, port, sock=None):
        """Basic service detection"""
        service_map = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt",
            9000: "TCP-Server"
        }
        
        # Basic service by port
        basic_service = service_map.get(port, "Unknown")
        
        # Try banner grabbing for common services
        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
            
            # Try to get banner
            if port in [21, 22, 25, 110]:
                sock.settimeout(3)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return f"{basic_service} ({banner[:50]}{'...' if len(banner) > 50 else ''})"
            elif port in [80, 8080]:
                # HTTP banner grab
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "Server:" in response:
                    server_line = [line for line in response.split('\n') if 'Server:' in line]
                    if server_line:
                        server = server_line[0].split('Server:')[1].strip()
                        return f"{basic_service} ({server})"
                return f"{basic_service} (Web Server)"
            elif port == 9000:
                # Special handling for our vulnerable server
                sock.send(b"info\n")
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if "Vulnerable" in response:
                    return "Vulnerable TCP Server (Lab Target)"
                return "TCP Service"
            
        except Exception:
            pass
        
        return basic_service
    
    def get_port_ranges(self, port_spec):
        """Parse port specification into list of ports"""
        if port_spec == 'common':
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
                   1723, 3306, 3389, 5900, 8080, 9000]
        elif port_spec == 'all':
            return range(1, 65536)
        elif port_spec == 'well-known':
            return range(1, 1024)
        elif '-' in port_spec:
            start, end = map(int, port_spec.split('-'))
            return range(start, end + 1)
        elif ',' in port_spec:
            return [int(p) for p in port_spec.split(',')]
        else:
            return [int(port_spec)]
    
    def scan(self, target, ports, service_detection=True):
        """Main scanning function"""
        self.scan_start = datetime.now()
        
        print(f"Starting port scan against {target}")
        print(f"Scan started: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scanning {len(list(ports))} ports...")
        print("-" * 50)
        
        results = []
        threads = []
        port_list = list(ports)
        
        # Threading for faster scans
        for port in port_list:
            thread = threading.Thread(
                target=self.scan_port, 
                args=(target, port, results, service_detection)
            )
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        self.scan_end = datetime.now()
        self.open_ports = sorted(results)
        
        return self.open_ports
    
    def print_results(self, target):
        """Print comprehensive scan results"""
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Target: {target}")
        print(f"Scan duration: {(self.scan_end - self.scan_start).total_seconds():.2f} seconds")
        print(f"Open ports found: {len(self.open_ports)}")
        
        if self.open_ports:
            print(f"\nOPEN PORTS:")
            print("-" * 40)
            for port in self.open_ports:
                service = self.service_info.get(port, "Unknown")
                print(f"{port:>6}/tcp    {service}")
        else:
            print("\nNo open ports found.")
        
        # Security assessment
        self.security_assessment()
    
    def security_assessment(self):
        """Provide basic security assessment"""
        print(f"\nSECURITY ASSESSMENT:")
        print("-" * 40)
        
        if 9000 in self.open_ports:
            print("⚠️  CRITICAL: Vulnerable TCP server detected on port 9000")
            print("   This service is intentionally vulnerable for testing")
        
        if 8080 in self.open_ports:
            print("⚠️  WARNING: HTTP service on port 8080 may be vulnerable")
            print("   Test for web vulnerabilities (XSS, directory traversal)")
        
        if 22 in self.open_ports:
            print("ℹ️  INFO: SSH service detected - ensure strong authentication")
        
        if 80 in self.open_ports or 443 in self.open_ports:
            print("ℹ️  INFO: Web server detected - test for common vulnerabilities")
        
        if 3306 in self.open_ports:
            print("⚠️  WARNING: MySQL database exposed - check access controls")
        
        # General recommendations
        print(f"\nRECOMMENDations:")
        print("- Run vulnerability scans against discovered services")
        print("- Test authentication mechanisms")
        print("- Check for default credentials")
        print("- Analyze service banners for version information")
    
    def export_results(self, filename, target):
        """Export results to JSON file"""
        results = {
            "target": target,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "duration": (self.scan_end - self.scan_start).total_seconds(),
            "open_ports": self.open_ports,
            "services": self.service_info,
            "total_ports": len(self.open_ports)
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults exported to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Port Scanner for Security Testing')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Ports to scan (common/all/well-known/1-1000/80,443,8080)')
    parser.add_argument('-t', '--timeout', type=int, default=1, 
                       help='Connection timeout in seconds')
    parser.add_argument('--threads', type=int, default=100, 
                       help='Number of concurrent threads')
    parser.add_argument('-s', '--service-detection', action='store_true', default=True,
                       help='Enable service detection')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--fast', action='store_true', 
                       help='Fast scan (reduce timeout and increase threads)')
    parser.add_argument('--stealth', action='store_true',
                       help='Stealth scan (slower, less detectable)')
    
    args = parser.parse_args()
    
    # Adjust settings based on scan type
    if args.fast:
        args.timeout = 0.5
        args.threads = 200
    elif args.stealth:
        args.timeout = 3
        args.threads = 10
    
    # Initialize scanner
    scanner = PortScanner(timeout=args.timeout, threads=args.threads)
    
    try:
        # Get ports to scan
        ports = scanner.get_port_ranges(args.ports)
        
        # Resolve target if it's a hostname
        try:
            target_ip = socket.gethostbyname(args.target)
            if target_ip != args.target:
                print(f"Resolved {args.target} to {target_ip}")
        except socket.gaierror:
            print(f"Could not resolve hostname: {args.target}")
            sys.exit(1)
        
        # Run scan
        open_ports = scanner.scan(args.target, ports, args.service_detection)
        
        # Display results
        scanner.print_results(args.target)
        
        # Export if requested
        if args.output:
            scanner.export_results(args.output, args.target)
    
    except KeyboardInterrupt:
        print(f"\nScan interrupted by user")
        if scanner.open_ports:
            print(f"Partial results: {len(scanner.open_ports)} ports found")
            scanner.print_results(args.target)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()