#!/usr/bin/env python3
"""
Connection Tester - Tests network connectivity and service responses
Supports TCP, HTTP, and combined testing with detailed logging
"""
import socket
import time
import sys
import logging
import os
import requests
from datetime import datetime
import argparse
import threading
import json

class ConnectionTester:
    def __init__(self, log_dir=None):
        self.setup_logging(log_dir)
        self.results = {
            'tcp_tests': [],
            'http_tests': [],
            'summary': {}
        }
    
    def setup_logging(self, log_dir):
        """Setup logging with fallback locations"""
        if log_dir is None:
            log_dir = os.path.expanduser("~/logs")
        
        # Create log directory with proper permissions
        try:
            os.makedirs(log_dir, mode=0o755, exist_ok=True)
            log_file = os.path.join(log_dir, "attacker.log")
        except PermissionError:
            log_dir = "/tmp"
            log_file = os.path.join(log_dir, "attacker.log")
        
        # Setup logging
        try:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Connection tester initialized. Log: {log_file}")
        except Exception as e:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
            self.logger = logging.getLogger(__name__)
            self.logger.warning(f"File logging failed: {e}")
    
    def test_tcp_connection(self, target, port, timeout=3):
        """Test a single TCP connection"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Connection successful, try to get some data
                response_data = ""
                try:
                    # Send a simple probe
                    sock.send(b"info\n")
                    time.sleep(0.5)
                    response = sock.recv(1024)
                    response_data = response.decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                duration = time.time() - start_time
                sock.close()
                
                test_result = {
                    'timestamp': datetime.now().isoformat(),
                    'target': target,
                    'port': port,
                    'status': 'SUCCESS',
                    'duration': round(duration, 3),
                    'response_length': len(response_data),
                    'response_preview': response_data[:100] if response_data else None
                }
                
                self.logger.info(f"TCP SUCCESS {target}:{port} - Duration: {duration:.3f}s, Response: {len(response_data)} chars")
                return test_result
                
            else:
                duration = time.time() - start_time
                sock.close()
                
                test_result = {
                    'timestamp': datetime.now().isoformat(),
                    'target': target,
                    'port': port,
                    'status': 'FAILED',
                    'duration': round(duration, 3),
                    'error': f'Connection failed (code: {result})'
                }
                
                self.logger.warning(f"TCP FAILED {target}:{port} - Connection refused")
                return test_result
                
        except socket.timeout:
            duration = time.time() - start_time
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'port': port,
                'status': 'TIMEOUT',
                'duration': round(duration, 3),
                'error': f'Connection timeout after {timeout}s'
            }
            self.logger.warning(f"TCP TIMEOUT {target}:{port} - No response within {timeout}s")
            return test_result
            
        except Exception as e:
            duration = time.time() - start_time
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'port': port,
                'status': 'ERROR',
                'duration': round(duration, 3),
                'error': str(e)
            }
            self.logger.error(f"TCP ERROR {target}:{port} - {e}")
            return test_result
    
    def test_http_endpoint(self, target, port, endpoint, timeout=5):
        """Test a specific HTTP endpoint"""
        url = f"http://{target}:{port}{endpoint}"
        start_time = time.time()
        
        try:
            response = requests.get(url, timeout=timeout)
            duration = time.time() - start_time
            
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'status': 'SUCCESS',
                'duration': round(duration, 3),
                'http_status': response.status_code,
                'response_length': len(response.text),
                'headers': dict(response.headers),
                'response_preview': response.text[:200] if response.text else None
            }
            
            self.logger.info(f"HTTP SUCCESS {url} - Status: {response.status_code}, Size: {len(response.text)} bytes")
            return test_result
            
        except requests.exceptions.Timeout:
            duration = time.time() - start_time
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'status': 'TIMEOUT',
                'duration': round(duration, 3),
                'error': f'HTTP timeout after {timeout}s'
            }
            self.logger.warning(f"HTTP TIMEOUT {url}")
            return test_result
            
        except requests.exceptions.ConnectionError:
            duration = time.time() - start_time
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'status': 'CONNECTION_ERROR',
                'duration': round(duration, 3),
                'error': 'Connection refused or host unreachable'
            }
            self.logger.warning(f"HTTP CONNECTION_ERROR {url}")
            return test_result
            
        except Exception as e:
            duration = time.time() - start_time
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'status': 'ERROR',
                'duration': round(duration, 3),
                'error': str(e)
            }
            self.logger.error(f"HTTP ERROR {url} - {e}")
            return test_result
    
    def run_tcp_tests(self, target, port, count=3, interval=2, timeout=3):
        """Run multiple TCP connection tests"""
        print(f"Testing TCP connection to {target}:{port}")
        print(f"Running {count} tests with {interval}s intervals...")
        print("-" * 50)
        
        for i in range(count):
            print(f"Test {i+1}/{count}: ", end="", flush=True)
            result = self.test_tcp_connection(target, port, timeout)
            self.results['tcp_tests'].append(result)
            
            status_color = {
                'SUCCESS': '\033[92m',  # Green
                'FAILED': '\033[91m',   # Red
                'TIMEOUT': '\033[93m',  # Yellow
                'ERROR': '\033[91m'     # Red
            }
            reset_color = '\033[0m'
            
            color = status_color.get(result['status'], '')
            print(f"{color}{result['status']}{reset_color} ({result['duration']}s)")
            
            if result['status'] == 'SUCCESS' and result.get('response_preview'):
                print(f"  Response: {result['response_preview'][:50]}...")
            
            if i < count - 1:
                time.sleep(interval)
        
        return self.results['tcp_tests']
    
    def run_http_tests(self, target, port=8080, endpoints=None):
        """Run HTTP endpoint tests"""
        if endpoints is None:
            endpoints = ['/', '/info', '/echo?msg=test', '/file?name=test.txt', '/status']
        
        print(f"Testing HTTP endpoints on {target}:{port}")
        print(f"Testing {len(endpoints)} endpoints...")
        print("-" * 50)
        
        for endpoint in endpoints:
            print(f"Testing {endpoint}: ", end="", flush=True)
            result = self.test_http_endpoint(target, port, endpoint)
            self.results['http_tests'].append(result)
            
            if result['status'] == 'SUCCESS':
                print(f"\033[92mSUCCESS\033[0m (Status: {result['http_status']}, Size: {result['response_length']} bytes)")
                
                # Check for interesting content
                if result.get('response_preview'):
                    content = result['response_preview'].lower()
                    if any(indicator in content for indicator in ['error', 'exception', 'debug', 'password', 'secret']):
                        print(f"  \033[93m⚠️ Interesting content detected\033[0m")
                    if 'script' in content or '<' in content:
                        print(f"  \033[93m⚠️ HTML/Script content - potential XSS vector\033[0m")
            else:
                color = '\033[91m' if result['status'] == 'ERROR' else '\033[93m'
                print(f"{color}{result['status']}\033[0m")
        
        return self.results['http_tests']
    
    def run_combined_tests(self, target, tcp_port=9000, http_port=8080, tcp_count=3):
        """Run both TCP and HTTP tests"""
        print(f"Running combined connectivity tests against {target}")
        print(f"TCP Port: {tcp_port}, HTTP Port: {http_port}")
        print("=" * 60)
        
        # TCP Tests
        print("\n1. TCP CONNECTION TESTS")
        print("=" * 30)
        self.run_tcp_tests(target, tcp_port, count=tcp_count)
        
        # HTTP Tests  
        print(f"\n2. HTTP ENDPOINT TESTS")
        print("=" * 30)
        self.run_http_tests(target, http_port)
        
        # Generate summary
        self.generate_summary()
        
        return self.results
    
    def generate_summary(self):
        """Generate test summary statistics"""
        tcp_total = len(self.results['tcp_tests'])
        tcp_success = len([t for t in self.results['tcp_tests'] if t['status'] == 'SUCCESS'])
        
        http_total = len(self.results['http_tests'])
        http_success = len([t for t in self.results['http_tests'] if t['status'] == 'SUCCESS'])
        
        self.results['summary'] = {
            'tcp_total': tcp_total,
            'tcp_success': tcp_success,
            'tcp_success_rate': (tcp_success / tcp_total * 100) if tcp_total > 0 else 0,
            'http_total': http_total,
            'http_success': http_success,
            'http_success_rate': (http_success / http_total * 100) if http_total > 0 else 0,
            'overall_tests': tcp_total + http_total,
            'overall_success': tcp_success + http_success
        }
        
        # Print summary
        print(f"\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        if tcp_total > 0:
            print(f"TCP Tests: {tcp_success}/{tcp_total} successful ({self.results['summary']['tcp_success_rate']:.1f}%)")
        
        if http_total > 0:
            print(f"HTTP Tests: {http_success}/{http_total} successful ({self.results['summary']['http_success_rate']:.1f}%)")
        
        total_tests = self.results['summary']['overall_tests']
        total_success = self.results['summary']['overall_success']
        
        if total_tests > 0:
            overall_rate = (total_success / total_tests) * 100
            print(f"Overall: {total_success}/{total_tests} tests successful ({overall_rate:.1f}%)")
            
            # Assessment
            if overall_rate >= 80:
                print(f"\033[92m✓ Excellent connectivity - target is highly accessible\033[0m")
            elif overall_rate >= 60:
                print(f"\033[93m⚠ Good connectivity - some services may be filtered\033[0m")
            else:
                print(f"\033[91m✗ Poor connectivity - target may be down or heavily filtered\033[0m")
    
    def export_results(self, filename):
        """Export detailed results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results exported to: {filename}")
        self.logger.info(f"Results exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Connection Tester for Security Testing')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, help='TCP port to test', default=9000)
    parser.add_argument('-t', '--type', choices=['tcp', 'http', 'both'], default='both',
                       help='Type of test to run')
    parser.add_argument('-c', '--count', type=int, help='Number of TCP tests', default=3)
    parser.add_argument('-i', '--interval', type=int, help='Interval between tests', default=2)
    parser.add_argument('--timeout', type=int, help='Connection timeout', default=3)
    parser.add_argument('--http-port', type=int, help='HTTP port', default=8080)
    parser.add_argument('--endpoints', help='HTTP endpoints (comma-separated)', 
                       default='/, /info, /echo?msg=test, /file?name=test.txt, /status')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--log-dir', help='Log directory path')
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = ConnectionTester(log_dir=args.log_dir)
    
    try:
        if args.type == 'tcp':
            tester.run_tcp_tests(args.target, args.port, args.count, args.interval, args.timeout)
        elif args.type == 'http':
            endpoints = [ep.strip() for ep in args.endpoints.split(',')]
            tester.run_http_tests(args.target, args.http_port, endpoints)
        else:  # both
            tester.run_combined_tests(args.target, args.port, args.http_port, args.count)
        
        # Export results if requested
        if args.output:
            tester.export_results(args.output)
    
    except KeyboardInterrupt:
        print(f"\nTest interrupted by user")
        if tester.results['tcp_tests'] or tester.results['http_tests']:
            tester.generate_summary()
    except Exception as e:
        tester.logger.error(f"Test failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()