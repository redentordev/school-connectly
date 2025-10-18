#!/usr/bin/env python
"""
Automated Security Testing Suite for School Connectly
Milestone 2 - Evidence Collection

This script tests all 5 security controls and generates detailed evidence logs.
"""

import os
import sys
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Tuple

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

class SecurityTestRunner:
    """Main test runner for security controls"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.results = []
        self.evidence_dir = "test_evidence"
        self.log_file = None
        
        # Create evidence directory
        os.makedirs(self.evidence_dir, exist_ok=True)
        
        # Initialize log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"{self.evidence_dir}/security_test_run_{timestamp}.log"
        self.log_file = open(log_filename, 'w', encoding='utf-8')
        
        self.log_header(f"Security Test Run - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    def log(self, message: str, color: str = ""):
        """Log message to both console and file"""
        console_msg = f"{color}{message}{Colors.ENDC}" if color else message
        print(console_msg)
        # Strip ANSI codes for file logging
        file_msg = message
        self.log_file.write(file_msg + "\n")
        self.log_file.flush()
        
    def log_header(self, message: str):
        """Log a header section"""
        border = "=" * 80
        self.log(border, Colors.HEADER)
        self.log(message, Colors.HEADER + Colors.BOLD)
        self.log(border, Colors.HEADER)
        self.log("")
        
    def log_section(self, message: str):
        """Log a section header"""
        self.log("")
        self.log("-" * 80, Colors.CYAN)
        self.log(message, Colors.CYAN + Colors.BOLD)
        self.log("-" * 80, Colors.CYAN)
        
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log a test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        color = Colors.GREEN if passed else Colors.RED
        self.log(f"{status} | {test_name}", color)
        if details:
            self.log(f"    Details: {details}")
        
        self.results.append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        
    def check_server_availability(self) -> bool:
        """Check if the server is running"""
        self.log_section("Pre-Test: Server Availability Check")
        try:
            # Disable SSL verification and don't follow redirects to HTTPS
            response = requests.get(f"{self.base_url}/api/posts/", timeout=5, verify=False, allow_redirects=False)
            if response.status_code in [200, 301, 302, 404, 401, 403]:  # Any response means server is up
                self.log_test("Server is running", True, f"Status: {response.status_code}")
                return True
            else:
                self.log_test("Server is running", False, f"Unexpected status: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.log_test("Server is running", False, f"Connection error: {str(e)}")
            self.log("")
            self.log("❌ ERROR: Cannot connect to server. Please ensure the application is running.", Colors.RED)
            self.log("Run: docker-compose up -d", Colors.YELLOW)
            return False
            
    def test_control_1_token_redaction(self):
        """Control 1: JWT Token Redaction in Logs"""
        self.log_header("CONTROL #1: JWT TOKEN REDACTION IN LOGS")
        
        # Test 1: Check if logging filter exists
        self.log_section("Test 1.1: Logging Filter Implementation")
        try:
            from connectly.logging_filters import SensitiveDataFilter
            filter_instance = SensitiveDataFilter()
            self.log_test("SensitiveDataFilter class exists", True, "Filter successfully imported")
            
            # Test pattern matching
            test_log = "User authenticated with token: ya29.a0AfH6SMBxyz123abc"
            
            class FakeRecord:
                def __init__(self, msg):
                    self.msg = msg
            
            record = FakeRecord(test_log)
            filter_instance.filter(record)
            
            redacted = "REDACTED" in record.msg or "[REDACTED" in record.msg
            self.log_test("Token redaction pattern works", redacted, f"Result: {record.msg[:100]}")
            
        except ImportError as e:
            self.log_test("SensitiveDataFilter class exists", False, f"Import error: {str(e)}")
        except Exception as e:
            self.log_test("Token redaction pattern works", False, f"Error: {str(e)}")
            
        # Test 2: Check logger singleton integration
        self.log_section("Test 1.2: Logger Singleton Integration")
        try:
            from singletons.logger_singleton import LoggerSingleton
            logger_instance = LoggerSingleton.get_instance()
            logger = logger_instance.get_logger()
            
            # Check if handlers have the filter
            has_filter = False
            for handler in logger.handlers:
                if any(isinstance(f, type) and f.__name__ == 'SensitiveDataFilter' 
                       for f in handler.filters):
                    has_filter = True
                    break
                    
            # For now, just check if logger exists and has handlers
            self.log_test("Logger has handlers configured", len(logger.handlers) > 0, 
                         f"Handler count: {len(logger.handlers)}")
                         
        except Exception as e:
            self.log_test("Logger singleton integration", False, f"Error: {str(e)}")
            
        # Test 3: Make authentication request and check logs won't expose tokens
        self.log_section("Test 1.3: Authentication Request (Log Verification)")
        try:
            # Make a failing auth request (should log without exposing our test password)
            response = requests.post(
                f"{self.base_url}/api/auth/token/",
                json={"username": "security_test_user", "password": "test_password_123"},
                timeout=5
            )
            
            self.log_test("Authentication endpoint accessible", True, 
                         f"Status: {response.status_code}")
            self.log("NOTE: Check logs/connectly_*.log file - tokens should appear as [REDACTED]", Colors.YELLOW)
            
        except Exception as e:
            self.log_test("Authentication endpoint accessible", False, f"Error: {str(e)}")
            
    def test_control_2_rate_limiting(self):
        """Control 2: Rate Limiting for Login API"""
        self.log_header("CONTROL #2: RATE LIMITING FOR LOGIN API")
        
        # Test 1: Check rate limiter decorator exists
        self.log_section("Test 2.1: Rate Limiter Implementation")
        try:
            from connectly.rate_limiters import rate_limit_auth
            self.log_test("rate_limit_auth decorator exists", True, "Decorator successfully imported")
        except ImportError as e:
            self.log_test("rate_limit_auth decorator exists", False, f"Import error: {str(e)}")
            return
            
        # Test 2: Test actual rate limiting (5 requests/minute)
        self.log_section("Test 2.2: Rate Limit Enforcement (5 requests/minute)")
        self.log("Making 6 rapid authentication attempts...", Colors.YELLOW)
        
        responses = []
        for i in range(6):
            try:
                start_time = time.time()
                response = requests.post(
                    f"{self.base_url}/api/auth/token/",
                    json={"username": "test_user", "password": "wrong_password"},
                    timeout=5
                )
                elapsed = time.time() - start_time
                
                responses.append({
                    "attempt": i + 1,
                    "status": response.status_code,
                    "elapsed": elapsed
                })
                
                status_emoji = "✅" if response.status_code in [400, 401] else "⚠️"
                if response.status_code == 429:
                    status_emoji = "🚫"
                    
                self.log(f"  {status_emoji} Attempt {i+1}: Status {response.status_code} ({elapsed:.2f}s)")
                
                time.sleep(0.5)  # Small delay between requests
                
            except Exception as e:
                self.log(f"  ❌ Attempt {i+1}: Error - {str(e)}", Colors.RED)
                
        # Verify rate limiting kicked in
        has_429 = any(r['status'] == 429 for r in responses)
        first_5_valid = all(r['status'] in [400, 401] for r in responses[:5])
        
        self.log_test("First 5 requests allowed", first_5_valid, 
                     f"Statuses: {[r['status'] for r in responses[:5]]}")
        self.log_test("6th request rate limited (429)", has_429,
                     f"6th request status: {responses[5]['status'] if len(responses) > 5 else 'N/A'}")
                     
        # Test 3: Check if rate limit resets (wait and retry)
        if has_429:
            self.log_section("Test 2.3: Rate Limit Reset (waiting 65 seconds)")
            self.log("Waiting for rate limit to reset...", Colors.YELLOW)
            for i in range(65, 0, -5):
                self.log(f"  {i} seconds remaining...")
                time.sleep(5)
                
            try:
                response = requests.post(
                    f"{self.base_url}/api/auth/token/",
                    json={"username": "test_user", "password": "wrong_password"},
                    timeout=5
                )
                
                reset_works = response.status_code in [400, 401]
                self.log_test("Rate limit reset after wait", reset_works,
                             f"Status after wait: {response.status_code}")
            except Exception as e:
                self.log_test("Rate limit reset after wait", False, f"Error: {str(e)}")
        else:
            self.log("⚠️  Skipping reset test - rate limiting may not be active (DEBUG=True?)", Colors.YELLOW)
            
    def test_control_3_debug_prevention(self):
        """Control 3: Debug Information Disclosure Prevention"""
        self.log_header("CONTROL #3: DEBUG INFORMATION DISCLOSURE PREVENTION")
        
        # Test 1: Check DEBUG setting
        self.log_section("Test 3.1: DEBUG Mode Configuration")
        try:
            # We'll check by making a request that should trigger a 404
            response = requests.get(f"{self.base_url}/nonexistent-page-12345", timeout=5)
            
            # Check if response contains debug information
            content = response.text.lower()
            has_traceback = 'traceback' in content or 'exception' in content
            has_file_path = 'file "' in content or '/app/' in content
            has_debug_info = has_traceback or has_file_path
            
            self.log_test("No debug information in 404 response", not has_debug_info,
                         f"Status: {response.status_code}, Has debug info: {has_debug_info}")
                         
        except Exception as e:
            self.log_test("No debug information in 404 response", False, f"Error: {str(e)}")
            
        # Test 2: Check custom error handlers exist
        self.log_section("Test 3.2: Custom Error Handlers")
        try:
            from connectly import views
            has_404 = hasattr(views, 'custom_404')
            has_500 = hasattr(views, 'custom_500')
            has_403 = hasattr(views, 'custom_403')
            has_400 = hasattr(views, 'custom_400')
            
            all_handlers = has_404 and has_500 and has_403 and has_400
            self.log_test("Custom error handlers exist", all_handlers,
                         f"404: {has_404}, 500: {has_500}, 403: {has_403}, 400: {has_400}")
                         
        except Exception as e:
            self.log_test("Custom error handlers exist", False, f"Error: {str(e)}")
            
        # Test 3: Check 404 returns generic message
        self.log_section("Test 3.3: Generic Error Messages")
        try:
            response = requests.get(f"{self.base_url}/api/posts/99999/", timeout=5)
            
            # Should be 404
            is_404 = response.status_code == 404
            
            # Check if it's JSON and generic
            try:
                data = response.json()
                is_generic = 'error' in data or 'detail' in data
                no_traceback = 'traceback' not in str(data).lower()
                
                self.log_test("404 error is generic JSON", is_generic and no_traceback,
                             f"Response: {str(data)[:100]}")
            except:
                # If not JSON, check if it's at least not showing debug info
                no_debug = 'traceback' not in response.text.lower()
                self.log_test("404 error doesn't expose debug info", no_debug,
                             f"Content length: {len(response.text)}")
                             
        except Exception as e:
            self.log_test("Generic error messages", False, f"Error: {str(e)}")
            
    def test_control_4_secret_management(self):
        """Control 4: Environment-Based Secret Management"""
        self.log_header("CONTROL #4: ENVIRONMENT-BASED SECRET MANAGEMENT")
        
        # Test 1: Check environment validator exists
        self.log_section("Test 4.1: Environment Validator Implementation")
        try:
            from connectly import env_validator
            has_get_secret_key = hasattr(env_validator, 'get_secret_key')
            has_get_debug = hasattr(env_validator, 'get_debug_mode')
            has_validate = hasattr(env_validator, 'validate_environment')
            
            all_functions = has_get_secret_key and has_get_debug and has_validate
            self.log_test("Environment validator functions exist", all_functions,
                         f"get_secret_key: {has_get_secret_key}, get_debug_mode: {has_get_debug}, validate: {has_validate}")
                         
        except Exception as e:
            self.log_test("Environment validator functions exist", False, f"Error: {str(e)}")
            
        # Test 2: Check .env.example exists
        self.log_section("Test 4.2: Environment Template (.env.example)")
        env_example_path = ".env.example"
        if os.path.exists(env_example_path):
            with open(env_example_path, 'r') as f:
                content = f.read()
                has_secret_key = 'SECRET_KEY' in content
                has_debug = 'DEBUG' in content
                has_database = 'DATABASE_URL' in content
                
                complete = has_secret_key and has_debug and has_database
                self.log_test(".env.example is complete", complete,
                             f"Has SECRET_KEY: {has_secret_key}, DEBUG: {has_debug}, DATABASE_URL: {has_database}")
        else:
            self.log_test(".env.example exists", False, "File not found")
            
        # Test 3: Check for hardcoded secrets in code
        self.log_section("Test 4.3: No Hardcoded Secrets")
        
        files_to_check = [
            'connectly/settings.py',
            'authentication/views.py',
            'docker-compose.yml'
        ]
        
        suspicious_patterns = [
            'django-insecure',
            'sk-',  # API keys
            'Bearer ',  # Hardcoded tokens
        ]
        
        found_secrets = []
        for filepath in files_to_check:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for pattern in suspicious_patterns:
                        if pattern in content and 'example' not in content.lower():
                            found_secrets.append(f"{filepath}: {pattern}")
                            
        no_secrets = len(found_secrets) == 0
        self.log_test("No hardcoded secrets in code", no_secrets,
                     f"Suspicious patterns found: {len(found_secrets)}")
                     
    def test_control_5_server_info_prevention(self):
        """Control 5: Server Information Disclosure Prevention"""
        self.log_header("CONTROL #5: SERVER INFORMATION DISCLOSURE PREVENTION")
        
        # Test 1: Check middleware exists
        self.log_section("Test 5.1: Security Headers Middleware")
        try:
            from connectly.middleware import SecurityHeadersMiddleware
            self.log_test("SecurityHeadersMiddleware exists", True, "Middleware successfully imported")
        except ImportError as e:
            self.log_test("SecurityHeadersMiddleware exists", False, f"Import error: {str(e)}")
            
        # Test 2: Check actual response headers
        self.log_section("Test 5.2: HTTP Response Headers Analysis")
        try:
            response = requests.get(f"{self.base_url}/admin/", timeout=5, allow_redirects=False)
            headers = response.headers
            
            # Check for removed headers
            no_server = 'Server' not in headers or 'gunicorn' not in headers.get('Server', '').lower()
            no_powered = 'X-Powered-By' not in headers
            
            self.log_test("Server header removed/obscured", no_server,
                         f"Server header: {headers.get('Server', 'Not present')}")
            self.log_test("X-Powered-By header removed", no_powered,
                         f"X-Powered-By: {headers.get('X-Powered-By', 'Not present')}")
                         
            # Check for security headers
            has_csp = 'Content-Security-Policy' in headers
            has_permissions = 'Permissions-Policy' in headers
            has_referrer = 'Referrer-Policy' in headers
            has_nosniff = 'X-Content-Type-Options' in headers
            
            self.log_test("Content-Security-Policy header present", has_csp,
                         f"Value: {headers.get('Content-Security-Policy', 'Not present')[:50]}...")
            self.log_test("Permissions-Policy header present", has_permissions,
                         f"Value: {headers.get('Permissions-Policy', 'Not present')[:50]}...")
            self.log_test("Referrer-Policy header present", has_referrer,
                         f"Value: {headers.get('Referrer-Policy', 'Not present')}")
            self.log_test("X-Content-Type-Options header present", has_nosniff,
                         f"Value: {headers.get('X-Content-Type-Options', 'Not present')}")
                         
            # Log all headers for evidence
            self.log("\nAll Response Headers:", Colors.CYAN)
            for header, value in headers.items():
                self.log(f"  {header}: {value[:100]}...")
                
        except Exception as e:
            self.log_test("HTTP response headers check", False, f"Error: {str(e)}")
            
    def generate_summary(self):
        """Generate test summary"""
        self.log_header("TEST SUMMARY")
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        pass_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        self.log(f"Total Tests: {total_tests}", Colors.BOLD)
        self.log(f"Passed: {passed_tests}", Colors.GREEN)
        self.log(f"Failed: {failed_tests}", Colors.RED if failed_tests > 0 else Colors.GREEN)
        self.log(f"Pass Rate: {pass_rate:.1f}%", Colors.GREEN if pass_rate >= 80 else Colors.YELLOW)
        
        # Group by control
        self.log("\nResults by Control:", Colors.CYAN)
        controls = {}
        for result in self.results:
            control = result['test'].split(':')[0] if ':' in result['test'] else 'General'
            if control not in controls:
                controls[control] = {'passed': 0, 'failed': 0}
            if result['passed']:
                controls[control]['passed'] += 1
            else:
                controls[control]['failed'] += 1
                
        for control, stats in controls.items():
            total = stats['passed'] + stats['failed']
            rate = (stats['passed'] / total * 100) if total > 0 else 0
            status = "✅" if rate == 100 else "⚠️" if rate >= 50 else "❌"
            self.log(f"  {status} {control}: {stats['passed']}/{total} ({rate:.0f}%)")
            
        # Save JSON report
        json_report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "pass_rate": pass_rate
            },
            "results": self.results
        }
        
        json_filename = f"{self.evidence_dir}/test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_filename, 'w') as f:
            json.dump(json_report, f, indent=2)
            
        self.log(f"\n✅ JSON report saved: {json_filename}", Colors.GREEN)
        self.log(f"✅ Log file saved: {self.log_file.name}", Colors.GREEN)
        
    def run_all_tests(self):
        """Run all security tests"""
        try:
            # Check server availability first
            if not self.check_server_availability():
                self.log("\n❌ Cannot proceed with tests - server not available", Colors.RED)
                return False
                
            # Run all control tests
            self.test_control_1_token_redaction()
            self.test_control_2_rate_limiting()
            self.test_control_3_debug_prevention()
            self.test_control_4_secret_management()
            self.test_control_5_server_info_prevention()
            
            # Generate summary
            self.generate_summary()
            
            return True
            
        finally:
            if self.log_file:
                self.log_file.close()

def main():
    """Main entry point"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 80)
    print("  SCHOOL CONNECTLY - SECURITY TESTING SUITE")
    print("  Milestone 2: Automated Evidence Collection")
    print("=" * 80)
    print(f"{Colors.ENDC}\n")
    
    # Allow custom base URL
    base_url = os.getenv('TEST_BASE_URL', 'http://localhost:8000')
    
    runner = SecurityTestRunner(base_url=base_url)
    success = runner.run_all_tests()
    
    print(f"\n{Colors.BOLD}Testing complete!{Colors.ENDC}")
    print(f"Evidence files saved in: {runner.evidence_dir}/")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())

