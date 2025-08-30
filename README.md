Advanced XSS Scanner
A powerful and stealthy Cross-Site Scripting (XSS) vulnerability scanner designed for security professionals and ethical hackers.

Features
Stealthy Scanning: Uses random user agents and delays between requests to avoid detection

Comprehensive Testing: Tests both form inputs and URL parameters

Multiple Payload Support: Loads XSS payloads from an external file

Authentication Support: Allows scanning of authenticated areas with cookies

Proxy Support: Route requests through proxies for anonymity

Detailed Reporting: Saves findings to a text file with full details

Error Handling: Robust error handling for reliable scanning

Installation
Clone or download the scanner files:

bash
git clone https://github.com/VastScientist69/StealthyXSSSCANNER/edit/main/README.md
cd StealthyXSSScanner
Install required dependencies:

bash
pip install requests beautifulsoup4
Ensure you have the xss-payloads.txt file in the same directory as the scanner.

Usage
Basic Scanning
bash
python xss_scanner.py http://example.com/vulnerable-page
Advanced Options
bash
# Use custom payload file
python xss_scanner.py http://example.com --payloads my-payloads.txt

# Add cookies for authenticated scanning
python xss_scanner.py http://example.com --cookies "session=abc123; user=admin"

# Use a proxy
python xss_scanner.py http://example.com --proxy http://proxy:8080

# Set custom delay between requests (seconds)
python xss_scanner.py http://example.com --delay 2

# Combine options
python xss_scanner.py http://example.com --cookies "session=abc123" --proxy http://proxy:8080 --delay 1.5
Payload File Format
The xss-payloads.txt file should contain one XSS payload per line. Comments start with # and are ignored.

Example:

text
# Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# Obfuscated payloads
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
Output
The scanner will display findings in real-time and save them to xss_findings.txt:

text
URL: http://example.com/search
Method: GET
Field: query
Payload: <script>alert('XSS')</script>
Response length: 2456
--------------------------------------------------
Advanced Configuration
You can modify the following variables in the code for custom behavior:

REQUEST_DELAY: Range of delays between requests (default: 1-3 seconds)

USER_AGENTS: List of user agents to rotate through

timeout: Request timeout in seconds (default: 10)

Ethical Use
This tool is intended for:

Security professionals conducting authorized assessments

Developers testing their own applications

Educational purposes in controlled environments

Always obtain proper authorization before scanning any website or application.

Disclaimer
This tool is provided for educational and ethical testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have permission to test the target systems.

Contributing
Contributions are welcome! Please feel free to submit pull requests with:

New payloads for xss-payloads.txt

Bug fixes

Performance improvements

New features

License
This project is licensed under the MIT License - see the LICENSE file for details.

