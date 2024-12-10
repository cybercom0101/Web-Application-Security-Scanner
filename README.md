# Web Application Security Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python Version](https://img.shields.io/badge/python-3.x-green.svg)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Logging](#logging)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

## Overview
The **Web Application Security Scanner** is a Python-based tool designed to identify common security vulnerabilities in web applications. It performs various tests, including SQL Injection, Cross-Site Scripting (XSS), Command Injection, Local File Inclusion (LFI), Remote File Inclusion (RFI), Server-Side Request Forgery (SSRF), and checks for security headers. This scanner utilizes concurrent requests to enhance scanning efficiency.

## Features
- **SQL Injection Testing**: Identifies SQL injection vulnerabilities with multiple payloads.
- **Cross-Site Scripting (XSS) Testing**: Detects XSS vulnerabilities using context-aware payloads.
- **Command Injection Testing**: Checks for command injection vulnerabilities.
- **Local and Remote File Inclusion Testing**: Tests for both LFI and RFI vulnerabilities.
- **Server-Side Request Forgery (SSRF) Testing**: Identifies SSRF vulnerabilities.
- **Security Headers Check**: Validates essential security headers and their configurations.
- **Web Crawling**: Discovers forms and links for further testing.
- **Logging**: Logs scan results and errors for later analysis.

## Requirements
- Python 3.x
- `requests` library
- `beautifulsoup4` library

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/cybercom0101/web-app-security-scanner.git
   cd web-app-security-scanner

2. **Install the required libraries**:
   ```bash
   pip install -r requirements.txt

## Usage
1. **Run the scanner**:
   ```bash
   python Webappscanner.py

2. **Input the target URL when prompted.**:
   ```bash
   Enter the URL to scan: http://example.com

## Logging
   - All scan results and errors are recorded in the web_scanner.log file. This log can be reviewed to understand detected vulnerabilities and any issues encountered during the scan.

## License
   - This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
   - This tool is intended for educational purposes and authorized security testing only. Ensure you have permission before scanning any web application.

