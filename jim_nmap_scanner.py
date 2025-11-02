#!/usr/bin/env python3
"""
Nmap Vulnerability Scanner v3.5
Author: Sir Jimbet (https://github.com/jimbet/)
Scans IP addresses with nmap, extracts service information, and checks CVE's for vulnerabilities
"""

import subprocess
import json
import re
import sys
import socket
import requests
from datetime import datetime
from typing import Dict, List, Optional
import threading
import time
import tempfile
import os
from colorama import Fore, Back, Style, init

# Check for SOCKS support
try:
    from requests.packages.urllib3.contrib.socks import SOCKSProxyManager
    SOCKS_AVAILABLE = True
except ImportError:
    try:
        import socks
        SOCKS_AVAILABLE = True
    except ImportError:
        SOCKS_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

# ============================================================================
# COLOR CONFIGURATION
# ============================================================================
class Colors:
    HEADER = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    CRITICAL = Fore.RED + Back.WHITE + Style.BRIGHT
    VULN_HIGH = Fore.RED + Style.BRIGHT
    VULN_MEDIUM = Fore.YELLOW + Style.BRIGHT
    VULN_LOW = Fore.GREEN + Style.BRIGHT
    RESET = Style.RESET_ALL

# ============================================================================
# NMAP SCAN PROFILES
# ============================================================================
SCAN_PROFILES = {
    "1": {
        "name": "Quick Scan",
        "flags": ["-T4", "-F"],
        "description": "Fast scan of common ports"
    },
    "2": {
        "name": "Aggressive Scan",
        "flags": ["-A"],
        "description": "OS detection, version detection, script scanning, and traceroute"
    },
    "3": {
        "name": "Full Port Scan",
        "flags": ["-p-", "-sV"],
        "description": "Scan all 65535 ports with version detection"
    },
    "4": {
        "name": "Stealth SYN Scan",
        "flags": ["-sS", "-sV", "-T2"],
        "description": "SYN stealth scan with version detection (requires root)"
    },
    "5": {
        "name": "Skip Host Discovery",
        "flags": ["-Pn", "-sV", "-T4"],
        "description": "Treat all hosts as online, skip ping (for firewalled hosts)"
    },
    "6": {
        "name": "Comprehensive Scan",
        "flags": ["-A", "-p-", "-Pn", "-T4"],
        "description": "All ports + aggressive scan, no ping (thorough but slow)"
    },
    "7": {
        "name": "Top 1000 Ports",
        "flags": ["--top-ports", "1000", "-sV"],
        "description": "Scan top 1000 most common ports with version detection"
    },
    "8": {
        "name": "UDP Scan",
        "flags": ["-sU", "--top-ports", "100"],
        "description": "Top 100 UDP ports (requires root, very slow)"
    },
    "9": {
        "name": "Custom",
        "flags": [],
        "description": "Enter your own nmap flags"
    }
}

# ============================================================================
# PROXY CONFIGURATIONS
# ============================================================================
PROXY_TYPES = {
    "1": {
        "name": "Direct Connection",
        "description": "No proxy, direct connection",
        "env": {}
    },
    "2": {
        "name": "HTTP Proxy",
        "description": "Use HTTP proxy",
        "env": {"type": "http"}
    },
    "3": {
        "name": "SOCKS5 Proxy",
        "description": "Use SOCKS5 proxy",
        "env": {"type": "socks5"}
    },
    "4": {
        "name": "Tor (SOCKS5)",
        "description": "Route through Tor network (127.0.0.1:9050)",
        "env": {"type": "socks5", "host": "127.0.0.1", "port": "9050"}
    }
}

# ============================================================================
# API CONFIGURATION - Add your API keys here
# ============================================================================
NVD_API_KEY = ""  # Get from: https://nvd.nist.gov/developers/request-an-api-key
SNYK_API_KEY = ""  # Get from: https://app.snyk.io/account (Settings -> General -> API Token)
VULNERS_API_KEY = ""  # Get from: https://vulners.com/userinfo (Free tier available)
# ============================================================================

class NmapVulnScanner:
    def __init__(self, proxy_config: Dict = None):
        self.results = {
            "scan_info": {},
            "domain": "",
            "hosts": []
        }
        self.session = requests.Session()
        self.proxy_config = proxy_config or {}

        # Configure proxy for API requests
        if self.proxy_config.get("type") == "socks5":
            host = self.proxy_config.get("host", "127.0.0.1")
            port = self.proxy_config.get("port", "9050")

            # First configure the proxy
            self.session.proxies.update({
                'http': f'socks5h://{host}:{port}',
                'https': f'socks5h://{host}:{port}'
            })

            # Then test if Tor is working (if it's localhost:9050)
            if host == "127.0.0.1" and port == "9050":
                if not self.test_tor_connection(host, port):
                    print(f"{Colors.ERROR}[!] Tor connection failed. Cannot continue with Tor.{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Start Tor with: sudo systemctl start tor{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Or check: systemctl status tor{Colors.RESET}")
                    sys.exit(1)

        elif self.proxy_config.get("type") == "http":
            host = self.proxy_config.get("host")
            port = self.proxy_config.get("port")
            self.session.proxies.update({
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            })
            print(f"{Colors.SUCCESS}[+] HTTP proxy configured: {host}:{port}{Colors.RESET}")

    def test_tor_connection(self, host: str, port: str) -> bool:
        """
        Comprehensive Tor connection test
        1. Check if Tor port is open
        2. Test connection through Tor
        3. Verify IP is different from direct connection
        4. Test connectivity to external sites
        """
        import socket as sock

        print(f"\n{Colors.HEADER}{'='*70}")
        print(f"  TOR CONNECTION TEST")
        print(f"{'='*70}{Colors.RESET}\n")

        # Step 1: Check if Tor port is listening
        print(f"{Colors.INFO}[1/4] Checking if Tor port {port} is open...{Colors.RESET}")
        try:
            test_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            test_socket.settimeout(3)
            result = test_socket.connect_ex((host, int(port)))
            test_socket.close()

            if result == 0:
                print(f"{Colors.SUCCESS}  ✓ Port {port} is open and accepting connections{Colors.RESET}")
            else:
                print(f"{Colors.ERROR}  ✗ Port {port} is not accessible (connection refused){Colors.RESET}")
                print(f"{Colors.WARNING}  ! Is Tor service running? Try: sudo systemctl start tor{Colors.RESET}")
                return False
        except Exception as e:
            print(f"{Colors.ERROR}  ✗ Error checking port: {e}{Colors.RESET}")
            return False

        # Step 2: Get our real IP (direct connection)
        print(f"\n{Colors.INFO}[2/4] Getting your real IP address...{Colors.RESET}")
        real_ip = None
        try:
            direct_session = requests.Session()
            response = direct_session.get('https://api.ipify.org?format=json', timeout=10)
            real_ip = response.json().get('ip')
            print(f"{Colors.SUCCESS}  ✓ Your real IP: {real_ip}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.WARNING}  ! Could not determine real IP: {e}{Colors.RESET}")
            print(f"{Colors.INFO}  ! Continuing with Tor test...{Colors.RESET}")

        # Step 3: Test Tor connection and get Tor IP
        print(f"\n{Colors.INFO}[3/4] Testing connection through Tor...{Colors.RESET}")
        tor_ip = None
        is_tor = False

        try:
            # Test with Tor check service
            print(f"{Colors.INFO}  → Connecting to check.torproject.org...{Colors.RESET}")
            response = self.session.get('https://check.torproject.org/api/ip', timeout=15)
            data = response.json()
            is_tor = data.get('IsTor', False)
            tor_ip = data.get('IP', 'Unknown')

            if is_tor:
                print(f"{Colors.SUCCESS}  ✓ Successfully connected through Tor network{Colors.RESET}")
                print(f"{Colors.SUCCESS}  ✓ Your Tor exit node IP: {tor_ip}{Colors.RESET}")

                if real_ip and tor_ip != real_ip:
                    print(f"{Colors.SUCCESS}  ✓ IP successfully changed (Real: {real_ip} → Tor: {tor_ip}){Colors.RESET}")
                elif real_ip and tor_ip == real_ip:
                    print(f"{Colors.WARNING}  ! Warning: Tor IP matches real IP (possible leak){Colors.RESET}")
            else:
                print(f"{Colors.ERROR}  ✗ Connection is NOT going through Tor{Colors.RESET}")
                return False

        except requests.exceptions.ProxyError as e:
            print(f"{Colors.ERROR}  ✗ Proxy error: Cannot connect through Tor{Colors.RESET}")
            print(f"{Colors.WARNING}  ! Error: {e}{Colors.RESET}")
            return False
        except requests.exceptions.Timeout:
            print(f"{Colors.ERROR}  ✗ Connection timeout through Tor{Colors.RESET}")
            print(f"{Colors.WARNING}  ! Tor might be too slow or not working properly{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.ERROR}  ✗ Error testing Tor: {e}{Colors.RESET}")
            return False

        # Step 4: Test connectivity to common sites
        print(f"\n{Colors.INFO}[4/4] Testing connectivity to external sites...{Colors.RESET}")

        test_sites = [
            ('https://www.google.com', 'Google'),
            ('https://www.cloudflare.com', 'Cloudflare'),
            ('https://api.ipify.org', 'IPify API')
        ]

        successful_tests = 0
        for url, name in test_sites:
            try:
                print(f"{Colors.INFO}  → Testing {name}...{Colors.RESET}", end=' ')
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    print(f"{Colors.SUCCESS}✓{Colors.RESET}")
                    successful_tests += 1
                else:
                    print(f"{Colors.WARNING}! (HTTP {response.status_code}){Colors.RESET}")
            except requests.exceptions.Timeout:
                print(f"{Colors.WARNING}✗ (Timeout){Colors.RESET}")
            except Exception as e:
                print(f"{Colors.WARNING}✗ ({str(e)[:30]}){Colors.RESET}")

        if successful_tests >= 2:
            print(f"\n{Colors.SUCCESS}  ✓ External connectivity working ({successful_tests}/{len(test_sites)} sites accessible){Colors.RESET}")
        elif successful_tests >= 1:
            print(f"\n{Colors.WARNING}  ! Limited connectivity ({successful_tests}/{len(test_sites)} sites accessible){Colors.RESET}")
            print(f"{Colors.INFO}  ! Tor may be slow but functional{Colors.RESET}")
        else:
            print(f"\n{Colors.ERROR}  ✗ No external connectivity through Tor{Colors.RESET}")
            return False

        # Final summary
        print(f"\n{Colors.HEADER}{'='*70}")
        print(f"  TOR CONNECTION: {'VERIFIED' if is_tor else 'FAILED'}")
        print(f"{'='*70}{Colors.RESET}\n")

        if is_tor:
            print(f"{Colors.SUCCESS}✓ All checks passed - Tor is working correctly!{Colors.RESET}")
            print(f"{Colors.INFO}[i] Your traffic will be routed through Tor network{Colors.RESET}")
            print(f"{Colors.INFO}[i] Exit node location may vary during the scan{Colors.RESET}\n")

        return is_tor

    def check_proxychains(self) -> bool:
        """Check if proxychains is installed"""
        try:
            result = subprocess.run(['which', 'proxychains4'],
                                  capture_output=True,
                                  text=True,
                                  timeout=5)
            if result.returncode == 0:
                return True

            # Try proxychains (older version)
            result = subprocess.run(['which', 'proxychains'],
                                  capture_output=True,
                                  text=True,
                                  timeout=5)
            return result.returncode == 0
        except:
            return False

    def configure_proxychains(self, host: str, port: str) -> bool:
        """Configure proxychains for the SOCKS proxy"""
        try:
            proxychains_conf = os.path.expanduser("~/.proxychains/proxychains.conf")
            os.makedirs(os.path.dirname(proxychains_conf), exist_ok=True)

            config_content = f"""# Proxychains configuration for nmap scanner
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 {host} {port}
"""
            with open(proxychains_conf, 'w') as f:
                f.write(config_content)

            print(f"{Colors.SUCCESS}[+] Proxychains configured at {proxychains_conf}{Colors.RESET}")
            return True
        except Exception as e:
            print(f"{Colors.ERROR}[!] Failed to configure proxychains: {e}{Colors.RESET}")
            return False

    def validate_ip(self, ip: str) -> bool:
        """Validate IPv4 or IPv6 address"""
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        elif re.match(ipv6_pattern, ip):
            return True
        return False

    def validate_domain(self, domain: str) -> bool:
        """Validate domain/subdomain format"""
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))

    def resolve_domain(self, domain: str) -> Dict:
        """Resolve domain to IP addresses"""
        print(f"{Colors.INFO}[*] Resolving domain: {domain}...{Colors.RESET}")

        result = {
            "domain": domain,
            "ipv4": [],
            "ipv6": []
        }

        try:
            # Get all IP addresses for the domain
            addr_info = socket.getaddrinfo(domain, None)

            for info in addr_info:
                family = info[0]
                ip = info[4][0]

                if family == socket.AF_INET and ip not in result["ipv4"]:
                    result["ipv4"].append(ip)
                elif family == socket.AF_INET6 and ip not in result["ipv6"]:
                    result["ipv6"].append(ip)

            if result["ipv4"]:
                print(f"{Colors.SUCCESS}[+] IPv4 addresses:{Colors.RESET}")
                for ip in result["ipv4"]:
                    print(f"    {Colors.INFO}- {ip}{Colors.RESET}")

            if result["ipv6"]:
                print(f"{Colors.SUCCESS}[+] IPv6 addresses:{Colors.RESET}")
                for ip in result["ipv6"]:
                    print(f"    {Colors.INFO}- {ip}{Colors.RESET}")

            if not result["ipv4"] and not result["ipv6"]:
                print(f"{Colors.ERROR}[!] No IP addresses found for {domain}{Colors.RESET}")
                return None

            return result

        except socket.gaierror:
            print(f"{Colors.ERROR}[!] Failed to resolve domain: {domain}{Colors.RESET}")
            return None
        except Exception as e:
            print(f"{Colors.ERROR}[!] Error resolving domain: {e}{Colors.RESET}")
            return None

    def select_ips_to_scan(self, resolved: Dict) -> List[str]:
        """Let user select which IPs to scan"""
        all_ips = resolved["ipv4"] + resolved["ipv6"]

        if len(all_ips) == 1:
            return all_ips

        print(f"\n{Colors.HEADER}{'='*70}")
        print(f"  SELECT IP ADDRESSES TO SCAN")
        print(f"{'='*70}{Colors.RESET}\n")

        for idx, ip in enumerate(all_ips, 1):
            ip_type = "IPv4" if ip in resolved["ipv4"] else "IPv6"
            print(f"{Colors.INFO}[{idx}]{Colors.RESET} {ip} ({ip_type})")

        print(f"{Colors.INFO}[A]{Colors.RESET} Scan ALL addresses")
        print()

        while True:
            choice = input(f"{Colors.HEADER}Select IPs to scan [1-{len(all_ips)}, A for all]: {Colors.RESET}").strip().upper()

            if choice == 'A':
                print(f"{Colors.SUCCESS}[+] Selected: All {len(all_ips)} addresses{Colors.RESET}")
                return all_ips

            # Parse comma-separated choices
            try:
                choices = [int(c.strip()) for c in choice.split(',')]
                selected = []
                for c in choices:
                    if 1 <= c <= len(all_ips):
                        selected.append(all_ips[c-1])
                    else:
                        print(f"{Colors.ERROR}[!] Invalid choice: {c}{Colors.RESET}")
                        selected = []
                        break

                if selected:
                    print(f"{Colors.SUCCESS}[+] Selected {len(selected)} address(es){Colors.RESET}")
                    return selected
            except ValueError:
                print(f"{Colors.ERROR}[!] Invalid input. Use numbers separated by commas or 'A' for all{Colors.RESET}")

    def get_ip_type(self, ip: str) -> str:
        """Determine if IP is IPv4 or IPv6"""
        if '.' in ip:
            return 'ipv4'
        elif ':' in ip:
            return 'ipv6'
        return 'unknown'

    def generate_filename(self, target: str) -> str:
        """Generate filename with target and datetime"""
        # Handle domain or IP
        safe_target = target.replace(':', '-').replace('.', '-').replace('/', '-')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"scan_{safe_target}_{timestamp}.json"

    def run_nmap_scan(self, target: str, scan_flags: List[str]) -> Optional[str]:
        """Execute nmap scan with real-time output monitoring"""
        flags_str = ' '.join(scan_flags)
        print(f"{Colors.INFO}[*] Starting nmap scan on {target} with flags: {flags_str}...{Colors.RESET}")

        # Create temporary file for XML output
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as tmp_file:
            xml_output_file = tmp_file.name

        try:
            # Build nmap command with verbose output and XML output
            cmd = ['nmap', '-v'] + scan_flags + ['-oX', xml_output_file, target]

            # Handle SOCKS proxy for nmap using proxychains
            if self.proxy_config.get("type") == "socks5":
                host = self.proxy_config.get("host", "127.0.0.1")
                port = self.proxy_config.get("port", "9050")

                print(f"\n{Colors.WARNING}[!] Nmap doesn't support SOCKS proxies directly{Colors.RESET}")
                print(f"{Colors.INFO}[i] Checking for proxychains...{Colors.RESET}")

                if not self.check_proxychains():
                    print(f"\n{Colors.ERROR}[!] ProxyChains not found!{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Install with: sudo apt install proxychains4{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Or on macOS: brew install proxychains-ng{Colors.RESET}")
                    print(f"\n{Colors.WARNING}[!] Options:{Colors.RESET}")
                    print(f"    1. Install proxychains and re-run the scan")
                    print(f"    2. Run nmap scan WITHOUT proxy (direct connection)")

                    choice = input(f"\n{Colors.HEADER}Continue without proxy? [y/N]: {Colors.RESET}").strip().lower()
                    if choice != 'y':
                        return None
                    print(f"{Colors.WARNING}[!] Proceeding with DIRECT connection (no proxy){Colors.RESET}")
                else:
                    print(f"{Colors.SUCCESS}[+] ProxyChains found{Colors.RESET}")

                    # Configure proxychains
                    if self.configure_proxychains(host, port):
                        # Determine which proxychains command to use
                        proxychains_cmd = 'proxychains4'
                        if subprocess.run(['which', 'proxychains4'],
                                        capture_output=True).returncode != 0:
                            proxychains_cmd = 'proxychains'

                        # Prepend proxychains to command
                        cmd = [proxychains_cmd, '-f',
                               os.path.expanduser("~/.proxychains/proxychains.conf"),
                               '-q'] + cmd

                        print(f"{Colors.SUCCESS}[+] Nmap will be routed through {host}:{port}{Colors.RESET}")
                    else:
                        print(f"{Colors.ERROR}[!] Failed to configure proxychains{Colors.RESET}")
                        return None

            print(f"{Colors.WARNING}[*] Live scan progress (press Ctrl+C to abort):{Colors.RESET}\n")

            # Run nmap with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Monitor output in real-time
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break

                # Color code different types of output
                line = line.strip()
                if not line:
                    continue

                if 'Discovered open port' in line:
                    print(f"{Colors.SUCCESS}  ✓ {line}{Colors.RESET}")
                elif 'Completed' in line or 'done' in line.lower():
                    print(f"{Colors.INFO}  ▸ {line}{Colors.RESET}")
                elif 'Timing:' in line:
                    print(f"{Colors.WARNING}  ⏱ {line}{Colors.RESET}")
                elif 'Increasing send delay' in line:
                    print(f"{Colors.WARNING}  ⚠ {line}{Colors.RESET}")
                elif 'Starting' in line or 'Initiating' in line:
                    print(f"{Colors.HEADER}  → {line}{Colors.RESET}")
                elif 'error' in line.lower() or 'failed' in line.lower():
                    print(f"{Colors.ERROR}  ✗ {line}{Colors.RESET}")
                else:
                    print(f"{Colors.INFO}  {line}{Colors.RESET}")

            # Wait for process to complete
            return_code = process.wait()

            if return_code != 0:
                print(f"\n{Colors.ERROR}[!] Nmap scan failed with return code: {return_code}{Colors.RESET}")
                os.unlink(xml_output_file)
                return None

            # Read XML output
            print(f"\n{Colors.SUCCESS}[+] Nmap scan completed successfully{Colors.RESET}")
            with open(xml_output_file, 'r') as f:
                xml_content = f.read()

            # Clean up temp file
            os.unlink(xml_output_file)

            return xml_content

        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.RESET}")
            try:
                process.kill()
            except:
                pass
            if os.path.exists(xml_output_file):
                os.unlink(xml_output_file)
            return None
        except FileNotFoundError:
            print(f"{Colors.ERROR}[!] Nmap not found. Please install nmap.{Colors.RESET}")
            if os.path.exists(xml_output_file):
                os.unlink(xml_output_file)
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.ERROR}[!] Error running nmap: {e}{Colors.RESET}")
            if os.path.exists(xml_output_file):
                os.unlink(xml_output_file)
            return None

    def parse_nmap_output(self, xml_output: str) -> Dict:
        """Parse nmap XML output to extract services and versions"""
        import xml.etree.ElementTree as ET

        host_data = {
            "ip": "",
            "hostname": "",
            "os": [],
            "ports": []
        }

        print(f"{Colors.INFO}[*] Parsing nmap results...{Colors.RESET}")

        try:
            root = ET.fromstring(xml_output)

            # Get host IP
            host = root.find('.//host')
            if host is not None:
                addr = host.find('.//address[@addrtype="ipv4"]')
                if addr is None:
                    addr = host.find('.//address[@addrtype="ipv6"]')
                if addr is not None:
                    host_data["ip"] = addr.get('addr', '')

                # Get hostname
                hostname = host.find('.//hostname')
                if hostname is not None:
                    host_data["hostname"] = hostname.get('name', '')

                # Get OS detection
                os_matches = host.findall('.//osmatch')
                for os_match in os_matches[:3]:
                    host_data["os"].append({
                        "name": os_match.get('name', ''),
                        "accuracy": os_match.get('accuracy', '')
                    })

                # Get port information
                ports = host.findall('.//port')
                for port in ports:
                    port_id = port.get('portid', '')
                    protocol = port.get('protocol', '')

                    state = port.find('state')
                    port_state = state.get('state', '') if state is not None else ''

                    if port_state != 'open':
                        continue

                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', '')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')

                        # Get service banner from script output
                        banner = ""
                        script = port.find('.//script[@id="banner"]')
                        if script is not None:
                            banner = script.get('output', '')

                        port_data = {
                            "port": port_id,
                            "protocol": protocol,
                            "state": port_state,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "banner": banner,
                            "cpe": []
                        }

                        # Extract CPE
                        cpes = service.findall('cpe')
                        for cpe in cpes:
                            port_data["cpe"].append(cpe.text)

                        host_data["ports"].append(port_data)

        except ET.ParseError as e:
            print(f"{Colors.ERROR}[!] Error parsing XML: {e}{Colors.RESET}")

        return host_data

    def search_cve_nvd(self, product: str, version: str) -> List[Dict]:
        """Search NVD for CVEs"""
        if not product:
            return []

        print(f"{Colors.INFO}[*] [NVD] Searching CVEs for {product} {version}...{Colors.RESET}")

        vulnerabilities = []

        try:
            api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": f"{product} {version}" if version else product,
                "resultsPerPage": 20
            }

            headers = {"User-Agent": "NmapVulnScanner/3.1"}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY

            response = self.session.get(api_url, params=params, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve = vuln.get('cve', {})
                        cve_id = cve.get('id', '')

                        descriptions = cve.get('descriptions', [])
                        description = ""
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break

                        metrics = cve.get('metrics', {})
                        cvss_score = "N/A"
                        severity = "N/A"

                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 'N/A')
                            severity = cvss_data.get('baseSeverity', 'N/A')
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 'N/A')

                        published = cve.get('published', '')

                        vulnerabilities.append({
                            "cve_id": cve_id,
                            "description": description[:200] + "..." if len(description) > 200 else description,
                            "cvss_score": cvss_score,
                            "severity": severity,
                            "published": published,
                            "source": "NVD",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        })

                    print(f"{Colors.SUCCESS}[+] [NVD] Found {len(vulnerabilities)} CVEs{Colors.RESET}")
                else:
                    print(f"{Colors.INFO}[+] [NVD] No CVEs found{Colors.RESET}")
            elif response.status_code == 403:
                print(f"{Colors.WARNING}[!] [NVD] API rate limit exceeded{Colors.RESET}")
            else:
                print(f"{Colors.WARNING}[!] [NVD] API returned status code: {response.status_code}{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.ERROR}[!] [NVD] Error querying: {e}{Colors.RESET}")

        return vulnerabilities

    def search_vulners(self, product: str, version: str) -> List[Dict]:
        """Search Vulners.com for vulnerabilities"""
        if not product or not VULNERS_API_KEY:
            return []

        print(f"{Colors.INFO}[*] [Vulners] Searching for {product} {version}...{Colors.RESET}")

        vulnerabilities = []

        try:
            api_url = "https://vulners.com/api/v3/burp/software/"

            params = {
                "software": product,
                "version": version if version else "",
                "type": "software",
                "apiKey": VULNERS_API_KEY
            }

            response = self.session.get(api_url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data.get('result') == 'OK':
                    vulns = data.get('data', {}).get('search', [])

                    for vuln in vulns[:20]:
                        vulnerabilities.append({
                            "cve_id": vuln.get('id', 'N/A'),
                            "description": vuln.get('description', '')[:200],
                            "cvss_score": vuln.get('cvss', {}).get('score', 'N/A'),
                            "severity": self.cvss_to_severity(vuln.get('cvss', {}).get('score', 0)),
                            "published": vuln.get('published', ''),
                            "source": "Vulners",
                            "url": f"https://vulners.com/search?query={vuln.get('id', '')}"
                        })

                    print(f"{Colors.SUCCESS}[+] [Vulners] Found {len(vulnerabilities)} vulnerabilities{Colors.RESET}")
                else:
                    print(f"{Colors.INFO}[+] [Vulners] No vulnerabilities found{Colors.RESET}")
            else:
                print(f"{Colors.WARNING}[!] [Vulners] API returned status code: {response.status_code}{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.ERROR}[!] [Vulners] Error querying: {e}{Colors.RESET}")

        return vulnerabilities

    def search_snyk(self, product: str, version: str) -> List[Dict]:
        """Search Snyk for vulnerabilities"""
        if not product or not SNYK_API_KEY:
            return []

        print(f"{Colors.INFO}[*] [Snyk] Searching for {product} {version}...{Colors.RESET}")

        vulnerabilities = []

        try:
            # Snyk uses package ecosystem-specific endpoints
            # This is a simplified version - you may need to adjust based on package type
            api_url = "https://api.snyk.io/v1/test/npm"

            headers = {
                "Authorization": f"token {SNYK_API_KEY}",
                "Content-Type": "application/json"
            }

            # Note: Snyk API requires package name in ecosystem format (npm, maven, etc.)
            # This is a basic implementation
            payload = {
                "package": product,
                "version": version if version else "latest"
            }

            response = self.session.post(api_url, json=payload, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()

                issues = data.get('issues', {}).get('vulnerabilities', [])

                for issue in issues[:20]:
                    vulnerabilities.append({
                        "cve_id": issue.get('identifiers', {}).get('CVE', ['N/A'])[0],
                        "description": issue.get('title', '')[:200],
                        "cvss_score": issue.get('cvssScore', 'N/A'),
                        "severity": issue.get('severity', 'N/A').upper(),
                        "published": issue.get('publicationTime', ''),
                        "source": "Snyk",
                        "url": issue.get('url', '')
                    })

                print(f"{Colors.SUCCESS}[+] [Snyk] Found {len(vulnerabilities)} vulnerabilities{Colors.RESET}")
            else:
                print(f"{Colors.INFO}[+] [Snyk] No vulnerabilities found or API error{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.ERROR}[!] [Snyk] Error querying: {e}{Colors.RESET}")

        return vulnerabilities

    def cvss_to_severity(self, score) -> str:
        """Convert CVSS score to severity rating"""
        try:
            score = float(score)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0:
                return "LOW"
        except:
            pass
        return "N/A"

    def get_severity_color(self, severity: str) -> str:
        """Get color based on vulnerability severity"""
        severity_upper = str(severity).upper()
        if severity_upper in ['CRITICAL', 'HIGH']:
            return Colors.VULN_HIGH
        elif severity_upper == 'MEDIUM':
            return Colors.VULN_MEDIUM
        elif severity_upper == 'LOW':
            return Colors.VULN_LOW
        return Colors.INFO

    def scan_and_analyze(self, target: str, ips_to_scan: List[str], scan_flags: List[str], is_domain: bool = False):
        """Main scan and analysis workflow"""

        # Store domain name if applicable
        if is_domain:
            self.results["domain"] = target
            print(f"\n{Colors.HEADER}{'='*70}")
            print(f"  SCANNING DOMAIN: {target}")
            print(f"{'='*70}{Colors.RESET}\n")

        # Scan each IP
        for idx, ip in enumerate(ips_to_scan, 1):
            print(f"\n{Colors.HEADER}{'='*70}")
            print(f"  SCANNING IP {idx}/{len(ips_to_scan)}: {ip}")
            print(f"{'='*70}{Colors.RESET}\n")

            ip_type = self.get_ip_type(ip)
            print(f"{Colors.SUCCESS}[+] Target type: {ip_type.upper()}{Colors.RESET}")

            # Run nmap scan
            xml_output = self.run_nmap_scan(ip, scan_flags)
            if not xml_output:
                print(f"{Colors.WARNING}[!] Skipping {ip} due to scan failure{Colors.RESET}")
                continue

            # Parse nmap output
            host_data = self.parse_nmap_output(xml_output)

            if not host_data["ip"]:
                print(f"{Colors.ERROR}[!] No host data found for {ip}{Colors.RESET}")
                continue

            print(f"\n{Colors.HEADER}[+] Host: {host_data['ip']}{Colors.RESET}")
            if host_data["hostname"]:
                print(f"{Colors.SUCCESS}[+] Hostname: {host_data['hostname']}{Colors.RESET}")

            if host_data["os"]:
                print(f"{Colors.INFO}[+] OS Detection:{Colors.RESET}")
                for os in host_data["os"]:
                    print(f"    {Colors.SUCCESS}- {os['name']} (Accuracy: {os['accuracy']}%){Colors.RESET}")

            # Check vulnerabilities for each service
            for port_info in host_data["ports"]:
                print(f"\n{Colors.HEADER}[+] Port {port_info['port']}/{port_info['protocol']} - {port_info['service']}{Colors.RESET}")

                if port_info["product"]:
                    print(f"    {Colors.INFO}Product: {port_info['product']} {port_info['version']}{Colors.RESET}")

                    # Search multiple vulnerability databases
                    all_cves = []

                    # NVD (always try)
                    nvd_cves = self.search_cve_nvd(port_info["product"], port_info["version"])
                    all_cves.extend(nvd_cves)

                    # Vulners (if API key configured)
                    if VULNERS_API_KEY:
                        vulners_cves = self.search_vulners(port_info["product"], port_info["version"])
                        all_cves.extend(vulners_cves)

                    # Snyk (if API key configured)
                    if SNYK_API_KEY:
                        snyk_cves = self.search_snyk(port_info["product"], port_info["version"])
                        all_cves.extend(snyk_cves)

                    # Remove duplicates based on CVE ID
                    seen_cves = set()
                    unique_cves = []
                    for cve in all_cves:
                        cve_id = cve.get('cve_id', '')
                        if cve_id and cve_id not in seen_cves:
                            seen_cves.add(cve_id)
                            unique_cves.append(cve)

                    # Sort by severity
                    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'N/A': 4}
                    unique_cves.sort(key=lambda x: severity_order.get(x.get('severity', 'N/A'), 4))

                    if unique_cves:
                        print(f"    {Colors.CRITICAL}[!] Found {len(unique_cves)} potential vulnerabilities from {len(set(c.get('source') for c in unique_cves))} sources{Colors.RESET}")

                        for vuln in unique_cves[:5]:
                            severity = vuln.get('severity', 'N/A')
                            color = self.get_severity_color(severity)
                            cve_id = vuln.get('cve_id', 'N/A')
                            cvss = vuln.get('cvss_score', 'N/A')
                            source = vuln.get('source', 'Unknown')
                            print(f"        {color}• {cve_id} - Severity: {severity} (CVSS: {cvss}) [{source}]{Colors.RESET}")

                        if len(unique_cves) > 5:
                            print(f"        {Colors.WARNING}... and {len(unique_cves) - 5} more (see JSON output){Colors.RESET}")

                        port_info["vulnerabilities"] = unique_cves
                    else:
                        print(f"    {Colors.SUCCESS}[+] No vulnerabilities found{Colors.RESET}")
                        port_info["vulnerabilities"] = []
                else:
                    print(f"    {Colors.WARNING}No product version detected{Colors.RESET}")
                    port_info["vulnerabilities"] = []

            # Add host to results
            self.results["hosts"].append(host_data)

        # Add scan info
        vuln_sources = []
        if NVD_API_KEY or True:  # NVD works without key (rate limited)
            vuln_sources.append("NVD")
        if VULNERS_API_KEY:
            vuln_sources.append("Vulners")
        if SNYK_API_KEY:
            vuln_sources.append("Snyk")

        self.results["scan_info"] = {
            "target": target,
            "is_domain": is_domain,
            "scanned_ips": ips_to_scan,
            "timestamp": datetime.now().isoformat(),
            "scanner": f"nmap {' '.join(scan_flags)}",
            "proxy_type": self.proxy_config.get("name", "Direct"),
            "vulnerability_sources": vuln_sources
        }

        # Export
        output_file = self.generate_filename(target)
        self.export_json(output_file)

    def export_json(self, filename: str):
        """Export results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n{Colors.SUCCESS}[+] Results exported to {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}[!] Error exporting to JSON: {e}{Colors.RESET}")

def display_scan_profiles():
    """Display available scan profiles"""
    print(f"\n{Colors.HEADER}{'='*70}")
    print(f"  NMAP SCAN PROFILES")
    print(f"{'='*70}{Colors.RESET}\n")

    for key, profile in SCAN_PROFILES.items():
        flags_str = ' '.join(profile['flags']) if profile['flags'] else 'Custom flags'
        print(f"{Colors.INFO}[{key}]{Colors.RESET} {Colors.SUCCESS}{profile['name']}{Colors.RESET}")
        print(f"    {Colors.WARNING}Flags:{Colors.RESET} {flags_str}")
        print(f"    {Colors.INFO}Description:{Colors.RESET} {profile['description']}")
        print()

def get_scan_choice():
    """Get user's scan profile choice"""
    while True:
        choice = input(f"{Colors.HEADER}Select scan profile [1-9]: {Colors.RESET}").strip()

        if choice in SCAN_PROFILES:
            profile = SCAN_PROFILES[choice]

            if choice == "9":
                print(f"{Colors.INFO}[*] Enter custom nmap flags (e.g., -sS -p 80,443 -T4){Colors.RESET}")
                custom_flags = input(f"{Colors.HEADER}Flags: {Colors.RESET}").strip()
                if custom_flags:
                    return custom_flags.split()
                else:
                    print(f"{Colors.ERROR}[!] No flags provided, try again{Colors.RESET}")
                    continue

            # Check if root required
            if '-sS' in profile['flags'] or '-sU' in profile['flags']:
                if os.geteuid() != 0:
                    print(f"{Colors.WARNING}[!] Warning: This scan requires root privileges{Colors.RESET}")
                    proceed = input(f"{Colors.HEADER}Continue anyway? [y/N]: {Colors.RESET}").strip().lower()
                    if proceed != 'y':
                        continue

            print(f"{Colors.SUCCESS}[+] Selected: {profile['name']}{Colors.RESET}")
            return profile['flags']
        else:
            print(f"{Colors.ERROR}[!] Invalid choice. Please select 1-9{Colors.RESET}")

def display_proxy_options():
    """Display proxy configuration options"""
    print(f"\n{Colors.HEADER}{'='*70}")
    print(f"  NETWORK CONNECTION TYPE")
    print(f"{'='*70}{Colors.RESET}\n")

    for key, proxy in PROXY_TYPES.items():
        print(f"{Colors.INFO}[{key}]{Colors.RESET} {Colors.SUCCESS}{proxy['name']}{Colors.RESET}")
        print(f"    {Colors.INFO}{proxy['description']}{Colors.RESET}")
        print()

def get_proxy_choice():
    """Get user's proxy choice"""
    while True:
        choice = input(f"{Colors.HEADER}Select connection type [1-4]: {Colors.RESET}").strip()

        if choice in PROXY_TYPES:
            proxy = PROXY_TYPES[choice]

            if choice == "2":  # HTTP Proxy
                host = input(f"{Colors.HEADER}Proxy host: {Colors.RESET}").strip()
                port = input(f"{Colors.HEADER}Proxy port: {Colors.RESET}").strip()
                if host and port:
                    return {"type": "http", "host": host, "port": port, "name": "HTTP Proxy"}
                else:
                    print(f"{Colors.ERROR}[!] Invalid proxy configuration{Colors.RESET}")
                    continue

            elif choice == "3":  # SOCKS5
                # Check if SOCKS support is available
                if not SOCKS_AVAILABLE:
                    print(f"\n{Colors.ERROR}[!] SOCKS support not available{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Install with: pip install requests[socks]{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Or: pip install PySocks{Colors.RESET}")
                    continue

                host = input(f"{Colors.HEADER}SOCKS5 host: {Colors.RESET}").strip()
                port = input(f"{Colors.HEADER}SOCKS5 port: {Colors.RESET}").strip()
                if host and port:
                    return {"type": "socks5", "host": host, "port": port, "name": "SOCKS5 Proxy"}
                else:
                    print(f"{Colors.ERROR}[!] Invalid proxy configuration{Colors.RESET}")
                    continue

            elif choice == "4":  # Tor
                # Check if SOCKS support is available
                if not SOCKS_AVAILABLE:
                    print(f"\n{Colors.ERROR}[!] SOCKS support not available{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Install with: pip install requests[socks]{Colors.RESET}")
                    print(f"{Colors.INFO}[i] Or: pip install PySocks{Colors.RESET}")
                    continue

                print(f"\n{Colors.INFO}[i] Tor will be tested automatically after selection{Colors.RESET}")
                return {"type": "socks5", "host": "127.0.0.1", "port": "9050", "name": "Tor"}

            else:  # Direct
                return {"type": "direct", "name": "Direct Connection"}
        else:
            print(f"{Colors.ERROR}[!] Invalid choice. Please select 1-4{Colors.RESET}")

def display_api_status():
    """Display configured API status"""
    print(f"\n{Colors.HEADER}{'='*70}")
    print(f"  VULNERABILITY DATABASE API STATUS")
    print(f"{'='*70}{Colors.RESET}\n")

    # NVD
    if NVD_API_KEY:
        print(f"{Colors.SUCCESS}[✓] NVD (National Vulnerability Database){Colors.RESET}")
        print(f"    Status: API key configured")
        print(f"    URL: https://nvd.nist.gov/")
    else:
        print(f"{Colors.WARNING}[~] NVD (National Vulnerability Database){Colors.RESET}")
        print(f"    Status: No API key (rate limited to 5 requests per 30 seconds)")
        print(f"    Get key: https://nvd.nist.gov/developers/request-an-api-key")

    print()

    # Vulners
    if VULNERS_API_KEY:
        print(f"{Colors.SUCCESS}[✓] Vulners.com{Colors.RESET}")
        print(f"    Status: API key configured")
        print(f"    URL: https://vulners.com/")
    else:
        print(f"{Colors.WARNING}[✗] Vulners.com{Colors.RESET}")
        print(f"    Status: Not configured (skipped)")
        print(f"    Get key: https://vulners.com/userinfo (Free tier: 50 requests/day)")

    print()

    # Snyk
    if SNYK_API_KEY:
        print(f"{Colors.SUCCESS}[✓] Snyk{Colors.RESET}")
        print(f"    Status: API key configured")
        print(f"    URL: https://snyk.io/")
    else:
        print(f"{Colors.WARNING}[✗] Snyk{Colors.RESET}")
        print(f"    Status: Not configured (skipped)")
        print(f"    Get key: https://snyk.io/account (Settings -> API Token)")

    #print(f"\n{Colors.INFO}[i] Additional free vulnerability databases:{Colors.RESET}")
    #print(f"    • CVE Details: https://www.cvedetails.com/")
    #print(f"    • Exploit-DB: https://www.exploit-db.com/")
    #print(f"    • VulnDB: https://vuldb.com/ (API available)")
    #print(f"    • CIRCL CVE Search: https://cve.circl.lu/")
    #print(f"    • GitHub Advisory: https://github.com/advisories")
    print()

def main():
    print(f"""
    {Colors.HEADER}╔════════════════════════════════════════════════════════════╗
    ║   Sir Jimbet - Advanced nmap Vulnerability Scanner v3.5    ║
    ║   Scan, Detect, Identify CVEs for vulnerabilities          ║
    ║              https://github.com/jimbet                     ║
    ╚════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

    # Display API status
    display_api_status()

    # Get target
    target = input(f"{Colors.HEADER}Enter target (IP address, IPv6, domain, or subdomain): {Colors.RESET}").strip()
    if not target:
        print(f"{Colors.ERROR}[!] No target specified{Colors.RESET}")
        sys.exit(1)

    # Determine if it's a domain or IP
    scanner_temp = NmapVulnScanner()
    is_domain = False
    ips_to_scan = []

    if scanner_temp.validate_ip(target):
        # It's an IP address
        print(f"{Colors.SUCCESS}[+] Target identified as IP address{Colors.RESET}")
        ips_to_scan = [target]
    elif scanner_temp.validate_domain(target):
        # It's a domain/subdomain
        print(f"{Colors.SUCCESS}[+] Target identified as domain/subdomain{Colors.RESET}")
        is_domain = True

        # Resolve domain
        resolved = scanner_temp.resolve_domain(target)
        if not resolved:
            print(f"{Colors.ERROR}[!] Failed to resolve domain{Colors.RESET}")
            sys.exit(1)

        # Let user select IPs to scan
        ips_to_scan = scanner_temp.select_ips_to_scan(resolved)
    else:
        print(f"{Colors.ERROR}[!] Invalid target. Please enter a valid IP address or domain{Colors.RESET}")
        sys.exit(1)

    # Select proxy/connection type
    display_proxy_options()
    proxy_config = get_proxy_choice()

    # Note: Tor will be tested automatically when NmapVulnScanner is initialized
    # No need for duplicate testing here

    # Select scan profile
    display_scan_profiles()
    scan_flags = get_scan_choice()

    # Confirm
    print(f"\n{Colors.WARNING}[*] Ready to scan {target}{Colors.RESET}")
    if is_domain:
        print(f"{Colors.INFO}[*] Will scan {len(ips_to_scan)} IP address(es){Colors.RESET}")
        for ip in ips_to_scan:
            print(f"    {Colors.INFO}- {ip}{Colors.RESET}")
    print(f"{Colors.INFO}[*] Connection: {proxy_config.get('name')}{Colors.RESET}")
    print(f"{Colors.INFO}[*] Scan flags: {' '.join(scan_flags)}{Colors.RESET}")

    # Show which vulnerability databases will be queried
    vuln_sources = ["NVD"]
    if VULNERS_API_KEY:
        vuln_sources.append("Vulners")
    if SNYK_API_KEY:
        vuln_sources.append("Snyk")
    print(f"{Colors.INFO}[*] Vulnerability sources: {', '.join(vuln_sources)}{Colors.RESET}")

    confirm = input(f"{Colors.HEADER}Start scan? [Y/n]: {Colors.RESET}").strip().lower()

    if confirm and confirm != 'y':
        print(f"{Colors.ERROR}[!] Scan cancelled{Colors.RESET}")
        sys.exit(0)

    scanner = NmapVulnScanner(proxy_config)
    scanner.scan_and_analyze(target, ips_to_scan, scan_flags, is_domain)

if __name__ == "__main__":
    main()
