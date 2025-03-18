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
import requests
from jinja2 import Environment, FileSystemLoader
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from tqdm import tqdm
import xml.etree.ElementTree as ET
import json
import ipaddress
import sqlite3

from scanners.nmap_scanner import NmapScanner
from reporting.enhanced_html import EnhancedHTMLReport
from integrations.cve_data import CVEDataProvider

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

class InteractiveSystemTester:
    def __init__(self):
        self.targets = []
        self.discovered_targets = {}  # Store LAN scan results: {IP: {mac, os, version, ports}}
        self.port_range = "1-1024"
        self.profile = "all"
        self.verbose = False
        self.stealth_mode = False
        self.use_tor = False
        self.network_interface = None  # New variable for selected network interface
        self.proxy_pool = []  # List of proxies (e.g., Tor exit nodes)
        self.results = {}
        self.nmap_results = {}  # Store Nmap results (ports, services, vulnerabilities)
        self.cve_details = {}  # Store enriched CVE data from NVD
        self.lock = threading.Lock()
        self.task_queue = Queue()
        self.setup_templates()
        self.setup_prompt()
        self.setup_database()
        self.last_report_files = {}
        self.max_retries = 3
        self.automation_interval = 0  # Default: automation disabled (0 seconds)
        self.automation_thread = None

    def setup_templates(self):
        """Create templates directory and basic HTML template if not exists"""
        os.makedirs("templates", exist_ok=True)
        if not os.path.exists("templates/report.html"):
            with open("templates/report.html", "w") as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Interactive System Test Report - {{ timestamp }}</title>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        h1 { color: #333; }
                        h2, h3 { color: #555; }
                        pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; }
                        .severity-high { color: red; font-weight: bold; }
                        .severity-medium { color: orange; }
                        .severity-low { color: green; }
                        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                    </style>
                    <script>
                        function filterTable() {
                            var input = document.getElementById("ipFilter").value.toLowerCase();
                            var tables = document.getElementsByTagName("table");
                            for (var i = 0; i < tables.length; i++) {
                                var tr = tables[i].getElementsByTagName("tr");
                                for (var j = 1; j < tr.length; j++) {
                                    var td = tr[j].getElementsByTagName("td")[0];
                                    if (td) {
                                        var txtValue = td.textContent || td.innerText;
                                        if (txtValue.toLowerCase().indexOf(input) > -1) {
                                            tr[j].style.display = "";
                                        } else {
                                            tr[j].style.display = "none";
                                        }
                                    }
                                }
                            }
                        }
                    </script>
                </head>
                <body>
                    <h1>Interactive System Test Report - {{ timestamp }}</h1>
                    <input type="text" id="ipFilter" onkeyup="filterTable()" placeholder="Filter by IP...">
                    {% if targets %}
                        <h2>Discovered Targets</h2>
                        <table>
                            <tr><th>IP Address</th><th>MAC Address</th><th>Platform</th><th>Version</th><th>Open Ports</th><th>Scan Timestamp</th></tr>
                            {% for target in targets %}
                                <tr>
                                    <td>{{ target[1] }}</td>
                                    <td>{{ target[2] or 'N/A' }}</td>
                                    <td>{{ target[3] or 'Unknown' }}</td>
                                    <td>{{ target[4] or 'N/A' }}</td>
                                    <td>{{ ', '.join([f"{p['port']}/{p['service']}" for p in target[6]]) }}</td>
                                    <td>{{ target[5] }}</td>
                                </tr>
                            {% endfor %}
                        </table>
                    {% endif %}
                    {% if test_results %}
                        <h2>Test Results</h2>
                        <table>
                            <tr><th>IP Address</th><th>Test Name</th><th>Result</th><th>Timestamp</th></tr>
                            {% for result in test_results %}
                                <tr>
                                    <td>{{ result[0] }}</td>
                                    <td>{{ result[1] }}</td>
                                    <td>{{ result[2][:50] + '...' if result[2]|length > 50 else result[2] }}</td>
                                    <td>{{ result[3] }}</td>
                                </tr>
                            {% endfor %}
                        </table>
                    {% endif %}
                    {% if vulnerabilities %}
                        <h2>Vulnerabilities</h2>
                        <table>
                            <tr><th>IP Address</th><th>Port</th><th>Script</th><th>Output</th><th>CVE</th><th>Score</th><th>Description</th><th>Timestamp</th></tr>
                            {% for vuln in vulnerabilities %}
                                <tr>
                                    <td>{{ vuln[0] }}</td>
                                    <td>{{ vuln[1] }}</td>
                                    <td>{{ vuln[2] }}</td>
                                    <td>{{ vuln[3][:30] + '...' if vuln[3]|length > 30 else vuln[3] }}</td>
                                    <td>{{ vuln[4] or 'N/A' }}</td>
                                    <td class="{% if vuln[5] >= 7 %}severity-high{% elif vuln[5] >= 4 %}severity-medium{% else %}severity-low{% endif %}">{{ vuln[5] }}</td>
                                    <td>{{ vuln[6][:30] + '...' if vuln[6]|length > 30 else vuln[6] }}</td>
                                    <td>{{ vuln[7] }}</td>
                                </tr>
                            {% endfor %}
                        </table>
                    {% endif %}
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
        self.bindings.add('c-c')(lambda event: sys.exit(0))
        self.completer = WordCompleter([
            'all', 'network', 'vulnerability', 'exploitation', 'anonymity', 'auditing', 'wireless',
            'yes', 'no', 'verbose', 'quiet', '127.0.0.1', 'lan',
            'configure', 'targets', 'run', 'export', 'exit', 'query_db', 'enhanced_report', 'configure_automation',
            'text', 'html', 'enhanced_html', 'csv'
        ], ignore_case=True)
        self.session = PromptSession(
            style=self.style,
            completer=self.completer,
            key_bindings=self.bindings,
            multiline=False,
            prompt_message=HTML('<prompt>SystemTester> </prompt>')
        )

    def setup_database(self):
        """Initialize SQLite database and create tables"""
        self.db_file = "system_tester.db"
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT,
                os TEXT,
                version TEXT,
                scan_timestamp TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                port INTEGER,
                service TEXT,
                version TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                test_name TEXT,
                result TEXT,
                timestamp TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                port INTEGER,
                script TEXT,
                output TEXT,
                cve TEXT,
                score REAL,
                description TEXT,
                timestamp TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        self.conn.commit()
        logging.info("SQLite database initialized")

    def store_target(self, ip, mac, os, version, ports):
        """Store discovered target in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO targets (ip, mac, os, version, scan_timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, mac, os, version, timestamp))
        target_id = self.cursor.lastrowid

        for port_info in ports:
            self.cursor.execute('''
                INSERT INTO ports (target_id, port, service, version)
                VALUES (?, ?, ?, ?)
            ''', (target_id, port_info['port'], port_info['service'], port_info['version']))

        self.conn.commit()
        return target_id

    def store_test_result(self, target_id, test_name, result):
        """Store test result in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO test_results (target_id, test_name, result, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (target_id, test_name, result, timestamp))
        self.conn.commit()

    def store_vulnerability(self, target_id, port, script, output, cve, score, description):
        """Store vulnerability in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO vulnerabilities (target_id, port, script, output, cve, score, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (target_id, port, script, output, cve, score, description, timestamp))
        self.conn.commit()

    def simulate_scan_data(self, num_targets=3):
        """Simulate scan data for automation"""
        for _ in range(num_targets):
            ip = f"192.168.1.{random.randint(1, 254)}"
            mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)]) if random.choice([True, False]) else None
            os = random.choice(["Linux", "Windows", "Unknown"])
            version = f"{random.randint(1, 10)}.{random.randint(0, 99)}" if os != "Unknown" else None
            ports = [
                {"port": random.randint(1, 65535), "service": random.choice(["ssh", "http", "https", "smb"]), "version": f"{random.randint(1, 10)}"}
                for _ in range(random.randint(1, 5))
            ]
            self.discovered_targets[ip] = {
                'mac': mac,
                'os': os,
                'version': version,
                'ports': ports
            }
            target_id = self.store_target(ip, mac, os, version, ports)

            # Simulate test results
            test_names = ["Nmap Scan", "Nikto Scan", "Metasploit Scan"]
            for test_name in test_names:
                result = f"[SUCCESS] {test_name}\nCompleted {test_name} on {ip} at {datetime.now().isoformat()}\n"
                self.store_test_result(target_id, test_name, result)

            # Simulate vulnerabilities
            if random.choice([True, False]):
                vuln_port = random.choice(ports)["port"]
                vuln_script = "vuln-check"
                vuln_output = f"Vulnerability detected on port {vuln_port}"
                cve = f"CVE-{random.randint(2010, 2025)}-{random.randint(1000, 9999)}" if random.choice([True, False]) else None
                score = random.uniform(0, 10)
                description = f"Description for {cve or 'unknown vulnerability'}" if cve else None
                self.store_vulnerability(target_id, vuln_port, vuln_script, vuln_output, cve, score, description)

        logging.info(f"Simulated data for {num_targets} targets")
        print(f"\033[92m[+] Simulated data for {num_targets} targets\033[0m")

    def automate_data_collection(self):
        """Automate periodic data collection"""
        while self.automation_interval > 0:
            print(f"\033[94m[*] Starting automated data collection at {datetime.now().isoformat()}...\033[0m")
            self.simulate_scan_data(random.randint(1, 5))  # Simulate 1-5 targets
            self.save_report(formats=['html'])  # Generate HTML report after each automation cycle
            time.sleep(self.automation_interval)

    def configure_automation(self):
        """Configure automation interval and start background thread"""
        print("\n\033[94m=== Configure Automation ===\033[0m")
        interval_input = self.session.prompt(
            HTML('<prompt>Enter automation interval in seconds (default: 3600, 0 to disable): </prompt>')
        )
        try:
            self.automation_interval = int(interval_input) if interval_input else 3600
            if self.automation_interval == 0:
                print("\033[93m[-] Automation disabled.\033[0m")
                return
            print(f"\033[92m[+] Automation configured with interval {self.automation_interval} seconds\033[0m")
            if self.automation_thread is None or not self.automation_thread.is_alive():
                self.automation_thread = threading.Thread(target=self.automate_data_collection, daemon=True)
                self.automation_thread.start()
        except ValueError:
            print("\033[91m[!] Invalid interval. Using default 3600 seconds.\033[0m")
            self.automation_interval = 3600
            if self.automation_thread is None or not self.automation_thread.is_alive():
                self.automation_thread = threading.Thread(target=self.automate_data_collection, daemon=True)
                self.automation_thread.start()

    def query_db(self):
        """Interactively query the database with enhanced filtering"""
        print("\n\033[94m=== Database Query ===\033[0m")
        query_type = self.session.prompt(
            HTML('<prompt>Choose query type (targets/results/vulnerabilities): </prompt>'),
            completer=WordCompleter(['targets', 'results', 'vulnerabilities'], ignore_case=True)
        ).lower()

        if query_type == "targets":
            filter_ip = self.session.prompt(HTML('<prompt>Enter IP to filter (or press Enter for all): </prompt>'))
            if filter_ip:
                self.cursor.execute('SELECT * FROM targets WHERE ip = ?', (filter_ip,))
            else:
                self.cursor.execute("SELECT * FROM targets")
            rows = self.cursor.fetchall()
            print("\nIP Address\tMAC Address\tPlatform\tVersion\t\tScan Timestamp")
            print("-" * 80)
            for row in rows:
                print(f"{row[1]}\t\t{row[2] or 'N/A'}\t\t{row[3] or 'Unknown'}\t\t{row[4] or 'N/A'}\t\t{row[5]}")
            print("-" * 80)

        elif query_type == "results":
            ip = self.session.prompt(HTML('<prompt>Enter IP to filter results (or press Enter for all): </prompt>'))
            if ip:
                self.cursor.execute('''
                    SELECT t.ip, tr.test_name, tr.result, tr.timestamp
                    FROM test_results tr
                    JOIN targets t ON tr.target_id = t.id
                    WHERE t.ip = ?
                ''', (ip,))
            else:
                self.cursor.execute('''
                    SELECT t.ip, tr.test_name, tr.result, tr.timestamp
                    FROM test_results tr
                    JOIN targets t ON tr.target_id = t.id
                ''')
            rows = self.cursor.fetchall()
            print("\nIP Address\tTest Name\tResult\tTimestamp")
            print("-" * 80)
            for row in rows:
                print(f"{row[0]}\t\t{row[1]}\t\t{row[2][:50] + '...' if len(row[2]) > 50 else row[2]}\t{row[3]}")
            print("-" * 80)

        elif query_type == "vulnerabilities":
            ip = self.session.prompt(HTML('<prompt>Enter IP to filter vulnerabilities (or press Enter for all): </prompt>'))
            min_score = self.session.prompt(HTML('<prompt>Enter minimum CVSS score to filter (or press Enter for all): </prompt>')) or 0
            try:
                min_score = float(min_score)
                if ip:
                    self.cursor.execute('''
                        SELECT t.ip, v.port, v.script, v.output, v.cve, v.score, v.description, v.timestamp
                        FROM vulnerabilities v
                        JOIN targets t ON v.target_id = t.id
                        WHERE t.ip = ? AND v.score >= ?
                    ''', (ip, min_score))
                else:
                    self.cursor.execute('''
                        SELECT t.ip, v.port, v.script, v.output, v.cve, v.score, v.description, v.timestamp
                        FROM vulnerabilities v
                        JOIN targets t ON v.target_id = t.id
                        WHERE v.score >= ?
                    ''', (min_score,))
                rows = self.cursor.fetchall()
                print("\nIP Address\tPort\tScript\tOutput\tCVE\tScore\tDescription\tTimestamp")
                print("-" * 100)
                for row in rows:
                    print(f"{row[0]}\t\t{row[1]}\t{row[2]}\t{row[3][:30] + '...' if len(row[3]) > 30 else row[3]}\t{row[4] or 'N/A'}\t{row[5]}\t{row[6][:30] + '...' if len(row[6]) > 30 else row[6]}\t{row[7]}")
                print("-" * 100)
            except ValueError:
                print("\033[91m[!] Invalid score value. Please enter a number.\033[0m")

    def check_tool(self, tool):
        """Check if a tool is installed"""
        cmd = f"which {tool}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env={"PATH": "/data/data/com.termux/files/usr/bin:/system/bin"})
        if result.returncode != 0:
            logging.error(f"{tool} not found")
            if self.verbose:
                print(f"\033[91m[!] Error: {tool} is not installed. Install with 'pkg install {tool}'.\033[0m")
            return False
        return True

    def setup_anonymity(self):
        """Setup anonymity using Tor, AnonSurf, or external proxies"""
        if not self.use_tor:
            return

        if self.check_tool("anonsurf"):
            print("\033[94m[*] Setting up AnonSurf for anonymity...\033[0m")
            subprocess.run("anonsurf start", shell=True, capture_output=True, text=True)
            time.sleep(5)
            result = subprocess.run("anonsurf myip", shell=True, capture_output=True, text=True)
            if self.verbose:
                print(f"\033[92m[+] AnonSurf IP: {result.stdout}\033[0m")
        elif self.check_tool("torsocks"):
            print("\033[94m[*] Using torsocks for anonymity...\033[0m")
            self.proxy_pool = self.fetch_tor_exit_nodes()
        else:
            print("\033[93m[-] Neither AnonSurf nor torsocks found. Anonymity features disabled.\033[0m")
            self.use_tor = False

    def fetch_tor_exit_nodes(self):
        """Fetch a list of Tor exit nodes as proxies"""
        try:
            response = requests.get("https://onionoo.torproject.org/details?type=relay&running=true", timeout=10)
            data = response.json()
            proxies = [f"socks5://{relay['a'][0]}:{relay['or_addresses'][0].split(':')[1]}" for relay in data['relays'] if 'exit' in relay['flags']]
            return proxies[:5]
        except Exception as e:
            logging.error(f"Failed to fetch Tor exit nodes: {str(e)}")
            return []

    def spoof_mac(self):
        """Spoof MAC address for stealth using the selected network interface"""
        if not self.stealth_mode:
            return

        if not self.network_interface:
            print("\033[93m[-] No network interface selected. Please configure one using 'configure'.\033[0m")
            return

        try:
            mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
            subprocess.run(f"ifconfig {self.network_interface} down", shell=True, check=True)
            subprocess.run(f"macchanger -m {mac} {self.network_interface}", shell=True, check=True)
            subprocess.run(f"ifconfig {self.network_interface} up", shell=True, check=True)
            print(f"\033[92m[+] MAC address spoofed to {mac} on {self.network_interface}\033[0m")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to spoof MAC address: {str(e)}")
            print(f"\033[91m[!] Failed to spoof MAC address on {self.network_interface}: {str(e)}\033[0m")

    def run_command(self, cmd, description, target=None, output_file=None, retries=0):
        """Run a shell command with retry logic and stealth enhancements"""
        target = target or self.targets[0]
        logging.info(f"Running {description} on {target}")
        if self.verbose:
            print(f"\033[92m[*] {description} on {target}...\033[0m")

        proxy = random.choice(self.proxy_pool) if self.proxy_pool and self.use_tor else None
        if proxy:
            cmd = f"proxychains -q {cmd}"

        if "nikto" in cmd or "sqlmap" in cmd:
            user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.{random.randint(0, 99)} (KHTML, like Gecko) Chrome/{random.randint(70, 90)}.0.{random.randint(0, 9999)}.0 Safari/{random.randint(500, 600)}.{random.randint(0, 99)}"
            if "nikto" in cmd:
                cmd += f" -useragent \"{user_agent}\""
            if "sqlmap" in cmd:
                cmd += f" --user-agent=\"{user_agent}\""

        for attempt in range(retries + 1):
            try:
                if output_file:
                    cmd += f" -oX {output_file}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600 + (attempt * 300), check=False)
                if result.returncode != 0:
                    error_msg = f"Error: {result.stderr}"
                    logging.error(f"{description} failed (attempt {attempt + 1}): {error_msg}")
                    with self.lock:
                        self.results[target][description] = f"[ERROR] {description} (Attempt {attempt + 1})\n{error_msg}\n"
                    if self.verbose:
                        print(f"\033[91m[!] Failed: {description} (Attempt {attempt + 1})\033[0m")
                    if attempt < retries:
                        time.sleep(random.uniform(2, 5))
                        continue
                    return False
                output = result.stdout
                with self.lock:
                    self.results[target][description] = f"[SUCCESS] {description}\n{output}\n"
                if self.verbose:
                    print(f"\033[92m[+] Completed: {description}\033[0m")

                # Store the result in the database
                self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
                target_id = self.cursor.fetchone()
                if target_id:
                    self.store_test_result(target_id[0], description, f"[SUCCESS] {description}\n{output}\n")

                return True
            except subprocess.TimeoutExpired:
                error_msg = "Command timed out"
                logging.error(f"{description} timed out (attempt {attempt + 1}): {error_msg}")
                with self.lock:
                    self.results[target][description] = f"[ERROR] {description} (Attempt {attempt + 1})\n{error_msg}\n"
                if self.verbose:
                    print(f"\033[91m[!] Failed: {description} (Timeout, Attempt {attempt + 1})\033[0m")
                if attempt < retries:
                    time.sleep(random.uniform(2, 5))
                    continue
                return False
            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                logging.error(f"{description} failed (attempt {attempt + 1}): {error_msg}")
                with self.lock:
                    self.results[target][description] = f"[ERROR] {description} (Attempt {attempt + 1})\n{error_msg}\n"
                if self.verbose:
                    print(f"\033[91m[!] Failed: {description} (Attempt {attempt + 1})\033[0m")
                if attempt < retries:
                    time.sleep(random.uniform(2, 5))
                    continue
                return False
        return False

    def worker(self):
        """Worker thread to process tasks from queue with error handling"""
        while True:
            try:
                target, cmd, description = self.task_queue.get_nowait()
                self.run_command(cmd, description, target, retries=self.max_retries - 1)
                self.task_queue.task_done()
            except Queue.Empty:
                break
            except Exception as e:
                logging.error(f"Worker thread error: {str(e)}")
                self.task_queue.task_done()

    def run_parallel_tasks(self, tasks):
        """Run tasks in parallel with a progress bar"""
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

    def run_scanner_plugins(self, target):
        """Run all scanner plugins on a target"""
        # Configure scanner options
        options = {
            'port_range': self.port_range,
            'stealth_mode': self.stealth_mode,
            'use_tor': self.use_tor,
            'verbose': self.verbose,
            'network_interface': self.network_interface
        }
        
        # Import all scanner plugins
        from scanners.nmap_scanner import NmapScanner
        from scanners.masscan_scanner import MasscanScanner
        from scanners.netcat_scanner import NetcatScanner
        from scanners.nikto_scanner import NiktoScanner
        from scanners.sqlmap_scanner import SQLMapScanner
        from scanners.metasploit_scanner import MetasploitScanner
        from scanners.lynis_scanner import LynisScanner
        from scanners.chkrootkit_scanner import ChkrootkitScanner
        from scanners.john_scanner import JohnScanner
        from scanners.anonsurf_scanner import AnonSurfScanner
        from scanners.aircrack_scanner import AircrackScanner
        
        scanners = []
        
        # Add scanners based on profile
        if self.profile in ["all", "network"]:
            scanners.append(NmapScanner(options))
            scanners.append(MasscanScanner(options))
            scanners.append(NetcatScanner(options))
        
        if self.profile in ["all", "vulnerability"]:
            scanners.append(NiktoScanner(options))
            scanners.append(SQLMapScanner(options))
            
            # For Metasploit, we need port info from a previous scan
            if target in self.nmap_results and 'ports' in self.nmap_results[target]:
                metasploit_options = options.copy()
                metasploit_options['port_info'] = self.nmap_results[target]['ports']
                scanners.append(MetasploitScanner(metasploit_options))
            else:
                scanners.append(MetasploitScanner(options))
        
        if self.profile in ["all", "exploitation"]:
            # John needs a hash file
            if hasattr(self, 'hash_file') and self.hash_file:
                john_options = options.copy()
                john_options['hash_file'] = self.hash_file
                if hasattr(self, 'wordlist') and self.wordlist:
                    john_options['wordlist'] = self.wordlist
                scanners.append(JohnScanner(john_options))
        
        if self.profile in ["all", "anonymity"]:
            scanners.append(AnonSurfScanner(options))
            
        if self.profile in ["all", "auditing"]:
            # Only run local auditing tools on localhost
            if target in ["127.0.0.1", "localhost", "::1"]:
                scanners.append(LynisScanner(options))
                scanners.append(ChkrootkitScanner(options))
                
        if self.profile in ["all", "wireless"]:
            # Only run wireless tools when specifically requested
            # since they need special handling
            aircrack_options = options.copy()
            aircrack_options['scan_duration'] = 30  # 30 seconds scan by default
            scanners.append(AircrackScanner(aircrack_options))
        
        # Run each scanner
        for scanner in scanners:
            try:
                scanner_name = scanner.__class__.__name__
                logging.info(f"Running {scanner_name} on {target}")
                
                if self.verbose:
                    print(f"\033[94m[*] Running {scanner_name} on {target}...\033[0m")
                    
                results = scanner.scan(target)
                
                # Store results in the database and results dict
                self.results[target][scanner_name] = results
                
                # Process vulnerabilities
                if 'vulnerabilities' in results and results['vulnerabilities']:
                    for vuln in results['vulnerabilities']:
                        # Get target ID from database
                        self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
                        target_id = self.cursor.fetchone()
                        
                        if target_id:
                            # Fetch CVE details if available
                            cve_details = {'score': 0, 'description': ''}
                            if vuln.get('cve'):
                                cve_details = self.fetch_cve_details(vuln['cve'])
                                
                            # Store vulnerability in database
                            self.store_vulnerability(
                                target_id[0],
                                vuln.get('port', 0),
                                vuln.get('script', scanner_name),
                                vuln.get('output', 'No output'),
                                vuln.get('cve'),
                                cve_details.get('score', 0),
                                cve_details.get('description', '')
                            )
                
                # Store test result in the database
                self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
                target_id = self.cursor.fetchone()
                if target_id:
                    # Create a summary result message
                    result_summary = f"[SUCCESS] {scanner_name}\n"
                    
                    # Add details based on scanner type
                    if scanner_name == 'NmapScanner' and 'ports' in results:
                        result_summary += f"Found {len(results['ports'])} open ports\n"
                    elif scanner_name == 'NiktoScanner' and 'vulnerabilities' in results:
                        result_summary += f"Found {len(results['vulnerabilities'])} web vulnerabilities\n"
                    elif scanner_name == 'LynisScanner':
                        result_summary += f"Found {len(results.get('warnings', []))} warnings and {len(results.get('suggestions', []))} suggestions\n"
                    elif scanner_name == 'ChkrootkitScanner':
                        result_summary += f"Found {len(results.get('infected', []))} infections and {len(results.get('suspicious', []))} suspicious items\n"
                    elif scanner_name == 'JohnScanner':
                        result_summary += f"Cracked {len(results.get('cracked_passwords', []))} passwords\n"
                    elif scanner_name == 'AnonSurfScanner':
                        result_summary += f"Anonymity status: {results.get('anonymity_status', 'Unknown')}\n"
                    elif scanner_name == 'AircrackScanner':
                        result_summary += f"Found {len(results.get('networks', []))} wireless networks and {len(results.get('vulnerabilities', []))} vulnerabilities\n"
                    
                    # Add raw output excerpt (first 500 chars)
                    if 'raw_output' in results and results['raw_output']:
                        excerpt = results['raw_output'][:500] + "..." if len(results['raw_output']) > 500 else results['raw_output']
                        result_summary += f"\nOutput excerpt:\n{excerpt}\n"
                    
                    # Store in database
                    self.store_test_result(target_id[0], scanner_name, result_summary)
                            
                if self.verbose:
                    print(f"\033[92m[+] Completed {scanner_name} on {target}\033[0m")
                    
            except Exception as e:
                logging.error(f"Error running {scanner.__class__.__name__}: {str(e)}")
                if self.verbose:
                    print(f"\033[91m[!] Error in {scanner.__class__.__name__}: {str(e)}\033[0m")

    def fetch_cve_details(self, cve_id):
        """Fetch enhanced CVE details using the CVE data provider"""
        if not hasattr(self, 'cve_provider'):
            self.cve_provider = CVEDataProvider()
            
        cve_data = self.cve_provider.get_cve_details(cve_id)
        if cve_data:
            return {
                'score': cve_data.get('base_score', 0),
                'description': cve_data.get('description', ''),
                'severity': cve_data.get('severity', 'Low'),
                'references': cve_data.get('references', []),
                'published': cve_data.get('published')
            }
        return {'score': 0, 'description': 'CVE details not available', 'severity': 'Unknown'}

    def parse_nmap_output(self, xml_file, target):
        """Parse Nmap XML output to extract CVEs, threats, and vulnerabilities"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            ports_info = []
            vulnerabilities = []

            for host in root.findall('host'):
                ip = host.find('.//address[@addrtype="ipv4"]').get('addr') if host.find('.//address[@addrtype="ipv4"]') is not None else target
                mac = host.find('.//address[@addrtype="mac"]').get('addr') if host.find('.//address[@addrtype="mac"]') is not None else 'N/A'
                os = host.find('.//osmatch').get('name') if host.find('.//osmatch') is not None else 'Unknown'
                version = host.find('.//osmatch/cpe').get('product') if host.find('.//osmatch/cpe') is not None else 'N/A'

                self.discovered_targets[ip] = {
                    'mac': mac,
                    'os': os,
                    'version': version,
                    'ports': []
                }

                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state != 'open':
                        continue
                    port_id = port.get('portid')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    service_version = service.get('version') if service is not None and service.get('version') else 'unknown'
                    ports_info.append({
                        'port': port_id,
                        'service': service_name,
                        'version': service_version
                    })
                    self.discovered_targets[ip]['ports'].append({
                        'port': port_id,
                        'service': service_name,
                        'version': service_version
                    })

                    for script in port.findall('.//script'):
                        script_id = script.get('id')
                        script_output = script.get('output')
                        if 'vuln' in script_id.lower() and script_output:
                            cve = None
                            for line in script_output.splitlines():
                                if 'CVE-' in line:
                                    cve = line.split('CVE-')[1].split(' ')[0]
                                    break
                            vuln = {
                                'port': port_id,
                                'script': script_id,
                                'output': script_output,
                                'cve': f"CVE-{cve}" if cve else None
                            }
                            if vuln['cve']:
                                vuln_details = self.fetch_cve_details(vuln['cve'])
                                vuln['score'] = vuln_details['score']
                                vuln['description'] = vuln_details['description']
                            vulnerabilities.append(vuln)

                # Store in database
                target_id = self.store_target(ip, mac, os, version, ports_info)
                for vuln in vulnerabilities:
                    self.store_vulnerability(
                        target_id,
                        vuln['port'],
                        vuln['script'],
                        vuln['output'],
                        vuln['cve'],
                        vuln.get('score', 0),
                        vuln.get('description', '')
                    )

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

    def get_default_interface(self):
        """Attempt to detect the default network interface"""
        try:
            result = subprocess.run("ip route | grep default", shell=True, capture_output=True, text=True)
            if result.stdout:
                interface = result.stdout.split()[4]
                print(f"\033[94m[*] Detected default interface: {interface}\033[0m")
                return interface
        except Exception as e:
            logging.error(f"Failed to detect default interface: {str(e)}")
            print(f"\033[91m[!] Failed to detect default interface: {str(e)}\033[0m")
        return "eth0"  # Fallback to eth0 if detection fails

    def scan_lan(self):
        """Scan the LAN network to discover active devices using the selected network interface"""
        if not self.check_tool("nmap"):
            return

        if not self.network_interface:
            self.network_interface = self.get_default_interface()
            print(f"\033[93m[-] No network interface selected. Using default: {self.network_interface}\033[0m")

        # Get the network range (e.g., 192.168.1.0/24)
        result = subprocess.run(f"ip -4 addr show {self.network_interface} | grep inet", shell=True, capture_output=True, text=True)
        if not result.stdout:
            print(f"\033[91m[!] Could not determine network range for {self.network_interface}. Please specify a valid interface.\033[0m")
            return
        ip_info = result.stdout.split()
        ip_address = ip_info[1].split('/')[0]
        subnet = ip_info[1].split('/')[1]
        network = ipaddress.ip_network(f"{ip_address}/{subnet}", strict=False)
        network_range = str(network.network_address) + "/" + str(network.prefixlen)

        xml_output = f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd = f"nmap -sn {network_range} -oX {xml_output}"
        if self.stealth_mode:
            cmd += " -T2 --max-retries 1 --scan-delay 1s --spoof-mac 0 -D RND:5"
        if self.run_command(cmd, f"Running LAN scan on {network_range}", output_file=xml_output):
            self.parse_lan_output(xml_output)
            try:
                os.remove(xml_output)
            except Exception as e:
                logging.warning(f"Could not delete LAN XML file {xml_output}: {str(e)}")

    def parse_lan_output(self, xml_file):
        """Parse Nmap LAN scan XML output to extract device information"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                ip = host.find('.//address[@addrtype="ipv4"]').get('addr') if host.find('.//address[@addrtype="ipv4"]') is not None else 'Unknown'
                mac = host.find('.//address[@addrtype="mac"]').get('addr') if host.find('.//address[@addrtype="mac"]') is not None else 'N/A'
                os = host.find('.//osmatch').get('name') if host.find('.//osmatch') is not None else 'Unknown'
                version = host.find('.//osmatch/cpe').get('product') if host.find('.//osmatch/cpe') is not None else 'N/A'
                ports = []
                for port in host.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('service').get('name') if port.find('service') is not None else 'unknown'
                        service_version = port.find('service').get('version') if port.find('service') is not None and port.find('service').get('version') else 'unknown'
                        ports.append({'port': port_id, 'service': service, 'version': service_version})

                self.discovered_targets[ip] = {
                    'mac': mac,
                    'os': os,
                    'version': version,
                    'ports': ports
                }

                # Store in database
                self.store_target(ip, mac, os, version, ports)

            logging.info(f"Discovered {len(self.discovered_targets)} devices on LAN")
            if self.verbose:
                print(f"\033[92m[+] Discovered {len(self.discovered_targets)} devices on LAN\033[0m")
        except Exception as e:
            logging.error(f"Error parsing LAN scan output: {str(e)}")
            if self.verbose:
                print(f"\033[91m[!] Error parsing LAN scan output: {str(e)}\033[0m")

    def display_targets(self):
        """Display discovered targets in a formatted table"""
        if not self.discovered_targets:
            print("\033[93m[-] No targets discovered. Please run a LAN scan first.\033[0m")
            return
        print("\n\033[94m=== Discovered Targets ===\033[0m")
        print("IP Address\tMAC Address\tPlatform\tVersion\t\tOpen Ports")
        print("-" * 80)
        for ip, details in self.discovered_targets.items():
            ports = ", ".join([f"{p['port']}/{p['service']}" for p in details.get('ports', [])])
            print(f"{ip}\t\t{details['mac']}\t\t{details['os']}\t\t{details['version']}\t\t{ports}")
        print("-" * 80)

    def select_targets(self):
        """Interactively select targets with LAN scan option"""
        print("\n\033[94m=== Target Selection ===\033[0m")
        method = self.session.prompt(
            HTML('<prompt>Choose target selection method (single/file/lan): </prompt>'),
            completer=WordCompleter(['single', 'file', 'lan'], ignore_case=True)
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
        elif method == 'lan':
            self.scan_lan()
            self.display_targets()
            if self.discovered_targets:
                selected_ips = self.session.prompt(
                    HTML('<prompt>Enter IP(s) to select (comma-separated, e.g., 192.168.1.1,192.168.1.2, or press Enter for all): </prompt>')
                )
                if selected_ips:
                    self.targets = [ip.strip() for ip in selected_ips.split(',') if ip.strip() in self.discovered_targets]
                else:
                    self.targets = list(self.discovered_targets.keys())
            else:
                print("\033[93m[-] No targets found. Using default target (127.0.0.1).\033[0m")
                self.targets = ["127.0.0.1"]
        else:
            print("\033[93m[-] Invalid method. Using default target (127.0.0.1).\033[0m")
            self.targets = ["127.0.0.1"]
        
        print(f"\033[92m[+] Selected targets: {', '.join(self.targets)}\033[0m")

    def run_nmap(self, target):
        """Run Nmap scan with enhanced stealth options"""
        if not self.check_tool("nmap"):
            return
            
        # Use plugin system if enabled
        if self.use_plugin_system:
            options = {
                'port_range': self.port_range,
                'stealth_mode': self.stealth_mode,
                'use_tor': self.use_tor,
                'verbose': self.verbose
            }
            
            scanner = NmapScanner(options)
            results = scanner.scan(target)
            
            # Store results for compatibility
            self.results[target]["Nmap Scan"] = results
            self.nmap_results[target] = {
                'ports': results.get('ports', []),
                'vulnerabilities': results.get('vulnerabilities', [])
            }
            
            # Process vulnerabilities
            # ... process vulnerabilities ...
            
            return True
        
        # Original implementation
        xml_output = f"nmap_output_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        cmd = f"nmap -p {self.port_range} -sV --script vuln {target}"
        if self.stealth_mode:
            cmd += " -T2 --max-retries 1 --scan-delay 1s --spoof-mac 0"
        if self.run_command(cmd, f"Running Nmap scan on {target}", target, output_file=xml_output):
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

        target = self.targets[0]
        if target not in self.nmap_results or not self.nmap_results[target]['ports']:
            print(f"\033[93m[-] No Nmap results available for {target}. Skipping Metasploit.\033[0m")
            return

        self.run_metasploit_vuln_scan(target)

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
                    print(f"    CVE: {vuln['cve']} (Score: {vuln['score']})")
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
        """Run Masscan with stealth options"""
        if not self.check_tool("masscan"):
            return
        cmd = f"masscan {target} -p {self.port_range} --rate {random.uniform(100, 500)}"
        if self.stealth_mode:
            cmd += " --wait 2 --randomize-hosts"
        self.run_command(cmd, f"Running Masscan on {target} (ports {self.port_range})", target)

    def run_netcat(self, target):
        """Run Netcat scan with stealth"""
        if not self.check_tool("nc"):
            return
        cmd = f"nc -z -nv {target} {self.port_range}"
        if self.stealth_mode:
            cmd += f" -w {random.uniform(1, 3)}"
        self.run_command(cmd, f"Running Netcat scan on {target} (ports {self.port_range})", target)

    def run_nikto(self, target):
        """Run Nikto for web vulnerability scanning with stealth"""
        if not self.check_tool("nikto"):
            return
        cmd = f"nikto -h {target}"
        if self.stealth_mode:
            cmd += " -Tuning 8"
        self.run_command(cmd, f"Running Nikto on {target}", target)

    def run_sqlmap(self, target):
        """Run SQLmap for SQL injection testing with stealth"""
        if not self.check_tool("sqlmap"):
            return
        cmd = f"sqlmap -u http://{target} --batch"
        if self.stealth_mode:
            cmd += f" --delay {random.uniform(0.5, 2)} --safe-url http://example.com --safe-freq {random.randint(2, 5)}"
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
        """Run Aircrack-ng for wireless testing using the selected network interface"""
        if not self.check_tool("aircrack-ng"):
            return

        if not self.network_interface:
            self.network_interface = self.get_default_interface()
            print(f"\033[93m[-] No network interface selected. Using default: {self.network_interface}\033[0m")

        cmd = f"airmon-ng start {self.network_interface} && airodump-ng {self.network_interface}mon"
        self.run_command(cmd, f"Running Aircrack-ng on {self.network_interface}", self.targets[0])

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
        """Save results to specified formats with enhanced database integration"""
        if not formats:
            formats = ['text', 'html', 'csv']

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"interactive_test_report_{timestamp}.txt"
        html_report_file = f"interactive_test_report_{timestamp}.html"
        csv_report_file = f"interactive_test_report_{timestamp}.csv"

        # Fetch data from database
        self.cursor.execute("SELECT * FROM targets")
        targets = self.cursor.fetchall()

        # Fetch ports for each target
        target_ports = {}
        for target in targets:
            target_id = target[0]
            self.cursor.execute("SELECT port, service, version FROM ports WHERE target_id = ?", (target_id,))
            ports = [{'port': row[0], 'service': row[1], 'version': row[2]} for row in self.cursor.fetchall()]
            target_with_ports = list(target) + [ports]
            target_ports[target_id] = target_with_ports

        self.cursor.execute('''
            SELECT t.ip, tr.test_name, tr.result, tr.timestamp
            FROM test_results tr
            JOIN targets t ON tr.target_id = t.id
        ''')
        test_results = self.cursor.fetchall()

        self.cursor.execute('''
            SELECT t.ip, v.port, v.script, v.output, v.cve, v.score, v.description, v.timestamp
            FROM vulnerabilities v
            JOIN targets t ON v.target_id = t.id
        ''')
        vulnerabilities = self.cursor.fetchall()

        saved_files = []
        try:
            if 'text' in formats:
                with open(report_file, "w") as f:
                    f.write(f"Interactive System Test Report - {datetime.now().isoformat()}\n")
                    f.write("=" * 50 + "\n\n")
                    if targets:
                        f.write("Discovered Targets:\n")
                        f.write("IP Address\tMAC Address\tPlatform\tVersion\t\tOpen Ports\tScan Timestamp\n")
                        f.write("-" * 80 + "\n")
                        for target in targets:
                            target_id = target[0]
                            ports = target_ports.get(target_id, [[]])[-1]
                            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in ports])
                            f.write(f"{target[1]}\t\t{target[2] or 'N/A'}\t\t{target[3] or 'Unknown'}\t\t{target[4] or 'N/A'}\t\t{ports_str}\t{target[5]}\n")
                        f.write("-" * 80 + "\n\n")
                    for target, result in self.results.items():
                        f.write(f"Target: {target}\n")
                        for test, output in result.items():
                            f.write(f"{test}\n{output}\n")
                logging.info(f"Text report saved to {report_file}")
                saved_files.append(report_file)

            if 'html' in formats:
                template = env.get_template("report.html")
                html_content = template.render(
                    timestamp=datetime.now().isoformat(),
                    results=self.results,
                    targets=list(target_ports.values()),
                    test_results=test_results,
                    vulnerabilities=vulnerabilities
                )
                with open(html_report_file, "w") as f:
                    f.write(html_content)
                logging.info(f"HTML report saved to {html_report_file}")
                saved_files.append(html_report_file)

            if 'csv' in formats:
                with open(csv_report_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Target", "Test", "Result"])
                    if targets:
                        writer.writerow(["Discovered Targets"])
                        writer.writerow(["IP Address", "MAC Address", "Platform", "Version", "Open Ports", "Scan Timestamp"])
                        for target in targets:
                            target_id = target[0]
                            ports = target_ports.get(target_id, [[]])[-1]
                            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in ports])
                            writer.writerow([target[1], target[2] or 'N/A', target[3] or 'Unknown', target[4] or 'N/A', ports_str, target[5]])
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
        if not self.results and not self.discovered_targets:
            print("\033[93m[-] No test results or discovered targets available to export. Please run a test or LAN scan first.\033[0m")
            return

        print("\n\033[94m=== Export Reports ===\033[0m")
        formats_input = self.session.prompt(
            HTML('<prompt>Select export formats (text, html, enhanced_html, csv, comma-separated, e.g., text,csv): </prompt>'),
            completer=WordCompleter(['text', 'html', 'enhanced_html', 'csv'], ignore_case=True)
        ).lower()

        if not formats_input:
            print("\033[93m[-] No formats selected. Export cancelled.\033[0m")
            return

        selected_formats = [fmt.strip() for fmt in formats_input.split(',')]
        valid_formats = ['text', 'html', 'enhanced_html', 'csv']
        formats_to_export = [fmt for fmt in selected_formats if fmt in valid_formats]

        if not formats_to_export:
            print("\033[93m[-] Invalid formats selected. Use: text, html, enhanced_html, csv.\033[0m")
            return

        # Handle enhanced_html separately
        if 'enhanced_html' in formats_to_export:
            formats_to_export.remove('enhanced_html')
            self.generate_enhanced_report()
            
        # Handle standard formats
        if formats_to_export:
            self.save_report(formats=formats_to_export)

    def generate_enhanced_report(self):
        """Generate enhanced HTML report with interactive elements"""
        enhanced_report = EnhancedHTMLReport(self.conn)
        report_file = enhanced_report.generate_report()
        self.last_report_files['enhanced_html'] = report_file
        return report_file

    def configure_settings(self):
        """Interactively configure test settings with network interface selection"""
        print("\n\033[94m=== Test Configuration ===\033[0m")
        self.port_range = self.session.prompt(
            HTML('<prompt>Enter port range (default: 1-1024): </prompt>')
        ) or "1-1024"
        
        self.profile = self.session.prompt(
            HTML('<prompt>Choose test profile (all/network/vulnerability/exploitation/anonymity/auditing/wireless): </prompt>'),
            completer=WordCompleter(['all', 'network', 'vulnerability', 'exploitation', 'anonymity', 'auditing', 'wireless'], ignore_case=True)
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

        # Network interface selection
        interfaces = self.get_available_interfaces()
        interface_list = ', '.join(interfaces) if interfaces else "None detected"
        
        print(f"\033[94m[*] Available network interfaces: {interface_list}\033[0m")
        
        self.network_interface = self.session.prompt(
            HTML('<prompt>Enter network interface for testing (e.g., eth0, wlan0, or press Enter to detect): </prompt>'),
            completer=WordCompleter(interfaces, ignore_case=True)
        )
        
        if not self.network_interface:
            self.network_interface = self.get_default_interface()
            print(f"\033[94m[*] Using default interface: {self.network_interface}\033[0m")
        
        # Special configuration for wireless testing
        if self.profile in ["all", "wireless"]:
            wireless_interfaces = self.get_wireless_interfaces()
            if wireless_interfaces:
                wireless_list = ', '.join(wireless_interfaces)
                print(f"\033[94m[*] Available wireless interfaces: {wireless_list}\033[0m")
                wireless_interface = self.session.prompt(
                    HTML('<prompt>Enter wireless interface for testing (or press Enter to use selected interface): </prompt>'),
                    completer=WordCompleter(wireless_interfaces, ignore_case=True)
                )
                if wireless_interface:
                    self.network_interface = wireless_interface
                    print(f"\033[94m[*] Using wireless interface: {self.network_interface}\033[0m")
            else:
                print("\033[93m[-] No wireless interfaces detected. Wireless testing may not work.\033[0m")

        if self.use_tor:
            self.setup_anonymity()
        if self.stealth_mode:
            self.spoof_mac()
        
        print(f"\033[92m[+] Configured: Port Range={self.port_range}, Profile={self.profile}, Verbose={self.verbose}, Stealth={self.stealth_mode}, Tor={self.use_tor}, Interface={self.network_interface}\033[0m")
        
        plugin_input = self.session.prompt(
            HTML('<prompt>Use enhanced plugin system? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.use_plugin_system = plugin_input == "yes"
        
        print(f"\033[92m[+] Plugin system: {'Enabled' if self.use_plugin_system else 'Disabled'}\033[0m")

    def get_available_interfaces(self):
        """Get a list of all network interfaces"""
        try:
            result = subprocess.run("ip -o link show | grep -v 'link/loopback' | awk -F': ' '{print $2}'", 
                                shell=True, capture_output=True, text=True)
            interfaces = [iface.strip() for iface in result.stdout.splitlines() if iface.strip()]
            return interfaces
        except Exception as e:
            logging.error(f"Failed to get network interfaces: {str(e)}")
            return []

    def get_wireless_interfaces(self):
        """Get a list of wireless interfaces"""
        try:
            result = subprocess.run("iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*'", 
                                shell=True, capture_output=True, text=True)
            interfaces = [iface.strip() for iface in result.stdout.splitlines() if iface.strip()]
            return interfaces
        except Exception as e:
            logging.error(f"Failed to get wireless interfaces: {str(e)}")
            return []

    def run_profile(self):
        """Run tests based on selected profile with enhanced parallel execution"""
        valid_profiles = ["all", "network", "vulnerability", "exploitation", "anonymity", "auditing", "wireless"]
        if self.profile not in valid_profiles:
            print(f"\033[91m[!] Invalid profile. Use one of: {', '.join(valid_profiles)}\033[0m")
            return

        # Initialize result dictionaries for all targets
        for target in self.targets:
            self.results[target] = {}
            self.nmap_results[target] = {'ports': [], 'vulnerabilities': []}

        try:
            if self.use_plugin_system:
                # Import the dynamic plugin loader and parallel executor
                from utils.plugin_loader import load_scanner_plugins
                from utils.parallel_executor import ParallelExecutor, ScanTask
                from tqdm import tqdm
                
                # Load all available plugins
                plugins = load_scanner_plugins()
                
                # Prepare base options for all plugins
                base_options = {
                    'port_range': self.port_range,
                    'stealth_mode': self.stealth_mode,
                    'use_tor': self.use_tor,
                    'verbose': self.verbose,
                    'network_interface': self.network_interface
                }
                
                # Configure scanner selection based on profile
                selected_scanners = []
                
                if self.profile == "all":
                    # Use all available plugins for "all" profile
                    selected_scanners = list(plugins.values())
                else:
                    # Use profile-specific plugins
                    if self.profile == "network":
                        selected_names = ["NmapScanner", "MasscanScanner", "NetcatScanner"]
                    elif self.profile == "vulnerability":
                        selected_names = ["NiktoScanner", "SQLMapScanner", "MetasploitScanner"]
                    elif self.profile == "exploitation":
                        selected_names = ["MetasploitScanner", "JohnScanner"]
                    elif self.profile == "anonymity":
                        selected_names = ["AnonSurfScanner"]
                    elif self.profile == "auditing":
                        selected_names = ["LynisScanner", "ChkrootkitScanner"]
                    elif self.profile == "wireless":
                        selected_names = ["AircrackScanner"]
                    
                    selected_scanners = [plugins[name] for name in selected_names if name in plugins]
                
                # Set up tasks for parallel execution
                scan_tasks = []
                
                # Init progress bar
                total_tasks = len(self.targets) * len(selected_scanners)
                progress_bar = tqdm(total=total_tasks, desc="Scanning Progress", 
                                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
                
                # Create executor with max workers based on target count and scan type
                executor = ParallelExecutor(
                    max_workers=min(10, len(self.targets) * 2),
                    cpu_intensive=(self.profile in ["auditing", "exploitation"])
                )
                
                # Define progress callback for updating tqdm
                def update_progress(description, completed, total):
                    progress_bar.set_description(description)
                    progress_bar.update(1)
                
                executor.set_progress_callback(update_progress)
                
                # Create tasks for all targets and scanners
                for target in self.targets:
                    for scanner_class in selected_scanners:
                        # Skip auditing tools for non-local targets
                        if scanner_class.__name__ in ["LynisScanner", "ChkrootkitScanner"] and \
                        target not in ["127.0.0.1", "localhost", "::1"]:
                            continue
                        
                        # Prepare custom options for specific scanners
                        custom_options = base_options.copy()
                        
                        # Special handling for certain scanners
                        if scanner_class.__name__ == "MetasploitScanner" and \
                        target in self.nmap_results and 'ports' in self.nmap_results[target]:
                            custom_options['port_info'] = self.nmap_results[target]['ports']
                        
                        elif scanner_class.__name__ == "JohnScanner":
                            # John needs a hash file
                            if not hasattr(self, 'hash_file') or not self.hash_file:
                                if self.verbose:
                                    print(f"\033[93m[-] Skipping JohnScanner: No hash file provided\033[0m")
                                continue
                            custom_options['hash_file'] = self.hash_file
                            if hasattr(self, 'wordlist') and self.wordlist:
                                custom_options['wordlist'] = self.wordlist
                        
                        elif scanner_class.__name__ == "AircrackScanner":
                            # Special options for wireless scanning
                            custom_options['scan_duration'] = 30  # 30 seconds scan duration
                        
                        # Set task priority - network scanners first, then vuln scanners, etc.
                        priority = 0
                        if scanner_class.__name__ in ["NmapScanner", "MasscanScanner"]:
                            priority = 100  # Highest priority
                        elif "vulnerability" in self.profile:
                            priority = 50
                        
                        # Create and add the task
                        task = ScanTask(
                            target=target, 
                            scanner_class=scanner_class, 
                            scanner_options=custom_options,
                            priority=priority
                        )
                        executor.add_task(task)
                
                # Execute all tasks in parallel
                print(f"\033[94m[*] Running {total_tasks} scan tasks on {len(self.targets)} targets using {executor.max_workers} parallel workers\033[0m")
                parallel_results = executor.execute()
                progress_bar.close()
                
                # Process results
                for target, scanners in parallel_results.items():
                    self.results[target] = scanners
                    
                    # Copy data from NmapScanner to nmap_results for compatibility
                    if "NmapScanner" in scanners:
                        nmap_results = scanners["NmapScanner"]
                        self.nmap_results[target]['ports'] = nmap_results.get('ports', [])
                        self.nmap_results[target]['vulnerabilities'] = nmap_results.get('vulnerabilities', [])
                    
                    # Process all vulnerabilities for database storage
                    for scanner_name, results in scanners.items():
                        if 'error' in results:
                            logging.error(f"Error in {scanner_name} on {target}: {results['error']}")
                            if self.verbose:
                                print(f"\033[91m[!] Error in {scanner_name} on {target}: {results['error']}\033[0m")
                            continue
                            
                        # Process vulnerabilities
                        if 'vulnerabilities' in results and results['vulnerabilities']:
                            self._process_vulnerabilities(target, scanner_name, results['vulnerabilities'])
                        
                        # Store test result in database
                        self._store_scan_result(target, scanner_name, results)
                
                print(f"\033[92m[+] Completed all scan tasks\033[0m")
                
            else:
                # Fall back to the original implementation if plugin system is disabled
                for target in self.targets:
                    self.run_scanner_plugins(target)
                    
                    # For backward compatibility, copy data from plugin results to nmap_results
                    if 'NmapScanner' in self.results[target]:
                        nmap_results = self.results[target]['NmapScanner']
                        self.nmap_results[target]['ports'] = nmap_results.get('ports', [])
                        self.nmap_results[target]['vulnerabilities'] = nmap_results.get('vulnerabilities', [])

                # Keep existing code for tools not yet converted to plugins
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

        # Generate reports
        self.save_report()
        self.generate_enhanced_report()

    def _process_vulnerabilities(self, target, scanner_name, vulnerabilities):
        """Process and store vulnerabilities in the database"""
        # Get target ID from database
        self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
        target_id = self.cursor.fetchone()
        
        if not target_id:
            return
            
        for vuln in vulnerabilities:
            # Fetch CVE details if available
            cve_details = {'score': 0, 'description': ''}
            if vuln.get('cve'):
                cve_details = self.fetch_cve_details(vuln['cve'])
                
            # Store vulnerability in database
            self.store_vulnerability(
                target_id[0],
                vuln.get('port', 0),
                vuln.get('script', scanner_name),
                vuln.get('output', 'No output'),
                vuln.get('cve'),
                cve_details.get('score', 0),
                cve_details.get('description', '')
            )

    def _store_scan_result(self, target, scanner_name, results):
        """Store scan results in the database"""
        # Get target ID
        self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
        target_id = self.cursor.fetchone()
        
        if not target_id:
            return
            
        # Create a summary result message
        result_summary = f"[SUCCESS] {scanner_name}\n"
        
        # Add details based on scanner type
        if scanner_name == 'NmapScanner' and 'ports' in results:
            result_summary += f"Found {len(results['ports'])} open ports\n"
        elif scanner_name == 'NiktoScanner' and 'vulnerabilities' in results:
            result_summary += f"Found {len(results['vulnerabilities'])} web vulnerabilities\n"
        elif scanner_name == 'LynisScanner':
            result_summary += f"Found {len(results.get('warnings', []))} warnings and {len(results.get('suggestions', []))} suggestions\n"
        elif scanner_name == 'ChkrootkitScanner':
            result_summary += f"Found {len(results.get('infected', []))} infections and {len(results.get('suspicious', []))} suspicious items\n"
        elif scanner_name == 'JohnScanner':
            result_summary += f"Cracked {len(results.get('cracked_passwords', []))} passwords\n"
        elif scanner_name == 'AnonSurfScanner':
            result_summary += f"Anonymity status: {results.get('anonymity_status', 'Unknown')}\n"
        elif scanner_name == 'AircrackScanner':
            result_summary += f"Found {len(results.get('networks', []))} wireless networks and {len(results.get('vulnerabilities', []))} vulnerabilities\n"
        
        # Add raw output excerpt (first 500 chars)
        if 'raw_output' in results and results['raw_output']:
            excerpt = results['raw_output'][:500] + "..." if len(results['raw_output']) > 500 else results['raw_output']
            result_summary += f"\nOutput excerpt:\n{excerpt}\n"
        
        # Store in database
        self.store_test_result(target_id[0], scanner_name, result_summary)

    def main_menu(self):
        """Main interactive menu"""
        print("\033[94m=== Welcome to Interactive System Tester for Parrot OS ===\033[0m")
        print("Type 'exit' or press Ctrl+C to quit.\n")
        
        while True:
            choice = self.session.prompt(
                HTML('<prompt>Choose an action (configure/targets/run/export/query_db/enhanced_report/configure_automation/exit): </prompt>')
            ).lower()

            if choice == "exit":
                if self.use_tor and self.check_tool("anonsurf"):
                    subprocess.run("anonsurf stop", shell=True, capture_output=True, text=True)
                self.conn.close()
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
            elif choice == "query_db":
                self.query_db()
            elif choice == "enhanced_report":
                self.generate_enhanced_report()
            elif choice == "configure_automation":
                self.configure_automation()
            else:
                print("\033[93m[-] Invalid choice. Options: configure, targets, run, export, query_db, enhanced_report, configure_automation, exit\033[0m")

def main():
    if os.geteuid() != 0:
        print("\033[91m[!] This script requires root privileges. Please run with sudo.\033[0m")
        sys.exit(1)

    tester = InteractiveSystemTester()
    tester.main_menu()

if __name__ == "__main__":
    main()