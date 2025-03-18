#!/usr/bin/env python3
import sqlite3
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
import requests

# Configure logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"automated_query_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Setup Jinja2 for HTML reporting
env = Environment(loader=FileSystemLoader("templates"))

class AutomatedQueryTool:
    def __init__(self):
        self.db_file = "query_tool.db"
        self.setup_database()
        self.setup_prompt()
        self.last_report_file = None
        self.automation_interval = 3600  # Default 1 hour interval for automation (in seconds)

    def setup_database(self):
        """Initialize SQLite database and create tables"""
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
            'add_data', 'query_db', 'generate_report', 'configure_automation', 'exit'
        ], ignore_case=True)
        self.session = PromptSession(
            style=self.style,
            completer=self.completer,
            key_bindings=self.bindings,
            multiline=False,
            prompt_message=HTML('<prompt>QueryTool> </prompt>')
        )

    def store_target(self, ip, mac=None, os=None, version=None, ports=None):
        """Store a target and its ports in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO targets (ip, mac, os, version, scan_timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, mac, os, version, timestamp))
        target_id = self.cursor.lastrowid

        if ports:
            for port_info in ports:
                self.cursor.execute('''
                    INSERT INTO ports (target_id, port, service, version)
                    VALUES (?, ?, ?, ?)
                ''', (target_id, port_info['port'], port_info['service'], port_info['version']))

        self.conn.commit()
        return target_id

    def store_test_result(self, target_id, test_name, result):
        """Store a test result in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO test_results (target_id, test_name, result, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (target_id, test_name, result, timestamp))
        self.conn.commit()

    def store_vulnerability(self, target_id, port, script, output, cve=None, score=0, description=None):
        """Store a vulnerability in the database"""
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO vulnerabilities (target_id, port, script, output, cve, score, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (target_id, port, script, output, cve, score, description, timestamp))
        self.conn.commit()

    def simulate_scan_data(self, num_targets=3):
        """Simulate scan data for automation (e.g., from a network scan)"""
        for _ in range(num_targets):
            ip = f"192.168.1.{random.randint(1, 254)}"
            mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)]) if random.choice([True, False]) else None
            os = random.choice(["Linux", "Windows", "Unknown"])
            version = f"{random.randint(1, 10)}.{random.randint(0, 99)}" if os != "Unknown" else None
            ports = [
                {"port": random.randint(1, 65535), "service": random.choice(["ssh", "http", "https", "smb"]), "version": f"{random.randint(1, 10)}"}
                for _ in range(random.randint(1, 5))
            ]
            target_id = self.store_target(ip, mac, os, version, ports)

            # Simulate test results
            test_names = ["Nmap Scan", "Nikto Scan", "Metasploit Scan"]
            for test_name in test_names:
                result = f"Completed {test_name} on {ip} at {datetime.now().isoformat()}"
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
        """Automate periodic data collection (simulated scans)"""
        while True:
            print(f"\033[94m[*] Starting automated data collection at {datetime.now().isoformat()}...\033[0m")
            self.simulate_scan_data(random.randint(1, 5))  # Simulate 1-5 targets
            time.sleep(self.automation_interval)

    def query_db(self):
        """Interactively query the database"""
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

    def generate_html_report(self):
        """Generate a dynamic HTML report from database data"""
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_report_file = f"reports/history_report_{timestamp}.html"

        # Fetch data from database
        self.cursor.execute("SELECT * FROM targets")
        targets = self.cursor.fetchall()

        self.cursor.execute('''
            SELECT t.ip, tr.test_name, tr.result, tr.timestamp
            FROM test_results tr
            JOIN targets t ON tr.target_id = t.id
        ''')
        results = self.cursor.fetchall()

        self.cursor.execute('''
            SELECT t.ip, v.port, v.script, v.output, v.cve, v.score, v.description, v.timestamp
            FROM vulnerabilities v
            JOIN targets t ON v.target_id = t.id
        ''')
        vulnerabilities = self.cursor.fetchall()

        # Render HTML template
        if not os.path.exists("templates/report.html"):
            with open("templates/report.html", "w") as f:
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>History Report - {{ timestamp }}</title>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        h1 { color: #333; }
                        h2 { color: #555; }
                        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        .severity-high { color: red; font-weight: bold; }
                        .severity-medium { color: orange; }
                        .severity-low { color: green; }
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
                    <h1>History Report - {{ timestamp }}</h1>
                    <input type="text" id="ipFilter" onkeyup="filterTable()" placeholder="Filter by IP...">
                    {% if targets %}
                        <h2>Discovered Targets</h2>
                        <table>
                            <tr><th>IP Address</th><th>MAC Address</th><th>Platform</th><th>Version</th><th>Scan Timestamp</th></tr>
                            {% for target in targets %}
                                <tr>
                                    <td>{{ target[1] }}</td>
                                    <td>{{ target[2] or 'N/A' }}</td>
                                    <td>{{ target[3] or 'Unknown' }}</td>
                                    <td>{{ target[4] or 'N/A' }}</td>
                                    <td>{{ target[5] }}</td>
                                </tr>
                            {% endfor %}
                        </table>
                    {% endif %}
                    {% if results %}
                        <h2>Test Results</h2>
                        <table>
                            <tr><th>IP Address</th><th>Test Name</th><th>Result</th><th>Timestamp</th></tr>
                            {% for result in results %}
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
                </body>
                </html>
                """)

        template = env.get_template("report.html")
        html_content = template.render(
            timestamp=datetime.now().isoformat(),
            targets=targets,
            results=results,
            vulnerabilities=vulnerabilities
        )
        with open(html_report_file, "w") as f:
            f.write(html_content)
        self.last_report_file = html_report_file
        logging.info(f"HTML report generated: {html_report_file}")
        print(f"\033[92m[+] HTML report generated: {html_report_file}\033[0m")
        print(f"\033[94m[*] Open {html_report_file} in a web browser to view the report.\033[0m")

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
            automation_thread = threading.Thread(target=self.automate_data_collection, daemon=True)
            automation_thread.start()
        except ValueError:
            print("\033[91m[!] Invalid interval. Using default 3600 seconds.\033[0m")
            self.automation_interval = 3600
            automation_thread = threading.Thread(target=self.automate_data_collection, daemon=True)
            automation_thread.start()

    def add_data(self):
        """Manually add data to the database (e.g., simulated or imported)"""
        print("\n\033[94m=== Add Data ===\033[0m")
        option = self.session.prompt(
            HTML('<prompt>Choose option (simulate/import): </prompt>'),
            completer=WordCompleter(['simulate', 'import'], ignore_case=True)
        ).lower()

        if option == "simulate":
            num_targets = int(self.session.prompt(HTML('<prompt>Enter number of targets to simulate (default: 3): </prompt>')) or 3)
            self.simulate_scan_data(num_targets)
        elif option == "import":
            file_path = self.session.prompt(HTML('<prompt>Enter path to CSV file with data: </prompt>'))
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ip = row.get("ip")
                        mac = row.get("mac")
                        os = row.get("os")
                        version = row.get("version")
                        ports = eval(row.get("ports", "[]")) if row.get("ports") else []  # Assuming ports as list of dicts
                        target_id = self.store_target(ip, mac, os, version, ports)
                        if row.get("test_name") and row.get("result"):
                            self.store_test_result(target_id, row["test_name"], row["result"])
                        if row.get("vuln_port") and row.get("vuln_script") and row.get("vuln_output"):
                            self.store_vulnerability(
                                target_id,
                                int(row["vuln_port"]),
                                row["vuln_script"],
                                row["vuln_output"],
                                row.get("cve"),
                                float(row.get("score", 0)),
                                row.get("description")
                            )
                print(f"\033[92m[+] Data imported from {file_path}\033[0m")
            else:
                print(f"\033[91m[!] File {file_path} not found.\033[0m")
        else:
            print("\033[93m[-] Invalid option. Use: simulate, import\033[0m")

    def main_menu(self):
        """Main interactive menu"""
        print("\033[94m=== Welcome to Automated Query Tool ===\033[0m")
        print("Type 'exit' or press Ctrl+C to quit.\n")
        
        while True:
            choice = self.session.prompt(
                HTML('<prompt>Choose an action (add_data/query_db/generate_report/configure_automation/exit): </prompt>')
            ).lower()

            if choice == "exit":
                self.conn.close()
                print("\033[92m[+] Exiting Automated Query Tool. Goodbye!\033[0m")
                break
            elif choice == "add_data":
                self.add_data()
            elif choice == "query_db":
                self.query_db()
            elif choice == "generate_report":
                self.generate_html_report()
            elif choice == "configure_automation":
                self.configure_automation()
            else:
                print("\033[93m[-] Invalid choice. Options: add_data, query_db, generate_report, configure_automation, exit\033[0m")

def main():
    try:
        # Replace os.geteuid() with a cross-platform solution
        import platform
        is_admin = False
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os
            is_admin = os.geteuid() == 0
            
        if not is_admin:
            print("\033[91m[!] This script may require admin/root privileges for some operations. Run with elevated permissions if needed.\033[0m")
            # Continue execution for basic operations
    except Exception as e:
        print(f"\033[93m[!] Could not determine admin status: {e}. Proceeding anyway.\033[0m")
        
    tool = AutomatedQueryTool()
    tool.main_menu()

if __name__ == "__main__":
    main()