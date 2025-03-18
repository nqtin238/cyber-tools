"""Enhanced HTML reporting module"""
import os
import logging
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class EnhancedHTMLReport:
    """Generate enhanced HTML reports with interactive elements"""
    
    def __init__(self, db_connection):
        """Initialize with database connection"""
        self.conn = db_connection
        self.cursor = db_connection.cursor()
        self.setup_templates()
        
    def setup_templates(self):
        """Setup Jinja2 templates directory and HTML template"""
        os.makedirs("templates", exist_ok=True)
        
        # Check if template exists (we created it in step 4)
        if not os.path.exists("templates/enhanced_report.html"):
            logging.error("Enhanced report template not found")
            
        self.env = Environment(loader=FileSystemLoader("templates"))
        
    def generate_report(self):
        """Generate enhanced HTML report from database data"""
        # Create reports directory if it doesn't exist
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"reports/enhanced_report_{timestamp}.html"
        
        # Fetch targets
        self.cursor.execute("SELECT id, ip, mac, os, version, scan_timestamp FROM targets")
        targets_raw = self.cursor.fetchall()
        
        targets = []
        for target in targets_raw:
            target_id, ip, mac, os_name, version, scan_timestamp = target
            
            # Fetch ports for this target
            self.cursor.execute("SELECT port, service FROM ports WHERE target_id = ?", (target_id,))
            ports_raw = self.cursor.fetchall()
            ports = [f"{port[0]}/{port[1]}" for port in ports_raw]
            
            targets.append({
                'id': target_id,
                'ip': ip,
                'mac': mac,
                'os': os_name,
                'version': version,
                'scan_timestamp': scan_timestamp,
                'ports': ports
            })
        
        # Fetch vulnerabilities
        self.cursor.execute("""
            SELECT t.ip, v.port, v.script, v.output, v.cve, v.score, v.description, v.timestamp
            FROM vulnerabilities v
            JOIN targets t ON v.target_id = t.id
        """)
        vulnerabilities_raw = self.cursor.fetchall()
        
        vulnerabilities = []
        for vuln in vulnerabilities_raw:
            ip, port, script, output, cve, score, description, timestamp = vuln
            vulnerabilities.append({
                'ip': ip,
                'port': port,
                'script': script,
                'output': output,
                'cve': cve,
                'score': score or 0,
                'description': description,
                'timestamp': timestamp
            })
        
        # Fetch test results
        self.cursor.execute("""
            SELECT t.ip, tr.test_name, tr.result, tr.timestamp
            FROM test_results tr
            JOIN targets t ON tr.target_id = t.id
        """)
        test_results_raw = self.cursor.fetchall()
        
        test_results = []
        for result in test_results_raw:
            ip, test_name, result_text, timestamp = result
            test_results.append({
                'ip': ip,
                'test_name': test_name,
                'result': result_text,
                'timestamp': timestamp
            })
        
        # Calculate summary statistics
        high_count = sum(1 for v in vulnerabilities if v['score'] >= 7.0)
        medium_count = sum(1 for v in vulnerabilities if 4.0 <= v['score'] < 7.0)
        low_count = sum(1 for v in vulnerabilities if v['score'] < 4.0)
        
        # Get most vulnerable systems
        vuln_counts = {}
        for vuln in vulnerabilities:
            ip = vuln['ip']
            vuln_counts[ip] = vuln_counts.get(ip, 0) + 1
        
        top_vulnerable_systems = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Render the template with data
        template = self.env.get_template("enhanced_report.html")
        report_html = template.render(
            timestamp=datetime.now().isoformat(),
            targets=targets,
            vulnerabilities=vulnerabilities,
            test_results=test_results,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            top_vulnerable_systems=top_vulnerable_systems
        )
        
        # Write the report to file
        with open(report_file, "w") as f:
            f.write(report_html)
            
        logging.info(f"Enhanced HTML report generated: {report_file}")
        print(f"\033[92m[+] Enhanced HTML report generated: {report_file}\033[0m")
        
        return report_file

    def generate_json(self, output_file):
        """
        Export the report data as a JSON file.
        """
        report_data = {
            "targets": targets,
            "vulnerabilities": vulnerabilities,
            "test_results": test_results,
            "summary": {
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "top_vulnerable_systems": top_vulnerable_systems,
            },
        }
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=4)
        logging.info(f"Report exported as JSON: {output_file}")