"""Recommendation engine for providing actionable insights from scan results"""
import logging
import re
from typing import Dict, List, Any

# Import the ML vulnerability predictor
from utils.ml_prediction import MLVulnerabilityPredictor

class RecommendationEngine:
    """
    Generate actionable security recommendations based on scan results
    """
    
    def __init__(self):
        """Initialize the recommendation engine with knowledge base"""
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        # Initialize ML predictor
        self.ml_predictor = None
        try:
            self.ml_predictor = MLVulnerabilityPredictor()
        except Exception as e:
            logging.warning(f"Could not initialize ML predictor: {str(e)}")
            
        # Common vulnerabilities dictionary
        self.common_vulns = {
            # SSH vulnerabilities
            "ssh_weak_cipher": {
                "pattern": r"(?i)(ssh.*weak.*cipher|ssh.*obsolete|ssh.*deprecated)",
                "recommendation": "Update SSH configuration to disable weak ciphers. Edit /etc/ssh/sshd_config and use only strong ciphers.",
                "severity": "medium",
                "remediation": """
                1. Edit /etc/ssh/sshd_config
                2. Add or update: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
                3. Restart SSH service: systemctl restart sshd
                """
            },
            # Web vulnerabilities
            "outdated_apache": {
                "pattern": r"(?i)(apache.*2\.2\.|apache.*2\.0\.|apache.*1\.|outdated.*apache)",
                "recommendation": "Update Apache to the latest stable version to patch known vulnerabilities.",
                "severity": "high",
                "remediation": """
                1. Run: apt update && apt upgrade apache2
                2. Alternatively, consider installing from source with the latest version
                """
            },
            "outdated_nginx": {
                "pattern": r"(?i)(nginx\/1\.[0-9]\.|(outdated|old).*nginx)",
                "recommendation": "Update NGINX to the latest stable version to patch known vulnerabilities.",
                "severity": "high",
                "remediation": """
                1. Run: apt update && apt upgrade nginx
                2. For newer versions, consider using the official NGINX repository
                """
            },
            "sql_injection": {
                "pattern": r"(?i)(sql injection|sqli vulnerability|sql.*injectable)",
                "recommendation": "Fix SQL injection vulnerabilities by using parameterized queries or an ORM.",
                "severity": "critical",
                "remediation": """
                1. Replace direct SQL string concatenation with prepared statements
                2. Implement input validation
                3. Use an ORM like SQLAlchemy or Hibernate
                4. Consider using a web application firewall (WAF)
                """
            },
            # Open ports
            "unnecessary_open_ports": {
                "pattern": r"(?i)(port.*open|open.*port)",
                "recommendation": "Close unnecessary ports to reduce attack surface.",
                "severity": "medium",
                "remediation": """
                1. Identify required ports for your services
                2. Configure firewall to close other ports: ufw deny PORT/tcp
                3. Disable unnecessary services: systemctl disable SERVICE
                """
            },
            # Default credentials
            "default_credentials": {
                "pattern": r"(?i)(default.*credential|default.*password|login.*default)",
                "recommendation": "Change default credentials for all services and devices.",
                "severity": "critical",
                "remediation": """
                1. Identify all services with default credentials
                2. Change all default passwords with strong alternatives
                3. Implement password rotation policy
                4. Consider password manager for team use
                """
            },
            # SSL/TLS issues
            "ssl_tls_vulnerabilities": {
                "pattern": r"(?i)(tls.*1\.0|ssl.*3\.0|ssl.*2\.0|weak.*cipher|poodle|heartbleed|freak|beast|insecure.*negotiation)",
                "recommendation": "Configure secure SSL/TLS settings and disable vulnerable protocols.",
                "severity": "high",
                "remediation": """
                1. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
                2. Enable only TLS 1.2 and TLS 1.3
                3. Use secure cipher suites
                4. Test with tools like Qualys SSL Labs
                """
            },
            # Misconfigurations
            "directory_listing": {
                "pattern": r"(?i)(directory.*listing.*enabled|directory.*browsing.*enabled)",
                "recommendation": "Disable directory listing/browsing on web servers.",
                "severity": "medium",
                "remediation": """
                1. For Apache: Add 'Options -Indexes' to .htaccess or httpd.conf
                2. For NGINX: Remove 'autoindex on' from configuration
                """
            },
            # Missing patches
            "missing_patches": {
                "pattern": r"(?i)(missing.*patch|outdated.*software|security.*update)",
                "recommendation": "Apply security patches and updates to all systems and applications.",
                "severity": "high",
                "remediation": """
                1. Run: apt update && apt upgrade
                2. Enable automatic security updates
                3. Implement a patch management system
                """
            }
        }
    
    def generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate recommendations based on scan results
        
        Args:
            scan_results: Dictionary containing scan results
            
        Returns:
            List of recommendation dictionaries with action items
        """
        recommendations = []
        ml_predictions = {}
        
        # Process all targets in scan results
        for target, target_results in scan_results.items():
            target_recommendations = []
            
            # Check for CVEs
            cves = self._extract_cves(target_results)
            if cves:
                target_recommendations.append({
                    "title": f"Patch {len(cves)} CVE vulnerabilities",
                    "details": f"Address {len(cves)} CVE vulnerabilities: {', '.join(cves[:5])}{'...' if len(cves) > 5 else ''}",
                    "severity": "high",
                    "actions": [
                        "Apply vendor security patches",
                        "Update affected software to the latest version",
                        "Implement mitigations where patches are not available"
                    ]
                })
            
            # Extract service information for ML prediction
            target_services = self._extract_services(target_results)
            if self.ml_predictor and target_services:
                try:
                    # Get ML-based predictions
                    predictions = self.ml_predictor.predict_service_vulnerabilities(target_services)
                    ml_predictions[target] = predictions
                    
                    # Add ML-based recommendations
                    if predictions:
                        for pred in predictions:
                            if pred['probability'] > 0.5:  # Only add high confidence predictions
                                service = pred['service']
                                title = f"Address potential vulnerability in {service['name']} (ML predicted)"
                                
                                # Get potential CVEs if available
                                cve_details = ""
                                if pred.get('potential_cves'):
                                    cves_list = [cve['id'] for cve in pred['potential_cves'][:3]]
                                    if cves_list:
                                        cve_details = f" Potential CVEs: {', '.join(cves_list)}"
                                
                                target_recommendations.append({
                                    "title": title,
                                    "details": f"ML model detected a {pred['probability']:.1%} chance of vulnerability in {service['name']} {service.get('version', '')} on port {service.get('port')}.{cve_details}",
                                    "severity": "high" if pred['probability'] > 0.7 else "medium",
                                    "actions": [
                                        f"Update {service['name']} to the latest version",
                                        "Implement security hardening specific to this service",
                                        "Consider replacing with a more secure alternative if applicable"
                                    ],
                                    "ml_predicted": True
                                })
                except Exception as e:
                    logging.error(f"Error generating ML predictions: {str(e)}")
            
            # Process each scanner's results
            for scanner_name, scanner_results in target_results.items():
                # Skip if there was an error in the scan
                if isinstance(scanner_results, dict) and "error" in scanner_results:
                    continue
                
                # Process Nmap results for open ports
                if scanner_name == "NmapScanner" and isinstance(scanner_results, dict):
                    self._process_nmap_results(target, scanner_results, target_recommendations)
                
                # Process vulnerability scanner results
                if "vulnerabilities" in scanner_results and isinstance(scanner_results["vulnerabilities"], list):
                    for vuln in scanner_results["vulnerabilities"]:
                        self._process_vulnerability(target, vuln, target_recommendations)
                
                # Process raw output for general patterns
                if "raw_output" in scanner_results and isinstance(scanner_results["raw_output"], str):
                    self._process_raw_output(target, scanner_results["raw_output"], target_recommendations)
            
            # Add target-specific recommendations to the main list
            for rec in target_recommendations:
                rec["target"] = target
                recommendations.append(rec)
            
        # Add general recommendations if certain scanners were used
        if any("SQLMapScanner" in target_results for target_results in scan_results.values()):
            recommendations.append({
                "title": "Implement Web Application Firewall",
                "details": "A Web Application Firewall can provide an additional layer of protection against SQL injection and other web application attacks.",
                "severity": "medium",
                "actions": [
                    "Consider deploying ModSecurity or similar WAF",
                    "Configure rules to block common attack patterns",
                    "Monitor WAF logs for potential attacks"
                ],
                "target": "general"
            })
        
        # If ML predictor provided risk assessments, add overall risk recommendations
        if ml_predictions and self.ml_predictor:
            high_risk_targets = []
            for target, predictions in ml_predictions.items():
                if predictions and any(pred['probability'] > 0.7 for pred in predictions):
                    high_risk_targets.append(target)
                    
            if high_risk_targets:
                recommendations.append({
                    "title": "Prioritize remediation based on ML risk assessment",
                    "details": f"ML model identified {len(high_risk_targets)} high-risk targets that should be prioritized for security remediation.",
                    "severity": "high",
                    "actions": [
                        f"Focus immediate remediation on: {', '.join(high_risk_targets[:5])}{'...' if len(high_risk_targets) > 5 else ''}",
                        "Consider isolating these systems until vulnerabilities are addressed",
                        "Implement more frequent security scans for high-risk systems"
                    ],
                    "target": "general",
                    "ml_predicted": True
                })
            
        # Sort recommendations by severity
        return sorted(recommendations, key=lambda x: self._severity_value(x["severity"]), reverse=True)
    
    def _extract_services(self, target_results):
        """Extract service information from scan results for ML prediction"""
        services = []
        
        # Process each scanner's results
        for scanner_name, scanner_results in target_results.items():
            # Skip if not a dictionary
            if not isinstance(scanner_results, dict):
                continue
            
            # Extract services from Nmap results
            if scanner_name == "NmapScanner" and "ports" in scanner_results:
                for port_info in scanner_results["ports"]:
                    services.append({
                        'name': port_info.get('service', 'unknown'),
                        'version': port_info.get('version', ''),
                        'port': port_info.get('port', 0)
                    })
        
        return services
    
    def generate_risk_assessment(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive risk assessment using both rule-based and ML techniques
        
        Args:
            scan_results: Dictionary containing scan results
            
        Returns:
            Dictionary with risk assessment results
        """
        if not self.ml_predictor:
            return {"error": "ML predictor not available"}
            
        risk_assessment = {}
        
        # Process each target
        for target, target_results in scan_results.items():
            # Prepare target data for ML assessment
            target_data = {
                'ip': target,
                'ports': []
            }
            
            # Extract OS info if available
            if "NmapScanner" in target_results and "os_info" in target_results["NmapScanner"]:
                target_data['os'] = target_results["NmapScanner"]["os_info"].get("name", "Unknown")
            
            # Extract ports and services
            services = self._extract_services(target_results)
            if services:
                target_data['ports'] = services
                
                # Get risk assessment from ML predictor
                assessment = self.ml_predictor.assess_target_risk(target_data)
                risk_assessment[target] = assessment
        
        return risk_assessment
    
    def _severity_value(self, severity):
        """Helper to convert severity string to numeric value for sorting"""
        severity_map = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        return severity_map.get(severity.lower(), 0)
    
    def _extract_cves(self, results):
        """Extract CVE IDs from scan results"""
        cves = set()
        
        # Process each scanner's results
        for scanner_name, scanner_results in results.items():
            # Skip if not a dictionary 
            if not isinstance(scanner_results, dict):
                continue
                
            # Check for vulnerabilities list
            if "vulnerabilities" in scanner_results and isinstance(scanner_results["vulnerabilities"], list):
                for vuln in scanner_results["vulnerabilities"]:
                    if "cve" in vuln and vuln["cve"]:
                        cves.add(vuln["cve"])
            
            # Check in raw output
            if "raw_output" in scanner_results and isinstance(scanner_results["raw_output"], str):
                cve_matches = self.cve_pattern.findall(scanner_results["raw_output"])
                cves.update(cve_matches)
        
        return list(cves)
    
    def _process_nmap_results(self, target, nmap_results, recommendations):
        """Process Nmap scan results for recommendations"""
        # Check for open ports
        if "ports" in nmap_results and isinstance(nmap_results["ports"], list):
            open_ports = nmap_results["ports"]
            if len(open_ports) > 10:
                recommendations.append({
                    "title": f"Reduce exposed services on {target}",
                    "details": f"Found {len(open_ports)} open ports which increases attack surface",
                    "severity": "medium",
                    "actions": [
                        "Review necessary services and disable unused ones",
                        "Implement firewall rules to restrict access to required ports only",
                        "Consider using port knocking for sensitive services"
                    ]
                })
            
            # Check for specific sensitive services
            sensitive_services = ["ftp", "telnet", "rsh", "rexec", "rlogin"]
            found_sensitive = [p for p in open_ports if any(s in p.get("service", "").lower() for s in sensitive_services)]
            
            if found_sensitive:
                recommendations.append({
                    "title": f"Replace insecure services on {target}",
                    "details": f"Found potentially insecure services: {', '.join([p.get('service', '') for p in found_sensitive])}",
                    "severity": "high",
                    "actions": [
                        "Replace FTP with SFTP or FTPS",
                        "Replace Telnet with SSH",
                        "Replace RSH/Rexec/Rlogin with SSH",
                        "Implement encrypted alternatives to legacy protocols"
                    ]
                })
    
    def _process_vulnerability(self, target, vuln, recommendations):
        """Process individual vulnerability findings"""
        # Skip if already handled as CVE
        if "cve" in vuln and vuln["cve"]:
            return
            
        # Process based on output or description
        if "output" in vuln and vuln["output"]:
            self._match_known_patterns(target, vuln["output"], recommendations)
        elif "description" in vuln and vuln["description"]:
            self._match_known_patterns(target, vuln["description"], recommendations)
    
    def _process_raw_output(self, target, raw_output, recommendations):
        """Process raw output text for known vulnerability patterns"""
        self._match_known_patterns(target, raw_output, recommendations)
    
    def _match_known_patterns(self, target, text, recommendations):
        """Match text against known vulnerability patterns"""
        for vuln_id, vuln_info in self.common_vulns.items():
            if re.search(vuln_info["pattern"], text):
                # Check if we already have this recommendation
                if not any(r["title"] == vuln_info["recommendation"] for r in recommendations):
                    recommendations.append({
                        "title": vuln_info["recommendation"],
                        "details": f"Found potential {vuln_id.replace('_', ' ')} vulnerability",
                        "severity": vuln_info["severity"],
                        "actions": vuln_info["remediation"].strip().split("\n"),
                    })

def get_recommendations_for_results(scan_results):
    """Helper function to get recommendations from scan results"""
    engine = RecommendationEngine()
    return engine.generate_recommendations(scan_results)

def get_risk_assessment_for_results(scan_results):
    """Helper function to get ML-based risk assessment from scan results"""
    engine = RecommendationEngine()
    return engine.generate_risk_assessment(scan_results)
