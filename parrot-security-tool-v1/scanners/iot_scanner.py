"""IoT device security scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import re
import tempfile
import os
import json
import requests

class IoTScanner(BaseScanner):
    """Scanner for IoT devices and related vulnerabilities"""
    
    def scan(self, target):
        """Run scans targeted at IoT devices and protocols"""
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        port_range = self.options.get('port_range', '1-10000')
        stealth_mode = self.options.get('stealth_mode', False)
        
        try:
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'devices': [],
                'protocols': {},
                'raw_output': '',
                'command': ''
            }
            
            # Common IoT ports and protocols to check
            iot_ports = {
                '1883': 'MQTT',
                '5683': 'CoAP',
                '8883': 'MQTT over TLS',
                '9000': 'UPnP',
                '80': 'HTTP',
                '443': 'HTTPS',
                '23': 'Telnet',
                '22': 'SSH',
                '25': 'SMTP',
                '5900': 'VNC',
                '8080': 'HTTP Alt',
                '4433': 'HTTPS Alt',
                '9443': 'HTTPS Alt',
                '2323': 'Telnet Alt',
                '4786': 'Cisco Smart Install',
                '37777': 'Dahua DVR',
                '49152': 'UPnP'
            }
            
            # Create temp file for nmap output
            fd, xml_output = tempfile.mkstemp(suffix='.xml', prefix='iot_scan_')
            os.close(fd)
            
            # Step 1: Scan for common IoT ports
            iot_port_list = ','.join(iot_ports.keys())
            nmap_cmd = f"nmap -p {iot_port_list} -sV --script discovery,vuln {target} -oX {xml_output}"
            
            if stealth_mode:
                nmap_cmd += " -T2 --max-retries 1 --scan-delay 2s"
                
            self.results['command'] = nmap_cmd
            if verbose:
                print(f"\033[94m[*] Scanning for IoT devices on {target}...\033[0m")
                
            nmap_result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)
            self.results['raw_output'] += f"Nmap IoT scan:\n{nmap_result.stdout}\n{nmap_result.stderr}\n\n"
            
            # Parse nmap XML output
            if os.path.exists(xml_output):
                self._parse_nmap_output(xml_output, target, iot_ports)
                
            # Step 2: Check for UPnP devices
            upnp_cmd = f"nmap -p 1900 -sU --script=upnp-info {target}"
            self.results['command'] += f"\n{upnp_cmd}"
            
            upnp_result = subprocess.run(upnp_cmd, shell=True, capture_output=True, text=True)
            self.results['raw_output'] += f"UPnP scan:\n{upnp_result.stdout}\n{upnp_result.stderr}\n\n"
            
            # Extract UPnP device information
            upnp_pattern = r"Server: (.*?)(?:\r?\n|\r|$)"
            for match in re.finditer(upnp_pattern, upnp_result.stdout):
                device_info = match.group(1).strip()
                if device_info and not any(d.get('name') == device_info for d in self.results['devices']):
                    self.results['devices'].append({
                        'name': device_info,
                        'type': 'UPnP Device',
                        'port': 1900,
                        'protocol': 'UPnP'
                    })
            
            # Step 3: Search for common IoT default credentials
            self._check_default_credentials(target)
            
            # Step 4: Check for specific IoT CVEs
            self._check_iot_cves(target)
            
            if verbose:
                print(f"\033[92m[+] Identified {len(self.results['devices'])} IoT devices and {len(self.results['vulnerabilities'])} vulnerabilities\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in IoT scanning: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temporary files
            if os.path.exists(xml_output):
                os.remove(xml_output)
    
    def _parse_nmap_output(self, xml_file, target, iot_ports):
        """Parse Nmap XML output to extract IoT device information"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    if port.find('state').get('state') != 'open':
                        continue
                        
                    port_id = port.get('portid')
                    service = port.find('service')
                    
                    if not service:
                        continue
                        
                    service_name = service.get('name', '')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    # Check if this is likely an IoT service
                    is_iot = False
                    device_type = "Unknown"
                    
                    # Check against known IoT ports
                    if port_id in iot_ports:
                        is_iot = True
                        protocol = iot_ports[port_id]
                        self.results['protocols'][protocol] = self.results['protocols'].get(protocol, 0) + 1
                    
                    # Check product name for IoT indicators
                    iot_keywords = ['cam', 'dvr', 'router', 'gateway', 'iot', 'smart', 'sensor', 
                                    'thermostat', 'home', 'nest', 'ring', 'hub', 'wemo', 'hue']
                    
                    for keyword in iot_keywords:
                        if keyword.lower() in product.lower():
                            is_iot = True
                            device_type = product
                            break
                    
                    if is_iot:
                        device_info = {
                            'port': port_id,
                            'service': service_name,
                            'name': product,
                            'version': version,
                            'type': device_type
                        }
                        
                        # Check if we've already added this device
                        if not any(d.get('name') == product and d.get('port') == port_id for d in self.results['devices']):
                            self.results['devices'].append(device_info)
                    
                    # Check for vulnerabilities in scripts
                    for script in port.findall('.//script'):
                        if 'vuln' in script.get('id', ''):
                            output = script.get('output', '')
                            
                            # Extract CVE if present
                            cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', output)
                            cve = cve_match.group(1) if cve_match else None
                            
                            self.results['vulnerabilities'].append({
                                'port': port_id,
                                'script': script.get('id', ''),
                                'output': output,
                                'cve': cve
                            })
        except Exception as e:
            logging.error(f"Error parsing Nmap output: {str(e)}")
    
    def _check_default_credentials(self, target):
        """Check for default credentials on common IoT services"""
        # Common default credential pairs
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('root', ''),
            ('admin', '1234'),
            ('admin', '12345'),
            ('admin', 'admin1234'),
        ]
        
        # Check for web interfaces
        web_ports = ['80', '8080', '443', '8443']
        for port in web_ports:
            for username, password in default_creds:
                try:
                    protocol = 'https' if port in ['443', '8443'] else 'http'
                    url = f"{protocol}://{target}:{port}/login"
                    
                    # Very simple check - just see if the URL exists
                    try:
                        response = requests.get(url, timeout=3, verify=False)
                        
                        # If we get a login page, report it
                        if response.status_code == 200 and ('login' in response.text.lower() or 'password' in response.text.lower()):
                            self.results['vulnerabilities'].append({
                                'port': port,
                                'script': 'default-creds',
                                'output': f"Potential default credentials check needed: {url}",
                                'cve': None
                            })
                            break  # Only report once per port
                    except:
                        pass
                except Exception as e:
                    continue
    
    def _check_iot_cves(self, target):
        """Check for specific IoT-related CVEs"""
        # List of IoT-specific CVE checks
        iot_cve_checks = [
            {
                'cve': 'CVE-2017-8225',
                'description': 'IP Camera Authentication Bypass',
                'ports': ['80', '8080', '443', '8443'],
                'check_command': f"curl -s -m 3 http://{target}:%PORT%/system.ini?loginuse&loginpas"
            },
            {
                'cve': 'CVE-2019-11477',
                'description': 'TCP SACK Panic (affects Linux-based IoT devices)',
                'ports': ['22'],
                'check_command': f"nmap -p 22 --script ssh-auth-methods {target}"
            },
            {
                'cve': 'CVE-2019-12780',
                'description': 'ZeroShell Auth Bypass',
                'ports': ['80', '443'],
                'check_command': f"curl -s -m 3 http://{target}:%PORT%/cgi-bin/kerbynet?Action=StartSessionSubmit&User=&PW="
            }
        ]
        
        # Run checks
        for cve_check in iot_cve_checks:
            for port in cve_check['ports']:
                cmd = cve_check['check_command'].replace('%PORT%', port)
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                    
                    # Very basic detection - if we got output and no error, consider it vulnerable
                    # In a real implementation, you'd need more sophisticated checks
                    if result.returncode == 0 and result.stdout and not "not found" in result.stdout.lower():
                        self.results['vulnerabilities'].append({
                            'port': port,
                            'script': 'iot-cve-check',
                            'output': f"Potentially vulnerable to {cve_check['description']}",
                            'cve': cve_check['cve']
                        })
                except:
                    # Timeout or other error, skip this check
                    continue