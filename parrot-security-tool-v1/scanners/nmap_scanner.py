"""Nmap scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import xml.etree.ElementTree as ET
import os
import tempfile

class NmapScanner(BaseScanner):
    """Nmap vulnerability scanner plugin"""
    
    def __init__(self, options=None):
        super().__init__(options)
        self.metadata = {
            "name": "NmapScanner",
            "description": "Performs network scans using Nmap",
            "supported_protocols": ["TCP", "UDP"],
            "expected_runtime": "Medium",
        }
    
    def scan(self, target):
        """Run nmap vulnerability scan"""
        # Extract options with defaults
        port_range = self.options.get('port_range', '1-1024')
        stealth = self.options.get('stealth_mode', False)
        
        # Create temp file for XML output
        fd, xml_output = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
        os.close(fd)
        
        try:
            # Build the command
            cmd = f"nmap -p {port_range} -sV --script vuln {target} -oX {xml_output}"
            if stealth:
                cmd += " -T2 --max-retries 1 --scan-delay 1s --spoof-mac 0"
                
            # Run the command
            logging.info(f"Running Nmap scan on {target}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse the XML output
            self.results = {'ports': [], 'vulnerabilities': []}
            
            if result.returncode == 0 and os.path.exists(xml_output):
                self._parse_xml_output(xml_output, target)
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Nmap scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(xml_output):
                os.remove(xml_output)
                
    def _parse_xml_output(self, xml_file, target):
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                # Parse port data
                for port in host.findall('.//port'):
                    state = port.find('state').get('state')
                    if state != 'open':
                        continue
                        
                    port_id = port.get('portid')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    service_version = service.get('version') if service is not None and service.get('version') else 'unknown'
                    
                    self.results['ports'].append({
                        'port': port_id,
                        'service': service_name,
                        'version': service_version
                    })
                    
                    # Parse vulnerabilities from scripts
                    for script in port.findall('.//script'):
                        script_id = script.get('id')
                        if 'vuln' in script_id.lower():
                            output = script.get('output')
                            cve = None
                            
                            # Extract CVE if available
                            if output and 'CVE-' in output:
                                cve_start = output.find('CVE-')
                                cve_end = output.find(' ', cve_start)
                                if cve_end == -1:
                                    cve_end = output.find('\n', cve_start)
                                if cve_end != -1:
                                    cve = output[cve_start:cve_end].strip()
                                    
                            self.results['vulnerabilities'].append({
                                'port': port_id,
                                'script': script_id,
                                'output': output,
                                'cve': cve
                            })
        except Exception as e:
            logging.error(f"Error parsing Nmap XML: {str(e)}")