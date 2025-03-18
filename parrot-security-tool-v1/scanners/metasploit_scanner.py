"""Metasploit scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import re

class MetasploitScanner(BaseScanner):
    """Metasploit framework scanner plugin"""
    
    def scan(self, target):
        """Run Metasploit auxiliary scanners"""
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        
        # Create temp file for commands
        fd, rc_file = tempfile.mkstemp(suffix='.rc', prefix='msf_')
        os.close(fd)
        
        # Create temp file for output
        fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='msf_output_')
        os.close(fd)
        
        try:
            # Build MSF commands based on port information
            # For this we need ports info, which could come from a previous Nmap scan
            port_info = self.options.get('port_info', [])
            
            msf_commands = []
            
            # If we have port info, run targeted scanners
            if port_info:
                for port_data in port_info:
                    port = port_data.get('port')
                    service = port_data.get('service', '').lower()
                    
                    if service == 'ssh':
                        msf_commands.append(f"use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set RPORT {port}; run;")
                    elif service in ['http', 'https']:
                        msf_commands.append(f"use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT {port}; run;")
                        msf_commands.append(f"use auxiliary/scanner/http/dir_scanner; set RHOSTS {target}; set RPORT {port}; run;")
                    elif service == 'smb':
                        msf_commands.append(f"use auxiliary/scanner/smb/smb_version; set RHOSTS {target}; run;")
                    elif service == 'ftp':
                        msf_commands.append(f"use auxiliary/scanner/ftp/ftp_version; set RHOSTS {target}; set RPORT {port}; run;")
            else:
                # Without port info, run general scanners
                msf_commands.append(f"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run;")
                msf_commands.append(f"use auxiliary/scanner/discovery/udp_sweep; set RHOSTS {target}; run;")
            
            # Always add a general vulnerability scanner
            msf_commands.append(f"use auxiliary/scanner/http/http_vuln_scanner; set RHOSTS {target}; run;")
            
            # Add exit command
            msf_commands.append("exit")
            
            # Write commands to RC file
            with open(rc_file, 'w') as f:
                f.write("\n".join(msf_commands))
            
            # Build the command to run Metasploit
            cmd = f"msfconsole -q -r {rc_file} -o {output_file}"
                
            # Run the command
            logging.info(f"Running Metasploit scan on {target}")
            if verbose:
                print(f"\033[94m[*] Running Metasploit scan on {target}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'command': cmd,
                'raw_output': ''
            }
            
            # Read output file
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    content = f.read()
                    self.results['raw_output'] = content
                    
                    # Parse for vulnerabilities
                    vuln_patterns = [
                        r"Vulnerability found: (.*)",
                        r"is vulnerable to (.*)",
                        r"Found (.*) vulnerability"
                    ]
                    
                    for pattern in vuln_patterns:
                        for match in re.finditer(pattern, content):
                            vuln_text = match.group(1)
                            
                            # Check for CVEs
                            cve_pattern = r"(CVE-\d{4}-\d{4,7})"
                            cve_match = re.search(cve_pattern, vuln_text)
                            cve = cve_match.group(1) if cve_match else None
                            
                            # Extract port if available
                            port_pattern = r"port (\d+)"
                            port_match = re.search(port_pattern, vuln_text)
                            port = port_match.group(1) if port_match else 0
                            
                            self.results['vulnerabilities'].append({
                                'script': 'metasploit',
                                'port': port,
                                'output': vuln_text,
                                'cve': cve
                            })
            
            if verbose:
                print(f"\033[92m[+] Metasploit found {len(self.results['vulnerabilities'])} vulnerabilities on {target}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Metasploit scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp files
            for file in [rc_file, output_file]:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except Exception as e:
                        logging.warning(f"Could not delete temp file {file}: {str(e)}")