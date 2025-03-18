"""Nikto web vulnerability scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import random
import re

class NiktoScanner(BaseScanner):
    """Nikto web vulnerability scanner plugin"""
    
    def scan(self, target):
        """Run Nikto web vulnerability scan"""
        # Extract options with defaults
        stealth = self.options.get('stealth_mode', False)
        verbose = self.options.get('verbose', False)
        
        # Create temp file for output
        fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='nikto_')
        os.close(fd)
        
        try:
            # Build the command
            cmd = f"nikto -h {target} -o {output_file}"
            
            # Add stealth options
            if stealth:
                # Generate random user agent
                user_agents = [
                    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.{random.randint(1, 99)} (KHTML, like Gecko) Chrome/{random.randint(70, 90)}.0.{random.randint(1000, 9999)}.0 Safari/{random.randint(500, 600)}.{random.randint(1, 99)}",
                    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{random.randint(10, 15)}_{random.randint(1, 7)}) AppleWebKit/{random.randint(600, 610)}.{random.randint(1, 40)}.{random.randint(1, 99)} (KHTML, like Gecko) Version/{random.randint(10, 15)}.{random.randint(1, 7)} Safari/{random.randint(600, 610)}.{random.randint(1, 40)}.{random.randint(1, 99)}",
                    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/{random.randint(500, 600)}.{random.randint(1, 99)} (KHTML, like Gecko) Chrome/{random.randint(70, 90)}.0.{random.randint(1000, 9999)}.0 Safari/{random.randint(500, 600)}.{random.randint(1, 99)}"
                ]
                user_agent = random.choice(user_agents)
                cmd += f" -useragent \"{user_agent}\" -Tuning 123bde"
            
            # Run the command
            logging.info(f"Running Nikto scan on {target}")
            if verbose:
                print(f"\033[94m[*] Running Nikto scan on {target}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr
            }
            
            # Parse the output file
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    content = f.read()
                    
                    # Parse vulnerabilities - look for lines with vulnerability patterns
                    vuln_pattern = r"- .*: (.*)"
                    for match in re.finditer(vuln_pattern, content):
                        vuln_text = match.group(1)
                        
                        # Check for CVEs in the text
                        cve_pattern = r"(CVE-\d{4}-\d{4,7})"
                        cve_match = re.search(cve_pattern, vuln_text)
                        cve = cve_match.group(1) if cve_match else None
                        
                        # Add to vulnerabilities list
                        self.results['vulnerabilities'].append({
                            'script': 'nikto',
                            'port': 80,  # Default to HTTP port
                            'output': vuln_text,
                            'cve': cve
                        })
            
            if verbose:
                print(f"\033[92m[+] Nikto found {len(self.results['vulnerabilities'])} issues on {target}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Nikto scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(output_file):
                os.remove(output_file)