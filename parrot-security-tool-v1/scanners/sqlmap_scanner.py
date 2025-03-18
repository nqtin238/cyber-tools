"""SQLMap SQL injection scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import random
import json
import re

class SQLMapScanner(BaseScanner):
    """SQLMap SQL injection scanner plugin"""
    
    def scan(self, target):
        """Run SQLMap scan for SQL injection vulnerabilities"""
        # Extract options with defaults
        stealth = self.options.get('stealth_mode', False)
        verbose = self.options.get('verbose', False)
        
        # Create temp directory for output
        output_dir = tempfile.mkdtemp(prefix='sqlmap_')
        
        try:
            # Build the command
            cmd = f"sqlmap -u http://{target} --batch --output-dir={output_dir} --json-output"
            
            # Add stealth options
            if stealth:
                # Generate random user agent
                user_agents = [
                    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.{random.randint(1, 99)} (KHTML, like Gecko) Chrome/{random.randint(70, 90)}.0.{random.randint(1000, 9999)}.0 Safari/{random.randint(500, 600)}.{random.randint(1, 99)}",
                    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{random.randint(10, 15)}_{random.randint(1, 7)}) AppleWebKit/{random.randint(600, 610)}.{random.randint(1, 40)}.{random.randint(1, 99)} (KHTML, like Gecko) Version/{random.randint(10, 15)}.{random.randint(1, 7)} Safari/{random.randint(600, 610)}.{random.randint(1, 40)}.{random.randint(1, 99)}",
                    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/{random.randint(500, 600)}.{random.randint(1, 99)} (KHTML, like Gecko) Chrome/{random.randint(70, 90)}.0.{random.randint(1000, 9999)}.0 Safari/{random.randint(500, 600)}.{random.randint(1, 99)}"
                ]
                user_agent = random.choice(user_agents)
                delay = random.uniform(0.5, 2)
                cmd += f" --user-agent=\"{user_agent}\" --delay={delay} --random-agent --safe-freq {random.randint(2, 5)}"
            
            # Run the command
            logging.info(f"Running SQLMap scan on {target}")
            if verbose:
                print(f"\033[94m[*] Running SQLMap scan on {target}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr
            }
            
            # Check for SQLMap JSON output file
            target_dir = os.path.join(output_dir, target.replace(':', '_'))
            json_file = os.path.join(target_dir, 'log')
            
            if os.path.exists(json_file):
                try:
                    with open(json_file, 'r') as f:
                        sqlmap_data = json.load(f)
                        
                    # Process data for vulnerabilities
                    if 'data' in sqlmap_data and sqlmap_data['data']:
                        for vuln_type, details in sqlmap_data['data'].items():
                            if details and isinstance(details, dict) and details.get('1', {}).get('status') == 1:
                                self.results['vulnerabilities'].append({
                                    'script': 'sqlmap',
                                    'port': 80,  # Default to HTTP port
                                    'output': f"SQL Injection vulnerability of type {vuln_type} detected",
                                    'cve': None  # SQLMap doesn't typically report CVEs
                                })
                except Exception as e:
                    logging.error(f"Error parsing SQLMap JSON output: {str(e)}")
            
            # Also check for standard output indicators of vulnerabilities
            if "is vulnerable" in result.stdout or "appears to be" in result.stdout:
                # Extract the specific vulnerability type using regex
                vuln_pattern = r"(GET|POST).*is vulnerable to ([^ ]+)"
                match = re.search(vuln_pattern, result.stdout)
                if match:
                    vuln_type = match.group(2)
                    
                    # Add to vulnerabilities if not already added
                    if not any(v['output'].find(vuln_type) >= 0 for v in self.results['vulnerabilities']):
                        self.results['vulnerabilities'].append({
                            'script': 'sqlmap',
                            'port': 80,  # Default to HTTP port
                            'output': f"SQL Injection vulnerability of type {vuln_type} detected",
                            'cve': None
                        })
            
            if verbose:
                print(f"\033[92m[+] SQLMap found {len(self.results['vulnerabilities'])} SQL injection vulnerabilities on {target}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in SQLMap scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up output directory
            try:
                import shutil
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception as e:
                logging.warning(f"Error cleaning up SQLMap temp directory: {str(e)}")