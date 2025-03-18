"""Chkrootkit rootkit detection scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import re

class ChkrootkitScanner(BaseScanner):
    """Chkrootkit rootkit detection scanner plugin"""
    
    def scan(self, target):
        """Run chkrootkit rootkit detection scan"""
        # Note: chkrootkit runs on the local system
        
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        
        try:
            # Check if target is localhost or local IP
            is_local = target in ['127.0.0.1', 'localhost', '::1']
            
            if not is_local:
                logging.warning(f"Chkrootkit runs on localhost. Target {target} will be ignored.")
                if verbose:
                    print(f"\033[93m[!] Warning: Chkrootkit runs on localhost. Target {target} will be ignored.\033[0m")
            
            # Build the command
            cmd = "chkrootkit"
                
            # Run the command
            logging.info("Running Chkrootkit rootkit detection scan")
            if verbose:
                print(f"\033[94m[*] Running Chkrootkit rootkit detection scan...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr,
                'infected': [],
                'suspicious': []
            }
            
            # Parse the output for infected or suspicious items
            for line in result.stdout.splitlines():
                # Check for INFECTED patterns
                if "INFECTED" in line:
                    self.results['infected'].append(line.strip())
                    
                    # Add as a vulnerability
                    self.results['vulnerabilities'].append({
                        'script': 'chkrootkit',
                        'port': 0,  # Not port specific
                        'output': line.strip(),
                        'cve': None  # Chkrootkit doesn't report CVEs
                    })
                
                # Check for suspicious patterns
                elif "suspicious" in line.lower():
                    self.results['suspicious'].append(line.strip())
            
            if verbose:
                print(f"\033[92m[+] Chkrootkit found {len(self.results['infected'])} infections and {len(self.results['suspicious'])} suspicious items\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Chkrootkit scan: {str(e)}")
            return {'error': str(e)}