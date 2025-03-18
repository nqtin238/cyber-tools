"""Netcat scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import re
import random

class NetcatScanner(BaseScanner):
    """Netcat port scanner plugin"""
    
    def scan(self, target):
        """Run netcat port scan"""
        # Extract options with defaults
        port_range = self.options.get('port_range', '1-1024')
        stealth = self.options.get('stealth_mode', False)
        verbose = self.options.get('verbose', False)
        
        try:
            # Build the command
            cmd = f"nc -z -nv {target} {port_range}"
            
            if stealth:
                # Add a random wait time if in stealth mode
                cmd += f" -w {random.uniform(1, 3)}"
                
            # Run the command
            logging.info(f"Running Netcat scan on {target} (ports {port_range})")
            if verbose:
                print(f"\033[94m[*] Running Netcat scan on {target}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse the output for open ports
            open_ports = []
            if result.stderr:  # Netcat outputs to stderr
                # Look for successful connections
                port_pattern = r"Connection to .* (\d+) port .* succeeded!"
                for match in re.finditer(port_pattern, result.stderr):
                    port = match.group(1)
                    open_ports.append({
                        'port': port,
                        'service': 'unknown',  # Netcat doesn't identify services
                        'version': 'unknown'
                    })
            
            self.results = {
                'ports': open_ports,
                'command': cmd,
                'raw_output': result.stderr + result.stdout
            }
            
            if verbose:
                print(f"\033[92m[+] Netcat found {len(open_ports)} open ports on {target}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Netcat scan: {str(e)}")
            return {'error': str(e)}