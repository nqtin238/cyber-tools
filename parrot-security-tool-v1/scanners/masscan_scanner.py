"""Masscan scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import re

class MasscanScanner(BaseScanner):
    """Masscan port scanner plugin"""
    
    def scan(self, target):
        """Run masscan scan"""
        # Extract options with defaults
        port_range = self.options.get('port_range', '1-1024')
        stealth = self.options.get('stealth_mode', False)
        verbose = self.options.get('verbose', False)
        
        # Create temp file for output
        fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='masscan_')
        os.close(fd)
        
        try:
            # Build the command
            rate = random.uniform(100, 500) if stealth else 1000
            cmd = f"masscan {target} -p {port_range} --rate {rate} -oL {output_file}"
            
            if stealth:
                cmd += " --wait 2 --randomize-hosts"
                
            # Run the command
            logging.info(f"Running Masscan on {target} (ports {port_range})")
            if verbose:
                print(f"\033[94m[*] Running Masscan on {target}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse the output
            self.results = {
                'ports': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr
            }
            
            # Read output file and parse results
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    for line in f:
                        # Skip comments
                        if line.startswith('#'):
                            continue
                            
                        # Parse line - format is: ip,port,proto,service,...
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            port = parts[1]
                            protocol = parts[2]
                            self.results['ports'].append({
                                'port': port,
                                'protocol': protocol,
                                'service': 'unknown',  # Masscan doesn't do service detection
                                'version': 'unknown'
                            })
            
            if verbose:
                print(f"\033[92m[+] Masscan found {len(self.results['ports'])} open ports on {target}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Masscan scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(output_file):
                os.remove(output_file)