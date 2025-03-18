"""Lynis security auditing scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import re

class LynisScanner(BaseScanner):
    """Lynis security auditing scanner plugin"""
    
    def scan(self, target):
        """Run Lynis security audit scan"""
        # Note: Lynis typically runs on the local system
        # For remote systems, you'd need to run it via SSH or other methods
        
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        
        # Create temp file for output
        fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='lynis_')
        os.close(fd)
        
        try:
            # Check if target is localhost or local IP
            is_local = target in ['127.0.0.1', 'localhost', '::1']
            
            if not is_local:
                logging.warning(f"Lynis typically runs on localhost. Target {target} may not be accessible.")
                if verbose:
                    print(f"\033[93m[!] Warning: Lynis typically runs on localhost. Target {target} may not be accessible.\033[0m")
            
            # Build the command
            cmd = f"lynis audit system --report-file {output_file}"
                
            # Run the command
            logging.info(f"Running Lynis security audit")
            if verbose:
                print(f"\033[94m[*] Running Lynis security audit...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'vulnerabilities': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr,
                'warnings': [],
                'suggestions': []
            }
            
            # Parse the output
            warning_pattern = r"(\[\s*WARNING\s*\])\s*(.*)"
            suggestion_pattern = r"(\[\s*SUGGESTION\s*\])\s*(.*)"
            
            for line in result.stdout.splitlines():
                # Extract warnings
                warning_match = re.search(warning_pattern, line)
                if warning_match:
                    self.results['warnings'].append(warning_match.group(2).strip())
                    
                    # Add severe warnings as vulnerabilities
                    if "Critical" in line or "High" in line:
                        self.results['vulnerabilities'].append({
                            'script': 'lynis',
                            'port': 0,  # Not port specific
                            'output': warning_match.group(2).strip(),
                            'cve': None  # Lynis doesn't typically report CVEs directly
                        })
                
                # Extract suggestions
                suggestion_match = re.search(suggestion_pattern, line)
                if suggestion_match:
                    self.results['suggestions'].append(suggestion_match.group(2).strip())
            
            # Read report file for more details if available
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    self.results['report'] = f.read()
            
            if verbose:
                print(f"\033[92m[+] Lynis found {len(self.results['warnings'])} warnings and {len(self.results['suggestions'])} suggestions\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in Lynis scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except Exception as e:
                    logging.warning(f"Could not delete Lynis output file {output_file}: {str(e)}")