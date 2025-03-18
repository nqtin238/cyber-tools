"""John the Ripper password cracking scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import re

class JohnScanner(BaseScanner):
    """John the Ripper password cracking scanner plugin"""
    
    def scan(self, target):
        """Run John the Ripper password cracking"""
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        hash_file = self.options.get('hash_file')
        wordlist = self.options.get('wordlist', "/usr/share/wordlists/rockyou.txt")
        
        # Validate required parameters
        if not hash_file:
            logging.error("Hash file is required for John the Ripper")
            return {'error': "Hash file is required"}
            
        # Create temp file for output
        fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='john_')
        os.close(fd)
        
        try:
            # Check if hash file exists
            if not os.path.exists(hash_file):
                error_msg = f"Hash file {hash_file} not found"
                logging.error(error_msg)
                return {'error': error_msg}
            
            # Check if wordlist exists
            if not os.path.exists(wordlist):
                logging.warning(f"Wordlist {wordlist} not found. Using default.")
                wordlist = "/usr/share/wordlists/rockyou.txt"
            
            # Build the command
            cmd = f"john --wordlist={wordlist} {hash_file} --output={output_file}"
                
            # Run the command
            logging.info(f"Running John the Ripper with wordlist {wordlist}")
            if verbose:
                print(f"\033[94m[*] Running John the Ripper on {hash_file} with wordlist {wordlist}...\033[0m")
                
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Initialize results
            self.results = {
                'cracked_passwords': [],
                'command': cmd,
                'raw_output': result.stdout + result.stderr
            }
            
            # Check for cracked passwords
            show_cmd = f"john --show {hash_file}"
            show_result = subprocess.run(show_cmd, shell=True, capture_output=True, text=True)
            
            if show_result.stdout:
                # Parse cracked passwords
                for line in show_result.stdout.splitlines():
                    if line and ":" in line and not line.startswith("0 password"):
                        self.results['cracked_passwords'].append(line.strip())
            
            # Also check the output file
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Look for password patterns
                    password_pattern = r"([^\s:]+):([^\s:]+)"
                    for match in re.finditer(password_pattern, content):
                        credential = f"{match.group(1)}:{match.group(2)}"
                        if credential not in self.results['cracked_passwords']:
                            self.results['cracked_passwords'].append(credential)
            
            if verbose:
                print(f"\033[92m[+] John the Ripper cracked {len(self.results['cracked_passwords'])} passwords\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in John the Ripper scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except Exception as e:
                    logging.warning(f"Could not delete John output file {output_file}: {str(e)}")