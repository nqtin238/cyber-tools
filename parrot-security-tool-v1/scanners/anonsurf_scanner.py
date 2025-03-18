"""AnonSurf anonymity status scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import re
import requests

class AnonSurfScanner(BaseScanner):
    """AnonSurf anonymity status checker plugin"""
    
    def scan(self, target):
        """Check AnonSurf and Tor status"""
        # Note: AnonSurf checks are mostly about the local system's anonymity status
        
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        
        try:
            # Initialize results
            self.results = {
                'anonymity_status': 'Unknown',
                'anonsurf_running': False,
                'tor_running': False,
                'public_ip': None,
                'tor_ip': None,
                'raw_output': ''
            }
            
            # Check AnonSurf status
            anonsurf_cmd = "anonsurf status"
            anonsurf_result = subprocess.run(anonsurf_cmd, shell=True, capture_output=True, text=True)
            self.results['raw_output'] += f"AnonSurf Status:\n{anonsurf_result.stdout}\n{anonsurf_result.stderr}\n\n"
            
            # Check if AnonSurf is running
            if "activated" in anonsurf_result.stdout.lower() or "started" in anonsurf_result.stdout.lower():
                self.results['anonsurf_running'] = True
                self.results['anonymity_status'] = 'AnonSurf Active'
            
            # Check real IP
            try:
                ip_response = requests.get("https://api.ipify.org", timeout=5)
                self.results['public_ip'] = ip_response.text
            except Exception as e:
                logging.error(f"Error checking public IP: {str(e)}")
            
            # Check Tor IP if AnonSurf is running
            if self.results['anonsurf_running']:
                try:
                    tor_cmd = "anonsurf myip"
                    tor_result = subprocess.run(tor_cmd, shell=True, capture_output=True, text=True)
                    self.results['raw_output'] += f"Tor IP Check:\n{tor_result.stdout}\n{tor_result.stderr}\n\n"
                    
                    # Extract IP from output
                    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                    ip_match = re.search(ip_pattern, tor_result.stdout)
                    if ip_match:
                        self.results['tor_ip'] = ip_match.group(0)
                except Exception as e:
                    logging.error(f"Error checking Tor IP: {str(e)}")
            
            # Check Tor connection
            try:
                tor_check_cmd = "curl --socks5 localhost:9050 https://check.torproject.org/api/ip"
                tor_check_result = subprocess.run(tor_check_cmd, shell=True, capture_output=True, text=True)
                self.results['raw_output'] += f"Tor Connection Check:\n{tor_check_result.stdout}\n{tor_check_result.stderr}\n\n"
                
                if "You are using Tor" in tor_check_result.stdout or "Congratulations" in tor_check_result.stdout:
                    self.results['tor_running'] = True
                    if not self.results['anonsurf_running']:
                        self.results['anonymity_status'] = 'Tor Active (without AnonSurf)'
            except Exception as e:
                logging.error(f"Error checking Tor connection: {str(e)}")
            
            if verbose:
                if self.results['anonymity_status'] == 'AnonSurf Active':
                    print(f"\033[92m[+] AnonSurf is active. Your traffic is anonymized.\033[0m")
                elif self.results['anonymity_status'] == 'Tor Active (without AnonSurf)':
                    print(f"\033[93m[!] Tor is active but AnonSurf is not running.\033[0m")
                else:
                    print(f"\033[91m[!] No anonymization service detected. Your real IP is exposed.\033[0m")
                
                if self.results['public_ip']:
                    print(f"\033[94m[*] Current public IP: {self.results['public_ip']}\033[0m")
                if self.results['tor_ip']:
                    print(f"\033[94m[*] Tor exit node IP: {self.results['tor_ip']}\033[0m")
                
            return self.results
        except Exception as e:
            logging.error(f"Error in AnonSurf check: {str(e)}")
            return {'error': str(e)}