"""Aircrack-ng wireless security scanner implementation"""
from scanners import BaseScanner
import subprocess
import logging
import tempfile
import os
import re
import time
import signal
import threading

class AircrackScanner(BaseScanner):
    """Aircrack-ng wireless security scanner plugin"""
    
    def __init__(self, options=None):
        super().__init__(options)
        self.monitor_process = None
        self.capture_process = None
        self.stop_event = threading.Event()
    
    def scan(self, target):
        """Run Aircrack-ng wireless scan"""
        # Extract options with defaults
        verbose = self.options.get('verbose', False)
        network_interface = self.options.get('network_interface')
        scan_duration = self.options.get('scan_duration', 30)  # Default 30 seconds
        
        # Create temp files for outputs
        fd, networks_file = tempfile.mkstemp(suffix='.csv', prefix='aircrack_networks_')
        os.close(fd)
        
        fd, capture_file = tempfile.mkstemp(suffix='.cap', prefix='aircrack_capture_')
        os.close(fd)
        
        try:
            # Check if we have a network interface
            if not network_interface:
                # Try to find a wireless interface
                interfaces = self._get_wireless_interfaces()
                if interfaces:
                    network_interface = interfaces[0]
                    logging.info(f"Selected wireless interface: {network_interface}")
                else:
                    error_msg = "No wireless interfaces found"
                    logging.error(error_msg)
                    return {'error': error_msg}
            
            # Initialize results
            self.results = {
                'networks': [],
                'clients': [],
                'vulnerabilities': [],
                'raw_output': '',
                'command': ''
            }
            
            # Step 1: Enable monitor mode
            monitor_interface = self._enable_monitor_mode(network_interface)
            if not monitor_interface:
                error_msg = f"Failed to enable monitor mode on {network_interface}"
                logging.error(error_msg)
                return {'error': error_msg}
            
            self.results['raw_output'] += f"Enabled monitor mode on {network_interface} (monitor interface: {monitor_interface})\n\n"
            
            if verbose:
                print(f"\033[94m[*] Scanning wireless networks with {monitor_interface}...\033[0m")
            
            # Step 2: Scan for networks
            networks = self._scan_networks(monitor_interface, networks_file, scan_duration)
            self.results['networks'] = networks
            
            if verbose:
                print(f"\033[92m[+] Found {len(networks)} wireless networks\033[0m")
            
            # Step 3: Look for vulnerabilities in each network
            for network in networks:
                # Check for WEP encryption (vulnerable)
                if network.get('encryption') == 'WEP':
                    self.results['vulnerabilities'].append({
                        'script': 'aircrack-ng',
                        'port': 0,  # Not port-specific
                        'output': f"WEP encryption detected on network {network.get('essid')} ({network.get('bssid')})",
                        'cve': None  # No specific CVE
                    })
                    
                # Check for WPS enabled networks (potentially vulnerable)
                if network.get('wps') == 'Yes':
                    self.results['vulnerabilities'].append({
                        'script': 'aircrack-ng',
                        'port': 0,
                        'output': f"WPS enabled on network {network.get('essid')} ({network.get('bssid')}) - potentially vulnerable to WPS attacks",
                        'cve': 'CVE-2011-5053'  # WPS vulnerability
                    })
            
            # Step 4: Disable monitor mode
            self._disable_monitor_mode(network_interface, monitor_interface)
            
            return self.results
        except Exception as e:
            logging.error(f"Error in Aircrack-ng scan: {str(e)}")
            return {'error': str(e)}
        finally:
            # Clean up temp files
            for file in [networks_file, capture_file]:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except Exception as e:
                        logging.warning(f"Could not delete temp file {file}: {str(e)}")
            
            # Make sure all processes are killed
            self._kill_processes()
    
    def _get_wireless_interfaces(self):
        """Get available wireless interfaces"""
        try:
            cmd = "iwconfig 2>&1 | grep -o '^[a-zA-Z0-9]*'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            interfaces = [iface for iface in result.stdout.splitlines() if iface.strip()]
            return interfaces
        except Exception as e:
            logging.error(f"Error getting wireless interfaces: {str(e)}")
            return []
    
    def _enable_monitor_mode(self, interface):
        """Enable monitor mode on the wireless interface"""
        try:
            cmd = f"airmon-ng start {interface}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # airmon-ng might create a new interface like "wlan0mon"
            monitor_interface = None
            
            # Check for "monitor mode enabled on" pattern
            pattern = re.compile(r'monitor mode (enabled|vif|on) (.*?)(\(|\)|\s|$)')
            match = pattern.search(result.stdout)
            if match:
                monitor_interface = match.group(2).strip()
            
            # If no match, try another approach - check if interface + "mon" exists
            if not monitor_interface:
                mon_interface = f"{interface}mon"
                check_cmd = f"iwconfig {mon_interface} 2>/dev/null | grep -q Monitor"
                if subprocess.run(check_cmd, shell=True).returncode == 0:
                    monitor_interface = mon_interface
            
            # If still no match, assume it's the original interface
            if not monitor_interface:
                monitor_interface = interface
            
            return monitor_interface
        except Exception as e:
            logging.error(f"Failed to enable monitor mode: {str(e)}")
            return None
    
    def _scan_networks(self, interface, output_file, duration=30):
        """Scan for wireless networks using airodump-ng"""
        try:
            cmd = f"airodump-ng --output-format csv --write {output_file} {interface}"
            
            # Start airodump-ng in background
            self.capture_process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL, 
                preexec_fn=os.setsid
            )
            
            # Wait for specified duration
            time.sleep(duration)
            
            # Stop the process
            if self.capture_process:
                try:
                    os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                except:
                    pass
            
            # Process the CSV output
            networks = []
            csv_path = f"{output_file}-01.csv"
            if os.path.exists(csv_path):
                with open(csv_path, 'r', errors='ignore') as f:
                    csv_data = f.read()
                
                # Parse networks section (first section until "Station MAC")
                networks_section = csv_data.split("Station MAC")[0] if "Station MAC" in csv_data else csv_data
                
                # Skip header
                lines = networks_section.strip().split("\n")[1:]
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    # Split the CSV line, handling potential issues
                    fields = [f.strip() for f in line.split(",")]
                    if len(fields) < 14:
                        continue
                    
                    bssid = fields[0]
                    
                    # Skip invalid BSSIDs
                    if not re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                        continue
                    
                    first_seen = fields[1]
                    last_seen = fields[2]
                    channel = fields[3]
                    speed = fields[4]
                    privacy = fields[5]
                    cipher = fields[6]
                    authentication = fields[7]
                    power = fields[8]
                    beacons = fields[9]
                    iv = fields[10]
                    lan_ip = fields[11]
                    id_length = fields[12]
                    essid = fields[13]
                    
                    # Determine encryption type
                    encryption = "Unknown"
                    if "WPA" in privacy and "WPA2" in privacy:
                        encryption = "WPA/WPA2"
                    elif "WPA2" in privacy:
                        encryption = "WPA2"
                    elif "WPA" in privacy:
                        encryption = "WPA"
                    elif "WEP" in privacy:
                        encryption = "WEP"
                    elif "OPN" in privacy:
                        encryption = "Open"
                    
                    # Check for WPS (simplified - in reality, you'd need wash or specific scanning)
                    wps = "Unknown"
                    
                    networks.append({
                        'bssid': bssid,
                        'essid': essid,
                        'channel': channel,
                        'encryption': encryption,
                        'cipher': cipher,
                        'authentication': authentication,
                        'power': power,
                        'wps': wps
                    })
            
            return networks
        except Exception as e:
            logging.error(f"Error scanning networks: {str(e)}")
            return []
    
    def _disable_monitor_mode(self, original_interface, monitor_interface):
        """Disable monitor mode"""
        try:
            cmd = f"airmon-ng stop {monitor_interface}"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Also try to restore original interface
            cmd = f"ip link set {original_interface} up"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return True
        except Exception as e:
            logging.error(f"Error disabling monitor mode: {str(e)}")
            return False
    
    def _kill_processes(self):
        """Kill any running aircrack processes"""
        try:
            # Kill monitor process
            if self.monitor_process:
                try:
                    os.killpg(os.getpgid(self.monitor_process.pid), signal.SIGTERM)
                except:
                    pass
            
            # Kill capture process
            if self.capture_process:
                try:
                    os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
                except:
                    pass
                
            # Also try to kill any lingering airodump-ng processes
            subprocess.run("pkill -f airodump-ng", shell=True)
            
        except Exception as e:
            logging.error(f"Error killing aircrack processes: {str(e)}")
            
    def __del__(self):
        """Destructor to ensure processes are killed"""
        self._kill_processes()