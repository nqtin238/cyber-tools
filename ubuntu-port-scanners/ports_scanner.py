#!/usr/bin/env python3
import argparse
import csv
import json
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import paramiko
import yaml
import logging
import tenacity

logging.basicConfig(filename="port_scan.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class ServerPortScanner:
    def __init__(self, config_file=None):
        self.servers = []
        self.scan_results = {}
        self.config_file = config_file
        logging.info(f"Initialized Scanner with config file: {config_file}")
        self.check_dependencies()

    def check_dependencies(self):
        required_tools = ["netstat", "lsof"]
        for tool in required_tools:
            if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                logging.error(f"Required tool {tool} not found. Please install it.")
                sys.exit(1)

    def load_config(self):
        try:
            if not os.path.exists(self.config_file):
                raise FileNotFoundError(f"Config file {self.config_file} not found.")
            with open(self.config_file, 'r') as file:
                config = yaml.safe_load(file)
            if not config or 'servers' not in config:
                raise ValueError("Invalid configuration format. 'servers' section is missing.")
            self.servers = config['servers']
            for server in self.servers:
                if 'password' in server:
                    server['password'] = os.getenv(server['password'].replace('${', '').replace('}', ''), server['password'])
                if 'key_file' in server and not os.path.exists(server['key_file']):
                    raise FileNotFoundError(f"SSH key file not found: {server['key_file']}")
            logging.info(f"Loaded {len(self.servers)} server(s) from {self.config_file}")
        except FileNotFoundError as e:
            logging.error(str(e))
            sys.exit(1)
        except ValueError as e:
            logging.error(str(e))
            sys.exit(1)
        except Exception as e:
            logging.error(f"Unexpected error loading config: {str(e)}")
            sys.exit(1)

    def parse_port_range(self, port_range):
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            return range(start, end + 1)
        return [int(p) for p in port_range.split(',')]

    def scan_local_ports(self, server_info):
        hostname = server_info['hostname']
        ports_to_scan = self.parse_port_range(args.ports) if 'args' in locals() else range(1, 1025)
        logging.info(f"Scanning local ports on {hostname}...")
        try:
            cmd = ["ss", "-tuln"]  # Use ss instead of netstat for modern systems
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise Exception(f"Command failed with error: {result.stderr}")
            listening_ports = []
            for line in result.stdout.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_port = parts[4].rsplit(':', 1)
                        if len(addr_port) == 2:
                            port = int(addr_port[1])
                            if port in ports_to_scan:
                                proto = "tcp" if "tcp" in line.lower() else "udp"
                                listening_ports.append({
                                    "port": port,
                                    "protocol": proto,
                                    "address": addr_port[0],
                                    "pid": self._get_pid_for_port(str(port), proto)
                                })
            return {
                "hostname": hostname,
                "scan_time": datetime.now().isoformat(),
                "ports": listening_ports
            }
        except Exception as e:
            logging.error(f"Error scanning local ports on {hostname}: {str(e)}")
            return {"hostname": hostname, "error": str(e), "ports": []}

    def _get_pid_for_port(self, port, proto):
        try:
            cmd = ["lsof", "-i", f"{proto}:{port}", "-t"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                if pids:
                    pid = pids[0]
                    proc_cmd = ["ps", "-p", pid, "-o", "comm="]
                    proc_result = subprocess.run(proc_cmd, capture_output=True, text=True)
                    if proc_result.returncode == 0:
                        process_name = proc_result.stdout.strip()
                        return f"{pid} ({process_name})"
            return "Unknown"
        except Exception:
            return "Unknown"

    @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(2))
    def scan_remote_ports(self, server_info):
        hostname = server_info['hostname']
        username = server_info.get('username', '')
        password = server_info.get('password', '')
        key_file = server_info.get('key_file', '')
        logging.info(f"Scanning remote ports on {hostname}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if not username:
                raise ValueError(f"Username is required for {hostname}")
            kwargs = {"username": username, "timeout": 10}
            if key_file:
                kwargs["key_filename"] = key_file
            elif password:
                kwargs["password"] = password
            else:
                raise ValueError(f"Authentication method (password or key_file) required for {hostname}")
            client.connect(hostname, **kwargs)
            stdin, stdout, stderr = client.exec_command("ss -tuln", timeout=30)
            output = stdout.read().decode()
            if stderr.read().decode():
                logging.warning(f"Warning on {hostname}: {stderr.read().decode()}")
            listening_ports = []
            for line in output.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_port = parts[4].rsplit(':', 1)
                        if len(addr_port) == 2:
                            port = int(addr_port[1])
                            proto = "tcp" if "tcp" in line.lower() else "udp"
                            stdin, stdout, stderr = client.exec_command(f"lsof -i {proto}:{port} -t")
                            pid = stdout.read().decode().strip()
                            pid_info = f"{pid} (Unknown)" if pid else "Unknown"
                            if pid:
                                stdin, stdout, stderr = client.exec_command(f"ps -p {pid} -o comm=")
                                process_name = stdout.read().decode().strip()
                                pid_info = f"{pid} ({process_name})"
                            listening_ports.append({
                                "port": port,
                                "protocol": proto,
                                "address": addr_port[0],
                                "pid": pid_info
                            })
            return {
                "hostname": hostname,
                "scan_time": datetime.now().isoformat(),
                "ports": listening_ports
            }
        except (paramiko.AuthenticationException, paramiko.SSHException) as e:
            logging.error(f"SSH error on {hostname}: {str(e)}")
            return {"hostname": hostname, "error": str(e), "ports": []}
        except Exception as e:
            logging.error(f"Error scanning remote ports on {hostname}: {str(e)}")
            return {"hostname": hostname, "error": str(e), "ports": []}
        finally:
            client.close()

    def scan_server(self, server_info):
        is_local = server_info.get('local', False)
        if is_local:
            return self.scan_local_ports(server_info)
        else:
            return self.scan_remote_ports(server_info)

    def scan_all_servers(self):
        print(f"Starting port scan on {len(self.servers)} server(s)...")
        logging.info(f"Scanning {len(self.servers)} servers")
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.scan_server, self.servers))
        for result in results:
            hostname = result['hostname']
            self.scan_results[hostname] = result
            print(f"Completed scan for {hostname}")
        total_ports = sum(len(result.get('ports', [])) for result in self.scan_results.values())
        print(f"Scan completed. Total open ports found: {total_ports}")
        logging.info(f"Scan completed with {total_ports} open ports")
        return self.scan_results

    def export_results(self, format='json', output_file=None):
        if not self.scan_results:
            print("No scan results to export.")
            return
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"port_scan_{timestamp}.{format}"
        try:
            if format == 'json':
                with open(output_file, 'w') as file:
                    json.dump(self.scan_results, file, indent=2)
            elif format == 'csv':
                with open(output_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Hostname', 'Port', 'Protocol', 'Address', 'Process'])
                    for hostname, result in self.scan_results.items():
                        if 'error' in result:
                            writer.writerow([hostname, 'ERROR', '', '', result['error']])
                        else:
                            for port_info in result['ports']:
                                writer.writerow([
                                    hostname,
                                    port_info['port'],
                                    port_info['protocol'],
                                    port_info['address'],
                                    port_info['pid']
                                ])
            print(f"Results exported to {output_file}")
            logging.info(f"Results exported to {output_file}")
        except Exception as e:
            print(f"Error exporting results: {str(e)}")
            logging.error(f"Error exporting results: {str(e)}")

    def generate_ufw_rules(self, output_file=None):
        if not self.scan_results:
            print("No scan results to generate UFW rules.")
            return
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ufw_rules_{timestamp}.sh"
        if input(f"Generate UFW rules and save to {output_file}? (yes/no): ").lower() != 'yes':
            print("UFW rule generation cancelled.")
            return
        try:
            current_rules = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
            with open(output_file, 'w') as file:
                file.write("#!/bin/bash\n\n")
                file.write("# UFW rules generated by Server Port Scanner\n")
                file.write(f"# Generated on {datetime.now().isoformat()}\n\n")
                file.write("# Reset UFW to defaults\n")
                file.write("ufw --force reset\n\n")
                file.write("# Set default policies\n")
                file.write("ufw default deny incoming\n")
                file.write("ufw default allow outgoing\n\n")
                file.write("# Allow SSH (port 22) first to avoid lockouts\n")
                file.write("ufw allow ssh\n\n")
                file.write("# Application specific rules\n")
                for hostname, result in self.scan_results.items():
                    if 'error' not in result:
                        file.write(f"# Rules for {hostname}\n")
                        for port_info in result['ports']:
                            port = port_info['port']
                            proto = port_info['protocol']
                            process = port_info['pid']
                            address = port_info['address']
                            if address in ['127.0.0.1', '::1']:
                                file.write(f"# Skipping localhost-only port {port}/{proto} for {process}\n")
                                continue
                            rule_exists = f"{port}/{proto}" in current_rules
                            if not rule_exists:
                                file.write(f"ufw allow {port}/{proto} # {process}\n")
                            else:
                                file.write(f"# Rule for {port}/{proto} already exists\n")
                        file.write("\n")
                file.write("# Enable UFW\n")
                file.write("ufw --force enable\n")
            print(f"UFW rules generated and saved to {output_file}")
            print("Review the rules in the file and run `chmod +x {output_file} && sudo ./{output_file}` to apply.")
            logging.info(f"UFW rules generated and saved to {output_file}")
        except Exception as e:
            print(f"Error generating UFW rules: {str(e)}")
            logging.error(f"Error generating UFW rules: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Scan Ubuntu servers for open ports')
    parser.add_argument('-c', '--config', required=True, help='Path to YAML configuration file (e.g., servers.yaml)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('-u', '--ufw', action='store_true',
                        help='Generate UFW rules based on scan results')
    parser.add_argument('--ports', default='1-1024',
                        help='Port range to scan (e.g., 1-1024 or 22,80,443)')
    parser.add_argument('--nmap', action='store_true',
                        help='Use nmap for detailed scanning (requires nmap installed)')
    parser.epilog = """
Configuration File Format (servers.yaml):
- servers:
  - hostname: <server-name-or-ip>
    local: <true/false>          # True for local, False for remote
    username: <username>         # Required for remote
    password: <password>         # Optional, or use ${ENV_VAR} for security
    key_file: <path-to-key>      # Optional, alternative to password
  - ... (more servers)
"""
    args = parser.parse_args()
    scanner = ServerPortScanner(args.config)
    scanner.load_config()
    scanner.scan_all_servers()
    scanner.export_results(args.format, args.output)
    if args.ufw:
        scanner.generate_ufw_rules()

if __name__ == '__main__':
    main()