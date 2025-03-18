#!/usr/bin/env python3
import argparse
import csv
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import paramiko
import logging
import tenacity
from proxmoxer import ProxmoxAPI
from getpass import getpass

# Configure logging
logging.basicConfig(
    filename="port_scan_pve.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class ProxmoxPortScanner:
    def __init__(self, host, user, password=None, token_name=None, token_value=None, verify_ssl=True):
        self.servers = []
        self.scan_results = {}
        self.proxmox = None
        self.connect_to_proxmox(host, user, password, token_name, token_value, verify_ssl)
        logging.info(f"Initialized ProxmoxPortScanner for host {host}")

    def connect_to_proxmox(self, host, user, password, token_name, token_value, verify_ssl):
        """Connect to Proxmox API"""
        try:
            if password:
                self.proxmox = ProxmoxAPI(
                    host, user=user, password=password, verify_ssl=verify_ssl
                )
            elif token_name and token_value:
                self.proxmox = ProxmoxAPI(
                    host, user=user, token_name=token_name, token_value=token_value, verify_ssl=verify_ssl
                )
            else:
                raise ValueError("Either password or token_name/token_value must be provided")
            logging.info(f"Successfully connected to Proxmox at {host}")
        except Exception as e:
            logging.error(f"Failed to connect to Proxmox: {str(e)}")
            print(f"Error connecting to Proxmox: {str(e)}")
            sys.exit(1)

    def fetch_servers(self):
        """Fetch all VMs and containers from Proxmox, filtering for running Ubuntu instances"""
        try:
            servers = []
            nodes = self.proxmox.nodes.get()
            for node in nodes:
                node_name = node['node']
                # Fetch VMs
                vms = self.proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    if vm['status'] == 'running':
                        vm_config = self.proxmox.nodes(node_name).qemu(vm['vmid']).config.get()
                        os_type = vm_config.get('ostype', '').lower()
                        if 'ubuntu' in os_type or 'linux' in os_type:  # Filter for Ubuntu/Linux VMs
                            ip = self._get_vm_ip(node_name, 'qemu', vm['vmid'])
                            if ip:
                                servers.append({
                                    'hostname': ip,
                                    'local': False,
                                    'username': 'ubuntu',  # Default, can be overridden
                                    'password': None,  # To be set via args/env
                                    'key_file': None,  # To be set via args/env
                                    'vmid': vm['vmid'],
                                    'name': vm['name']
                                })
                # Fetch Containers (LXC)
                containers = self.proxmox.nodes(node_name).lxc.get()
                for container in containers:
                    if container['status'] == 'running':
                        container_config = self.proxmox.nodes(node_name).lxc(container['vmid']).config.get()
                        os_type = container_config.get('ostype', '').lower()
                        if 'Ubuntu' in os_type:  # Filter for Ubuntu containers
                            ip = self._get_vm_ip(node_name, 'lxc', container['vmid'])
                            if ip:
                                servers.append({
                                    'hostname': ip,
                                    'local': False,
                                    'username': 'root',  # Default for LXC, can be overridden
                                    'password': None,  # To be set via args/env
                                    'key_file': None,  # To be set via args/env
                                    'vmid': container['vmid'],
                                    'name': container['name']
                                })
            self.servers = servers
            logging.info(f"Fetched {len(self.servers)} running Ubuntu servers from Proxmox")
            print(f"Fetched {len(self.servers)} running Ubuntu servers:")
            for server in self.servers:
                print(f" - {server['name']} (VMID: {server['vmid']}, IP: {server['hostname']})")
        except Exception as e:
            logging.error(f"Failed to fetch servers from Proxmox: {str(e)}")
            print(f"Error fetching servers: {str(e)}")
            sys.exit(1)

    def _get_vm_ip(self, node_name, vm_type, vmid):
        """Get IP address of a VM or container"""
        try:
            if vm_type == 'qemu':
                interfaces = self.proxmox.nodes(node_name).qemu(vmid).agent.network_get_interfaces.get()
            else:  # lxc
                interfaces = self.proxmox.nodes(node_name).lxc(vmid).agent.network_get_interfaces.get()
            for iface in interfaces:
                if iface['name'] != 'lo':  # Exclude loopback
                    for addr in iface.get('ip-addresses', []):
                        if addr['ip-address-type'] == 'ipv4' and not addr['ip-address'].startswith('169.254'):
                            return addr['ip-address']
        except Exception as e:
            logging.warning(f"Could not fetch IP for {vm_type}/{vmid}: {str(e)}")
        return None

    def check_dependencies(self):
        """Check for required system tools"""
        required_tools = ["ss", "lsof"]
        for tool in required_tools:
            if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                logging.error(f"Required tool {tool} not found. Please install it.")
                print(f"Error: Required tool {tool} not found. Install it with 'sudo apt install {tool}'.")
                sys.exit(1)

    def parse_port_range(self, port_range):
        """Parse port range string into a list of ports"""
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            return range(start, end + 1)
        return [int(p) for p in port_range.split(',')]

    def scan_local_ports(self, server_info):
        """Scan ports on the local machine (if running on Proxmox host)"""
        hostname = server_info['hostname']
        ports_to_scan = self.parse_port_range(args.ports) if 'args' in globals() else range(1, 1025)
        logging.info(f"Scanning local ports on {hostname}...")
        try:
            cmd = ["ss", "-tuln"]
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
                "name": server_info.get('name', hostname),
                "vmid": server_info.get('vmid', 'N/A'),
                "scan_time": datetime.now().isoformat(),
                "ports": listening_ports
            }
        except Exception as e:
            logging.error(f"Error scanning local ports on {hostname}: {str(e)}")
            return {
                "hostname": hostname,
                "name": server_info.get('name', hostname),
                "vmid": server_info.get('vmid', 'N/A'),
                "error": str(e),
                "ports": []
            }

    def _get_pid_for_port(self, port, proto):
        """Get process ID using a specific port"""
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
        """Scan ports on a remote VM/container via SSH"""
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
                "name": server_info.get('name', hostname),
                "vmid": server_info.get('vmid', 'N/A'),
                "scan_time": datetime.now().isoformat(),
                "ports": listening_ports
            }
        except (paramiko.AuthenticationException, paramiko.SSHException) as e:
            logging.error(f"SSH error on {hostname}: {str(e)}")
            return {
                "hostname": hostname,
                "name": server_info.get('name', hostname),
                "vmid": server_info.get('vmid', 'N/A'),
                "error": str(e),
                "ports": []
            }
        except Exception as e:
            logging.error(f"Error scanning remote ports on {hostname}: {str(e)}")
            return {
                "hostname": hostname,
                "name": server_info.get('name', hostname),
                "vmid": server_info.get('vmid', 'N/A'),
                "error": str(e),
                "ports": []
            }
        finally:
            client.close()

    def scan_server(self, server_info):
        """Scan a server - either local (Proxmox host) or remote (VM/container)"""
        is_local = server_info.get('local', False)
        if is_local:
            return self.scan_local_ports(server_info)
        else:
            return self.scan_remote_ports(server_info)

    def scan_all_servers(self):
        """Scan all servers in parallel"""
        print(f"Starting port scan on {len(self.servers)} server(s)...")
        logging.info(f"Scanning {len(self.servers)} servers")
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.scan_server, self.servers))
        for result in results:
            hostname = result['hostname']
            self.scan_results[hostname] = result
            print(f"Completed scan for {result['name']} (IP: {hostname}, VMID: {result['vmid']})")
        total_ports = sum(len(result.get('ports', [])) for result in self.scan_results.values())
        print(f"Scan completed. Total open ports found: {total_ports}")
        logging.info(f"Scan completed with {total_ports} open ports")
        return self.scan_results

    def export_results(self, format='json', output_file=None):
        """Export scan results to file"""
        if not self.scan_results:
            print("No scan results to export.")
            return
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"port_scan_pve_{timestamp}.{format}"
        try:
            if format == 'json':
                with open(output_file, 'w') as file:
                    json.dump(self.scan_results, file, indent=2)
            elif format == 'csv':
                with open(output_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Hostname', 'Name', 'VMID', 'Port', 'Protocol', 'Address', 'Process'])
                    for hostname, result in self.scan_results.items():
                        if 'error' in result:
                            writer.writerow([hostname, result.get('name', hostname), result.get('vmid', 'N/A'), 'ERROR', '', '', result['error']])
                        else:
                            for port_info in result['ports']:
                                writer.writerow([
                                    hostname,
                                    result.get('name', hostname),
                                    result.get('vmid', 'N/A'),
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
        """Generate UFW rules based on scan results"""
        if not self.scan_results:
            print("No scan results to generate UFW rules.")
            return
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ufw_rules_pve_{timestamp}.sh"
        if input(f"Generate UFW rules and save to {output_file}? (yes/no): ").lower() != 'yes':
            print("UFW rule generation cancelled.")
            return
        try:
            current_rules = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
            with open(output_file, 'w') as file:
                file.write("#!/bin/bash\n\n")
                file.write("# UFW rules generated by Proxmox Port Scanner\n")
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
                        file.write(f"# Rules for {result.get('name', hostname)} (IP: {hostname}, VMID: {result.get('vmid', 'N/A')})\n")
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
    parser = argparse.ArgumentParser(description='Scan Proxmox VMs and containers for open ports')
    parser.add_argument('--host', required=True, help='Proxmox host (e.g., pve.example.com or 192.168.1.100)')
    parser.add_argument('--user', required=True, help='Proxmox user (e.g., root@pam)')
    parser.add_argument('--password', help='Proxmox password (prompted if not provided)')
    parser.add_argument('--token-name', help='Proxmox API token name (alternative to password)')
    parser.add_argument('--token-value', help='Proxmox API token value (alternative to password)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification for Proxmox API')
    parser.add_argument('--ssh-user', default='Ubuntu', help='SSH username for VMs (default: Ubuntu)')
    parser.add_argument('--ssh-password', help='SSH password for VMs (prompted if not provided)')
    parser.add_argument('--ssh-key', help='Path to SSH private key file for VMs')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('-u', '--ufw', action='store_true',
                        help='Generate UFW rules based on scan results')
    parser.add_argument('--ports', default='1-1024',
                        help='Port range to scan (e.g., 1-1024 or 22,80,443)')
    parser.epilog = """
Authentication Options:
- Use --password for password-based Proxmox authentication.
- Alternatively, use --token-name and --token-value for token-based authentication.
- SSH credentials (--ssh-user, --ssh-password, --ssh-key) are used to connect to VMs/containers.
"""
    args = parser.parse_args()

    # Prompt for Proxmox password if not provided
    password = args.password if args.password else getpass("Enter Proxmox password: ")
    # Prompt for SSH password if not provided
    ssh_password = args.ssh_password if args.ssh_password else getpass("Enter SSH password for VMs: ")

    scanner = ProxmoxPortScanner(
        host=args.host,
        user=args.user,
        password=password,
        token_name=args.token_name,
        token_value=args.token_value,
        verify_ssl=not args.no_verify_ssl
    )

    # Fetch servers and set SSH credentials
    scanner.fetch_servers()
    for server in scanner.servers:
        server['username'] = args.ssh_user
        server['password'] = ssh_password
        server['key_file'] = args.ssh_key

    scanner.scan_all_servers()
    scanner.export_results(args.format, args.output)
    if args.ufw:
        scanner.generate_ufw_rules()

if __name__ == '__main__':
    main()