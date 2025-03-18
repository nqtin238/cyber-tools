- Required Tools on VMs/Containers: Ensure ss and lsof are installed on each Ubuntu system:
sudo apt update
sudo apt install iproute2 lsof

- Dependencies: Install the required Python packages:
pip install proxmoxer requests paramiko tenacity

======= SETUP PROXMOX API ACCESS =======
# Option A: Password-Based Authentication

## Use your Proxmox user’s password (e.g., root@pam).
## This is simpler but less secure for automation.

# Option B: Token-Based Authentication (Recommended)

## Create an API Token in Proxmox:

### 1. Log in to the Proxmox web interface (e.g., https://192.168.1.100:8006).
### 2. Go to Datacenter > Permissions > API Tokens.
### 3. Click Add to create a new token for your user (e.g., root@pam).
### 4. Note the Token ID (e.g., scanner-token) and Secret (you’ll only see this once).

## Set Permissions: Ensure the token has permissions to access VM/container details:
### 1. Go to Datacenter > Permissions.
### 2. Add a permission for the token with role PVEAuditor (or higher, like PVEAdmin) and path /.

======= List of All Tool Commands =======

- Basic Scan with Password Authentication: cans all running Ubuntu VMs/containers on Proxmox and exports results in JSON format.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam

- Basic Scan with Token Authentication: Uses a Proxmox API token instead of a password.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --token-name scanner-token --token-value your-token-secret

- Specify SSH Credentials (Password): Provides SSH password to avoid prompt.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --token-name scanner-token --token-value your-token-secret --ssh-user ubuntu --ssh-password your-ssh-password

- Specify SSH Credentials (Key): Uses an SSH key for VM/container access.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --token-name scanner-token --token-value your-token-secret --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa

- Scan Specific Ports: Scans only the specified ports (e.g., 22, 80, 443).
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa --ports 22,80,443

- Generate UFW Rules: Generates UFW rules for the scanned ports.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa --ufw

- Export in CSV Format: Exports results in CSV format to a specified file.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa --format csv --output my_ports.csv

- Disable SSL Verification (if needed): Disables SSL verification for Proxmox API (e.g., self-signed certificates)
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa --no-verify-ssl
 
- Combined Options: Scans specific ports, exports to CSV, and generates UFW rules.
./ports_scanner_pve.py --host 192.168.1.100 --user root@pam --token-name scanner-token --token-value your-token-secret --ssh-user ubuntu --ssh-key ~/.ssh/id_rsa --ports 1-1024 --format csv --output my_ports.csv --ufw

======= Quick Recap of Input Locations =======
Main Input: Command-line arguments (--host, --user, --token-name, --ssh-user, etc.).
No Config File Needed: Proxmox API fetches server details automatically.