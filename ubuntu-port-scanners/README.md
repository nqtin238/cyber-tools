
Main Input: servers.yaml file (defines servers to scan).
Additional Input: Command-line arguments (--config, --ports, --format, etc.).

======= Steps to Use =======

- Run the scanner:
./port_scanner.py --config servers.yaml

- Run with specific port range:
./port_scanner.py --config servers.yaml --ports 1-1024

- Use nmap for detailed scan (requires nmap installed):
./port_scanner.py --config servers.yaml --nmap

- Generate UFW rules (optional):
./port_scanner.py --config servers.yaml --ufw

- Export in CSV format (optional):
./port_scanner.py --config servers.yaml --format csv --output my_ports.csv