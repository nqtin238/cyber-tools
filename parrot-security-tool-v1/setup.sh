#!/bin/bash

# Security Testing Framework - Automated Setup Script
# This script installs required packages, sets up a Python environment,
# and configures the security testing framework.

set -e  # Exit on error

# ANSI color codes for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Check Python version compatibility
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"

if [[ $(echo -e "$PYTHON_VERSION\n$REQUIRED_VERSION" | sort -V | head -n1) != "$REQUIRED_VERSION" ]]; then
    echo "Error: Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Add --dry-run option
DRY_RUN=false
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if $DRY_RUN; then
    echo "Dry run: Simulating setup process..."
    echo "Python version check: PASSED"
    echo "Dependencies to install: $(cat requirements.txt)"
    exit 0
fi

# Print banner
echo -e "${BLUE}"
echo "====================================================="
echo " Security Testing Framework - Automated Installation"
echo "====================================================="
echo -e "${NC}"

# Create requirements.txt if it doesn't exist
create_requirements() {
    echo -e "${YELLOW}Creating requirements.txt...${NC}"
    cat > requirements.txt << EOF
# Core dependencies
jinja2>=3.0.0
prompt_toolkit>=3.0.0
requests>=2.25.0
schedule>=1.0.0
python-dateutil>=2.8.0
tqdm>=4.60.0
colorama>=0.4.4

# Database and storage
SQLAlchemy>=1.4.0

# Parsing and data processing
lxml>=4.6.0
beautifulsoup4>=4.9.0
pandas>=1.3.0
openpyxl>=3.0.0

# Networking
scapy>=2.4.0
paramiko>=2.7.0
pyOpenSSL>=20.0.0
cryptography>=3.4.0
python-nmap>=0.7.1

# Plugins support
importlib-metadata>=4.0.0
EOF
    echo -e "${GREEN}Created requirements.txt${NC}"
}

# Function to check if a package is installed
check_package() {
    dpkg -l "$1" &> /dev/null
    return $?
}

# Install system packages
install_system_packages() {
    echo -e "${YELLOW}Checking and installing system packages...${NC}"
    
    # Update package lists
    echo -e "${BLUE}Updating package lists...${NC}"
    apt update -q
    
    # List of required packages
    PACKAGES=(
        python3-dev
        python3-pip
        python3-venv
        nmap
        nikto
        aircrack-ng
        sqlmap
        masscan
        john
        lynis
        chkrootkit
        macchanger
        net-tools
        tor
        tor-geoipdb
        proxychains
        netcat-openbsd
        curl
        build-essential
        libssl-dev
        libffi-dev
        libxml2-dev
        libxslt1-dev
        zlib1g-dev
        libreadline-dev
        git
    )
    
    # Check if metasploit repository is needed
    if ! check_package "metasploit-framework"; then
        echo -e "${YELLOW}Metasploit not found, we'll need to add Kali repositories...${NC}"
        if [[ ! -f /etc/apt/sources.list.d/kali.list ]]; then
            echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list.d/kali.list
            wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add -
            apt update -q
        fi
        PACKAGES+=(metasploit-framework)
    fi
    
    # Check each package and install if missing
    MISSING_PACKAGES=()
    for pkg in "${PACKAGES[@]}"; do
        if ! check_package "$pkg"; then
            MISSING_PACKAGES+=("$pkg")
        fi
    done
    
    # Install missing packages
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Installing missing packages: ${MISSING_PACKAGES[*]}${NC}"
        apt install -y "${MISSING_PACKAGES[@]}"
        echo -e "${GREEN}All required system packages installed!${NC}"
    else
        echo -e "${GREEN}All required system packages are already installed!${NC}"
    fi
    
    # Enable and start tor service
    if systemctl list-unit-files tor.service &> /dev/null; then
        echo -e "${BLUE}Configuring Tor service...${NC}"
        systemctl enable tor.service
        systemctl restart tor.service
        echo -e "${GREEN}Tor service enabled and started${NC}"
    fi
}

# Set up Python virtual environment
setup_python_env() {
    echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
    
    # Create venv directory if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        echo -e "${GREEN}Created virtual environment${NC}"
    else
        echo -e "${GREEN}Virtual environment already exists${NC}"
    fi
    
    # Activate virtual environment
    echo -e "${BLUE}Activating virtual environment...${NC}"
    source venv/bin/activate
    
    # Upgrade pip
    echo -e "${BLUE}Upgrading pip...${NC}"
    pip install --upgrade pip
    
    # Check if requirements.txt exists, create it if not
    if [ ! -f "requirements.txt" ]; then
        create_requirements
    fi
    
    # Install Python dependencies
    echo -e "${BLUE}Installing Python dependencies...${NC}"
    pip install -r requirements.txt
    
    echo -e "${GREEN}Python environment setup complete!${NC}"
}

# Set up directory structure
setup_directories() {
    echo -e "${YELLOW}Creating directory structure...${NC}"
    
    # Create necessary directories
    mkdir -p logs reports templates scanners utils reporting integrations
    
    # Create __init__.py files for Python packages
    for dir in scanners utils reporting integrations; do
        if [ ! -f "$dir/__init__.py" ]; then
            echo -e "# $dir package" > "$dir/__init__.py"
        fi
    done
    
    # Create base scanner class if it doesn't exist
    if [ ! -f "scanners/__init__.py" ] || ! grep -q "BaseScanner" "scanners/__init__.py"; then
        echo -e "${BLUE}Creating base scanner class...${NC}"
        cat > scanners/__init__.py << EOF
"""Scanner plugin system"""
import importlib
import os
import logging
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Base class for all scanner plugins"""
    
    def __init__(self, options=None):
        self.options = options or {}
        self.results = {}
        
    @abstractmethod
    def scan(self, target):
        """Run the scan implementation"""
        pass
        
    def get_results(self):
        """Return scan results"""
        return self.results
EOF
    fi
    
    echo -e "${GREEN}Directory structure setup complete!${NC}"
}

# Run environment check
run_environment_check() {
    echo -e "${YELLOW}Running environment check...${NC}"
    
    # Activate virtual environment if not already activated
    if [ -z "$VIRTUAL_ENV" ]; then
        source venv/bin/activate
    fi
    
    # Check if setup_environment.py exists
    if [ -f "setup_environment.py" ]; then
        python setup_environment.py --dependencies
    else
        echo -e "${YELLOW}setup_environment.py not found - skipping environment check${NC}"
        echo -e "${BLUE}Creating placeholder setup_environment.py...${NC}"
        
        cat > setup_environment.py << 'EOF'
#!/usr/bin/env python3
"""
Setup environment for the Security Testing Tools
Creates necessary directories and initializes the required file structure.
"""

import os
import sys
import logging
import argparse
import shutil

def setup_environment(force=False):
    """Setup the required directory structure and files"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create directories
    directories = [
        'logs',
        'reports',
        'templates',
        'scanners',
        'utils',
        'reporting',
        'integrations'
    ]
    
    for directory in directories:
        dir_path = os.path.join(base_dir, directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            print(f"Created directory: {dir_path}")
        else:
            print(f"Directory already exists: {dir_path}")
    
    # Create __init__.py files for Python packages
    for directory in ['scanners', 'utils', 'reporting', 'integrations']:
        init_file = os.path.join(base_dir, directory, '__init__.py')
        if not os.path.exists(init_file) or force:
            with open(init_file, 'w') as f:
                if directory == 'scanners':
                    f.write("""\"\"\"Scanner plugin system\"\"\"
import importlib
import os
import logging
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    \"\"\"Base class for all scanner plugins\"\"\"
    
    def __init__(self, options=None):
        self.options = options or {}
        self.results = {}
        
    @abstractmethod
    def scan(self, target):
        \"\"\"Run the scan implementation\"\"\"
        pass
        
    def get_results(self):
        \"\"\"Return scan results\"\"\"
        return self.results
""")
                else:
                    f.write(f"""\"\"\"
{directory.capitalize()} package for security testing tools
\"\"\"

# This file marks this directory as a Python package
""")
            print(f"Created/updated package file: {init_file}")
    
    print("\nEnvironment setup complete!")

def check_dependencies():
    """Check if required external tools are installed"""
    tools = [
        'nmap',
        'nikto',
        'sqlmap',
        'john',
        'lynis',
        'chkrootkit',
        'aircrack-ng',
        'macchanger',
        'tor',
        'proxychains'
    ]
    
    missing_tools = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing_tools.append(tool)
    
    if missing_tools:
        print("\nWARNING: The following tools are not installed or not in PATH:")
        for tool in missing_tools:
            print(f"  - {tool}")
        print("\nSome functionality may be limited. Please install these tools for full functionality.")
    else:
        print("\nAll required external tools are installed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Setup environment for Security Testing Tools")
    parser.add_argument("-f", "--force", action="store_true", help="Force overwrite of existing files")
    parser.add_argument("-d", "--dependencies", action="store_true", help="Check for external dependencies")
    
    args = parser.parse_args()
    
    setup_environment(args.force)
    
    if args.dependencies:
        check_dependencies()
EOF
        chmod +x setup_environment.py
        
        # Run the newly created script
        python setup_environment.py --dependencies
    fi
    
    echo -e "${GREEN}Environment check complete!${NC}"
}

# Main installation process
main() {
    echo -e "${YELLOW}Starting installation process...${NC}"
    
    # Install system packages
    install_system_packages
    
    # Setup directory structure
    setup_directories
    
    # Setup Python environment
    setup_python_env
    
    # Run environment check
    run_environment_check
    
    echo -e "${GREEN}Installation complete!${NC}"
    echo -e "${BLUE}To start using the framework:${NC}"
    echo -e "  1. Activate the virtual environment: ${YELLOW}source venv/bin/activate${NC}"
    echo -e "  2. Run the tester: ${YELLOW}sudo -E python interactive_system_tester.py${NC}"
    echo -e "     (The -E flag preserves your virtual environment)"
    echo -e ""
    echo -e "${YELLOW}Note:${NC} Some scanners require root privileges to work properly."
}

# Execute main function
main