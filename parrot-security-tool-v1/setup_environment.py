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
    
    # Copy scanner plugins if not existing or force is True
    source_dir = os.path.join(base_dir, 'scanners')
    scanner_files = [
        'nmap_scanner.py',
        'masscan_scanner.py',
        'netcat_scanner.py',
        'nikto_scanner.py',
        'sqlmap_scanner.py',
        'metasploit_scanner.py',
        'lynis_scanner.py',
        'chkrootkit_scanner.py',
        'john_scanner.py',
        'anonsurf_scanner.py',
        'aircrack_scanner.py'
    ]
    
    # Verify scanner files exist
    missing_files = []
    for scanner_file in scanner_files:
        file_path = os.path.join(source_dir, scanner_file)
        if not os.path.exists(file_path):
            missing_files.append(scanner_file)
    
    if missing_files:
        print("\nWARNING: The following scanner files are missing:")
        for file in missing_files:
            print(f"  - {file}")
        print("\nPlease ensure all scanner plugins are properly installed.")
    else:
        print("\nAll required scanner plugins are present.")
    
    # Initialize utils directory
    utils_dir = os.path.join(base_dir, 'utils')
    plugin_loader_file = os.path.join(utils_dir, 'plugin_loader.py')
    if not os.path.exists(plugin_loader_file) or force:
        # You would write the plugin_loader.py content here
        # We've already created it, so we'll just check for it
        if not os.path.exists(plugin_loader_file):
            print(f"WARNING: Plugin loader file is missing: {plugin_loader_file}")
    
    print("\nEnvironment setup complete!")

def check_dependencies():
    """Check if required external tools are installed"""
    tools = [
        'nmap',
        'nikto',
        'sqlmap',
        'msfconsole',
        'aircrack-ng',
        'john',
        'lynis',
        'chkrootkit',
        'anonsurf'
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