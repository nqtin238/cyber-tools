#!/usr/bin/env python3
# File: ai-tools/app/tools/network/nmap_scanner.py
# Purpose: Nmap scanner wrapper for network reconnaissance
# Usage: Use this class to perform various types of nmap scans

import nmap
import json
import os
import time
import platform
from datetime import datetime
from typing import Dict, List, Set, Optional
from app.utils.logger import get_logger
from app.core.config import settings

logger = get_logger(__name__)

class NmapScanner:
    def __init__(self):
        """Initialize the nmap scanner with configuration."""
        self.scanner = nmap.PortScanner()
        self.target_ip = settings.NMAP.TARGET_IP
        self.timing = settings.NMAP.TIMING
        self.is_windows = platform.system().lower() == 'windows'
        
        # Create date-stamped directories for results
        timestamp = datetime.now().strftime("%Y-%m-%d")
        self.raw_output_dir = os.path.join(settings.NMAP.OUTPUT_DIR, timestamp)
        self.extract_output_dir = os.path.join("results", "extract", "nmap", timestamp)
        
        # Create directories if they don't exist
        os.makedirs(self.raw_output_dir, exist_ok=True)
        os.makedirs(self.extract_output_dir, exist_ok=True)
        
        logger.info(f"Initialized NmapScanner for target: {self.target_ip}")
        logger.info(f"Operating System: {'Windows' if self.is_windows else 'Unix-like'}")
        logger.info(f"Raw output directory: {self.raw_output_dir}")
        logger.info(f"Extract output directory: {self.extract_output_dir}")

    def _save_scan_results(self, scan_type: str) -> None:
        """Save scan results in multiple formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{self.target_ip}_{scan_type}_{timestamp}"
        
        try:
            # Save nmap output
            nmap_path = os.path.join(self.raw_output_dir, f"{base_filename}.nmap")
            with open(nmap_path, 'w') as f:
                f.write(self.scanner.get_nmap_last_output())
            
            # Save scan data as JSON
            json_path = os.path.join(self.raw_output_dir, f"{base_filename}.json")
            with open(json_path, 'w') as f:
                json.dump(self.scanner[self.target_ip], f, indent=2)
            
            # Save command line output
            cmd_path = os.path.join(self.raw_output_dir, f"{base_filename}.cmd")
            with open(cmd_path, 'w') as f:
                f.write(self.scanner.command_line())
            
            logger.info(f"Saved scan results to {self.raw_output_dir}")
            
        except Exception as e:
            logger.error(f"Error saving scan results: {e}")
            raise

    def _extract_and_save_ports(self) -> None:
        """Extract open ports and save to a text file."""
        open_ports = set()
        
        try:
            # Get scan results directly from scanner object
            if self.target_ip in self.scanner.all_hosts():
                host_data = self.scanner[self.target_ip]
                
                # Extract TCP ports
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            open_ports.add(f"TCP {port}/{service} {version}".strip())
                
                # Extract UDP ports
                if 'udp' in host_data:
                    for port, port_info in host_data['udp'].items():
                        if port_info['state'] == 'open':
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            open_ports.add(f"UDP {port}/{service} {version}".strip())
            
            # Save to file
            output_file = os.path.join(self.extract_output_dir, f"{self.target_ip}_open_ports.txt")
            with open(output_file, 'w') as f:
                f.write(f"Open ports for {self.target_ip}:\n")
                f.write("=" * 50 + "\n")
                for port in sorted(open_ports):
                    f.write(f"{port}\n")
            
            logger.info(f"Saved open ports to {output_file}")
            
        except Exception as e:
            logger.error(f"Error extracting ports: {e}")
            raise

    def _get_scan_arguments(self, scan_type) -> str:
        """Get scan arguments based on platform and scan type."""
        base_args = scan_type.arguments
        
        # Modify arguments for Windows
        if self.is_windows:
            # Remove sudo-specific arguments
            base_args = base_args.replace('-O', '')  # OS detection requires root/sudo
            base_args = base_args.replace('-sS', '-sT')  # Use TCP connect scan instead of SYN scan
            
            # Add Windows-specific timing
            base_args = f"-T{self.timing} {base_args}"
        
        return base_args.strip()

    def run_scan_type(self, scan_type) -> Dict:
        """Run a specific type of nmap scan."""
        try:
            logger.info(f"Running {scan_type.name} scan on {self.target_ip}")
            
            # Get platform-specific arguments
            scan_args = self._get_scan_arguments(scan_type)
            logger.info(f"Scan arguments: {scan_args}")
            
            # Skip OS detection on Windows
            if self.is_windows and scan_type.name == 'os_detection':
                logger.warning("OS detection is not available on Windows. Skipping this scan.")
                return {"status": "skipped", "reason": "not_supported_on_windows"}
            
            # Run the scan
            self.scanner.scan(
                hosts=self.target_ip,
                arguments=scan_args
            )
            
            # Save results
            self._save_scan_results(scan_type.name)
            
            # Extract and save ports
            self._extract_and_save_ports()
            
            # Get scan results
            results = {}
            if self.target_ip in self.scanner.all_hosts():
                results = self.scanner[self.target_ip]
            
            logger.info(f"Completed {scan_type.name} scan")
            return results
            
        except Exception as e:
            logger.error(f"Error during {scan_type.name} scan: {e}")
            raise

    def run_all_scans(self) -> Dict:
        """Run all enabled scan types sequentially."""
        all_results = {}
        
        try:
            for scan_type in settings.NMAP.SCAN_TYPES:
                if scan_type.enabled:
                    logger.info(f"Running scan type: {scan_type.name}")
                    results = self.run_scan_type(scan_type)
                    all_results[scan_type.name] = results
                    
                    # Add a small delay between scans
                    time.sleep(2)
            
            return all_results
            
        except Exception as e:
            logger.error(f"Error running all scans: {e}")
            raise

    def get_scan_summary(self) -> Dict:
        """Get a summary of the scan results."""
        try:
            summary = {
                'target': self.target_ip,
                'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'open_ports': [],
                'os_info': {},
                'services': {}
            }
            
            # Read the latest port file
            port_file = os.path.join(self.extract_output_dir, f"{self.target_ip}_open_ports.txt")
            if os.path.exists(port_file):
                with open(port_file, 'r') as f:
                    summary['open_ports'] = [line.strip() for line in f if line.strip() and not line.startswith('=')]
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting scan summary: {e}")
            raise 