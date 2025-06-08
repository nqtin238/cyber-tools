#!/usr/bin/env python3
# File: ai-tools/run.py
# Purpose: Main entry point for the AI Security Tool
# Usage: Run this script to start the tool and access its features

import os
import sys
import json
from datetime import datetime
from app.tools.network.nmap_scanner import NmapScanner
from app.utils.logger import get_logger
from app.core.config import settings

logger = get_logger(__name__)

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the tool's header."""
    print("\n" + "=" * 80)
    print("AI Security Tool - Network Scanner".center(80))
    print("=" * 80 + "\n")

def print_menu():
    """Print the main menu options."""
    print("\nAvailable Tools:")
    print("1. Nmap Scanner")
    print("2. Exit")
    print("\n" + "-" * 80)

def print_nmap_menu():
    """Print the Nmap scanner menu options."""
    print("\nNmap Scanner Options:")
    print("1. Run All Scans")
    print("2. Run OS Detection")
    print("3. Run TCP Port Scan")
    print("4. Run UDP Port Scan")
    print("5. Run Service Enumeration")
    print("6. View Last Scan Results")
    print("7. Back to Main Menu")
    print("\n" + "-" * 80)

def view_last_scan_results():
    """View the results of the last scan."""
    target_ip = settings.NMAP.TARGET_IP
    timestamp = datetime.now().strftime("%Y-%m-%d")
    extract_dir = os.path.join("results", "extract", "nmap", timestamp)
    results_file = os.path.join(extract_dir, f"{target_ip}_open_ports.txt")
    
    if os.path.exists(results_file):
        print(f"\nLast scan results for {target_ip}:")
        print("=" * 80)
        with open(results_file, 'r') as f:
            print(f.read())
    else:
        print("\nNo previous scan results found.")

def get_scan_type_by_name(name: str):
    """Get scan type configuration by name."""
    for scan_type in settings.NMAP.SCAN_TYPES:
        if scan_type.name == name:
            return scan_type
    return None

def run_nmap_scanner():
    """Run the Nmap scanner with menu options."""
    scanner = NmapScanner()
    
    while True:
        print_nmap_menu()
        choice = input("Enter your choice (1-7): ").strip()
        
        if choice == "1":
            print("\nRunning all scans...")
            results = scanner.run_all_scans()
            print("\nScan completed. Results saved to:")
            print(f"- Raw results: {scanner.raw_output_dir}")
            print(f"- Extracted ports: {scanner.extract_output_dir}")
            
        elif choice == "2":
            print("\nRunning OS detection scan...")
            scan_type = get_scan_type_by_name('os_detection')
            if scan_type:
                scanner.run_scan_type(scan_type)
            
        elif choice == "3":
            print("\nRunning TCP port scan...")
            scan_type = get_scan_type_by_name('tcp_scan')
            if scan_type:
                scanner.run_scan_type(scan_type)
            
        elif choice == "4":
            print("\nRunning UDP port scan...")
            scan_type = get_scan_type_by_name('udp_scan')
            if scan_type:
                scanner.run_scan_type(scan_type)
            
        elif choice == "5":
            print("\nRunning service enumeration...")
            scan_type = get_scan_type_by_name('service_enumeration')
            if scan_type:
                scanner.run_scan_type(scan_type)
            
        elif choice == "6":
            view_last_scan_results()
            
        elif choice == "7":
            break
            
        else:
            print("\nInvalid choice. Please try again.")
        
        input("\nPress Enter to continue...")
        clear_screen()
        print_header()

def main():
    """Main function to run the tool."""
    try:
        while True:
            clear_screen()
            print_header()
            print_menu()
            
            choice = input("Enter your choice (1-2): ").strip()
            
            if choice == "1":
                clear_screen()
                print_header()
                run_nmap_scanner()
            elif choice == "2":
                print("\nThank you for using AI Security Tool!")
                sys.exit(0)
            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")
                
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
