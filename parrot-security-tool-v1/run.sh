#!/bin/bash

# Security Testing Framework - Launcher Script
# This script activates the Python virtual environment and runs the framework with proper permissions

# ANSI color codes for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found. Please run setup.sh first.${NC}"
    exit 1
fi

# Check if main script exists
MAIN_SCRIPT="interactive_system_tester.py"
if [ ! -f "$MAIN_SCRIPT" ]; then
    echo -e "${RED}Main script not found: $MAIN_SCRIPT${NC}"
    echo -e "${YELLOW}Checking for alternatives...${NC}"
    
    # Try to find similar Python scripts
    ALTERNATIVES=$(find . -maxdepth 1 -name "*.py" -type f | grep -v "__" | grep -v "setup_")
    
    if [ -n "$ALTERNATIVES" ]; then
        echo -e "${YELLOW}Found alternative scripts:${NC}"
        select script in $ALTERNATIVES; do
            if [ -n "$script" ]; then
                MAIN_SCRIPT=$(basename "$script")
                echo -e "${GREEN}Using $MAIN_SCRIPT as main script${NC}"
                break
            else
                echo -e "${RED}Invalid selection${NC}"
            fi
        done
    else
        echo -e "${RED}No Python scripts found. Please make sure the framework is properly installed.${NC}"
        exit 1
    fi
fi

# Print banner
echo -e "${BLUE}"
echo "====================================================="
echo " Security Testing Framework - Launcher"
echo "====================================================="
echo -e "${NC}"

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Some scanners require root privileges to work properly.${NC}"
    echo -e "${YELLOW}Would you like to run with sudo? [y/N]${NC}"
    read -r run_as_root
    
    if [[ "$run_as_root" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Running with sudo...${NC}"
        sudo -E python "$MAIN_SCRIPT" "$@"
    else
        echo -e "${YELLOW}Running without sudo (limited functionality)...${NC}"
        python "$MAIN_SCRIPT" "$@"
    fi
else
    echo -e "${GREEN}Running with root privileges...${NC}"
    python "$MAIN_SCRIPT" "$@"
fi

# Deactivate virtual environment
deactivate