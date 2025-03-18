"""Lynis security auditing scanner implementation"""
from scanners.base_scanner import BaseScanner
import subprocess
import logging
import tempfile
import os
import re
import asyncio
import time

class LynisScanner(BaseScanner):
    """Lynis security auditing scanner plugin"""
    # Define which profiles this scanner belongs to
    profile_tags = ["all", "auditing", "compliance"]
    
    def __init__(self, options=None):
        super().__init__(options)
        
    def scan(self, target):
        """Run Lynis scan on target"""
        if target not in ["127.0.0.1", "localhost", "::1"]:
            return {
                "error": "Lynis scanner only works on localhost",
                "raw_output": ""
            }
            
        # Check if lynis is installed
        try:
            result = subprocess.run(["which", "lynis"], capture_output=True, text=True)
            if result.returncode != 0:
                return {
                    "error": "Lynis not found. Please install Lynis.",
                    "raw_output": ""
                }
        except Exception as e:
            return {
                "error": f"Error checking for Lynis: {str(e)}",
                "raw_output": ""
            }
            
        # Create temporary directory for output
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(temp_dir, "lynis_report.dat")
            log_file = os.path.join(temp_dir, "lynis_log.log")
            
            try:
                start_time = time.time()
                # Run Lynis audit
                cmd = ["sudo", "lynis", "audit", "system", 
                       "--no-colors", 
                       f"--report-file={output_file}", 
                       f"--log-file={log_file}"]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                
                scan_duration = time.time() - start_time
                raw_output = result.stdout
                
                # Parse results
                warnings = []
                suggestions = []
                
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        for line in f:
                            if "warning[]" in line:
                                warnings.append(line.split("=")[1].strip())
                            elif "suggestion[]" in line:
                                suggestions.append(line.split("=")[1].strip())
                                
                # Calculate statistics
                warning_count = len(warnings)
                suggestion_count = len(suggestions)
                
                return {
                    "warnings": warnings,
                    "suggestions": suggestions,
                    "warning_count": warning_count,
                    "suggestion_count": suggestion_count,
                    "scan_duration": scan_duration,
                    "raw_output": raw_output
                }
                
            except subprocess.TimeoutExpired:
                return {
                    "error": "Lynis scan timed out after 10 minutes",
                    "raw_output": ""
                }
            except Exception as e:
                return {
                    "error": f"Error running Lynis scan: {str(e)}",
                    "raw_output": ""
                }
                
    async def async_scan(self, target):
        """Run Lynis scan asynchronously"""
        # Create a coroutine that runs the scan in a separate thread
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.scan, target)