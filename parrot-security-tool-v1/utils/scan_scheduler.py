"""
Scan Scheduler for automated security testing
Implements a flexible scheduler for running security scans at predefined intervals
"""

import os
import time
import json
import logging
import threading
import schedule
import datetime
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional, Union
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

@dataclass
class ScheduledScan:
    """Data class representing a scheduled scan"""
    name: str
    targets: List[str]
    profile: str
    frequency: str  # daily, weekly, monthly, custom
    time: str  # HH:MM format
    day: Optional[Union[int, str]] = None  # Day of week (0-6) or day of month (1-31)
    port_range: str = "1-1024"
    stealth_mode: bool = False
    notify_email: Optional[str] = None
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    enabled: bool = True
    options: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    def calculate_next_run(self):
        """Calculate the next run time based on frequency"""
        now = datetime.datetime.now()
        
        if self.frequency == "daily":
            hour, minute = map(int, self.time.split(':'))
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += datetime.timedelta(days=1)
        
        elif self.frequency == "weekly":
            hour, minute = map(int, self.time.split(':'))
            day = int(self.day) if self.day is not None else 0  # Default to Monday (0)
            
            # Find the next occurrence of the specified day
            days_ahead = day - now.weekday()
            if days_ahead <= 0:  # Target day already happened this week
                days_ahead += 7
                
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            next_run += datetime.timedelta(days=days_ahead)
            
        elif self.frequency == "monthly":
            hour, minute = map(int, self.time.split(':'))
            day = int(self.day) if self.day is not None else 1  # Default to 1st day
            
            # Start with the target day in the current month
            try:
                next_run = now.replace(day=day, hour=hour, minute=minute, second=0, microsecond=0)
            except ValueError:
                # Handle invalid days (e.g., 31st in a 30-day month)
                # Go to the 1st of next month
                if now.month == 12:
                    next_run = now.replace(year=now.year+1, month=1, day=1, hour=hour, minute=minute, second=0, microsecond=0)
                else:
                    next_run = now.replace(month=now.month+1, day=1, hour=hour, minute=minute, second=0, microsecond=0)
            
            # If the target day already passed this month, go to next month
            if next_run <= now:
                if now.month == 12:
                    next_run = next_run.replace(year=now.year+1, month=1)
                else:
                    next_run = next_run.replace(month=now.month+1)
                    
        elif self.frequency == "custom":
            # For custom interval, use options['interval_hours']
            interval_hours = self.options.get('interval_hours', 24)
            
            if self.last_run:
                last_run_dt = datetime.datetime.fromisoformat(self.last_run)
                next_run = last_run_dt + datetime.timedelta(hours=interval_hours)
            else:
                # If never run before, schedule based on current time
                hour, minute = map(int, self.time.split(':'))
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += datetime.timedelta(hours=interval_hours)
        else:
            # Default to daily if invalid frequency
            hour, minute = map(int, self.time.split(':'))
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += datetime.timedelta(days=1)
        
        self.next_run = next_run.isoformat()


class ScanScheduler:
    """Manages automated security scans on schedule"""
    
    def __init__(self, config_file: str = "scan_scheduler.json", log_file: str = "scan_scheduler.log"):
        """Initialize the scan scheduler"""
        self.config_file = config_file
        self.scans = []
        self.scheduler_thread = None
        self.stop_event = threading.Event()
        
        # Configure logging
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        
        # Load existing scans
        self.load_scans()
    
    def load_scans(self):
        """Load scheduled scans from config file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                
                self.scans = []
                for scan_data in data:
                    scan = ScheduledScan(**scan_data)
                    # Recalculate next run time
                    scan.calculate_next_run()
                    self.scans.append(scan)
                    
                logging.info(f"Loaded {len(self.scans)} scheduled scans")
            except Exception as e:
                logging.error(f"Error loading scheduled scans: {str(e)}")
                self.scans = []
    
    def save_scans(self):
        """Save scheduled scans to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump([scan.to_dict() for scan in self.scans], f, indent=2)
            logging.info(f"Saved {len(self.scans)} scheduled scans")
        except Exception as e:
            logging.error(f"Error saving scheduled scans: {str(e)}")
    
    def add_scan(self, scan: ScheduledScan):
        """Add a new scheduled scan"""
        scan.calculate_next_run()
        self.scans.append(scan)
        self.save_scans()
        logging.info(f"Added new scheduled scan: {scan.name}")
        return scan
    
    def update_scan(self, name: str, updated_scan: ScheduledScan) -> bool:
        """Update an existing scheduled scan"""
        for i, scan in enumerate(self.scans):
            if scan.name == name:
                updated_scan.calculate_next_run()
                self.scans[i] = updated_scan
                self.save_scans()
                logging.info(f"Updated scheduled scan: {name}")
                return True
        return False
    
    def delete_scan(self, name: str) -> bool:
        """Delete a scheduled scan"""
        for i, scan in enumerate(self.scans):
            if scan.name == name:
                del self.scans[i]
                self.save_scans()
                logging.info(f"Deleted scheduled scan: {name}")
                return True
        return False
    
    def get_scan(self, name: str) -> Optional[ScheduledScan]:
        """Get a scheduled scan by name"""
        for scan in self.scans:
            if scan.name == name:
                return scan
        return None
    
    def execute_scan(self, scan: ScheduledScan):
        """Execute a scheduled scan"""
        logging.info(f"Executing scheduled scan: {scan.name}")
        
        # Update last run time
        now = datetime.datetime.now()
        scan.last_run = now.isoformat()
        
        # Update next run time
        scan.calculate_next_run()
        
        # Save changes
        self.save_scans()
        
        # Build command to run the scan
        cmd = [
            "python", "interactive_system_tester.py",
            "--headless",
            "--profile", scan.profile,
            "--port-range", scan.port_range,
            "--targets", ",".join(scan.targets),
        ]
        
        if scan.stealth_mode:
            cmd.append("--stealth")
            
        # Add custom options
        for key, value in scan.options.items():
            if value is True:
                cmd.append(f"--{key}")
            elif value is not False and value is not None:
                cmd.append(f"--{key}={value}")
        
        try:
            # Run the scan
            output_dir = os.path.expanduser("~/scan_reports")
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(output_dir, f"{scan.name}_{timestamp}.log")
            
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                # Wait for process to complete
                process.wait()
            
            # Check if report was generated
            report_file = None
            for ext in ['html', 'txt', 'csv']:
                pattern = f"*{timestamp}.{ext}"
                reports = list(Path(output_dir).glob(pattern))
                if reports:
                    report_file = str(reports[0])
                    break
            
            # Send notification if email is configured
            if scan.notify_email:
                self.send_notification(
                    scan, 
                    success=(process.returncode == 0),
                    report_file=report_file
                )
                
            logging.info(f"Completed scheduled scan: {scan.name}")
            return True
            
        except Exception as e:
            logging.error(f"Error executing scheduled scan {scan.name}: {str(e)}")
            
            # Send failure notification
            if scan.notify_email:
                self.send_notification(scan, success=False, error=str(e))
                
            return False
    
    def send_notification(self, scan: ScheduledScan, success: bool, report_file: Optional[str] = None, error: Optional[str] = None):
        """Send email notification about scan results"""
        # Check if email configuration is available
        smtp_server = os.environ.get("SCAN_SMTP_SERVER")
        smtp_port = os.environ.get("SCAN_SMTP_PORT", "587")
        smtp_user = os.environ.get("SCAN_SMTP_USER")
        smtp_password = os.environ.get("SCAN_SMTP_PASSWORD")
        sender_email = os.environ.get("SCAN_SENDER_EMAIL")
        
        if not all([smtp_server, smtp_user, smtp_password, sender_email]):
            logging.error("Email notification configuration missing")
            return False
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = scan.notify_email
        
        if success:
            msg['Subject'] = f"Security Scan Completed: {scan.name}"
            body = f"""
            <html>
            <body>
                <h2>Security Scan Completed Successfully</h2>
                <p><strong>Scan Name:</strong> {scan.name}</p>
                <p><strong>Targets:</strong> {', '.join(scan.targets)}</p>
                <p><strong>Profile:</strong> {scan.profile}</p>
                <p><strong>Completion Time:</strong> {scan.last_run}</p>
                <p><strong>Next Scheduled Run:</strong> {scan.next_run}</p>
                
                <p>The scan report can be found at: {report_file}</p>
                
                <p>This is an automated message from the Security Testing Framework.</p>
            </body>
            </html>
            """
        else:
            msg['Subject'] = f"Security Scan Failed: {scan.name}"
            body = f"""
            <html>
            <body>
                <h2>Security Scan Failed</h2>
                <p><strong>Scan Name:</strong> {scan.name}</p>
                <p><strong>Targets:</strong> {', '.join(scan.targets)}</p>
                <p><strong>Profile:</strong> {scan.profile}</p>
                <p><strong>Time:</strong> {scan.last_run}</p>
                
                <p><strong>Error:</strong> {error or "Unknown error"}</p>
                
                <p>This is an automated message from the Security Testing Framework.</p>
            </body>
            </html>
            """
            
        msg.attach(MIMEText(body, 'html'))
        
        try:
            # Send email
            server = smtplib.SMTP(smtp_server, int(smtp_port))
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Sent notification email to {scan.notify_email}")
            return True
        except Exception as e:
            logging.error(f"Failed to send notification email: {str(e)}")
            return False
    
    def check_due_scans(self):
        """Check for scans that are due to run"""
        now = datetime.datetime.now()
        
        for scan in self.scans:
            if not scan.enabled:
                continue
                
            if not scan.next_run:
                scan.calculate_next_run()
                continue
            
            next_run_dt = datetime.datetime.fromisoformat(scan.next_run)
            if next_run_dt <= now:
                # Scan is due
                logging.info(f"Scan due: {scan.name}")
                self.execute_scan(scan)
    
    def run_scheduler(self):
        """Run the scheduler in a loop"""
        logging.info("Starting scan scheduler")
        
        while not self.stop_event.is_set():
            try:
                self.check_due_scans()
            except Exception as e:
                logging.error(f"Error in scheduler: {str(e)}")
                
            # Sleep for a minute
            time.sleep(60)
            
        logging.info("Scan scheduler stopped")
    
    def start(self):
        """Start the scheduler in a background thread"""
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            logging.warning("Scheduler already running")
            return
            
        self.stop_event.clear()
        self.scheduler_thread = threading.Thread(target=self.run_scheduler)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        
        logging.info("Scan scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if not self.scheduler_thread or not self.scheduler_thread.is_alive():
            logging.warning("Scheduler not running")
            return
            
        self.stop_event.set()
        self.scheduler_thread.join(timeout=5)
        
        logging.info("Scan scheduler stopped")
        
    def get_status(self):
        """Get the status of the scheduler"""
        return {
            "running": self.scheduler_thread is not None and self.scheduler_thread.is_alive(),
            "scans": len(self.scans),
            "enabled_scans": sum(1 for scan in self.scans if scan.enabled),
            "next_scan": min((scan.next_run for scan in self.scans if scan.enabled), default=None)
        }


if __name__ == "__main__":
    # Example usage
    scheduler = ScanScheduler()
    
    # Add a daily scan
    daily_scan = ScheduledScan(
        name="Daily Local Scan",
        targets=["127.0.0.1"],
        profile="network",
        frequency="daily",
        time="03:00",
        port_range="1-1024",
        stealth_mode=True,
        notify_email="admin@example.com"
    )
    scheduler.add_scan(daily_scan)
    
    # Add a weekly scan
    weekly_scan = ScheduledScan(
        name="Weekly Network Scan",
        targets=["192.168.1.0/24"],
        profile="vulnerability",
        frequency="weekly",
        time="02:00",
        day=6,  # Sunday
        port_range="1-10000",
        stealth_mode=True
    )
    scheduler.add_scan(weekly_scan)
    
    # Start the scheduler
    scheduler.start()
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        scheduler.stop()