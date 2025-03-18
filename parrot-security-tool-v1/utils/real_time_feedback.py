"""Real-time feedback utilities for providing scan progress updates"""
import time
import threading
import logging
from typing import Callable, Dict, Any, Optional
from queue import Queue
import sys

class ScanProgressMonitor:
    """
    Monitor and display real-time progress of scans
    Provides text-based and callback-based progress reporting
    """
    
    def __init__(self, total_tasks=0, update_interval=0.5):
        """
        Initialize the scan progress monitor
        
        Args:
            total_tasks: Total number of tasks to complete
            update_interval: How often to update the display (seconds)
        """
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.start_time = None
        self.update_interval = update_interval
        self.lock = threading.RLock()
        self.callbacks = []
        self.task_queue = Queue()
        self.status_message = "Initializing..."
        self.running = False
        self.thread = None
        self.progress_data = {
            "targets": {},
            "scanners": {},
            "current_target": None,
            "current_scanner": None
        }
    
    def add_callback(self, callback_fn: Callable[[Dict[str, Any]], None]):
        """Add a callback function that will receive progress updates"""
        self.callbacks.append(callback_fn)
    
    def start(self):
        """Start the progress monitor"""
        with self.lock:
            self.running = True
            self.start_time = time.time()
            
            # Start the update thread
            self.thread = threading.Thread(target=self._update_loop, daemon=True)
            self.thread.start()
            logging.debug("Progress monitor started")
    
    def stop(self):
        """Stop the progress monitor"""
        with self.lock:
            self.running = False
            if self.thread:
                self.thread.join(timeout=1.0)
                self.thread = None
            logging.debug("Progress monitor stopped")
    
    def set_total_tasks(self, total_tasks):
        """Set or update the total number of tasks"""
        with self.lock:
            self.total_tasks = total_tasks
            self._notify_callbacks()
    
    def update(self, status_message, increment=1):
        """
        Update progress with a new status message and increment completed tasks
        
        Args:
            status_message: Status message to display
            increment: How many tasks to increment (default: 1)
        """
        with self.lock:
            self.status_message = status_message
            self.completed_tasks += increment
            if self.completed_tasks > self.total_tasks:
                self.completed_tasks = self.total_tasks
                
            self._notify_callbacks()
    
    def update_scanner_progress(self, scanner_name, target, completed_items, total_items, status=None):
        """Update progress for a specific scanner and target"""
        with self.lock:
            # Update target info
            if target not in self.progress_data["targets"]:
                self.progress_data["targets"][target] = {
                    "scanners": {},
                    "completed": False
                }
            
            # Update scanner info for this target
            target_scanners = self.progress_data["targets"][target]["scanners"]
            if scanner_name not in target_scanners:
                target_scanners[scanner_name] = {
                    "completed_items": 0,
                    "total_items": 0,
                    "status": "Initializing",
                    "start_time": time.time(),
                    "completed": False
                }
            
            # Update values
            target_scanners[scanner_name]["completed_items"] = completed_items
            target_scanners[scanner_name]["total_items"] = total_items
            if status:
                target_scanners[scanner_name]["status"] = status
                
            # Mark as complete if done
            if completed_items >= total_items and total_items > 0:
                target_scanners[scanner_name]["completed"] = True
                target_scanners[scanner_name]["end_time"] = time.time()
            
            # Update current state
            self.progress_data["current_target"] = target
            self.progress_data["current_scanner"] = scanner_name
            
            # Update aggregated scanner info
            if scanner_name not in self.progress_data["scanners"]:
                self.progress_data["scanners"][scanner_name] = {
                    "completed_targets": 0,
                    "total_targets": len(self.progress_data["targets"]),
                    "start_time": time.time()
                }
            
            # Check if scanner completed for this target
            scanner_info = self.progress_data["scanners"][scanner_name]
            completed_for_scanner = sum(
                1 for t in self.progress_data["targets"].values() 
                if scanner_name in t["scanners"] and t["scanners"][scanner_name].get("completed", False)
            )
            scanner_info["completed_targets"] = completed_for_scanner
            
            # Create status message
            self.status_message = f"{scanner_name} on {target}: {completed_items}/{total_items}"
            
            # Calculate overall progress
            total_scanner_target_pairs = len(self.progress_data["scanners"]) * len(self.progress_data["targets"])
            completed_pairs = sum(
                s["completed_targets"] for s in self.progress_data["scanners"].values()
            )
            
            if total_scanner_target_pairs > 0:
                self.completed_tasks = completed_pairs
                self.total_tasks = total_scanner_target_pairs
            
            self._notify_callbacks()
    
    def mark_target_complete(self, target):
        """Mark a target as completely scanned"""
        with self.lock:
            if target in self.progress_data["targets"]:
                self.progress_data["targets"][target]["completed"] = True
                self._notify_callbacks()
    
    def get_progress_percentage(self):
        """Get the current progress as a percentage"""
        if self.total_tasks == 0:
            return 0
        return (self.completed_tasks / self.total_tasks) * 100
    
    def get_estimated_time_remaining(self):
        """Get the estimated time remaining in seconds"""
        if self.start_time is None or self.completed_tasks == 0 or self.total_tasks == 0:
            return None
            
        elapsed_time = time.time() - self.start_time
        tasks_per_second = self.completed_tasks / max(elapsed_time, 0.001)
        remaining_tasks = self.total_tasks - self.completed_tasks
        
        if tasks_per_second > 0:
            return remaining_tasks / tasks_per_second
        return None
    
    def get_progress_data(self):
        """Get all progress data as a dictionary"""
        with self.lock:
            progress_percentage = self.get_progress_percentage()
            remaining_time = self.get_estimated_time_remaining()
            
            return {
                "completed": self.completed_tasks,
                "total": self.total_tasks,
                "percentage": progress_percentage,
                "status": self.status_message,
                "elapsed_time": time.time() - self.start_time if self.start_time else 0,
                "remaining_time": remaining_time,
                "targets": self.progress_data["targets"],
                "scanners": self.progress_data["scanners"],
                "current_target": self.progress_data["current_target"],
                "current_scanner": self.progress_data["current_scanner"]
            }
    
    def _update_loop(self):
        """Background thread that updates the display and calls callbacks"""
        while self.running:
            try:
                self._update_display()
                time.sleep(self.update_interval)
            except Exception as e:
                logging.error(f"Error in progress monitor update loop: {str(e)}")
    
    def _update_display(self):
        """Update the display with current progress"""
        with self.lock:
            if self.task_queue.qsize() > 0:
                while not self.task_queue.empty():
                    try:
                        status_message, increment = self.task_queue.get_nowait()
                        self.status_message = status_message
                        self.completed_tasks += increment
                        if self.completed_tasks > self.total_tasks:
                            self.completed_tasks = self.total_tasks
                    except:
                        break
            
            self._notify_callbacks()
    
    def _notify_callbacks(self):
        """Notify all registered callbacks with current progress data"""
        progress_data = self.get_progress_data()
        for callback in self.callbacks:
            try:
                callback(progress_data)
            except Exception as e:
                logging.error(f"Error in progress callback: {str(e)}")

class ConsoleProgressPrinter:
    """
    Simple console progress printer that updates a single line
    with progress information
    """
    
    def __init__(self, clear_line=True):
        """
        Initialize the console progress printer
        
        Args:
            clear_line: Whether to clear the line before printing (for nice updates)
        """
        self.clear_line = clear_line
        self.last_print_time = 0
        self.print_interval = 0.25  # Don't update more than 4 times per second
    
    def update_progress(self, progress_data):
        """Update the console with progress information"""
        now = time.time()
        if now - self.last_print_time < self.print_interval:
            return
            
        self.last_print_time = now
        
        percentage = progress_data["percentage"]
        status = progress_data["status"]
        elapsed = progress_data["elapsed_time"]
        remaining = progress_data["remaining_time"]
        
        # Format elapsed and remaining time
        elapsed_str = self._format_time(elapsed)
        remaining_str = self._format_time(remaining) if remaining is not None else "??:??"
        
        # Create the progress bar
        bar_length = 30
        filled_length = int(bar_length * percentage / 100)
        bar = "█" * filled_length + "░" * (bar_length - filled_length)
        
        # Format the output line
        output = f"\r[{bar}] {percentage:.1f}% | {status} | {elapsed_str}/{remaining_str}"
        
        # Clear the line if needed
        if self.clear_line:
            sys.stdout.write("\r" + " " * 80)  # Clear the line
        
        # Print the output
        sys.stdout.write(output)
        sys.stdout.flush()
    
    def _format_time(self, seconds):
        """Format time in seconds to MM:SS format"""
        if seconds is None:
            return "??:??"
        
        minutes, seconds = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{minutes:02d}:{seconds:02d}"

def create_progress_monitor(total_tasks=0, console_output=True):
    """
    Create and configure a progress monitor with optional console output
    
    Args:
        total_tasks: Initial total number of tasks
        console_output: Whether to show progress in console
        
    Returns:
        Configured ScanProgressMonitor instance
    """
    monitor = ScanProgressMonitor(total_tasks)
    
    if console_output:
        printer = ConsoleProgressPrinter()
        monitor.add_callback(printer.update_progress)
    
    # Start the monitoring thread
    monitor.start()
    
    return monitor
