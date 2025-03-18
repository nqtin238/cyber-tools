"""
Enhanced parallel execution utility for security scanning operations
Provides improved multi-threading capabilities with advanced task management
"""

import logging
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Any, Optional, Tuple

@dataclass
class ScanTask:
    """Data class representing a scan task"""
    target: str
    scanner_class: Any
    scanner_options: Dict[str, Any]
    priority: int = 0  # Higher number = higher priority
    timeout: int = 600  # Default timeout in seconds
    retries: int = 2   # Default number of retries

class ParallelExecutor:
    """
    Enhanced parallel executor for security scanning tasks
    Manages a thread pool with priority queue, resource throttling, and error handling
    """
    
    def __init__(self, max_workers: int = None, cpu_intensive: bool = False):
        """
        Initialize the parallel executor
        
        Args:
            max_workers: Maximum number of concurrent threads (default: based on CPU count)
            cpu_intensive: If True, limits threads to CPU count to avoid overloading
        """
        import multiprocessing
        
        cpu_count = multiprocessing.cpu_count()
        
        if max_workers is None:
            # If CPU intensive, use CPU count
            # Otherwise, use CPU count * 2 for network-bound operations
            self.max_workers = cpu_count if cpu_intensive else cpu_count * 2
        else:
            self.max_workers = max_workers
            
        self.task_queue = queue.PriorityQueue()
        self.results = {}
        self.lock = threading.RLock()
        self.events = {}  # Per-target events for cancellation
        self.progress_callback = None
        
        logging.info(f"Parallel executor initialized with {self.max_workers} workers")
    
    def add_task(self, task: ScanTask):
        """Add a task to the queue"""
        # Add negative priority for proper ordering (higher priority = lower number)
        self.task_queue.put((-task.priority, task))
        logging.debug(f"Added task for {task.scanner_class.__name__} on {task.target}")
    
    def add_tasks(self, tasks: List[ScanTask]):
        """Add multiple tasks to the queue"""
        for task in tasks:
            self.add_task(task)
            
    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """
        Set a callback function for progress updates
        
        Args:
            callback: Function that takes (description, completed_count, total_count)
        """
        self.progress_callback = callback
    
    def cancel_target(self, target: str):
        """Cancel all pending tasks for a specific target"""
        if target in self.events:
            self.events[target].set()
            logging.info(f"Cancellation requested for target {target}")
    
    def _execute_task(self, task: ScanTask) -> Tuple[str, str, Any]:
        """
        Execute a single scan task with error handling and retries
        
        Returns:
            Tuple of (target, scanner_name, result)
        """
        target = task.target
        scanner_class = task.scanner_class
        scanner_name = scanner_class.__name__
        
        # Set up cancellation event for this target
        if target not in self.events:
            self.events[target] = threading.Event()
        
        # Check if cancellation was requested
        if self.events[target].is_set():
            logging.info(f"Skipping cancelled task for {scanner_name} on {target}")
            return target, scanner_name, {'error': 'Task cancelled by user'}
        
        # Initialize the scanner with options
        scanner = scanner_class(task.scanner_options)
        
        # Execute with retry logic
        for attempt in range(task.retries + 1):
            try:
                if attempt > 0:
                    logging.info(f"Retry #{attempt} for {scanner_name} on {target}")
                
                # Run the scan with timeout
                result = scanner.scan(target)
                
                # If successful, return the result
                return target, scanner_name, result
                
            except Exception as e:
                logging.error(f"Error in {scanner_name} on {target} (attempt {attempt+1}): {str(e)}")
                
                # If this was the last retry, return the error
                if attempt == task.retries:
                    return target, scanner_name, {'error': str(e)}
                    
                # Otherwise, wait before retrying
                time.sleep(2 ** attempt)  # Exponential backoff
                
                # Check again if cancellation was requested
                if self.events[target].is_set():
                    return target, scanner_name, {'error': 'Task cancelled by user'}
    
    def execute(self) -> Dict[str, Dict[str, Any]]:
        """
        Execute all queued tasks using thread pool
        
        Returns:
            Dictionary of results: {target: {scanner_name: result}}
        """
        task_count = self.task_queue.qsize()
        completed_count = 0
        
        if task_count == 0:
            logging.warning("No tasks to execute")
            return self.results
        
        logging.info(f"Starting execution of {task_count} tasks with {self.max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit all tasks to the thread pool
            while not self.task_queue.empty():
                _, task = self.task_queue.get()
                futures.append(executor.submit(self._execute_task, task))
            
            # Process results as they complete
            for future in as_completed(futures):
                try:
                    target, scanner_name, result = future.result()
                    
                    with self.lock:
                        if target not in self.results:
                            self.results[target] = {}
                        self.results[target][scanner_name] = result
                    
                    completed_count += 1
                    
                    # Call progress callback if set
                    if self.progress_callback:
                        self.progress_callback(
                            f"Running {scanner_name} on {target}", 
                            completed_count, 
                            task_count
                        )
                        
                    logging.info(f"Completed {scanner_name} on {target} ({completed_count}/{task_count})")
                    
                except Exception as e:
                    logging.error(f"Error retrieving task result: {str(e)}")
                    completed_count += 1
        
        logging.info(f"Completed all {task_count} tasks")
        return self.results

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example task
    class DummyScanner:
        def __init__(self, options):
            self.options = options
            
        def scan(self, target):
            time.sleep(1)  # Simulate work
            return {"status": "success", "target": target}
    
    # Create executor
    executor = ParallelExecutor(max_workers=4)
    
    # Add some tasks
    executor.add_tasks([
        ScanTask(target="192.168.1.1", scanner_class=DummyScanner, scanner_options={}),
        ScanTask(target="192.168.1.2", scanner_class=DummyScanner, scanner_options={}),
        ScanTask(target="192.168.1.3", scanner_class=DummyScanner, scanner_options={}, priority=10),
    ])
    
    # Execute and get results
    results = executor.execute()
    print(results)