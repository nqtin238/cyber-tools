"""Resource monitoring and limiting utilities for performance optimization"""
import os
import time
import logging
import threading
import asyncio
from typing import Dict, Optional, Callable, List

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logging.warning("psutil module not found. Resource limiting will be disabled.")

class ResourceLimit:
    """Represents a limit on a system resource"""
    
    def __init__(self, name: str, threshold: float, current_func: Callable[[], float]):
        """
        Initialize a resource limit
        
        Args:
            name: Name of the resource (e.g., "CPU")
            threshold: Threshold value (0-100 for percentages)
            current_func: Function that returns current resource usage
        """
        self.name = name
        self.threshold = threshold
        self.current_func = current_func
        self.exceeded = False
        self.current_value = 0
        
    def check(self) -> bool:
        """
        Check if this resource is over its threshold
        
        Returns:
            True if resource usage exceeds threshold
        """
        try:
            self.current_value = self.current_func()
            self.exceeded = self.current_value > self.threshold
            return self.exceeded
        except Exception as e:
            logging.error(f"Error checking {self.name} resource: {str(e)}")
            return False
    
    def get_usage_percent(self) -> float:
        """Get resource usage as a percentage of threshold"""
        if self.threshold <= 0:
            return 100.0
        return (self.current_value / self.threshold) * 100.0
    
    def __str__(self) -> str:
        return f"{self.name}: {self.current_value:.1f}/{self.threshold:.1f} ({'EXCEEDED' if self.exceeded else 'OK'})"

class ResourceLimiter:
    """
    Monitors and limits resource usage to prevent system overload
    Both synchronous and asynchronous interfaces are provided
    """
    
    def __init__(self, 
                 cpu_limit_percent: float = 85.0, 
                 memory_limit_percent: float = 85.0,
                 io_limit_percent: float = 80.0,
                 check_interval: float = 1.0,
                 backoff_factor: float = 1.5,
                 max_backoff: float = 60.0):
        """
        Initialize the resource limiter
        
        Args:
            cpu_limit_percent: Maximum CPU usage percentage (0-100)
            memory_limit_percent: Maximum memory usage percentage (0-100)
            io_limit_percent: Maximum disk I/O usage percentage (0-100)
            check_interval: How often to check resource usage in seconds
            backoff_factor: Multiplier for backoff time when resources are exceeded
            max_backoff: Maximum backoff time in seconds
        """
        self.logger = logging.getLogger(__name__)
        self.check_interval = check_interval
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.enabled = HAS_PSUTIL
        self.process = psutil.Process(os.getpid()) if HAS_PSUTIL else None
        
        # Set up resource limits
        self.limits: List[ResourceLimit] = []
        
        if HAS_PSUTIL:
            # CPU limit
            self.limits.append(ResourceLimit(
                "CPU",
                cpu_limit_percent,
                lambda: psutil.cpu_percent(interval=0.1)
            ))
            
            # Memory limit
            self.limits.append(ResourceLimit(
                "Memory",
                memory_limit_percent,
                lambda: self.process.memory_percent()
            ))
            
            # I/O limit (based on disk usage)
            if hasattr(psutil, 'disk_io_counters'):
                self.limits.append(ResourceLimit(
                    "Disk I/O",
                    io_limit_percent,
                    self._get_io_percent
                ))
        
        # Initialize monitoring state
        self._last_io_counters = None
        self._last_io_time = time.time()
        self._monitoring = False
        self._monitor_thread = None
        self._monitor_task = None
        self._current_backoff = check_interval
        
        # Use an event to allow threads to wait
        self._resources_available = threading.Event()
        self._resources_available.set()  # Initially resources are available
        
        self.logger.info(f"Resource limiter initialized with limits: CPU {cpu_limit_percent}%, "
                         f"Memory {memory_limit_percent}%, I/O {io_limit_percent}%")
        
        if not HAS_PSUTIL:
            self.logger.warning("psutil module not found. Resource limiting is disabled.")
    
    def _get_io_percent(self) -> float:
        """Calculate disk I/O usage percentage"""
        if not hasattr(psutil, 'disk_io_counters'):
            return 0.0
            
        current_time = time.time()
        current_counters = psutil.disk_io_counters()
        
        if self._last_io_counters is None:
            self._last_io_counters = current_counters
            self._last_io_time = current_time
            return 0.0
            
        # Calculate I/O rate (bytes per second)
        time_diff = current_time - self._last_io_time
        if time_diff <= 0:
            return 0.0
            
        read_diff = current_counters.read_bytes - self._last_io_counters.read_bytes
        write_diff = current_counters.write_bytes - self._last_io_counters.write_bytes
        
        # Update last values
        self._last_io_counters = current_counters
        self._last_io_time = current_time
        
        # Calculate total I/O bytes per second
        io_bytes_per_sec = (read_diff + write_diff) / time_diff
        
        # Convert to a percentage (assuming 100MB/s is 100%)
        # This is a rough estimate and can be adjusted based on the system
        max_io_bytes_per_sec = 100 * 1024 * 1024  # 100 MB/s
        io_percent = (io_bytes_per_sec / max_io_bytes_per_sec) * 100
        
        return min(io_percent, 100.0)  # Cap at 100%
    
    def check_resources(self) -> Dict[str, bool]:
        """
        Check all resource limits
        
        Returns:
            Dict mapping resource names to boolean (True if exceeded)
        """
        if not self.enabled:
            return {}
            
        results = {}
        any_exceeded = False
        
        for limit in self.limits:
            exceeded = limit.check()
            results[limit.name] = exceeded
            if exceeded:
                any_exceeded = True
                self.logger.warning(f"Resource limit exceeded: {limit}")
        
        # Adjust backoff time based on resource usage
        if any_exceeded:
            self._resources_available.clear()
            self._current_backoff = min(self._current_backoff * self.backoff_factor, self.max_backoff)
        else:
            self._resources_available.set()
            self._current_backoff = self.check_interval
            
        return results
    
    def start_monitoring(self) -> bool:
        """
        Start background resource monitoring
        
        Returns:
            True if monitoring was started, False if it was already running or could not be started
        """
        if not self.enabled:
            return False
            
        if self._monitoring:
            return False  # Already monitoring
            
        self._monitoring = True
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_resources_thread,
            daemon=True
        )
        self._monitor_thread.start()
        self.logger.info("Resource monitoring started in background thread")
        return True
    
    def _monitor_resources_thread(self):
        """Background thread that periodically checks resource usage"""
        while self._monitoring:
            try:
                self.check_resources()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in resource monitoring thread: {str(e)}")
                time.sleep(self.check_interval * 2)  # Longer sleep after error
    
    def start_async_monitoring(self, loop=None):
        """Start asynchronous resource monitoring using asyncio"""
        if not self.enabled:
            return
            
        if self._monitoring:
            return  # Already monitoring
            
        self._monitoring = True
        
        if loop is None:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
        self._monitor_task = loop.create_task(self._monitor_resources_async())
        self.logger.info("Resource monitoring started asynchronously")
    
    async def _monitor_resources_async(self):
        """Asynchronous task that periodically checks resource usage"""
        while self._monitoring:
            try:
                self.check_resources()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in async resource monitoring: {str(e)}")
                await asyncio.sleep(self.check_interval * 2)
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self._monitoring = False
        
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            self._monitor_task = None
            
        # Thread will terminate on its own (daemon=True)
        self._monitor_thread = None
        
        self.logger.info("Resource monitoring stopped")
    
    def wait_for_resources(self, timeout=None):
        """
        Wait synchronously until resources are available or timeout
        
        Args:
            timeout: Maximum time to wait in seconds, or None for infinite
            
        Returns:
            True if resources are available, False if timed out
        """
        if not self.enabled:
            return True
            
        return self._resources_available.wait(timeout)
    
    async def wait_for_resources_async(self, timeout=None):
        """
        Wait asynchronously until resources are available
        
        Args:
            timeout: Maximum time to wait in seconds, or None for infinite
            
        Returns:
            True if resources are available, False if timed out
        """
        if not self.enabled:
            return True
            
        if self._resources_available.is_set():
            return True
            
        # Create a future that will be set when resources become available
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        
        def resource_available_callback():
            if not future.done():
                future.set_result(True)
        
        # Set up a thread to monitor the event and set the future
        def wait_for_event():
            if self._resources_available.wait(timeout):
                loop.call_soon_threadsafe(resource_available_callback)
            else:
                loop.call_soon_threadsafe(lambda: future.set_result(False) if not future.done() else None)
        
        thread = threading.Thread(target=wait_for_event, daemon=True)
        thread.start()
        
        # Wait for the future to be set
        return await future
    
    def get_resource_usage(self) -> Dict[str, float]:
        """
        Get current resource usage for all monitored resources
        
        Returns:
            Dict mapping resource names to current usage values
        """
        if not self.enabled:
            return {}
            
        return {limit.name: limit.current_value for limit in self.limits}
    
    def get_current_backoff(self) -> float:
        """Get current backoff time in seconds"""
        return self._current_backoff
