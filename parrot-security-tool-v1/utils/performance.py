"""
Performance optimization utilities for security testing framework.
Includes caching, resource monitoring, and scan optimization.
"""

import time
import threading
import os
import psutil
import logging
from typing import Dict, Any, Optional, Callable
from functools import wraps

logger = logging.getLogger(__name__)

class ResourceMonitor:
    """Monitors system resources during scans"""
    
    def __init__(self, interval: float = 1.0):
        """Initialize the resource monitor
        
        Args:
            interval: Sampling interval in seconds
        """
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None
        self._cpu_usage = []
        self._memory_usage = []
        self._disk_io = []
        self._network_io = []
        
    def start(self):
        """Start resource monitoring in a background thread"""
        if self._thread and self._thread.is_alive():
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self._thread.start()
        logger.debug("Resource monitoring started")
        
    def stop(self):
        """Stop the resource monitoring thread"""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        logger.debug("Resource monitoring stopped")
        
    def _monitor_resources(self):
        """Monitor resource usage at regular intervals"""
        process = psutil.Process(os.getpid())
        last_disk_io = psutil.disk_io_counters()
        last_net_io = psutil.net_io_counters()
        last_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                # CPU usage (percent)
                cpu_percent = process.cpu_percent()
                self._cpu_usage.append(cpu_percent)
                
                # Memory usage (MB)
                mem_info = process.memory_info()
                memory_mb = mem_info.rss / (1024 * 1024)
                self._memory_usage.append(memory_mb)
                
                # Disk I/O (bytes/sec)
                current_disk_io = psutil.disk_io_counters()
                current_time = time.time()
                disk_read_rate = (current_disk_io.read_bytes - last_disk_io.read_bytes) / (current_time - last_time)
                disk_write_rate = (current_disk_io.write_bytes - last_disk_io.write_bytes) / (current_time - last_time)
                self._disk_io.append((disk_read_rate, disk_write_rate))
                
                # Network I/O (bytes/sec)
                current_net_io = psutil.net_io_counters()
                net_recv_rate = (current_net_io.bytes_recv - last_net_io.bytes_recv) / (current_time - last_time)
                net_sent_rate = (current_net_io.bytes_sent - last_net_io.bytes_sent) / (current_time - last_time)
                self._network_io.append((net_recv_rate, net_sent_rate))
                
                # Update last values
                last_disk_io = current_disk_io
                last_net_io = current_net_io
                last_time = current_time
                
                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Error in resource monitoring: {str(e)}")
                time.sleep(self.interval)
                
    def get_stats(self) -> Dict[str, Any]:
        """Get resource usage statistics
        
        Returns:
            Dict containing usage statistics
        """
        if not self._cpu_usage:
            return {
                "cpu": {"avg": 0, "max": 0},
                "memory": {"avg": 0, "max": 0},
                "disk_io": {"read_avg": 0, "write_avg": 0},
                "network_io": {"recv_avg": 0, "sent_avg": 0}
            }
            
        stats = {
            "cpu": {
                "avg": sum(self._cpu_usage) / len(self._cpu_usage),
                "max": max(self._cpu_usage)
            },
            "memory": {
                "avg": sum(self._memory_usage) / len(self._memory_usage),
                "max": max(self._memory_usage)
            },
            "disk_io": {
                "read_avg": sum(r for r, _ in self._disk_io) / len(self._disk_io),
                "write_avg": sum(w for _, w in self._disk_io) / len(self._disk_io)
            },
            "network_io": {
                "recv_avg": sum(r for r, _ in self._network_io) / len(self._network_io),
                "sent_avg": sum(s for _, s in self._network_io) / len(self._network_io)
            }
        }
        return stats


class ResultsCache:
    """Cache for scan results to avoid redundant operations"""
    
    def __init__(self, max_size: int = 100, ttl: int = 3600):
        """Initialize the cache
        
        Args:
            max_size: Maximum number of items in cache
            ttl: Time-to-live for cache entries in seconds
        """
        self._cache = {}
        self._access_times = {}
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.RLock()
        
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a value from the cache
        
        Args:
            key: Cache key
            
        Returns:
            The cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                return None
                
            # Check if entry has expired
            access_time = self._access_times.get(key, 0)
            if time.time() - access_time > self._ttl:
                self._cache.pop(key, None)
                self._access_times.pop(key, None)
                return None
                
            # Update access time
            self._access_times[key] = time.time()
            return self._cache[key]
            
    def put(self, key: str, value: Dict[str, Any]) -> None:
        """Store a value in the cache
        
        Args:
            key: Cache key
            value: Value to store
        """
        with self._lock:
            # Maintain cache size limit
            if len(self._cache) >= self._max_size:
                # Remove least recently used entry
                oldest_key = min(self._access_times.items(), key=lambda x: x[1])[0]
                self._cache.pop(oldest_key, None)
                self._access_times.pop(oldest_key, None)
                
            self._cache[key] = value
            self._access_times[key] = time.time()
            
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            
    def clear_expired(self) -> None:
        """Clear all expired entries from the cache"""
        with self._lock:
            now = time.time()
            expired_keys = [k for k, t in self._access_times.items() if now - t > self._ttl]
            for key in expired_keys:
                self._cache.pop(key, None)
                self._access_times.pop(key, None)
            
            if expired_keys:
                logger.debug(f"Cleared {len(expired_keys)} expired cache entries")

# Create global cache instance
_results_cache = ResultsCache()

def cached_scan_result(ttl: Optional[int] = None):
    """Decorator to cache scan results
    
    Args:
        ttl: Optional time-to-live override in seconds
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(self, target, *args, **kwargs):
            # Generate cache key
            scanner_name = self.__class__.__name__
            key_parts = [scanner_name, target]
            
            # Include relevant options in the cache key
            if hasattr(self, 'options') and self.options:
                for opt_name, opt_value in self.options.items():
                    if opt_name in ('port_range', 'stealth_mode', 'profile'):
                        key_parts.append(f"{opt_name}={opt_value}")
            
            cache_key = ":".join(str(part) for part in key_parts)
            
            # Try to get from cache
            result = _results_cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {scanner_name} on {target}")
                return result
            
            # Execute the original function
            result = func(self, target, *args, **kwargs)
            
            # Store result in cache
            _results_cache.put(cache_key, result)
            logger.debug(f"Cached result for {scanner_name} on {target}")
            return result
        return wrapper
    return decorator
