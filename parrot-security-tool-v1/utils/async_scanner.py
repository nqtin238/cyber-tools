"""Asynchronous scanning utilities for enhanced parallel execution"""
import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Tuple, Type
import hashlib
import json

from utils.performance import ResourceMonitor, ResultsCache
from scanners.base_scanner import BaseScanner

class AsyncScanManager:
    """
    Manages asynchronous execution of scanner plugins
    Provides resource management and caching capabilities
    """
    
    def __init__(self, 
                 max_concurrent: int = 10,
                 resource_monitor: Optional[ResourceMonitor] = None,
                 results_cache: Optional[ResultsCache] = None):
        """
        Initialize the async scan manager
        
        Args:
            max_concurrent: Maximum number of concurrent scans
            resource_monitor: ResourceMonitor instance or None to create new one
            results_cache: ResultsCache instance or None to create new one
        """
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.resource_monitor = resource_monitor or ResourceMonitor()
        self.cache = results_cache or ResultsCache()
        self.progress_callback = None
        self.logger = logging.getLogger(__name__)
        
    def set_progress_callback(self, callback):
        """Set a callback function for progress reporting"""
        self.progress_callback = callback
        
    def _report_progress(self, message, completed, total):
        """Internal method to call progress callback if set"""
        if self.progress_callback:
            self.progress_callback(message, completed, total)
            
    def _generate_cache_key(self, scanner_class: Type[BaseScanner], target: str, options: Dict):
        """Generate a cache key for a scan"""
        key_parts = [
            scanner_class.__name__,
            target,
            json.dumps(options or {}, sort_keys=True)
        ]
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
            
    async def scan_target(self, 
                         scanner_class: Type[BaseScanner], 
                         target: str, 
                         options: Optional[Dict] = None) -> Dict:
        """
        Run a single scan asynchronously with resource management and caching
        
        Args:
            scanner_class: Scanner class to use
            target: Target to scan
            options: Scanner options
            
        Returns:
            Dict containing scan results
        """
        scanner_name = scanner_class.__name__
        
        # Check cache first
        cache_key = self._generate_cache_key(scanner_class, target, options)
        cached_result = self.cache.get(cache_key)
        
        if cached_result:
            self.logger.info(f"Using cached result for {scanner_name} on {target}")
            return cached_result
        
        # Acquire semaphore to limit concurrent scans
        async with self.semaphore:
            # Wait for sufficient resources before starting scan
            await self.resource_monitor.wait_for_resources()
            
            try:
                # Create scanner instance
                scanner = scanner_class(options)
                
                # Use async_scan if available, otherwise run scan in thread pool
                start_time = time.time()
                
                if hasattr(scanner, 'async_scan') and callable(scanner.async_scan):
                    self.logger.info(f"Running async scan {scanner_name} on {target}")
                    result = await scanner.async_scan(target)
                else:
                    self.logger.info(f"Running sync scan {scanner_name} on {target} in thread pool")
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, scanner.scan, target)
                
                # Add scan duration to result
                scan_duration = time.time() - start_time
                if isinstance(result, dict):
                    result['scan_duration'] = scan_duration
                
                # Cache the result
                self.cache.set(cache_key, result)
                
                return result
            except Exception as e:
                self.logger.error(f"Error scanning {target} with {scanner_name}: {str(e)}")
                return {"error": str(e), "raw_output": ""}
    
    async def scan_multiple_targets(self, 
                                   scanner_class: Type[BaseScanner], 
                                   targets: List[str], 
                                   options: Optional[Dict] = None) -> Dict[str, Dict]:
        """
        Run a scanner against multiple targets
        
        Args:
            scanner_class: Scanner class to use
            targets: List of targets to scan
            options: Scanner options
            
        Returns:
            Dict mapping targets to scan results
        """
        scanner_name = scanner_class.__name__
        total = len(targets)
        tasks = []
        results = {}
        
        self.logger.info(f"Starting {scanner_name} scans against {total} targets")
        
        for i, target in enumerate(targets):
            self._report_progress(f"Preparing {scanner_name} scan {i+1}/{total}", i, total)
            task = self.scan_target(scanner_class, target, options)
            tasks.append((target, asyncio.create_task(task)))
        
        for i, (target, task) in enumerate(tasks):
            self._report_progress(f"Running {scanner_name} scan {i+1}/{total}", i, total)
            result = await task
            results[target] = result
            
        return results
    
    async def scan_with_multiple_scanners(self, 
                                         target: str, 
                                         scanner_classes: List[Type[BaseScanner]], 
                                         options: Optional[Dict] = None) -> Dict[str, Dict]:
        """
        Run multiple scanners against a single target
        
        Args:
            target: Target to scan
            scanner_classes: List of scanner classes to use
            options: Scanner options (used for all scanners)
            
        Returns:
            Dict mapping scanner names to scan results
        """
        total = len(scanner_classes)
        tasks = []
        results = {}
        
        self.logger.info(f"Starting scans of {target} with {total} scanners")
        
        for i, scanner_class in enumerate(scanner_classes):
            scanner_name = scanner_class.__name__
            self._report_progress(f"Preparing {scanner_name} scan for {target} {i+1}/{total}", i, total)
            task = self.scan_target(scanner_class, target, options)
            tasks.append((scanner_name, asyncio.create_task(task)))
        
        for i, (scanner_name, task) in enumerate(tasks):
            self._report_progress(f"Running {scanner_name} scan for {target} {i+1}/{total}", i, total)
            result = await task
            results[scanner_name] = result
            
        return results
    
    async def scan_all(self, 
                       scanner_classes: List[Type[BaseScanner]], 
                       targets: List[str], 
                       options: Optional[Dict] = None) -> Dict[str, Dict[str, Dict]]:
        """
        Run all scanners against all targets
        
        Args:
            scanner_classes: List of scanner classes to use
            targets: List of targets to scan
            options: Scanner options (used for all scanners)
            
        Returns:
            Dict mapping targets to dicts mapping scanner names to scan results
        """
        total_scanners = len(scanner_classes)
        total_targets = len(targets)
        total_scans = total_scanners * total_targets
        task_count = 0
        
        self.logger.info(f"Starting {total_scans} scans with {total_scanners} scanners against {total_targets} targets")
        
        # Start resource monitoring
        self.resource_monitor.start_monitoring()
        
        try:
            all_tasks = []
            results = {target: {} for target in targets}
            
            # Create all tasks
            for target_idx, target in enumerate(targets):
                for scanner_idx, scanner_class in enumerate(scanner_classes):
                    scanner_name = scanner_class.__name__
                    task_count += 1
                    self._report_progress(
                        f"Preparing scan {task_count}/{total_scans}: {scanner_name} on {target}",
                        task_count,
                        total_scans
                    )
                    
                    # Prioritize tasks based on index to maintain predictable order
                    # We use target_idx * total_scanners + scanner_idx to ensure unique priorities
                    task = asyncio.create_task(
                        self.scan_target(scanner_class, target, options)
                    )
                    all_tasks.append((target, scanner_name, task))
            
            # Wait for all tasks and process results
            completed_count = 0
            for target, scanner_name, task in all_tasks:
                try:
                    result = await task
                    results[target][scanner_name] = result
                    completed_count += 1
                    self._report_progress(
                        f"Completed {completed_count}/{total_scans}: {scanner_name} on {target}",
                        completed_count, 
                        total_scans
                    )
                except Exception as e:
                    self.logger.error(f"Error scanning {target} with {scanner_name}: {str(e)}")
                    results[target][scanner_name] = {"error": str(e), "raw_output": ""}
                    completed_count += 1
            
            return results
            
        finally:
            # Stop resource monitoring
            self.resource_monitor.stop_monitoring()
