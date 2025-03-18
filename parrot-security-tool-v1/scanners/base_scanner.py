"""Base scanner class for security scanner plugins"""
import logging
import hashlib
import json
import asyncio
from utils.performance import cached_scan_result

class BaseScanner:
    """Base class for all scanner plugins"""
    profile_tags = ["all"]  # Default profile tags
    
    def __init__(self, options=None):
        """Initialize scanner with options"""
        self.options = options or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def scan(self, target):
        """Base scan method to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement this method")
    
    async def async_scan(self, target):
        """Async version of scan method, by default runs the sync version in a thread"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.scan, target)
    
    def get_cache_key(self, target):
        """Generate a unique cache key for this scan and target"""
        key_data = {
            "scanner": self.__class__.__name__,
            "target": target,
            "options": self.options
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
