"""Scanner plugin system"""
import importlib
import os
import logging
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Base class for all scanner plugins"""
    
    def __init__(self, options=None):
        self.options = options or {}
        self.results = {}
        
    @abstractmethod
    def scan(self, target):
        """Run the scan implementation"""
        pass
        
    def get_results(self):
        """Return scan results"""
        return self.results
