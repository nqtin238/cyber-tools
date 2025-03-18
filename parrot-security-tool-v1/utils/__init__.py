"""Utility modules for Parrot Security Tool"""

from .performance import ResourceMonitor, ResultsCache
from .scan_scheduler import ScanScheduler  # Changed from .performance import ScanScheduler
from .parallel_executor import ParallelExecutor, ScanTask
from .cache_manager import PersistentCache
from .resource_limiter import ResourceLimiter, ResourceLimit
from .async_scanner import AsyncScanManager
from .async_runner import AsyncRunner, run_async_task, get_or_create_event_loop
from .logging_config import initialize_logging, get_logger, log_with_context  # Import new logging utilities

# Set up the logging for the utils package
import logging
logger = logging.getLogger(__name__)

# Helper function to initialize the performance utilities
def init_performance_optimization():
    """Initialize performance optimization utilities"""
    try:
        import asyncio
        import platform
        
        # Use uvloop if available for non-Windows systems
        if platform.system() != "Windows":
            try:
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                logger.info("Performance enhancement: Using uvloop for improved asyncio performance")
            except ImportError:
                logger.debug("uvloop not available, using standard event loop")
        else:
            # Use selector event loop policy for better Windows performance
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            logger.debug("Performance enhancement: Using WindowsSelectorEventLoopPolicy for Windows")
            
        # Set up caching
        cache = PersistentCache()
        cache.clear_expired()
        
        return True
    except Exception as e:
        logger.error(f"Failed to initialize performance optimizations: {str(e)}")
        return False
