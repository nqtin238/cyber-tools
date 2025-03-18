"""Utility for running async tasks from synchronous code"""
import asyncio
import logging
import threading
import platform
from typing import Any, Callable, Dict, List, Optional
from .logging_config import get_logger

# Get a logger for this module
logger = get_logger(__name__)

def get_or_create_event_loop():
    """Get the current event loop or create a new one if needed"""
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        # No event loop in this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.debug("Created new event loop in current thread")
        return loop

def run_async_task(coro, loop=None):
    """
    Run an asynchronous coroutine from synchronous code
    
    Args:
        coro: Coroutine to run
        loop: Optional event loop to use
        
    Returns:
        Result of the coroutine
    """
    if loop is None:
        loop = get_or_create_event_loop()
    
    try:
        logger.debug(f"Running async task: {coro.__qualname__ if hasattr(coro, '__qualname__') else 'coroutine'}")
        result = loop.run_until_complete(coro)
        return result
    except Exception as e:
        logger.error(f"Error running async task: {str(e)}", exc_info=True)
        raise

class AsyncRunner:
    """Helper class for managing asyncio event loops and tasks"""
    def __init__(self, max_workers=10, use_threadpool=True):
        """
        Initialize AsyncRunner
        
        Args:
            max_workers: Maximum number of worker threads
            use_threadpool: Whether to use a thread pool for running async tasks
        """
        self.max_workers = max_workers
        self.use_threadpool = use_threadpool
        self.loop = None
        self._thread = None
        self._running = False
        self._tasks = []
        
        logger.debug(f"AsyncRunner initialized with {max_workers} max workers")
    
    def start(self):
        """Start the async event loop in a background thread"""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("AsyncRunner is already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._thread.start()
        logger.info("AsyncRunner started in background thread")
    
    def _run_event_loop(self):
        """Run the event loop in the current thread"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            logger.debug("Event loop started")
            self.loop.run_forever()
        except Exception as e:
            logger.error(f"Error in event loop: {str(e)}", exc_info=True)
        finally:
            # Clean up pending tasks
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            
            # Wait for tasks to cancel
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            
            self.loop.close()
            logger.debug("Event loop closed")
    
    def stop(self):
        """Stop the async event loop"""
        if not self._running or self.loop is None:
            logger.warning("AsyncRunner is not running")
            return
        
        self._running = False
        self.loop.call_soon_threadsafe(self.loop.stop)
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            logger.info("AsyncRunner stopped")
    
    def submit(self, coro):
        """
        Submit a coroutine to be executed
        
        Args:
            coro: Coroutine to run
            
        Returns:
            asyncio.Task: Task representing the execution
        """
        if not self._running or self.loop is None:
            logger.error("AsyncRunner is not running. Call start() first.")
            raise RuntimeError("AsyncRunner is not running")
        
        task = asyncio.run_coroutine_threadsafe(coro, self.loop)
        self._tasks.append(task)
        
        # Set up callback to remove task when done
        task.add_done_callback(lambda t: self._tasks.remove(t) if t in self._tasks else None)
        
        logger.debug(f"Task submitted: {coro.__qualname__ if hasattr(coro, '__qualname__') else 'coroutine'}")
        return task
