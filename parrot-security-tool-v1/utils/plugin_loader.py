"""Plugin loader utility for dynamically loading scanner plugins"""
import os
import importlib
import inspect
import logging
import asyncio
from scanners.base_scanner import BaseScanner
from .logging_config import get_logger

# Get a logger for this module
logger = get_logger(__name__)

def load_scanner_plugins():
    """Dynamically load all scanner plugins from the scanners package"""
    plugins = {}
    try:
        # Get the current directory of the script
        current_dir = os.path.dirname(os.path.abspath(__file__))
        scanners_dir = os.path.join(os.path.dirname(current_dir), 'scanners')
        
        # Make sure the scanners directory exists
        if not os.path.exists(scanners_dir):
            logger.error(f"Scanners directory not found at {scanners_dir}")
            return plugins
        
        # Get all Python files in the scanners directory
        plugin_files = [f for f in os.listdir(scanners_dir) 
                       if f.endswith('.py') and not f.startswith('__')]
        
        # Import each file and look for scanner classes
        for plugin_file in plugin_files:
            try:
                # Convert filename to module name (remove .py extension)
                module_name = f"scanners.{plugin_file[:-3]}"
                
                # Import the module
                module = importlib.import_module(module_name)
                
                # Find all classes in the module that inherit from BaseScanner
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, BaseScanner) and 
                        obj != BaseScanner):
                        plugins[name] = obj
                        logger.info(f"Loaded scanner plugin: {name}")
            except Exception as e:
                logger.error(f"Error loading plugin {plugin_file}: {str(e)}", exc_info=True)
        
        return plugins
    except Exception as e:
        logger.error(f"Error in load_scanner_plugins: {str(e)}", exc_info=True)
        return plugins

def get_plugin_by_name(plugin_name):
    """Get a specific plugin by name"""
    plugins = load_scanner_plugins()
    return plugins.get(plugin_name)

def get_plugins_for_profile(profile):
    """Get a list of plugins suitable for a specific profile"""
    plugins = load_scanner_plugins()
    
    # Filter plugins based on profile
    if profile == "all":
        return plugins
    
    profile_plugins = {}
    for name, plugin_class in plugins.items():
        # Check if plugin has profile_tags attribute
        if hasattr(plugin_class, 'profile_tags') and profile in plugin_class.profile_tags:
            profile_plugins[name] = plugin_class
        # Fallback to name-based matching
        elif profile.lower() in name.lower():
            profile_plugins[name] = plugin_class
            
    return profile_plugins

async def run_async_scan(scanner_instance, target):
    """Run a scanner asynchronously if it supports it, otherwise run in a thread pool"""
    if hasattr(scanner_instance, 'async_scan') and callable(scanner_instance.async_scan):
        return await scanner_instance.async_scan(target)
    else:
        # Run regular scan method in a thread pool executor
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, scanner_instance.scan, target)

async def run_parallel_scanners(scanners, targets, max_concurrent=10):
    """Run multiple scanners against multiple targets in parallel with concurrency limit"""
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = []
    results = {}
    
    for target in targets:
        if target not in results:
            results[target] = {}
        
        for scanner_name, scanner_class in scanners.items():
            tasks.append(
                run_scanner_for_target(semaphore, scanner_name, scanner_class, target, results)
            )
    
    await asyncio.gather(*tasks)
    return results

async def run_scanner_for_target(semaphore, scanner_name, scanner_class, target, results):
    """Run a scanner for a specific target with semaphore control"""
    async with semaphore:
        logger.debug(f"Starting {scanner_name} for target {target}")
        try:
            # Create scanner instance
            scanner = scanner_class()
            
            # Run the scan
            scan_result = await run_async_scan(scanner, target)
            
            # Store results
            results[target][scanner_name] = scan_result
            logger.info(f"Completed {scanner_name} scan for {target}")
            
        except Exception as e:
            logger.error(f"Error running {scanner_name} for {target}: {str(e)}", exc_info=True)
            results[target][scanner_name] = {"error": str(e)}

async def run_workflow(workflow_config, targets, feedback_callback=None):
    """Run a workflow of chained scanners that share data between them"""
    results = {target: {} for target in targets}
    workflow_context = {target: {} for target in targets}
    plugins = load_scanner_plugins()
    
    total_steps = len(workflow_config['steps']) * len(targets)
    completed_steps = 0
    
    for step_config in workflow_config['steps']:
        scanner_name = step_config['scanner']
        scanner_class = plugins.get(scanner_name)
        
        if not scanner_class:
            logger.error(f"Scanner {scanner_name} not found in available plugins")
            continue
            
        for target in targets:
            options = step_config.get('options', {}).copy()
            
            # Add context from previous steps
            options['workflow_context'] = workflow_context[target]
            
            # Update progress
            if feedback_callback:
                completed_steps += 1
                feedback_callback(f"Running {scanner_name}", completed_steps, total_steps)
            
            try:
                scanner_instance = scanner_class(options)
                
                if hasattr(scanner_instance, 'async_scan') and callable(scanner_instance.async_scan):
                    scan_result = await scanner_instance.async_scan(target)
                else:
                    loop = asyncio.get_event_loop()
                    scan_result = await loop.run_in_executor(None, scanner_instance.scan, target)
                
                # Store the result
                results[target][scanner_name] = scan_result
                
                # Update the workflow context with this scanner's results
                workflow_context[target][scanner_name] = scan_result
                
                # Handle specific data sharing between scanners
                if scanner_name == "NmapScanner" and "ports" in scan_result:
                    workflow_context[target]["open_ports"] = scan_result["ports"]
                elif scanner_name == "VulnerabilityScanner" and "vulnerabilities" in scan_result:
                    workflow_context[target]["known_vulnerabilities"] = scan_result["vulnerabilities"]
                
            except Exception as e:
                logger.error(f"Error in workflow step {scanner_name} for {target}: {str(e)}")
                results[target][scanner_name] = {"error": str(e)}
    
    return results, workflow_context