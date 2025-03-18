"""Workflow manager for executing custom scan workflows with data sharing between steps"""
import logging
import asyncio
import time
from typing import Dict, List, Any, Callable, Optional

from utils.plugin_loader import load_scanner_plugins, run_async_scan
from utils.real_time_feedback import ScanProgressMonitor

class WorkflowManager:
    """
    Manages the execution of custom scan workflows
    Handles data sharing between scan steps and provides progress updates
    """
    
    def __init__(self, progress_monitor: Optional[ScanProgressMonitor] = None):
        """
        Initialize the workflow manager
        
        Args:
            progress_monitor: Optional progress monitor for real-time updates
        """
        self.progress_monitor = progress_monitor
        self.plugins = load_scanner_plugins()
        
    async def run_workflow(self, workflow_config: Dict[str, Any], targets: List[str]) -> Dict[str, Any]:
        """
        Execute a workflow against targets
        
        Args:
            workflow_config: Workflow configuration dictionary with steps
            targets: List of target IPs/hostnames to scan
            
        Returns:
            Dictionary of results organized by target
        """
        if not workflow_config or not targets:
            logging.error("Invalid workflow configuration or empty targets list")
            return {}
            
        results = {target: {} for target in targets}
        workflow_context = {target: {} for target in targets}
        
        steps = workflow_config.get("steps", [])
        total_steps = len(steps) * len(targets)
        
        if self.progress_monitor:
            self.progress_monitor.set_total_tasks(total_steps)
            self.progress_monitor.update("Starting workflow execution", 0)
        
        step_index = 0
        for step_config in steps:
            scanner_name = step_config.get("scanner")
            scanner_class = self.plugins.get(scanner_name)
            
            if not scanner_class:
                logging.error(f"Scanner not found: {scanner_name}")
                continue
            
            scanner_options = step_config.get("options", {})
            
            for target_index, target in enumerate(targets):
                # Update progress monitor
                if self.progress_monitor:
                    self.progress_monitor.update(
                        f"Step {step_index+1}/{len(steps)}: Running {scanner_name} on {target}", 0
                    )
                
                # Create context for this step
                step_context = workflow_context[target].copy()
                scanner_options["workflow_context"] = step_context
                
                try:
                    # Create scanner instance with options
                    scanner = scanner_class(scanner_options)
                    
                    # Register progress updates if scanner supports it
                    if self.progress_monitor and hasattr(scanner, 'register_progress_callback'):
                        scanner.register_progress_callback(
                            lambda completed, total, status=None, s_name=scanner_name, t=target: 
                            self.progress_monitor.update_scanner_progress(s_name, t, completed, total, status)
                        )
                    
                    # Run the scan
                    start_time = time.time()
                    result = await run_async_scan(scanner, target)
                    duration = time.time() - start_time
                    
                    # Store result and context
                    results[target][scanner_name] = result
                    workflow_context[target][scanner_name] = result
                    
                    # Special handling for certain scanner types
                    if scanner_name == "NmapScanner" and isinstance(result, dict):
                        workflow_context[target]["open_ports"] = result.get("ports", [])
                        workflow_context[target]["os_info"] = result.get("os_info", {})
                        workflow_context[target]["host_info"] = result.get("host_info", {})
                    
                    # Update progress monitor
                    if self.progress_monitor:
                        self.progress_monitor.update(
                            f"Completed {scanner_name} on {target} in {duration:.1f}s",
                            1
                        )
                    
                    logging.info(f"Completed workflow step: {scanner_name} on {target} in {duration:.1f}s")
                    
                except Exception as e:
                    logging.error(f"Error in workflow step {step_index+1} ({scanner_name}) for {target}: {str(e)}")
                    results[target][scanner_name] = {"error": str(e)}
                    
                    # Update progress monitor
                    if self.progress_monitor:
                        self.progress_monitor.update(
                            f"Error in {scanner_name} on {target}: {str(e)}",
                            1
                        )
            
            step_index += 1
        
        # Complete progress monitoring
        if self.progress_monitor:
            self.progress_monitor.update("Workflow execution completed", 0)
        
        return results
    
    def get_compatible_scanners(self):
        """Get the list of scanners that can be used in workflows"""
        compatible_scanners = {}
        
        for name, scanner_class in self.plugins.items():
            # Check if the scanner has the necessary attributes/methods
            compatible_scanners[name] = {
                "name": name,
                "description": scanner_class.__doc__ or f"{name} scanner",
                "supports_async": hasattr(scanner_class, "async_scan") and callable(getattr(scanner_class, "async_scan")),
                "supported_options": self._get_scanner_options(scanner_class)
            }
        
        return compatible_scanners
    
    def _get_scanner_options(self, scanner_class):
        """Extract the supported options for a scanner class"""
        options = {}
        
        # Check if scanner has documented options
        if hasattr(scanner_class, "OPTIONS"):
            return scanner_class.OPTIONS
        
        # Try to infer from __init__ parameters
        import inspect
        try:
            init_signature = inspect.signature(scanner_class.__init__)
            for param_name, param in init_signature.parameters.items():
                if param_name not in ["self", "args", "kwargs"]:
                    options[param_name] = {
                        "type": "any",
                        "required": param.default == inspect.Parameter.empty,
                        "default": None if param.default == inspect.Parameter.empty else param.default
                    }
        except Exception as e:
            logging.debug(f"Error inferring options for {scanner_class.__name__}: {str(e)}")
            
        return options

async def run_workflow_from_profile(profile, targets, progress_monitor=None):
    """
    Helper function to run a workflow from a scan profile
    
    Args:
        profile: The scan profile containing the workflow configuration
        targets: List of targets to scan
        progress_monitor: Optional progress monitor for updates
        
    Returns:
        Scan results dictionary
    """
    workflow_config = profile.get("workflow")
    if not workflow_config:
        logging.error("Profile does not contain a valid workflow configuration")
        return {}
    
    workflow_manager = WorkflowManager(progress_monitor)
    return await workflow_manager.run_workflow(workflow_config, targets)
