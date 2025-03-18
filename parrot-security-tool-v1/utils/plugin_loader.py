"""Plugin loader utility for dynamically loading scanner plugins"""
import os
import importlib
import inspect
import logging
from scanners import BaseScanner

def load_scanner_plugins():
    """Dynamically load all scanner plugins from the scanners package"""
    plugins = {}
    try:
        # Get the current directory of the script
        current_dir = os.path.dirname(os.path.abspath(__file__))
        scanners_dir = os.path.join(current_dir, 'scanners')
        
        # Make sure the scanners directory exists
        if not os.path.exists(scanners_dir):
            logging.error(f"Scanners directory not found at {scanners_dir}")
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
                        logging.info(f"Loaded scanner plugin: {name}")
            except Exception as e:
                logging.error(f"Error loading plugin {plugin_file}: {str(e)}")
        
        return plugins
    except Exception as e:
        logging.error(f"Error in load_scanner_plugins: {str(e)}")
        return plugins

def get_plugin_by_name(plugin_name):
    """Get a specific plugin by name"""
    plugins = load_scanner_plugins()
    return plugins.get(plugin_name)

def get_plugins_for_profile(profile):
    """Get a list of plugins suitable for a specific profile"""
    plugins = load_scanner_plugins()
    
    # Define which plugins are suitable for each profile
    profile_plugins = {
        'network': ['NmapScanner', 'MasscanScanner', 'NetcatScanner'],
        'vulnerability': ['NmapScanner', 'NiktoScanner', 'SQLMapScanner', 'MetasploitScanner'],
        'exploitation': ['MetasploitScanner', 'JohnScanner'],
        'anonymity': ['AnonSurfScanner'],
        'auditing': ['LynisScanner', 'ChkrootkitScanner'],
        'wireless': ['AircrackScanner']
    }
    
    # For the 'all' profile, include all plugins
    if profile == 'all':
        return plugins
    
    # Get the plugins for the requested profile
    return {name: plugin for name, plugin in plugins.items() 
            if name in profile_plugins.get(profile, [])}