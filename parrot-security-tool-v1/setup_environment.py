#!/usr/bin/env python3
"""Environment setup script for the security tool"""
import os
import sys
import subprocess
import logging
import platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def check_python_version():
    """Check if Python version meets requirements"""
    required_version = (3, 8)
    current_version = sys.version_info
    
    if current_version < required_version:
        logger.error(f"Python {required_version[0]}.{required_version[1]} or higher is required")
        return False
        
    logger.info(f"Python version check passed: {platform.python_version()}")
    return True

def install_dependencies():
    """Install required Python packages"""
    requirements = [
        "psutil>=5.9.0",  # For resource monitoring
        "aiohttp>=3.8.1",  # For async HTTP requests
        "aiodns>=3.0.0",   # For async DNS resolution
        "cchardet>=2.1.7", # For faster character encoding detection
        "uvloop>=0.16.0;platform_system!='Windows'", # Faster event loop implementation for non-Windows
        "prompt_toolkit>=3.0.29",
        "tqdm>=4.64.0",
        "jinja2>=3.1.2",
        "python-dateutil>=2.8.2",
        "requests>=2.28.0",
        "ipaddress>=1.0.23"
    ]
    
    logger.info("Installing required Python packages...")
    
    for req in requirements:
        try:
            logger.info(f"Installing {req}")
            # Use pip to install the package
            subprocess.run(
                [sys.executable, "-m", "pip", "install", req],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {req}: {e.stderr.decode()}")
        except Exception as e:
            logger.error(f"Error installing {req}: {str(e)}")
    
    logger.info("Dependency installation complete")

def configure_asyncio():
    """Configure asyncio for optimal performance"""
    try:
        import asyncio
        
        # Use uvloop if available (not on Windows)
        if platform.system() != "Windows":
            try:
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                logger.info("AsyncIO configured with uvloop for improved performance")
            except ImportError:
                logger.warning("uvloop not available, using standard event loop")
        else:
            # On Windows, configure the selector event loop for better performance
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            logger.info("AsyncIO configured with WindowsSelectorEventLoopPolicy")
            
    except Exception as e:
        logger.error(f"Failed to configure AsyncIO: {str(e)}")

# Add a new function to setup logging
def configure_logging(args=None):
    """Configure logging system based on command line arguments"""
    from utils.logging_config import initialize_logging
    
    # Default values
    log_level = "INFO"
    json_format = False
    sentry_dsn = None
    
    # Override with command line arguments if provided
    if args:
        if hasattr(args, 'log_level') and args.log_level:
            log_level = args.log_level
        if hasattr(args, 'json_logs') and args.json_logs:
            json_format = True
        if hasattr(args, 'sentry_dsn') and args.sentry_dsn:
            sentry_dsn = args.sentry_dsn
    
    # Initialize the logging system
    initialize_logging(
        level=log_level,
        app_name="parrot-security-tool",
        sentry_dsn=sentry_dsn,
        json_format=json_format,
        log_to_console=True,
        log_to_file=True
    )
    
    logger.info(f"Logging system initialized with level {log_level} and JSON format: {json_format}")
    if sentry_dsn:
        logger.info("Sentry error tracking enabled")

def setup_environment(install_deps=True):
    """Set up the environment for the security tool"""
    logger.info("Setting up environment...")
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies if requested
    if install_deps:
        install_dependencies()
    
    # Configure AsyncIO
    configure_asyncio()
    
    # Create necessary directories
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("cache", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    logger.info("Environment setup complete")
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Set up the environment for the security tool")
    parser.add_argument("--no-deps", action="store_true", help="Skip installing dependencies")
    args = parser.parse_args()
    
    if setup_environment(not args.no_deps):
        logger.info("Environment setup successful")
        sys.exit(0)
    else:
        logger.error("Environment setup failed")
        sys.exit(1)