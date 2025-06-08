from pydantic_settings import BaseSettings
from pydantic import BaseModel
from typing import List, Dict, Optional
import yaml
import os
from pathlib import Path
from datetime import datetime

print("Starting configuration loading...")

class NmapScanType(BaseModel):
    name: str
    arguments: str
    enabled: bool

class NmapPerformance(BaseModel):
    MAX_PARALLEL_SCANS: int
    MAX_RETRIES: int

class NmapConfig(BaseModel):
    TARGET_IP: str = "192.168.1.1"
    TIMING: int = 4
    PERFORMANCE: NmapPerformance
    SCAN_TYPES: List[NmapScanType]
    OUTPUT_DIR: str = "results/raw/nmap"

class SecurityCheck(BaseModel):
    name: str
    enabled: bool
    timeout: int

class LoggingConfig(BaseModel):
    level: str
    format: str
    file: str

class Settings(BaseSettings):
    LMSTUDIO_API_URL: str
    LMSTUDIO_API_KEY: str
    LMSTUDIO_MODEL_NAME: str
    LMSTUDIO_TEMPERATURE: float
    LMSTUDIO_MAX_TOKENS: int
    LMSTUDIO_TOP_P: float
    SCAN_INTERVAL: int
    REPORT_DIR: str
    LOG_LEVEL: str
    DEFAULT_SSH_PORT: int
    DEFAULT_TIMEOUT: int
    NMAP: NmapConfig
    SECURITY_CHECKS: List[SecurityCheck]
    REPORT_FORMAT: str
    REPORT_SECTIONS: List[str]
    LOGGING: LoggingConfig

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

def load_yaml_config() -> dict:
    """Load configuration from YAML file."""
    try:
        # Get the project root directory (where config.yaml is located)
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "config.yaml"
        
        print(f"Looking for config file at: {config_path}")
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found at {config_path}")
        
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            print(f"Successfully loaded configuration from {config_path}")
            return config
    except Exception as e:
        print(f"Error loading configuration: {e}")
        raise

# Load YAML configuration
print("Loading YAML configuration...")
print(f"Current working directory: {os.getcwd()}")
yaml_config = load_yaml_config()
print(f"Loaded config: {yaml_config}")

# Create settings instance
print("Creating settings instance...")
settings = Settings(**yaml_config)

# Ensure report directory exists
os.makedirs(settings.REPORT_DIR, exist_ok=True)

# Create date-stamped output directory for nmap results
timestamp = datetime.now().strftime("%Y-%m-%d")
nmap_output_dir = os.path.join(settings.NMAP.OUTPUT_DIR, timestamp)
os.makedirs(nmap_output_dir, exist_ok=True)

# Configuration test
print("\nConfiguration Test:")
print(f"LM Studio API URL: {settings.LMSTUDIO_API_URL}")
print(f"LM Studio Model: {settings.LMSTUDIO_MODEL_NAME}")
print(f"Max Tokens: {settings.LMSTUDIO_MAX_TOKENS}")
print(f"Temperature: {settings.LMSTUDIO_TEMPERATURE}")
print(f"Top P: {settings.LMSTUDIO_TOP_P}")
print(f"Report Directory: {settings.REPORT_DIR}")
print(f"Nmap Target IP: {settings.NMAP.TARGET_IP}")
print(f"Nmap Output Directory: {nmap_output_dir}")
