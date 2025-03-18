"""Scan profile management utility for storing and loading scan configurations"""
import os
import json
import logging
from datetime import datetime

class ScanProfileManager:
    """Manages scan profiles for the security tool, allowing saving and loading of configurations"""
    
    def __init__(self, profiles_dir=None):
        """Initialize the scan profile manager"""
        if profiles_dir is None:
            # Default to a profiles directory in the user's home
            home_dir = os.path.expanduser("~")
            profiles_dir = os.path.join(home_dir, ".parrot_security_tool", "profiles")
        
        self.profiles_dir = profiles_dir
        os.makedirs(profiles_dir, exist_ok=True)
        self.default_profiles = {
            "quick_scan": {
                "name": "Quick Scan",
                "description": "Fast scan of common ports and vulnerabilities",
                "port_range": "1-1000",
                "scanners": ["NmapScanner", "NetcatScanner"],
                "stealth_mode": False,
                "max_concurrent": 5,
                "workflow": {
                    "name": "Quick Vulnerability Workflow",
                    "steps": [
                        {"scanner": "NmapScanner", "options": {"port_range": "1-1000"}},
                        {"scanner": "VulnerabilityScanner", "options": {}}
                    ]
                }
            },
            "full_scan": {
                "name": "Full Scan",
                "description": "Comprehensive scan of all ports and vulnerabilities",
                "port_range": "1-65535",
                "scanners": ["NmapScanner", "MasscanScanner", "NiktoScanner", "SQLMapScanner"],
                "stealth_mode": False,
                "max_concurrent": 3,
                "workflow": {
                    "name": "Full Security Audit Workflow",
                    "steps": [
                        {"scanner": "NmapScanner", "options": {"port_range": "1-65535"}},
                        {"scanner": "VulnerabilityScanner", "options": {}},
                        {"scanner": "NiktoScanner", "options": {}},
                        {"scanner": "SQLMapScanner", "options": {}}
                    ]
                }
            },
            "stealth_scan": {
                "name": "Stealth Scan",
                "description": "Low-profile scan to avoid detection",
                "port_range": "1-1024,3306,3389,8080,8443",
                "scanners": ["NmapScanner"],
                "stealth_mode": True,
                "max_concurrent": 2,
                "workflow": {
                    "name": "Stealth Reconnaissance Workflow",
                    "steps": [
                        {"scanner": "NmapScanner", "options": {"stealth": True, "timing": "1"}}
                    ]
                }
            },
            "web_audit": {
                "name": "Web Application Audit",
                "description": "Focused scan on web applications and services",
                "port_range": "80,443,8080,8443",
                "scanners": ["NiktoScanner", "SQLMapScanner"],
                "stealth_mode": False,
                "max_concurrent": 2,
                "workflow": {
                    "name": "Web Application Security Workflow",
                    "steps": [
                        {"scanner": "NmapScanner", "options": {"port_range": "80,443,8080,8443"}},
                        {"scanner": "NiktoScanner", "options": {}},
                        {"scanner": "SQLMapScanner", "options": {}}
                    ]
                }
            },
            "network_mapping": {
                "name": "Network Mapping",
                "description": "Map the network and discover devices",
                "port_range": "1-1024",
                "scanners": ["NmapScanner", "MasscanScanner"],
                "stealth_mode": False,
                "max_concurrent": 5,
                "workflow": {
                    "name": "Network Discovery Workflow",
                    "steps": [
                        {"scanner": "NmapScanner", "options": {"discovery_mode": True}}
                    ]
                }
            }
        }
        
        # Create default profiles if they don't exist
        self._ensure_default_profiles()
        
    def _ensure_default_profiles(self):
        """Create the default profiles if they don't exist"""
        for profile_id, profile in self.default_profiles.items():
            profile_path = os.path.join(self.profiles_dir, f"{profile_id}.json")
            if not os.path.exists(profile_path):
                self.save_profile(profile_id, profile)
                logging.info(f"Created default profile: {profile['name']}")
    
    def get_available_profiles(self):
        """Get a list of all available profile IDs"""
        profiles = []
        for filename in os.listdir(self.profiles_dir):
            if filename.endswith(".json"):
                profile_id = filename[:-5]  # Remove .json extension
                profiles.append(profile_id)
        return profiles
    
    def get_profile(self, profile_id):
        """Load a profile by its ID"""
        if not profile_id:
            return None
            
        profile_path = os.path.join(self.profiles_dir, f"{profile_id}.json")
        if not os.path.exists(profile_path):
            logging.warning(f"Profile {profile_id} not found")
            return None
        
        try:
            with open(profile_path, 'r') as file:
                profile = json.load(file)
            return profile
        except Exception as e:
            logging.error(f"Error loading profile {profile_id}: {str(e)}")
            return None
    
    def save_profile(self, profile_id, profile):
        """Save a profile with the given ID"""
        if not profile_id or not profile:
            return False
        
        # Add metadata
        if "metadata" not in profile:
            profile["metadata"] = {}
        
        profile["metadata"]["updated_at"] = datetime.now().isoformat()
        
        profile_path = os.path.join(self.profiles_dir, f"{profile_id}.json")
        try:
            with open(profile_path, 'w') as file:
                json.dump(profile, file, indent=4)
            logging.info(f"Profile saved: {profile_id}")
            return True
        except Exception as e:
            logging.error(f"Error saving profile {profile_id}: {str(e)}")
            return False
    
    def delete_profile(self, profile_id):
        """Delete a profile by its ID"""
        if not profile_id:
            return False
            
        profile_path = os.path.join(self.profiles_dir, f"{profile_id}.json")
        if not os.path.exists(profile_path):
            logging.warning(f"Profile {profile_id} not found for deletion")
            return False
        
        try:
            os.remove(profile_path)
            logging.info(f"Profile deleted: {profile_id}")
            return True
        except Exception as e:
            logging.error(f"Error deleting profile {profile_id}: {str(e)}")
            return False
    
    def create_workflow_from_profile(self, profile_id):
        """Extract workflow configuration from a profile"""
        profile = self.get_profile(profile_id)
        if not profile:
            return None
            
        return profile.get("workflow")
