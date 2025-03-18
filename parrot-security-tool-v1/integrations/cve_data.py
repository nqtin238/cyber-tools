"""Enhanced CVE data integration with NVD API"""
import requests
import json
import logging
import time
import os
from datetime import datetime

class CVEDataProvider:
    """Fetch and cache CVE data from the National Vulnerability Database (NVD) API"""
    
    def __init__(self, cache_file="cve_cache.json", api_key=None):
        """Initialize CVE data provider with optional cache file and API key"""
        self.cache_file = cache_file
        self.api_key = api_key
        self.cache = {}
        self.cache_age = {}
        self.cache_ttl = 86400  # Cache TTL in seconds (1 day)
        self.load_cache()
        
    def load_cache(self):
        """Load CVE data from cache file if it exists"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.cache = cache_data.get('cve_data', {})
                    self.cache_age = cache_data.get('cache_age', {})
                logging.info(f"Loaded {len(self.cache)} CVE entries from cache")
            except Exception as e:
                logging.error(f"Error loading CVE cache: {str(e)}")
                self.cache = {}
                self.cache_age = {}
        
    def save_cache(self):
        """Save CVE data to cache file"""
        try:
            cache_data = {
                'cve_data': self.cache,
                'cache_age': self.cache_age,
                'last_update': datetime.now().isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            logging.info(f"Saved {len(self.cache)} CVE entries to cache")
        except Exception as e:
            logging.error(f"Error saving CVE cache: {str(e)}")
    
    def get_cve_details(self, cve_id):
        """Get CVE details from cache or fetch from NVD API"""
        # Check if CVE is in cache and not expired
        current_time = time.time()
        if cve_id in self.cache and cve_id in self.cache_age:
            if current_time - self.cache_age[cve_id] < self.cache_ttl:
                logging.info(f"Using cached data for {cve_id}")
                return self.cache[cve_id]
        
        # Fetch from NVD API
        cve_data = self._fetch_from_nvd(cve_id)
        if cve_data:
            self.cache[cve_id] = cve_data
            self.cache_age[cve_id] = current_time
            # Periodically save cache (every 10 new entries)
            if len(self.cache) % 10 == 0:
                self.save_cache()
            return cve_data
        
        # Return cached data even if expired if API call failed
        if cve_id in self.cache:
            logging.warning(f"Using expired cached data for {cve_id}")
            return self.cache[cve_id]
            
        return None
    
    def _fetch_from_nvd(self, cve_id):
        """Fetch CVE data from NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {}
            
            # Add API key if available for higher rate limits
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            logging.info(f"Fetching CVE data for {cve_id} from NVD API")
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Extract CVSS scores
                    cvss_v3 = None
                    cvss_v2 = None
                    base_score = 0
                    
                    if 'metrics' in vuln:
                        # Try to get CVSS v3.1 score first
                        if 'cvssMetricV31' in vuln['metrics']:
                            cvss_v3 = vuln['metrics']['cvssMetricV31'][0]
                            base_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                        # Fall back to CVSS v3.0
                        elif 'cvssMetricV30' in vuln['metrics']:
                            cvss_v3 = vuln['metrics']['cvssMetricV30'][0]
                            base_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                        # Fall back to CVSS v2
                        elif 'cvssMetricV2' in vuln['metrics']:
                            cvss_v2 = vuln['metrics']['cvssMetricV2'][0]
                            base_score = cvss_v2.get('cvssData', {}).get('baseScore', 0)
                    
                    # Get description
                    description = ""
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                                
                    # Get references
                    references = []
                    if 'references' in vuln:
                        for ref in vuln['references']:
                            references.append({
                                'url': ref.get('url', ''),
                                'source': ref.get('source', '')
                            })
                    
                    # Determine severity based on CVSS score
                    severity = "Low"
                    if base_score >= 7.0:
                        severity = "High"
                    elif base_score >= 4.0:
                        severity = "Medium"
                            
                    # Construct result
                    result = {
                        'cve_id': cve_id,
                        'description': description,
                        'references': references,
                        'cvss_v3': cvss_v3,
                        'cvss_v2': cvss_v2,
                        'base_score': base_score,
                        'severity': severity,
                        'published': vuln.get('published'),
                        'last_modified': vuln.get('lastModified')
                    }
                    
                    logging.info(f"Successfully fetched data for {cve_id}")
                    # Respect rate limiting
                    time.sleep(0.6)  # Sleep to avoid hitting the rate limit
                    return result
            
            if response.status_code == 429:
                logging.warning(f"Rate limit hit for NVD API. Sleeping for 10 seconds.")
                time.sleep(10)  # Sleep longer on rate limit
                
            logging.error(f"Failed to fetch CVE data: {response.status_code}")
            return None
            
        except Exception as e:
            logging.error(f"Error fetching CVE data for {cve_id}: {str(e)}")
            return None
    
    def cleanup(self):
        """Save cache and perform cleanup"""
        self.save_cache()