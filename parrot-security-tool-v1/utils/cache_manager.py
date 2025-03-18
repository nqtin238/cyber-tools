"""Cache management utilities for storing and retrieving scan results"""
import os
import json
import time
import logging
import sqlite3
import hashlib
import pickle
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

class PersistentCache:
    """
    Persistent cache for scan results that persists between program runs
    Implements both file-based and database-based caching
    """
    
    def __init__(self, 
                 cache_dir: str = None, 
                 db_file: str = None,
                 max_age_days: int = 7,
                 compression: bool = True):
        """
        Initialize the persistent cache
        
        Args:
            cache_dir: Directory to store cache files (default: ~/.parrot_security_cache)
            db_file: SQLite database file (default: cache_dir/cache.db)
            max_age_days: Maximum age of cache entries in days
            compression: Whether to compress cache entries
        """
        self.logger = logging.getLogger(__name__)
        
        # Set up cache directory
        if cache_dir is None:
            self.cache_dir = os.path.expanduser("~/.parrot_security_cache")
        else:
            self.cache_dir = cache_dir
            
        # Create cache dir if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Set up database
        if db_file is None:
            self.db_file = os.path.join(self.cache_dir, "cache.db")
        else:
            self.db_file = db_file
            
        self.max_age_seconds = max_age_days * 86400  # Convert days to seconds
        self.compression = compression
        
        # Initialize database
        self._init_db()
        
        self.logger.info(f"Persistent cache initialized at {self.cache_dir}")
    
    def _init_db(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_cache (
                key TEXT PRIMARY KEY,
                scanner_name TEXT,
                target TEXT,
                options TEXT,
                data BLOB,
                timestamp REAL,
                scan_duration REAL
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scanner_target 
            ON scan_cache (scanner_name, target)
        ''')
        
        conn.commit()
        conn.close()
    
    def _generate_key(self, scanner_name: str, target: str, options: Dict) -> str:
        """Generate a unique key for a scan"""
        key_parts = [
            scanner_name,
            target,
            json.dumps(options or {}, sort_keys=True)
        ]
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def clear_expired(self):
        """Remove expired cache entries"""
        cutoff_time = time.time() - self.max_age_seconds
        
        # Clear from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache WHERE timestamp < ?", (cutoff_time,))
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleared {count} expired cache entries")
        
        # TODO: Also clean file-based cache in future versions
    
    def get(self, scanner_name: str, target: str, options: Dict = None) -> Optional[Dict]:
        """
        Get a scan result from the cache
        
        Args:
            scanner_name: Name of the scanner
            target: Target that was scanned
            options: Options used for the scan
            
        Returns:
            The cached scan result or None if not found or expired
        """
        key = self._generate_key(scanner_name, target, options)
        
        # Try to get from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT data, timestamp FROM scan_cache WHERE key = ?", 
            (key,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row is None:
            return None
            
        data_blob, timestamp = row
        
        # Check if expired
        if time.time() - timestamp > self.max_age_seconds:
            self.logger.debug(f"Cache entry for {scanner_name}:{target} has expired")
            return None
            
        # Deserialize the data
        try:
            if self.compression:
                import zlib
                decompressed = zlib.decompress(data_blob)
                result = pickle.loads(decompressed)
            else:
                result = pickle.loads(data_blob)
                
            self.logger.debug(f"Cache hit for {scanner_name}:{target}")
            return result
        except Exception as e:
            self.logger.error(f"Error deserializing cache entry: {str(e)}")
            return None
    
    def set(self, scanner_name: str, target: str, result: Dict, options: Dict = None) -> bool:
        """
        Store a scan result in the cache
        
        Args:
            scanner_name: Name of the scanner
            target: Target that was scanned
            result: Scan result to cache
            options: Options used for the scan
            
        Returns:
            True if successfully cached, False otherwise
        """
        key = self._generate_key(scanner_name, target, options)
        timestamp = time.time()
        scan_duration = result.get('scan_duration', 0)
        
        # Serialize the data
        try:
            data = pickle.dumps(result)
            if self.compression:
                import zlib
                data = zlib.compress(data)
        except Exception as e:
            self.logger.error(f"Error serializing cache entry: {str(e)}")
            return False
        
        # Store in database
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scan_cache (key, scanner_name, target, options, data, timestamp, scan_duration) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (key, scanner_name, target, json.dumps(options or {}), data, timestamp, scan_duration)
            )
            conn.commit()
            conn.close()
            
            self.logger.debug(f"Cached result for {scanner_name}:{target} ({len(data)} bytes)")
            return True
        except Exception as e:
            self.logger.error(f"Error storing cache entry: {str(e)}")
            return False
    
    def get_stats(self) -> Dict:
        """Get statistics about the cache"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) FROM scan_cache")
        total_count = cursor.fetchone()[0]
        
        # Get total size
        cursor.execute("SELECT SUM(LENGTH(data)) FROM scan_cache")
        total_size = cursor.fetchone()[0] or 0
        
        # Get oldest entry
        cursor.execute("SELECT MIN(timestamp) FROM scan_cache")
        oldest_timestamp = cursor.fetchone()[0]
        oldest_date = datetime.fromtimestamp(oldest_timestamp) if oldest_timestamp else None
        
        # Get newest entry
        cursor.execute("SELECT MAX(timestamp) FROM scan_cache")
        newest_timestamp = cursor.fetchone()[0]
        newest_date = datetime.fromtimestamp(newest_timestamp) if newest_timestamp else None
        
        # Get scanner stats
        cursor.execute("SELECT scanner_name, COUNT(*) FROM scan_cache GROUP BY scanner_name")
        scanner_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_count": total_count,
            "total_size_bytes": total_size,
            "total_size_mb": total_size / 1024 / 1024,
            "oldest_entry": str(oldest_date) if oldest_date else None,
            "newest_entry": str(newest_date) if newest_date else None,
            "scanner_counts": scanner_counts
        }
    
    def clear_all(self) -> int:
        """
        Clear all cache entries
        
        Returns:
            Number of entries cleared
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache")
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleared all {count} cache entries")
        return count
    
    def clear_for_scanner(self, scanner_name: str) -> int:
        """
        Clear all cache entries for a specific scanner
        
        Args:
            scanner_name: Name of the scanner
            
        Returns:
            Number of entries cleared
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache WHERE scanner_name = ?", (scanner_name,))
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleared {count} cache entries for {scanner_name}")
        return count
    
    def clear_for_target(self, target: str) -> int:
        """
        Clear all cache entries for a specific target
        
        Args:
            target: Target to clear
            
        Returns:
            Number of entries cleared
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_cache WHERE target = ?", (target,))
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        self.logger.info(f"Cleared {count} cache entries for target {target}")
        return count
