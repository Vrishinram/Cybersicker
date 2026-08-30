"""
Performance optimization and caching layer for CYBERSICKER
Implements multi-level caching with TTL and intelligent invalidation
"""

import time
import functools
from typing import Any, Callable, Optional, Dict, Tuple
from collections import OrderedDict
from datetime import datetime, timedelta
import hashlib
import json

class CacheEntry:
    """Represents a cache entry with metadata"""
    def __init__(self, value: Any, ttl: int = 3600):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl
        self.access_count = 0
        self.last_accessed = self.created_at
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return time.time() - self.created_at > self.ttl
    
    def access(self) -> Any:
        """Update access metadata and return value"""
        self.access_count += 1
        self.last_accessed = time.time()
        return self.value
    
    def get_age(self) -> float:
        """Get age of cache entry in seconds"""
        return time.time() - self.created_at

class LRUCache:
    """Least Recently Used cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        expired_keys = [
            key for key, entry in self.cache.items()
            if entry.is_expired()
        ]
        for key in expired_keys:
            del self.cache[key]
    
    def _evict_lru(self):
        """Evict least recently used entry"""
        if len(self.cache) >= self.max_size:
            # Remove least recently used
            self.cache.popitem(last=False)
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Store value in cache with optional TTL"""
        ttl = ttl or self.default_ttl
        self.cache[key] = CacheEntry(value, ttl)
        self.cache.move_to_end(key)
        self._evict_lru()
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache"""
        self._cleanup_expired()
        
        if key not in self.cache:
            self.misses += 1
            return None
        
        entry = self.cache[key]
        if entry.is_expired():
            del self.cache[key]
            self.misses += 1
            return None
        
        self.hits += 1
        self.cache.move_to_end(key)  # Mark as recently used
        return entry.access()
    
    def delete(self, key: str):
        """Remove specific cache entry"""
        if key in self.cache:
            del self.cache[key]
    
    def clear(self):
        """Clear all cache entries"""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2f}%",
            "total_requests": total_requests,
        }

# Global cache instance
_global_cache = LRUCache(max_size=1000, default_ttl=3600)

def cache_key(*args, **kwargs) -> str:
    """Generate cache key from function arguments"""
    key_parts = [str(arg) for arg in args]
    key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
    key_string = "|".join(key_parts)
    return hashlib.md5(key_string.encode()).hexdigest()

def cached(ttl: int = 3600, key_func: Optional[Callable] = None):
    """
    Decorator for caching function results
    
    Args:
        ttl: Time to live in seconds (default: 1 hour)
        key_func: Optional custom cache key function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key_str = key_func(*args, **kwargs)
            else:
                cache_key_str = cache_key(func.__name__, *args, **kwargs)
            
            # Try to get from cache
            cached_value = _global_cache.get(cache_key_str)
            if cached_value is not None:
                return cached_value
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            _global_cache.set(cache_key_str, result, ttl)
            return result
        
        return wrapper
    return decorator

def invalidate_cache(pattern: Optional[str] = None):
    """Clear cache entries matching pattern"""
    if pattern is None:
        _global_cache.clear()
    else:
        # Simple pattern matching
        keys_to_delete = [
            key for key in _global_cache.cache.keys()
            if pattern in key
        ]
        for key in keys_to_delete:
            _global_cache.delete(key)

def get_cache_stats() -> Dict[str, Any]:
    """Get global cache statistics"""
    return _global_cache.get_stats()

class QueryResultCache:
    """Specialized cache for database query results"""
    
    def __init__(self, ttl: int = 1800):  # 30 minutes default
        self.ttl = ttl
        self.cache = LRUCache(max_size=500, default_ttl=ttl)
    
    def cache_query(self, query_hash: str, results: Any):
        """Cache database query results"""
        self.cache.set(query_hash, results, self.ttl)
    
    def get_cached_query(self, query_hash: str) -> Optional[Any]:
        """Retrieve cached query results"""
        return self.cache.get(query_hash)
    
    def invalidate_by_table(self, table_name: str):
        """Invalidate cache for specific table"""
        invalidate_cache(f"table_{table_name}")

class APIResponseCache:
    """Specialized cache for external API responses"""
    
    def __init__(self, ttl: int = 600):  # 10 minutes default
        self.ttl = ttl
        self.cache = LRUCache(max_size=200, default_ttl=ttl)
    
    def cache_response(self, endpoint: str, params: Dict, response: Any):
        """Cache API response"""
        key = hashlib.md5(
            f"{endpoint}:{json.dumps(params, sort_keys=True)}".encode()
        ).hexdigest()
        self.cache.set(key, response, self.ttl)
        return key
    
    def get_cached_response(self, cache_key: str) -> Optional[Any]:
        """Retrieve cached API response"""
        return self.cache.get(cache_key)

# Create specialized cache instances
query_cache = QueryResultCache()
api_cache = APIResponseCache()
