import json
import logging
import time
from typing import Optional, Dict, Any
import redis.asyncio as aioredis
from config import settings

logger = logging.getLogger("WAF.Cache")


class WAFCache:
    """
    High-performance Cache-Aside client using asynchronous Redis
    with an in-memory LRU/TTL fallback when Redis is offline.
    Provides sub-5ms lookup for previously evaluated payload hashes.
    """

    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

    async def connect(self) -> None:
        """Initialize connection pool to Redis."""
        try:
            self._redis = aioredis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password,
                decode_responses=True,
                socket_timeout=0.2,       # 200ms timeout to avoid proxy stalls
                socket_connect_timeout=0.5
            )
            await self._redis.ping()
            logger.info("Connected to Redis cache successfully.")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}). Using in-memory fallback cache.")
            self._redis = None

    async def disconnect(self) -> None:
        """Gracefully close Redis connection pool."""
        if self._redis:
            await self._redis.aclose()
            logger.info("Disconnected from Redis cache.")

    async def get_verdict(self, payload_hash: str) -> Optional[Dict[str, Any]]:
        """
        Fast lookup of a cached verdict by SHA-256 payload hash.
        Checks Redis first, falls back to in-memory cache.
        """
        key = f"waf:verdict:{payload_hash}"
        if self._redis:
            try:
                val = await self._redis.get(key)
                if val:
                    data = json.loads(val)
                    data["source"] = "cache (redis)"
                    return data
            except Exception as e:
                logger.error(f"Error reading from Redis cache: {e}")

        # In-memory fallback lookup
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if entry["expires_at"] > time.time():
                data = dict(entry["data"])
                data["source"] = "cache (in-memory)"
                return data
            else:
                del self._memory_cache[key]

        return None

    async def set_verdict(
        self,
        payload_hash: str,
        verdict: str,
        score: float,
        reason: str,
        ttl: Optional[int] = None
    ) -> None:
        """
        Cache evaluation verdict with an expiration TTL (Cache-Aside pattern).
        """
        key = f"waf:verdict:{payload_hash}"
        data = {
            "verdict": verdict,
            "score": score,
            "reason": reason,
        }
        expire = ttl if ttl is not None else settings.cache_ttl_seconds

        if self._redis:
            try:
                await self._redis.set(key, json.dumps(data), ex=expire)
                return
            except Exception as e:
                logger.error(f"Error writing to Redis cache: {e}")

        # Store in-memory fallback
        self._memory_cache[key] = {
            "data": data,
            "expires_at": time.time() + expire
        }


# Singleton instance
waf_cache = WAFCache()
