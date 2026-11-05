from __future__ import annotations

import asyncio
import time
from typing import Any

import redis.asyncio as aioredis

from backend.core.config import get_settings


class CacheService:
    """Redis cache with an in-process fallback for development and tests."""

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None
        self._memory: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()
        self.status = "memory"

    async def connect(self) -> None:
        settings = get_settings()
        if not settings.redis_url:
            return
        try:
            client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )
            await client.ping()
            self._redis = client
            self.status = "connected"
        except Exception:
            self._redis = None
            self.status = "memory-fallback"

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def get(self, key: str) -> Any | None:
        if self._redis is not None:
            try:
                raw = await self._redis.get(f"ares:{key}")
                if raw is None:
                    return None
                import json

                return json.loads(raw)
            except Exception:
                pass
        async with self._lock:
            item = self._memory.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.time():
                self._memory.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        settings = get_settings()
        ttl = ttl or settings.cache_ttl_seconds
        if self._redis is not None:
            try:
                import json

                await self._redis.set(f"ares:{key}", json.dumps(value, default=str), ex=ttl)
                return
            except Exception:
                pass
        async with self._lock:
            self._memory[key] = (time.time() + ttl, value)

    async def delete(self, key: str) -> None:
        if self._redis is not None:
            try:
                await self._redis.delete(f"ares:{key}")
            except Exception:
                pass
        async with self._lock:
            self._memory.pop(key, None)

    async def incr_window(self, key: str, window: int) -> int:
        if self._redis is not None:
            try:
                full = f"ares:rl:{key}"
                count = await self._redis.incr(full)
                if count == 1:
                    await self._redis.expire(full, window)
                return int(count)
            except Exception:
                pass
        async with self._lock:
            now = time.time()
            count, expires = self._memory.get(f"rl:{key}", (0, now + window))
            if expires < now:
                count, expires = 0, now + window
            count += 1
            self._memory[f"rl:{key}"] = (expires, count)
            # Return shape compatibility: reuse tuple as (expiry, count)
            return int(count)


cache = CacheService()
