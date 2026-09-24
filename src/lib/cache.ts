// In-memory cache for expensive API lookups.
// TTL defaults to 10 minutes — long enough to make repeat navigation feel
// instant, short enough to keep data fresh for active investigations.
//
// Cache key is `${endpoint}:${ip}`. Stored values are the full JSON response
// plus the timestamp it was inserted.

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const TTL_MS = 10 * 60 * 1000; // 10 minutes

const cache = new Map<string, CacheEntry<unknown>>();

export function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.value as T;
}

export function setCached<T>(key: string, value: T, ttlMs: number = TTL_MS): void {
  cache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

export function cacheKey(endpoint: string, ...parts: (string | number)[]): string {
  return `${endpoint}:${parts.join(":")}`;
}

// Bound the cache so it doesn't grow forever.
const MAX_ENTRIES = 500;
export function pruneCache(): void {
  if (cache.size <= MAX_ENTRIES) return;
  // Drop the oldest 25% by insertion order.
  const dropCount = Math.floor(MAX_ENTRIES * 0.25);
  let i = 0;
  for (const k of cache.keys()) {
    cache.delete(k);
    if (++i >= dropCount) break;
  }
}
