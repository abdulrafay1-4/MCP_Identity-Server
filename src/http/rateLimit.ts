export interface RateLimiterOptions {
  windowMs: number;
  max: number;
  maxKeys?: number;
  now?: () => Date;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

const DEFAULT_MAX_KEYS = 10_000;

/**
 * Fixed window per key, in process. A key can get close to 2 * max across a window
 * boundary, and several instances need a shared limiter instead. Expired buckets are
 * evicted on every call and `maxKeys` caps the rest.
 */
export class RateLimiter {
  private readonly windowMs: number;
  private readonly max: number;
  private readonly maxKeys: number;
  private readonly now: () => Date;
  // Insertion order is window-start order, so the oldest windows come first.
  private readonly buckets = new Map<string, { count: number; windowStart: number }>();

  constructor(options: RateLimiterOptions) {
    this.windowMs = options.windowMs;
    this.max = options.max;
    this.maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    this.now = options.now ?? ((): Date => new Date());
  }

  get size(): number {
    return this.buckets.size;
  }

  check(key: string): RateLimitResult {
    const nowMs = this.now().getTime();
    this.evictExpired(nowMs);

    const bucket = this.buckets.get(key);
    if (!bucket || nowMs - bucket.windowStart >= this.windowMs) {
      // Delete first so the re-inserted bucket moves to the back of the map.
      this.buckets.delete(key);
      this.buckets.set(key, { count: 1, windowStart: nowMs });
      this.evictOverflow();
      return { allowed: true, retryAfterSeconds: 0 };
    }

    if (bucket.count < this.max) {
      bucket.count += 1;
      return { allowed: true, retryAfterSeconds: 0 };
    }

    const remainingMs = this.windowMs - (nowMs - bucket.windowStart);
    // At least 1: a Retry-After of 0 invites a tight retry loop.
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)) };
  }

  private evictExpired(nowMs: number): void {
    for (const [key, bucket] of this.buckets) {
      if (nowMs - bucket.windowStart < this.windowMs) {
        break;
      }
      this.buckets.delete(key);
    }
  }

  private evictOverflow(): void {
    for (const key of this.buckets.keys()) {
      if (this.buckets.size <= this.maxKeys) {
        break;
      }
      this.buckets.delete(key);
    }
  }
}
