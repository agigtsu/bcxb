/**
 * Distributed Rate Limiter with Redis Backend
 * 
 * Provides cross-instance rate limiting for multi-deployment scenarios.
 * Falls back to in-memory limiter if Redis unavailable.
 * 
 * Features:
 * - Redis-backed distributed counting
 * - Per-IP, per-API-key rate limits
 * - Sliding window algorithm
 * - Fallback to in-memory with warning
 * - Configurable limits and windows
 */

const redis = require('redis');
const MILLISECONDS_IN_SECOND = 1000;

class DistributedRateLimiter {
    constructor(options = {}) {
        this.redisUrl = options.redisUrl || process.env.REDIS_URL || 'redis://localhost:6379';
        this.windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
        this.maxRequests = options.maxRequests || 100;
        this.keyPrefix = options.keyPrefix || 'rate-limit:';
        
        this.limits = {
            perIp: options.perIpLimit || { windowMs: 60000, max: 30 },      // 30 req/min per IP
            perApiKey: options.perApiKeyLimit || { windowMs: 60000, max: 100 }, // 100 req/min per key
            global: options.globalLimit || { windowMs: 60000, max: 1000 }    // 1000 req/min globally
        };
        
        this.redisClient = null;
        this.inMemoryStore = new Map();
        this.useRedis = false;
        this.initPromise = this.initializeRedis();
    }
    
    async initializeRedis() {
        try {
            this.redisClient = redis.createClient({
                url: this.redisUrl,
                socket: { reconnectStrategy: (retries) => Math.min(retries * 50, 500) }
            });
            
            this.redisClient.on('error', (err) => {
                console.warn('[DistributedRateLimiter] Redis error, falling back to in-memory:', err.message);
                this.useRedis = false;
            });
            
            this.redisClient.on('connect', () => {
                console.log('[DistributedRateLimiter] Connected to Redis');
                this.useRedis = true;
            });
            
            await this.redisClient.connect();
            this.useRedis = true;
            console.log('[DistributedRateLimiter] Initialized with Redis backend');
            return true;
        } catch (err) {
            console.warn('[DistributedRateLimiter] Redis unavailable, using in-memory fallback:', err.message);
            this.useRedis = false;
            return false;
        }
    }
    
    /**
     * Check rate limit for given identifier and limit type
     * Returns { allowed: boolean, current: number, limit: number, resetTime: number }
     */
    async checkLimit(identifier, limitType = 'perIp') {
        await this.initPromise;
        
        const config = this.limits[limitType];
        const key = `${this.keyPrefix}${limitType}:${identifier}`;
        
        if (this.useRedis && this.redisClient) {
            return await this._checkRedisLimit(key, config);
        } else {
            return this._checkMemoryLimit(key, config);
        }
    }
    
    async _checkRedisLimit(key, config) {
        try {
            const now = Date.now();
            const windowStart = now - config.windowMs;
            
            // Remove old entries
            await this.redisClient.zRemRangeByScore(key, '-inf', windowStart);
            
            // Get current count
            const current = await this.redisClient.zCard(key);
            
            // Get reset time (oldest request in window)
            const oldest = await this.redisClient.zRange(key, 0, 0);
            let resetTime = now + config.windowMs;
            if (oldest.length > 0) {
                resetTime = parseInt(oldest[0]) + config.windowMs;
            }
            
            const allowed = current < config.max;
            
            if (allowed) {
                // Add new request
                await this.redisClient.zAdd(key, { score: now, value: now.toString() });
                await this.redisClient.expire(key, Math.ceil(config.windowMs / 1000));
            }
            
            return {
                allowed,
                current: current + (allowed ? 1 : 0),
                limit: config.max,
                resetTime,
                backend: 'redis'
            };
        } catch (err) {
            console.error('[DistributedRateLimiter] Redis check failed:', err.message);
            // Fallback to memory on error
            this.useRedis = false;
            return this._checkMemoryLimit(key, config);
        }
    }
    
    _checkMemoryLimit(key, config) {
        const now = Date.now();
        const windowStart = now - config.windowMs;
        
        if (!this.inMemoryStore.has(key)) {
            this.inMemoryStore.set(key, {
                timestamps: [],
                createdAt: now
            });
        }
        
        const entry = this.inMemoryStore.get(key);
        
        // Remove old timestamps
        entry.timestamps = entry.timestamps.filter(ts => ts > windowStart);
        
        const current = entry.timestamps.length;
        const allowed = current < config.max;
        
        let resetTime = now + config.windowMs;
        if (entry.timestamps.length > 0) {
            resetTime = Math.min(...entry.timestamps) + config.windowMs;
        }
        
        if (allowed) {
            entry.timestamps.push(now);
        }
        
        // Cleanup old entries periodically
        if (Math.random() < 0.01) {
            const cutoff = now - (24 * 60 * 60 * 1000); // 24 hours
            for (const [k, v] of this.inMemoryStore.entries()) {
                if (v.createdAt < cutoff) {
                    this.inMemoryStore.delete(k);
                }
            }
        }
        
        return {
            allowed,
            current: current + (allowed ? 1 : 0),
            limit: config.max,
            resetTime,
            backend: 'memory'
        };
    }
    
    /**
     * Express middleware for rate limiting
     */
    middleware() {
        return async (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            const apiKey = req.headers['x-api-key'] || 'anonymous';
            
            // Check IP-based limit
            const ipLimit = await this.checkLimit(ip, 'perIp');
            if (!ipLimit.allowed) {
                res.set('Retry-After', Math.ceil((ipLimit.resetTime - Date.now()) / 1000));
                return res.status(429).json({
                    error: 'Rate limit exceeded (IP)',
                    retryAfter: ipLimit.resetTime,
                    current: ipLimit.current,
                    limit: ipLimit.limit
                });
            }
            
            // Check API key based limit (if provided)
            if (apiKey !== 'anonymous') {
                const keyLimit = await this.checkLimit(apiKey, 'perApiKey');
                if (!keyLimit.allowed) {
                    res.set('Retry-After', Math.ceil((keyLimit.resetTime - Date.now()) / 1000));
                    return res.status(429).json({
                        error: 'Rate limit exceeded (API Key)',
                        retryAfter: keyLimit.resetTime,
                        current: keyLimit.current,
                        limit: keyLimit.limit
                    });
                }
            }
            
            // Attach rate limit info to response headers
            res.set('X-RateLimit-Limit', ipLimit.limit);
            res.set('X-RateLimit-Current', ipLimit.current);
            res.set('X-RateLimit-Reset', new Date(ipLimit.resetTime).toISOString());
            res.set('X-RateLimit-Backend', ipLimit.backend);
            
            next();
        };
    }
    
    /**
     * Get current stats for an identifier
     */
    async getStats(identifier, limitType = 'perIp') {
        await this.initPromise;
        
        const config = this.limits[limitType];
        const key = `${this.keyPrefix}${limitType}:${identifier}`;
        
        let current = 0;
        if (this.useRedis && this.redisClient) {
            current = await this.redisClient.zCard(key);
        } else if (this.inMemoryStore.has(key)) {
            const now = Date.now();
            const windowStart = now - config.windowMs;
            current = this.inMemoryStore.get(key).timestamps.filter(ts => ts > windowStart).length;
        }
        
        return {
            identifier,
            limitType,
            current,
            limit: config.max,
            windowMs: config.windowMs,
            utilizationPercent: Math.round((current / config.max) * 100)
        };
    }
    
    /**
     * Reset limit for identifier
     */
    async reset(identifier, limitType = 'perIp') {
        await this.initPromise;
        
        const key = `${this.keyPrefix}${limitType}:${identifier}`;
        
        if (this.useRedis && this.redisClient) {
            await this.redisClient.del(key);
        } else {
            this.inMemoryStore.delete(key);
        }
    }
    
    /**
     * Cleanup and close connections
     */
    async close() {
        if (this.redisClient) {
            await this.redisClient.quit();
        }
    }
}

module.exports = DistributedRateLimiter;
