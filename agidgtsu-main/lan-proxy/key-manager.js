const crypto = require('crypto');

class APIKeyManager {
    constructor() {
        this.keys = new Map();
        this.keyAudit = [];
    }

    generateKey(prefix = 'sk') {
        const randomPart = crypto.randomBytes(32).toString('hex');
        return `${prefix}_${Date.now()}_${randomPart}`;
    }

    createKey(options = {}) {
        const {
            name = 'unnamed',
            scopes = ['read', 'write'],
            expiresIn = 90 * 24 * 60 * 60 * 1000,
            rateLimit = 1000
        } = options;

        const key = this.generateKey(options.prefix || 'sk');
        const now = Date.now();
        const keyData = {
            key,
            name,
            scopes,
            created: now,
            expires: now + expiresIn,
            expiresIn,
            rateLimit,
            version: 1,
            enabled: true,
            lastUsed: null,
            usageCount: 0,
            rotations: []
        };

        this.keys.set(key, keyData);
        this.logAudit('KEY_CREATED', key, options);
        return keyData;
    }

    validateKey(apiKey) {
        const keyData = this.keys.get(apiKey);
        if (!keyData) {
            this.logAudit('KEY_NOT_FOUND', apiKey, { ip: 'unknown' });
            return { valid: false, reason: 'Key not found' };
        }

        if (!keyData.enabled) {
            this.logAudit('KEY_DISABLED', apiKey, { ip: 'unknown' });
            return { valid: false, reason: 'Key is disabled' };
        }

        if (Date.now() > keyData.expires) {
            this.logAudit('KEY_EXPIRED', apiKey, { ip: 'unknown' });
            return { valid: false, reason: 'Key has expired' };
        }

        keyData.lastUsed = Date.now();
        keyData.usageCount++;
        this.logAudit('KEY_USED', apiKey, { usageCount: keyData.usageCount });
        return { valid: true, scopes: keyData.scopes };
    }

    hasScope(apiKey, requiredScope) {
        const keyData = this.keys.get(apiKey);
        if (!keyData) return false;
        return keyData.scopes.includes(requiredScope);
    }

    rotateKey(oldKey) {
        const keyData = this.keys.get(oldKey);
        if (!keyData) {
            throw new Error('Key not found');
        }

        const newKey = this.generateKey();
        const newKeyData = {
            ...keyData,
            key: newKey,
            version: keyData.version + 1,
            created: Date.now(),
            expires: Date.now() + keyData.expiresIn
        };

        keyData.rotations.push({ oldKey, newKey, rotatedAt: Date.now() });
        this.keys.set(newKey, newKeyData);
        this.logAudit('KEY_ROTATED', oldKey, { newKey });
        return newKey;
    }

    revokeKey(apiKey) {
        const keyData = this.keys.get(apiKey);
        if (keyData) {
            keyData.enabled = false;
            this.logAudit('KEY_REVOKED', apiKey, {});
        }
    }

    logAudit(action, keyId, details) {
        this.keyAudit.push({
            timestamp: Date.now(),
            action,
            keyId: (keyId || '').substring(0, 20) + '***',
            details
        });

        if (this.keyAudit.length > 1000) {
            this.keyAudit.shift();
        }
    }

    getAuditLog(limit = 100) {
        return this.keyAudit.slice(-limit);
    }
}

module.exports = APIKeyManager;
