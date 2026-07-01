const crypto = require('crypto');

function normalizeSecret(secret) {
    if (!secret) {
        return null;
    }

    if (Buffer.isBuffer(secret)) {
        return secret;
    }

    const normalized = String(secret).trim();
    if (normalized.length === 0) {
        return null;
    }

    // Strict base64 validation: must match format AND decode to proper length
    const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
    if (base64Pattern.test(normalized) && normalized.length % 4 === 0) {
        try {
            const decoded = Buffer.from(normalized, 'base64');
            // Base64: 4 chars = 3 bytes. Validate ratio: decoded should be ~0.75 * input
            const expectedMinLength = Math.floor((normalized.length / 4) * 3);
            const expectedMaxLength = Math.ceil((normalized.length / 4) * 3);
            if (decoded.length >= expectedMinLength && decoded.length <= expectedMaxLength) {
                return decoded;
            }
        } catch (error) {
            // Not valid base64, fall through to UTF-8
        }
    }

    // Fallback: UTF-8 only, with minimum length validation (16 bytes)
    const utf8Buffer = Buffer.from(normalized, 'utf8');
    if (utf8Buffer.length < 16) {
        return null;  // Reject keys shorter than 128 bits
    }
    return utf8Buffer;
}

function isEncryptedEnvelope(value) {
    return Boolean(
        value &&
        typeof value === 'object' &&
        typeof value.iv === 'string' &&
        typeof value.tag === 'string' &&
        typeof value.ciphertext === 'string' &&
        value.ciphertext.length > 0
    );
}

function encryptPayload(plaintext, currentKey, keyVersion = 1) {
    try {
        if (!currentKey) {
            return null;
        }

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', currentKey, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag();

        return {
            version: keyVersion,
            iv: iv.toString('hex'),
            tag: tag.toString('hex'),
            ciphertext: encrypted,
            algorithm: 'aes-256-gcm'
        };
    } catch (error) {
        return null;
    }
}

function decryptPayload(encryptedData, currentKey) {
    try {
        if (!currentKey || !isEncryptedEnvelope(encryptedData)) {
            return null;
        }

        const iv = Buffer.from(encryptedData.iv, 'hex');
        const tag = Buffer.from(encryptedData.tag, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', currentKey, iv);
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return null;
    }
}

function decodeEncryptionKey(keyMaterial) {
    if (!keyMaterial) {
        return null;
    }

    if (Buffer.isBuffer(keyMaterial)) {
        return keyMaterial.length === 32 ? Buffer.from(keyMaterial) : null;
    }

    if (typeof keyMaterial !== 'string') {
        return null;
    }

    const trimmed = keyMaterial.trim();
    if (!trimmed) {
        return null;
    }

    const normalized = trimmed.replace(/^0x/i, '');
    if (/^[0-9a-f]{64}$/i.test(normalized)) {
        return Buffer.from(normalized, 'hex');
    }

    try {
        const legacyBuffer = Buffer.from(trimmed, 'base64');
        return legacyBuffer.length === 32 ? legacyBuffer : null;
    } catch (error) {
        return null;
    }
}

function createHmacSignature(secret, payload) {
    try {
        const key = normalizeSecret(secret);
        if (!key) {
            return null;
        }

        const message = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload ?? ''), 'utf8');
        return crypto.createHmac('sha256', key).update(message).digest('hex');
    } catch (error) {
        return null;
    }
}

function createPerRequestSignature(secret, payload, options = {}) {
    try {
        if (!secret) {
            return null;
        }

        const nonceBuffer = Buffer.isBuffer(options.nonce)
            ? options.nonce
            : (typeof options.nonce === 'string' && options.nonce)
                ? Buffer.from(options.nonce, 'hex')
                : crypto.randomBytes(32);
        const timestamp = Number(options.timestamp ?? Date.now());
        const method = String(options.method || '');
        const path = String(options.path || '');
        const info = Buffer.from(String(options.info || 'm7-per-request-signature-v1'), 'utf8');
        const key = normalizeSecret(secret);
        if (!key) {
            return null;
        }

        const derivedKey = crypto.hkdfSync(
            'sha256',
            key,
            nonceBuffer,
            info,
            32
        );
        const message = Buffer.concat([
            Buffer.from(String(timestamp), 'utf8'),
            Buffer.from(method, 'utf8'),
            Buffer.from(path, 'utf8'),
            nonceBuffer,
            Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload ?? ''), 'utf8')
        ]);
        const signature = crypto.createHmac('sha256', derivedKey).update(message).digest('hex');

        return {
            signature,
            metadata: {
                nonce: nonceBuffer.toString('hex'),
                timestamp,
                method,
                path,
                algorithm: 'hmac-sha256-hkdf-v1',
                info: info.toString('utf8')
            }
        };
    } catch (error) {
        return null;
    }
}

function verifyPerRequestSignature(signature, payload, secret, metadata) {
    try {
        if (!signature || !metadata) {
            return false;
        }

        const nonceBuffer = Buffer.isBuffer(metadata.nonce)
            ? metadata.nonce
            : Buffer.from(String(metadata.nonce || ''), 'hex');
        const expected = createPerRequestSignature(secret, payload, {
            nonce: nonceBuffer,
            timestamp: metadata.timestamp,
            method: metadata.method,
            path: metadata.path,
            info: metadata.info
        });

        if (!expected || !expected.signature) {
            return false;
        }

        const expectedBuffer = Buffer.from(expected.signature, 'hex');
        const providedBuffer = Buffer.from(String(signature), 'hex');
        if (expectedBuffer.length === 0 || providedBuffer.length === 0) {
            return false;
        }
        if (expectedBuffer.length !== providedBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
    } catch (error) {
        return false;
    }
}

function verifyHmacSignature(signature, payload, secret) {
    try {
        const expectedSignature = createHmacSignature(secret, payload);
        if (!expectedSignature || !signature) {
            return false;
        }

        const expectedBuffer = Buffer.from(expectedSignature, 'hex');
        const providedBuffer = Buffer.from(String(signature), 'hex');
        if (expectedBuffer.length === 0 || providedBuffer.length === 0) {
            return false;
        }
        if (expectedBuffer.length !== providedBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
    } catch (error) {
        return false;
    }
}

function shouldEncryptRequest(req, encryptionRules = {}) {
    if (!encryptionRules || !encryptionRules.enabled) {
        return false;
    }

    const headerName = encryptionRules.encryptByHeader?.headerName || 'X-Encrypt-Payload';
    const headerValue = req.get(headerName);
    if (encryptionRules.encryptByHeader?.enabled && headerValue === 'true') {
        return true;
    }

    if (encryptionRules.encryptByContentType?.enabled) {
        const contentType = req.get('content-type') || '';
        const allowedTypes = encryptionRules.encryptByContentType.types || [];
        if (allowedTypes.some((type) => contentType.includes(type))) {
            return true;
        }
    }

    return false;
}

function buildBody(reqBody) {
    if (reqBody === undefined || reqBody === null) {
        return '';
    }
    if (typeof reqBody === 'string') {
        return reqBody;
    }
    return JSON.stringify(reqBody);
}

module.exports = {
    normalizeSecret,
    isEncryptedEnvelope,
    encryptPayload,
    decryptPayload,
    decodeEncryptionKey,
    createHmacSignature,
    createPerRequestSignature,
    verifyPerRequestSignature,
    verifyHmacSignature,
    shouldEncryptRequest,
    buildBody
};
