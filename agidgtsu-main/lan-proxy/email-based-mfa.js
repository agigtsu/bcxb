/**
 * Email-Based MFA for API Key Management
 * 
 * Features:
 * - Generate API keys with email-based 2FA
 * - Send one-time verification codes to email
 * - Validate codes before activating keys
 * - Track API key usage and rotation history
 * - Configurable expiration and rotation policies
 */

const crypto = require('crypto');
const nodemailer = require('nodemailer'); // Add to package.json
const path = require('path');
const fs = require('fs').promises;

class EmailBasedMFA {
    constructor(options = {}) {
        this.smtpConfig = {
            host: options.smtpHost || process.env.SMTP_HOST || '127.0.0.1',
            port: options.smtpPort || parseInt(process.env.SMTP_PORT) || 25,
            secure: options.smtpSecure || (process.env.SMTP_SECURE === 'true'),
            auth: options.smtpAuth ? {
                user: options.smtpAuth.user || process.env.SMTP_USER,
                pass: options.smtpAuth.pass || process.env.SMTP_PASS
            } : null,
            requireTLS: options.requireTLS !== false
        };
        
        this.fromEmail = options.fromEmail || process.env.MAILER_FROM || 'api-security@localhost';
        this.codeExpiry = options.codeExpiry || 15 * 60 * 1000; // 15 minutes
        this.keyExpiry = options.keyExpiry || 90 * 24 * 60 * 60 * 1000; // 90 days
        this.maxCodeAttempts = options.maxCodeAttempts || 5;
        
        this.pendingKeys = new Map(); // { keyId: { email, code, expiresAt, attempts } }
        this.activeKeys = new Map(); // { keyId: { email, createdAt, expiresAt, lastUsed, secret } }
        this.keyHistory = new Map(); // { email: [] }
        
        this.transporter = this._initializeTransport();
        
        // Periodic cleanup of expired codes
        setInterval(() => this._cleanupExpiredCodes(), 5 * 60 * 1000);
    }
    
    _initializeTransport() {
        try {
            return nodemailer.createTransport(this.smtpConfig);
        } catch (err) {
            console.warn('[EmailBasedMFA] Failed to initialize mail transport:', err.message);
            return null;
        }
    }
    
    /**
     * Request a new API key with email verification
     * Returns: { keyId, verificationEmailSent, expiresIn }
     */
    async requestNewAPIKey(email, options = {}) {
        if (!this._isValidEmail(email)) {
            throw new Error('Invalid email address');
        }
        
        const keyId = crypto.randomBytes(16).toString('hex');
        const verificationCode = this._generateVerificationCode();
        const expiresAt = Date.now() + this.codeExpiry;
        
        this.pendingKeys.set(keyId, {
            email,
            code: crypto.createHash('sha256').update(verificationCode).digest('hex'),
            expiresAt,
            attempts: 0,
            metadata: options.metadata || {},
            createdAt: Date.now()
        });
        
        // Send verification email
        const emailSent = await this._sendVerificationEmail(email, verificationCode, keyId);
        
        if (!emailSent) {
            this.pendingKeys.delete(keyId);
            throw new Error('Failed to send verification email');
        }
        
        return {
            keyId,
            verificationEmailSent: true,
            expiresIn: this.codeExpiry,
            message: `Verification code sent to ${email}. Code expires in 15 minutes.`
        };
    }
    
    /**
     * Verify code and activate API key
     * Returns: { secret, keyId, expiresAt }
     */
    async verifyAndActivateKey(keyId, verificationCode) {
        const pending = this.pendingKeys.get(keyId);
        
        if (!pending) {
            throw new Error('Key request not found or already activated');
        }
        
        if (Date.now() > pending.expiresAt) {
            this.pendingKeys.delete(keyId);
            throw new Error('Verification code expired');
        }
        
        if (pending.attempts >= this.maxCodeAttempts) {
            this.pendingKeys.delete(keyId);
            throw new Error('Too many failed attempts. Please request a new key.');
        }
        
        // Verify code
        const codeHash = crypto.createHash('sha256').update(verificationCode).digest('hex');
        if (codeHash !== pending.code) {
            pending.attempts++;
            throw new Error(`Invalid code. ${this.maxCodeAttempts - pending.attempts} attempts remaining.`);
        }
        
        // Generate API key secret
        const secret = this._generateAPIKeySecret();
        const secretHash = crypto.createHash('sha256').update(secret).digest('hex');
        
        // Activate key
        const expiresAt = Date.now() + this.keyExpiry;
        this.activeKeys.set(keyId, {
            email: pending.email,
            createdAt: Date.now(),
            expiresAt,
            lastUsed: null,
            secret: secretHash,
            metadata: pending.metadata,
            rotationCount: 0
        });
        
        // Track in history
        if (!this.keyHistory.has(pending.email)) {
            this.keyHistory.set(pending.email, []);
        }
        this.keyHistory.get(pending.email).push({
            keyId,
            createdAt: Date.now(),
            expiresAt,
            status: 'active',
            type: 'creation'
        });
        
        // Remove from pending
        this.pendingKeys.delete(keyId);
        
        // Send activation confirmation
        await this._sendActivationEmail(pending.email, keyId);
        
        return {
            keyId,
            secret, // Return plaintext only once
            expiresAt,
            message: 'API key activated. Store the secret securely - it will not be shown again.'
        };
    }
    
    /**
     * Validate an API key
     * Returns: { valid, email, expiresAt, isExpired }
     */
    async validateAPIKey(keyId, secretProvided) {
        const key = this.activeKeys.get(keyId);
        
        if (!key) {
            return { valid: false, reason: 'Key not found' };
        }
        
        if (Date.now() > key.expiresAt) {
            return { valid: false, reason: 'Key expired', expiresAt: key.expiresAt, isExpired: true };
        }
        
        // Verify secret
        const secretHash = crypto.createHash('sha256').update(secretProvided).digest('hex');
        if (secretHash !== key.secret) {
            return { valid: false, reason: 'Invalid secret' };
        }
        
        // Update last used
        key.lastUsed = Date.now();
        
        return {
            valid: true,
            email: key.email,
            expiresAt: key.expiresAt,
            isExpired: false,
            daysUntilExpiry: Math.ceil((key.expiresAt - Date.now()) / (24 * 60 * 60 * 1000))
        };
    }
    
    /**
     * Initiate key rotation with email verification
     */
    async requestKeyRotation(keyId, email) {
        const key = this.activeKeys.get(keyId);
        
        if (!key) {
            throw new Error('Key not found');
        }
        
        if (key.email !== email) {
            throw new Error('Email does not match key owner');
        }
        
        // Mark old key for rotation
        const newKeyId = crypto.randomBytes(16).toString('hex');
        const verificationCode = this._generateVerificationCode();
        const expiresAt = Date.now() + this.codeExpiry;
        
        this.pendingKeys.set(newKeyId, {
            email,
            code: crypto.createHash('sha256').update(verificationCode).digest('hex'),
            expiresAt,
            attempts: 0,
            rotatingFrom: keyId,
            metadata: { rotation: true }
        });
        
        // Send rotation verification email
        const emailSent = await this._sendRotationEmail(email, verificationCode, keyId, newKeyId);
        
        if (!emailSent) {
            this.pendingKeys.delete(newKeyId);
            throw new Error('Failed to send rotation email');
        }
        
        return {
            rotationKeyId: newKeyId,
            verificationEmailSent: true,
            expiresIn: this.codeExpiry
        };
    }
    
    /**
     * Complete key rotation
     */
    async completeKeyRotation(newKeyId, verificationCode) {
        const result = await this.verifyAndActivateKey(newKeyId, verificationCode);
        const pending = this.pendingKeys.get(newKeyId);
        
        if (pending && pending.rotatingFrom) {
            // Deactivate old key
            const oldKey = this.activeKeys.get(pending.rotatingFrom);
            if (oldKey) {
                oldKey.status = 'rotated';
                oldKey.rotatedAt = Date.now();
                
                // Track in history
                if (this.keyHistory.has(pending.email)) {
                    this.keyHistory.get(pending.email).push({
                        keyId: pending.rotatingFrom,
                        rotatedAt: Date.now(),
                        status: 'rotated',
                        type: 'rotation'
                    });
                }
                
                // Keep in activeKeys for 24 hours (grace period)
                setTimeout(() => this.activeKeys.delete(pending.rotatingFrom), 24 * 60 * 60 * 1000);
            }
        }
        
        return result;
    }
    
    /**
     * Get key expiration warnings
     */
    getExpiringKeys(daysThreshold = 7) {
        const expiring = [];
        const cutoff = Date.now() + (daysThreshold * 24 * 60 * 60 * 1000);
        
        for (const [keyId, key] of this.activeKeys.entries()) {
            if (key.expiresAt <= cutoff && key.expiresAt > Date.now()) {
                expiring.push({
                    keyId,
                    email: key.email,
                    expiresAt: key.expiresAt,
                    daysUntilExpiry: Math.ceil((key.expiresAt - Date.now()) / (24 * 60 * 60 * 1000))
                });
            }
        }
        
        return expiring;
    }
    
    /**
     * Get key history for email
     */
    getKeyHistory(email) {
        return this.keyHistory.get(email) || [];
    }
    
    /**
     * Revoke an API key
     */
    async revokeKey(keyId, email, reason = 'User requested') {
        const key = this.activeKeys.get(keyId);
        
        if (!key || key.email !== email) {
            throw new Error('Unauthorized key revocation');
        }
        
        this.activeKeys.delete(keyId);
        
        // Track in history
        if (this.keyHistory.has(email)) {
            this.keyHistory.get(email).push({
                keyId,
                revokedAt: Date.now(),
                status: 'revoked',
                reason,
                type: 'revocation'
            });
        }
        
        // Send revocation confirmation
        await this._sendRevocationEmail(email, keyId, reason);
        
        return { keyId, revoked: true, timestamp: Date.now() };
    }
    
    // ===== PRIVATE METHODS =====
    
    _isValidEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    _generateVerificationCode() {
        return Math.random().toString(36).substring(2, 8).toUpperCase();
    }
    
    _generateAPIKeySecret() {
        return crypto.randomBytes(32).toString('hex');
    }
    
    async _sendVerificationEmail(email, code, keyId) {
        if (!this.transporter) {
            console.warn('[EmailBasedMFA] Mail transporter unavailable');
            return false;
        }
        
        const html = `
<h2>API Key Verification Required</h2>
<p>Your verification code is: <strong>${code}</strong></p>
<p>This code expires in 15 minutes.</p>
<p>Key ID: <code>${keyId}</code></p>
<p>If you did not request this, please ignore this email.</p>
        `;
        
        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'Verify Your API Key',
                html
            });
            return true;
        } catch (err) {
            console.error('[EmailBasedMFA] Failed to send verification email:', err.message);
            return false;
        }
    }
    
    async _sendActivationEmail(email, keyId) {
        if (!this.transporter) return;
        
        const html = `
<h2>API Key Activated</h2>
<p>Your API key has been activated and is ready to use.</p>
<p>Key ID: <code>${keyId}</code></p>
<p>This key will expire in 90 days. Plan your rotation accordingly.</p>
        `;
        
        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'API Key Activated',
                html
            });
        } catch (err) {
            console.error('[EmailBasedMFA] Failed to send activation email:', err.message);
        }
    }
    
    async _sendRotationEmail(email, code, oldKeyId, newKeyId) {
        if (!this.transporter) return false;
        
        const html = `
<h2>API Key Rotation Required</h2>
<p>A rotation has been requested for your API key.</p>
<p>Verification code: <strong>${code}</strong></p>
<p>This code expires in 15 minutes.</p>
<p>Old Key ID: <code>${oldKeyId}</code></p>
<p>New Key ID: <code>${newKeyId}</code></p>
        `;
        
        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'API Key Rotation Verification',
                html
            });
            return true;
        } catch (err) {
            console.error('[EmailBasedMFA] Failed to send rotation email:', err.message);
            return false;
        }
    }
    
    async _sendRevocationEmail(email, keyId, reason) {
        if (!this.transporter) return;
        
        const html = `
<h2>API Key Revoked</h2>
<p>The following API key has been revoked:</p>
<p>Key ID: <code>${keyId}</code></p>
<p>Reason: ${reason}</p>
<p>This key is no longer valid. If you did not request this, contact support.</p>
        `;
        
        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'API Key Revoked',
                html
            });
        } catch (err) {
            console.error('[EmailBasedMFA] Failed to send revocation email:', err.message);
        }
    }
    
    _cleanupExpiredCodes() {
        const now = Date.now();
        for (const [keyId, pending] of this.pendingKeys.entries()) {
            if (now > pending.expiresAt + (60 * 60 * 1000)) { // Keep for 1 hour after expiry
                this.pendingKeys.delete(keyId);
            }
        }
    }
}

module.exports = EmailBasedMFA;
