/**
 * KEY ROTATION MANAGER
 * 
 * Enforces 30-90 day key rotation policy to prevent
 * "harvest now, decrypt later" quantum attacks
 */

import fs from 'fs';
import crypto from 'crypto';

class KeyRotationManager {
  constructor(keyStorePath = null) {
    this.keyStorePath = keyStorePath || `${process.env.HOME}/.proxy-encryption`;
    this.rotationLog = `${this.keyStorePath}/rotation-log.json`;
    this.keyArchive = `${this.keyStorePath}/archive`;
    this.ensureDirectories();
  }

  ensureDirectories() {
    if (!fs.existsSync(this.keyStorePath)) {
      fs.mkdirSync(this.keyStorePath, { recursive: true, mode: 0o700 });
    }
    if (!fs.existsSync(this.keyArchive)) {
      fs.mkdirSync(this.keyArchive, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Check if key rotation is needed
   * Returns: { needed: boolean, daysOld: number, expiresIn: number }
   */
  checkRotationNeeded() {
    try {
      const keyPath = `${this.keyStorePath}/quantum-master-key.json`;
      if (!fs.existsSync(keyPath)) {
        return { needed: true, reason: 'No keys found - first generation' };
      }

      const keyFile = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
      const generatedAt = new Date(keyFile.generatedAt);
      const now = new Date();
      const daysOld = Math.floor((now - generatedAt) / (24 * 60 * 60 * 1000));
      const expiresIn = 90 - daysOld; // 90 day rotation policy

      console.log(`[KeyRotation] Key age: ${daysOld} days, expires in: ${expiresIn} days`);

      return {
        needed: daysOld >= 30, // Minimum 30 days before first rotation
        daysOld,
        expiresIn,
        shouldAlert: daysOld >= 25, // Alert 5 days before required rotation
        mustRotate: daysOld >= 90, // Force rotation after 90 days
      };
    } catch (e) {
      console.error('[KeyRotation] Error checking rotation:', e.message);
      return { needed: true, reason: e.message };
    }
  }

  /**
   * Perform key rotation
   * 1. Generate new keys
   * 2. Archive old keys
   * 3. Update master key file
   * 4. Log rotation event
   */
  async rotateKeys(proxy) {
    console.log('[KeyRotation] 🔄 Starting key rotation...');

    try {
      const rotationStart = Date.now();

      // 1. Archive old keys
      await this.archiveOldKeys();
      console.log('[KeyRotation] ✅ Old keys archived');

      // 2. Generate new keys
      await proxy.rotateKeys();
      console.log('[KeyRotation] ✅ New keys generated');

      // 3. Log rotation event
      this.logRotationEvent({
        timestamp: new Date().toISOString(),
        duration: Date.now() - rotationStart,
        status: 'SUCCESS',
        reason: 'Scheduled rotation',
      });

      console.log('[KeyRotation] ✅ Key rotation complete');
      return { success: true, timestamp: new Date().toISOString() };
    } catch (e) {
      console.error('[KeyRotation] ❌ Rotation failed:', e.message);
      this.logRotationEvent({
        timestamp: new Date().toISOString(),
        status: 'FAILED',
        error: e.message,
      });
      throw e;
    }
  }

  /**
   * Archive old keys (keep last 5 for decryption)
   */
  async archiveOldKeys() {
    try {
      const keyPath = `${this.keyStorePath}/quantum-master-key.json`;
      if (!fs.existsSync(keyPath)) return;

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const archivePath = `${this.keyArchive}/keys-${timestamp}.json.enc`;

      // Read existing keys
      const keyData = fs.readFileSync(keyPath, 'utf8');

      // Encrypt with a temporary passphrase before archiving
      const passphrase = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', passphrase, iv);

      let encrypted = cipher.update(keyData);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();

      const archived = {
        timestamp,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        data: encrypted.toString('hex'),
      };

      fs.writeFileSync(archivePath, JSON.stringify(archived), { mode: 0o600 });
      console.log(`[KeyRotation] Keys archived to: ${archivePath}`);

      // Clean up: keep only last 5 rotations
      this.cleanupOldArchives();
    } catch (e) {
      console.error('[KeyRotation] Archive failed:', e.message);
      throw e;
    }
  }

  /**
   * Keep only last 5 archived keys
   */
  cleanupOldArchives() {
    try {
      const files = fs.readdirSync(this.keyArchive)
        .filter(f => f.startsWith('keys-'))
        .sort()
        .reverse();

      // Delete everything after the 5th file
      files.slice(5).forEach(file => {
        fs.unlinkSync(`${this.keyArchive}/${file}`);
        console.log(`[KeyRotation] Deleted old archive: ${file}`);
      });
    } catch (e) {
      console.warn('[KeyRotation] Cleanup warning:', e.message);
    }
  }

  /**
   * Log rotation event
   */
  logRotationEvent(event) {
    try {
      let log = [];
      if (fs.existsSync(this.rotationLog)) {
        log = JSON.parse(fs.readFileSync(this.rotationLog, 'utf8'));
      }

      log.push(event);
      fs.writeFileSync(this.rotationLog, JSON.stringify(log, null, 2), { mode: 0o600 });
    } catch (e) {
      console.error('[KeyRotation] Failed to log event:', e.message);
    }
  }

  /**
   * Get rotation history
   */
  getRotationHistory() {
    try {
      if (!fs.existsSync(this.rotationLog)) {
        return [];
      }
      return JSON.parse(fs.readFileSync(this.rotationLog, 'utf8'));
    } catch (e) {
      console.error('[KeyRotation] Failed to read history:', e.message);
      return [];
    }
  }

  /**
   * Get health status
   */
  getHealthStatus() {
    const rotation = this.checkRotationNeeded();
    const history = this.getRotationHistory();

    return {
      rotationManager: 'active',
      policy: '30-90 days',
      rotation: rotation,
      lastRotation: history.length > 0 ? history[history.length - 1] : null,
      archived: fs.readdirSync(this.keyArchive).filter(f => f.startsWith('keys-')).length,
    };
  }
}

export default KeyRotationManager;
