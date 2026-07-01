const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class QuantumHybridEncryption {
  constructor(masterKeyPath = null) {
    this.masterKeyPath = masterKeyPath || path.join(process.env.HOME || '/tmp', '.proxy-encryption', 'quantum-hybrid-master-key.json');
    this.x25519KeyPair = null;
    this.statistics = {
      encrypted: 0,
      decrypted: 0,
      fallbacksUsed: 0,
    };
    this.capabilities = {
      pqcAvailable: false,
      fallbackMode: 'hybrid-and-classical',
      kyberImplemented: false,
      hybridFallback: true,
      classicalFallback: true,
      activeModes: ['x25519-hybrid', 'aes-256-gcm'],
      supportedModes: ['x25519-hybrid', 'aes-256-gcm'],
    };
    this.loadOrCreateMasterKeyPair();
  }

  loadOrCreateMasterKeyPair() {
    try {
      if (fs.existsSync(this.masterKeyPath)) {
        const data = JSON.parse(fs.readFileSync(this.masterKeyPath, 'utf8'));
        this.x25519KeyPair = {
          privateKey: crypto.createPrivateKey({ key: data.privateKey, format: 'pem', type: 'pkcs8' }),
          publicKey: crypto.createPublicKey({ key: data.publicKey, format: 'pem', type: 'spki' }),
        };
        return;
      }

      const pair = crypto.generateKeyPairSync('x25519');
      this.x25519KeyPair = pair;
      this.saveMasterKeyPair();
    } catch (error) {
      console.warn('[QuantumHybrid] Failed to load/create X25519 key pair:', error.message);
      this.x25519KeyPair = crypto.generateKeyPairSync('x25519');
    }
  }

  saveMasterKeyPair() {
    try {
      fs.mkdirSync(path.dirname(this.masterKeyPath), { recursive: true, mode: 0o700 });
      const payload = {
        privateKey: this.x25519KeyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
        publicKey: this.x25519KeyPair.publicKey.export({ format: 'pem', type: 'spki' }),
      };
      fs.writeFileSync(this.masterKeyPath, JSON.stringify(payload, null, 2), { mode: 0o600 });
    } catch (error) {
      console.warn('[QuantumHybrid] Failed to persist X25519 key pair:', error.message);
    }
  }

  getCapabilities() {
    return { ...this.capabilities };
  }

  encryptSync(plaintext, additionalData = '') {
    this.statistics.encrypted++;
    if (!plaintext || typeof plaintext !== 'string') {
      throw new Error('Plaintext must be a non-empty string');
    }

    const ephemeral = crypto.generateKeyPairSync('x25519');
    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: this.x25519KeyPair.publicKey,
    });

    const salt = crypto.randomBytes(16);
    const derivedKey = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(sharedSecret), Buffer.from(additionalData, 'utf8'), salt])).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }

    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      version: 1,
      algorithm: 'x25519-hybrid',
      publicKey: ephemeral.publicKey.export({ format: 'pem', type: 'spki' }),
      ciphertext: ciphertext.toString('hex'),
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      salt: salt.toString('hex'),
      timestamp: Date.now(),
      fallbackChain: ['x25519-hybrid', 'aes-256-gcm'],
    };
  }

  decryptSync(packet, additionalData = '') {
    this.statistics.decrypted++;
    if (!packet || typeof packet !== 'object') {
      throw new Error('Invalid packet');
    }

    if (packet.algorithm === 'x25519-hybrid') {
      const ephemeralPublic = crypto.createPublicKey({ key: packet.publicKey, format: 'pem', type: 'spki' });
      const sharedSecret = crypto.diffieHellman({
        privateKey: this.x25519KeyPair.privateKey,
        publicKey: ephemeralPublic,
      });
      const salt = Buffer.from(packet.salt || '', 'hex');
      const derivedKey = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(sharedSecret), Buffer.from(additionalData, 'utf8'), salt])).digest();
      const iv = Buffer.from(packet.iv || '', 'hex');
      const ciphertext = Buffer.from(packet.ciphertext || '', 'hex');
      const tag = Buffer.from(packet.tag || '', 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
      decipher.setAuthTag(tag);
      if (additionalData) {
        decipher.setAAD(Buffer.from(additionalData, 'utf8'));
      }
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    }

    if (packet.algorithm === 'aes-256-gcm') {
      return this.decryptAES256GCM(packet, additionalData);
    }

    throw new Error(`Unknown encryption algorithm: ${packet.algorithm}`);
  }

  encrypt(plaintext, additionalData = '') {
    return Promise.resolve(this.encryptSync(plaintext, additionalData));
  }

  decrypt(packet, additionalData = '') {
    return Promise.resolve(this.decryptSync(packet, additionalData));
  }

  decryptAES256GCM(packet, additionalData = '') {
    const salt = Buffer.from(packet.salt || '', 'hex');
    const derivedKey = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(packet.algorithm || ''), salt])).digest();
    const iv = Buffer.from(packet.iv || '', 'hex');
    const ciphertext = Buffer.from(packet.ciphertext || '', 'hex');
    const tag = Buffer.from(packet.tag || '', 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(tag);
    if (additionalData) {
      decipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }

  getHealthStatus() {
    return {
      status: 'healthy',
      engine: 'QuantumHybridEncryption',
      version: 'hybrid-and-classical',
      capabilities: this.getCapabilities(),
      activeFallbacks: ['x25519-hybrid', 'aes-256-gcm'],
      statistics: this.statistics,
    };
  }
}

module.exports = QuantumHybridEncryption;
