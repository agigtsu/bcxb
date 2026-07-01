/**
 * SERVER-MODERN.JS
 * 
 * Express.js server with automatic request/response encryption
 * Integrates ModernQuantumSafeProxy + KeyRotationManager
 * 
 * MODERN 2024 NIST-compliant quantum-safe encryption
 * Port: 8789 (LAN Proxy standard)
 */

import express from 'express';
import ModernQuantumSafeProxy from './quantum-safe-modern.js';
import KeyRotationManager from './key-rotation-manager.js';

const app = express();
const PORT = process.env.PORT || 8789;

// Initialize encryption and key rotation
const proxy = new ModernQuantumSafeProxy();
const rotationManager = new KeyRotationManager();

// Middleware to parse JSON
app.use(express.json({ limit: '50mb' }));

/**
 * Middleware: Auto-decrypt incoming requests if encrypted
 */
app.use(async (req, res, next) => {
  // Check for encryption header
  const encryptionAlgorithm = req.headers['x-encrypt-algorithm'];

  if (encryptionAlgorithm === 'auto') {
    try {
      // Extract encrypted payload from body
      if (req.body && req.body.encrypted && req.body.packet) {
        console.log('[Middleware] Decrypting incoming request...');

        const decrypted = proxy.decryptModern(
          req.body.packet,
          req.get('x-aad') || ''
        );

        // Replace body with decrypted data
        req.body = JSON.parse(decrypted);
        req.encrypted = true;

        console.log('[Middleware] ✅ Request decrypted successfully');
      }
    } catch (e) {
      console.error('[Middleware] ❌ Decryption failed:', e.message);
      return res.status(400).json({
        error: 'Decryption failed',
        message: e.message,
      });
    }
  }

  next();
});

/**
 * Middleware: Check if key rotation is needed
 */
app.use(async (req, res, next) => {
  const rotation = rotationManager.checkRotationNeeded();

  if (rotation.mustRotate) {
    console.warn('[Rotation] ⚠️ CRITICAL: Keys must be rotated immediately');
    res.setHeader('X-Rotation-Status', 'CRITICAL');
  } else if (rotation.shouldAlert) {
    console.warn(`[Rotation] ⚠️ Keys expire in ${rotation.expiresIn} days`);
    res.setHeader('X-Rotation-Status', 'WARNING');
  }

  next();
});

/**
 * POST /api/secure
 * Receive plaintext, return encrypted response
 */
app.post('/api/secure', async (req, res) => {
  try {
    const { message, data } = req.body;

    console.log('[API] Received secure request');

    // Process the request
    const response = {
      status: 'success',
      message: `Received: ${message}`,
      timestamp: new Date().toISOString(),
      data: data,
      encrypted: false,
    };

    // Check if client wants encrypted response
    const encryptResponse = req.get('x-encrypt-response') === 'true';

    if (encryptResponse) {
      const payload = JSON.stringify(response);
      const aad = req.get('x-aad') || '';

      const packet = proxy.encryptModern(payload, aad);

      console.log('[API] ✅ Response encrypted');
      return res.json({
        encrypted: true,
        packet: packet,
        algorithm: 'MODERN-2024-QUANTUM-SAFE',
      });
    }

    res.json(response);
  } catch (e) {
    console.error('[API] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/**
 * GET /health/encryption
 * Return encryption engine status and standards compliance
 */
app.get('/health/encryption', (req, res) => {
  try {
    const health = proxy.getHealthStatus();
    const rotation = rotationManager.checkRotationNeeded();

    res.json({
      status: 'operational',
      encryption: {
        engine: 'ModernQuantumSafeProxy',
        version: '2024-NIST-Compliant',
        health: health.status,
        ...health,
      },
      keyRotation: {
        policy: '30-90 days',
        ...rotation,
      },
      standards: [
        'FIPS 203 (Kyber1024)',
        'FIPS 204 (Dilithium2)',
        'NIST SP 800-38D (AES-256-GCM)',
        'RFC 7748 (X25519)',
        'RFC 8032 (Ed25519)',
        'RFC 8439 (XChaCha20-Poly1305)',
        'RFC 9106 (Argon2id)',
      ],
      endpoints: {
        secure: '/api/secure (POST)',
        health: '/health/encryption (GET)',
        admin: '/admin/rotation (POST)',
      },
    });
  } catch (e) {
    console.error('[Health] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/**
 * POST /admin/rotation
 * Manually trigger key rotation (requires authorization in production)
 */
app.post('/admin/rotation', async (req, res) => {
  try {
    console.log('[Admin] Key rotation requested');

    const rotation = rotationManager.checkRotationNeeded();

    if (!rotation.needed && !req.query.force) {
      return res.json({
        status: 'skipped',
        reason: 'Rotation not yet needed',
        rotation: rotation,
      });
    }

    // Perform rotation
    const result = await rotationManager.rotateKeys(proxy);

    res.json({
      status: 'success',
      rotation: result,
      nextRotation: rotationManager.checkRotationNeeded(),
    });
  } catch (e) {
    console.error('[Admin] Rotation error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/**
 * GET /admin/rotation/history
 * Get key rotation history
 */
app.get('/admin/rotation/history', (req, res) => {
  try {
    const history = rotationManager.getRotationHistory();
    const status = rotationManager.getHealthStatus();

    res.json({
      history: history,
      status: status,
    });
  } catch (e) {
    console.error('[Admin] History error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/**
 * GET /health
 * Basic health check
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    encryption: 'MODERN-2024-QUANTUM-SAFE',
  });
});

/**
 * Error handling middleware
 */
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

/**
 * Start server
 */
app.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`✅ MODERN 2024 QUANTUM-SAFE ENCRYPTION SERVER`);
  console.log(`${'='.repeat(60)}`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🔐 Engine: ModernQuantumSafeProxy`);
  console.log(`📊 Standards:`);
  console.log(`   • FIPS 203 (Kyber1024 - Post-Quantum KEM)`);
  console.log(`   • FIPS 204 (Dilithium2 - Post-Quantum Signing)`);
  console.log(`   • NIST SP 800-38D (AES-256-GCM - AEAD)`);
  console.log(`   • RFC 9106 (Argon2id - Memory-Hard KDF)`);
  console.log(`🔄 Key Rotation: 30-90 day policy`);
  console.log(`${'='.repeat(60)}\n`);

  console.log(`Endpoints:`);
  console.log(`  POST   /api/secure              - Encrypt/decrypt messages`);
  console.log(`  GET    /health/encryption       - Encryption status`);
  console.log(`  POST   /admin/rotation          - Trigger key rotation`);
  console.log(`  GET    /admin/rotation/history  - Rotation history`);
  console.log(`  GET    /health                  - Basic health check`);
  console.log(`${'='.repeat(60)}\n`);

  // Initial rotation check
  const rotation = rotationManager.checkRotationNeeded();
  if (rotation.shouldAlert || rotation.mustRotate) {
    console.warn(`⚠️  ROTATION ALERT: ${JSON.stringify(rotation)}`);
  }
});

export default app;
