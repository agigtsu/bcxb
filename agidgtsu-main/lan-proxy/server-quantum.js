import QuantumHybridEncryption from './quantum-hybrid-encryption.js';
import express from 'express';

const app = express();
const encryptor = new QuantumHybridEncryption(process.env.MASTER_KEY_PATH);

/**
 * Middleware: Auto-detect & decrypt incoming requests
 */
app.use(express.json({ verify: async (req, res, buf) => {
  const contentEncryption = req.headers['x-encrypt-algorithm'];
  
  if (contentEncryption === 'auto' || contentEncryption) {
    try {
      const packet = JSON.parse(buf.toString());
      req.decryptedBody = await encryptor.decrypt(packet, Buffer.from(req.path));
      req.decryptedWith = packet.algorithm;
      req.fallbackChain = packet.fallbackChain;
    } catch (err) {
      console.error('[Server] Decryption failed:', err.message);
      return res.status(400).json({ error: 'Decryption failed' });
    }
  }
} }));

/**
 * Endpoint: Encrypt response
 */
app.post('/api/secure', async (req, res) => {
  const responseData = { status: 'ok', timestamp: Date.now() };
  const encrypted = await encryptor.encrypt(
    Buffer.from(JSON.stringify(responseData)),
    Buffer.from(req.path)
  );

  res.json({
    encrypted,
    algorithm: encrypted.algorithm,
    fallbackChain: encrypted.fallbackChain,
  });
});

/**
 * Health Check: Show encryption capability
 */
app.get('/health/encryption', (req, res) => {
  res.json({
    engine: 'quantum-hybrid',
    algorithms: [
      { name: 'kyber-hybrid', status: 'ready', priority: 1 },
      { name: 'x25519-hybrid', status: 'ready', priority: 2 },
      { name: 'aes-256-gcm', status: 'ready', priority: 3 },
    ],
    fallbackEnabled: true,
  });
});

app.listen(8789, () => {
  console.log('🔐 Quantum-Hybrid Encryption Server running on 8789');
  console.log('   Algorithm chain: Kyber → X25519 → AES-256-GCM');
});
