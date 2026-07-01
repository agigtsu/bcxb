const assert = require('assert');
const ModernQuantumSafeProxy = require('./quantum-safe-modern.js');
const QuantumHybridEncryption = require('./quantum-hybrid-encryption.js');

function run() {
  const proxy = new ModernQuantumSafeProxy();
  const health = proxy.getHealthStatus();

  assert.ok(health.capabilities, 'expected capability report in health status');
  assert.strictEqual(health.capabilities.pqcAvailable, false, 'PQC should be reported as unavailable');
  assert.strictEqual(health.capabilities.kyberImplemented, false, 'Kyber should not be reported as implemented');
  assert.strictEqual(health.capabilities.fallbackMode, 'hybrid-and-classical', 'fallback mode should be explicit');
  assert.strictEqual(health.capabilities.hybridFallback, true, 'hybrid fallback should be active');
  assert.strictEqual(health.capabilities.classicalFallback, true, 'classical fallback should be active');

  const packet = proxy.encryptModern('legacy fallback payload', 'aad');
  const decrypted = proxy.decryptModern(packet, 'aad');
  assert.strictEqual(decrypted, 'legacy fallback payload', 'modern proxy should decrypt its own fallback payload');

  const hybrid = new QuantumHybridEncryption();
  const hybridHealth = hybrid.getHealthStatus();
  assert.ok(hybridHealth.capabilities, 'expected hybrid encryption capability report');
  assert.strictEqual(hybridHealth.capabilities.pqcAvailable, false, 'hybrid engine should report PQC as unavailable');
  assert.strictEqual(hybridHealth.capabilities.kyberImplemented, false, 'hybrid engine should report Kyber as unavailable');
  assert.strictEqual(hybridHealth.capabilities.fallbackMode, 'hybrid-and-classical');
  assert.strictEqual(hybridHealth.capabilities.hybridFallback, true, 'hybrid engine should have hybrid fallback active');
  assert.strictEqual(hybridHealth.capabilities.classicalFallback, true, 'hybrid engine should have classical fallback active');

  const hybridPacket = hybrid.encryptSync('hybrid fallback payload', 'aad');
  const hybridPlaintext = hybrid.decryptSync(hybridPacket, 'aad');
  assert.strictEqual(hybridPlaintext, 'hybrid fallback payload', 'hybrid engine should round-trip fallback payloads');

  console.log('✅ crypto capability tests passed');
}

try {
  run();
} catch (error) {
  console.error('❌ crypto capability tests failed');
  console.error(error.stack || error.message);
  process.exit(1);
}
