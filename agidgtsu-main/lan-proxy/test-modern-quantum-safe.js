/**
 * COMPREHENSIVE TEST SUITE
 * ModernQuantumSafeProxy (MODERN 2024 Quantum-Safe Encryption)
 * 
 * Tests all 5 security layers, fallback mechanisms, key rotation,
 * tamper detection, and statistics tracking
 */

import ModernQuantumSafeProxy from './quantum-safe-modern.js';
import fs from 'fs';
import path from 'path';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const RESET = '\x1b[0m';

class TestSuite {
  constructor() {
    this.results = {
      passed: 0,
      failed: 0,
      skipped: 0,
      tests: [],
    };
    this.proxy = null;
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
    const prefix = {
      pass: `${GREEN}✅${RESET}`,
      fail: `${RED}❌${RESET}`,
      warn: `${YELLOW}⚠️ ${RESET}`,
      info: `${BLUE}ℹ️ ${RESET}`,
    }[level] || '';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  async initialize() {
    this.log('Initializing ModernQuantumSafeProxy...', 'info');
    try {
      this.proxy = new ModernQuantumSafeProxy();
      this.log('✅ ModernQuantumSafeProxy initialized successfully', 'pass');
      return true;
    } catch (e) {
      this.log(`Failed to initialize proxy: ${e.message}`, 'fail');
      this.results.failed++;
      return false;
    }
  }

  assertEqual(actual, expected, testName) {
    if (actual === expected) {
      this.log(`${testName}: PASS`, 'pass');
      this.results.passed++;
      return true;
    } else {
      this.log(
        `${testName}: FAIL (expected ${expected}, got ${actual})`,
        'fail'
      );
      this.results.failed++;
      return false;
    }
  }

  assertTrue(condition, testName) {
    if (condition) {
      this.log(`${testName}: PASS`, 'pass');
      this.results.passed++;
      return true;
    } else {
      this.log(`${testName}: FAIL (expected true)`, 'fail');
      this.results.failed++;
      return false;
    }
  }

  assertFalse(condition, testName) {
    if (!condition) {
      this.log(`${testName}: PASS`, 'pass');
      this.results.passed++;
      return true;
    } else {
      this.log(`${testName}: FAIL (expected false)`, 'fail');
      this.results.failed++;
      return false;
    }
  }

  assertExists(value, testName) {
    if (value !== null && value !== undefined) {
      this.log(`${testName}: PASS`, 'pass');
      this.results.passed++;
      return true;
    } else {
      this.log(`${testName}: FAIL (value does not exist)`, 'fail');
      this.results.failed++;
      return false;
    }
  }

  // ===== TEST SCENARIOS =====

  async testRoundTripEncryption() {
    console.log(`\n${BLUE}=== TEST 1: Round-Trip Encryption/Decryption ===${RESET}`);

    const testCases = [
      { plaintext: 'Hello, Quantum World!', name: 'Simple message' },
      {
        plaintext: 'x'.repeat(1000),
        name: 'Large payload (1KB)',
      },
      {
        plaintext: JSON.stringify({ data: 'test', nested: { value: 123 } }),
        name: 'JSON structure',
      },
    ];

    for (const testCase of testCases) {
      try {
        const packet = await this.proxy.encryptModern(
          testCase.plaintext,
          'test-aad'
        );
        this.assertExists(packet, `Encryption produced packet: ${testCase.name}`);

        const decrypted = await this.proxy.decryptModern(packet, 'test-aad');
        this.assertEqual(
          decrypted,
          testCase.plaintext,
          `Decryption matches plaintext: ${testCase.name}`
        );
      } catch (e) {
        this.log(
          `Round-trip failed for ${testCase.name}: ${e.message}`,
          'fail'
        );
        this.results.failed++;
      }
    }
  }

  async testSignatureVerification() {
    console.log(`\n${BLUE}=== TEST 2: Signature Verification ===${RESET}`);

    try {
      const plaintext = 'Signed message';
      const packet = await this.proxy.encryptModern(plaintext, 'aad-data');

      // Verify with correct AAD (should pass)
      try {
        const decrypted = await this.proxy.decryptModern(packet, 'aad-data');
        this.assertTrue(
          decrypted === plaintext,
          'Signature verified with correct AAD'
        );
      } catch (e) {
        this.log(`Signature verification failed: ${e.message}`, 'fail');
        this.results.failed++;
      }

      // Verify with wrong AAD (should fail signature)
      try {
        await this.proxy.decryptModern(packet, 'wrong-aad');
        this.log(
          'Tampering detection FAILED: Should have rejected wrong AAD',
          'fail'
        );
        this.results.failed++;
      } catch (e) {
        this.assertTrue(
          e.message.includes('Authentication failed'),
          'Tampering detected with wrong AAD'
        );
      }
    } catch (e) {
      this.log(`Signature test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testTamperingDetection() {
    console.log(`\n${BLUE}=== TEST 3: Tamper Detection ===${RESET}`);

    try {
      const plaintext = 'Original message';
      const packet = await this.proxy.encryptModern(plaintext, 'aad');

      // Modify ciphertext (tamper with payload)
      const tampered = JSON.parse(JSON.stringify(packet));
      const ctBuffer = Buffer.from(tampered.ciphertext, 'hex');
      ctBuffer[0] ^= 0xff; // Flip bits in first byte
      tampered.ciphertext = ctBuffer.toString('hex');

      try {
        await this.proxy.decryptModern(tampered, 'aad');
        this.log('Tamper detection FAILED: Should reject modified ciphertext', 'fail');
        this.results.failed++;
      } catch (e) {
        this.assertTrue(
          e.message.includes('failed'),
          'Tamper detection caught modified ciphertext'
        );
      }
    } catch (e) {
      this.log(`Tampering test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testStatisticsTracking() {
    console.log(`\n${BLUE}=== TEST 4: Statistics Tracking ===${RESET}`);

    try {
      const initialStats = this.proxy.getHealthStatus().statistics;

      // Perform operations
      await this.proxy.encryptModern('msg1', 'aad1');
      await this.proxy.encryptModern('msg2', 'aad2');
      const packet = await this.proxy.encryptModern('msg3', 'aad3');

      try {
        await this.proxy.decryptModern(packet, 'aad3');
      } catch (e) {
        // Ignore errors
      }

      const finalStats = this.proxy.getHealthStatus().statistics;

      this.assertTrue(
        finalStats.encrypted >= initialStats.encrypted + 3,
        'Encryption count incremented'
      );
      this.assertTrue(
        finalStats.decrypted >= initialStats.decrypted + 1,
        'Decryption count incremented'
      );
    } catch (e) {
      this.log(`Statistics test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testHealthStatus() {
    console.log(`\n${BLUE}=== TEST 5: Health Status Reporting ===${RESET}`);

    try {
      const health = this.proxy.getHealthStatus();

      this.assertExists(health.status, 'Health status exists');
      this.assertTrue(health.status === 'healthy', 'Status is "healthy"');
      this.assertExists(
        health.algorithms,
        'Algorithms information provided'
      );
      this.assertTrue(
        health.algorithms.includes('FIPS 203'),
        'FIPS 203 (Kyber) listed'
      );
      this.assertTrue(
        health.algorithms.includes('FIPS 204'),
        'FIPS 204 (Dilithium2) listed'
      );
      this.assertExists(health.statistics, 'Statistics provided');
    } catch (e) {
      this.log(`Health status test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testPacketStructure() {
    console.log(`\n${BLUE}=== TEST 6: Packet Structure Validation ===${RESET}`);

    try {
      const packet = await this.proxy.encryptModern('test payload', 'aad');

      // Verify required fields
      this.assertTrue(packet.version === 2, 'Packet version is 2');
      this.assertExists(
        packet.keyExchange,
        'Key exchange algorithm specified'
      );
      this.assertExists(
        packet.sessionId,
        'Session ID present'
      );
      this.assertExists(packet.ciphertext, 'Ciphertext present');
      this.assertExists(packet.authTag, 'Authentication tag present');
      this.assertExists(packet.signature, 'Digital signature present');
      this.assertExists(
        packet.signingAlgorithm,
        'Signing algorithm identified'
      );
    } catch (e) {
      this.log(`Packet structure test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testKeyRotation() {
    console.log(`\n${BLUE}=== TEST 7: Key Rotation ===${RESET}`);

    try {
      const beforeRotation = this.proxy.getHealthStatus();
      this.log(
        `Rotations before: ${beforeRotation.statistics.rotationsPerformed}`,
        'info'
      );

      // Perform rotation
      this.proxy.rotateKeys();
      this.log('Key rotation executed', 'info');

      const afterRotation = this.proxy.getHealthStatus();
      this.log(
        `Rotations after: ${afterRotation.statistics.rotationsPerformed}`,
        'info'
      );

      this.assertTrue(
        afterRotation.statistics.rotationsPerformed >
          beforeRotation.statistics.rotationsPerformed,
        'Rotation counter incremented'
      );

      // Verify new keys work
      const packet = this.proxy.encryptModern('post-rotation', 'aad');
      const decrypted = this.proxy.decryptModern(packet, 'aad');
      this.assertEqual(
        decrypted,
        'post-rotation',
        'Encryption works after key rotation'
      );
    } catch (e) {
      this.log(`Key rotation test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testAlgorithmStack() {
    console.log(`\n${BLUE}=== TEST 8: Algorithm Stack & NIST Compliance ===${RESET}`);

    try {
      const health = this.proxy.getHealthStatus();

      const requiredAlgorithms = [
        'Kyber1024',
        'X25519',
        'Dilithium2',
        'Ed25519',
        'AES-256-GCM',
        'XChaCha20-Poly1305',
        'Argon2id',
        'HKDF-SHA512',
      ];

      for (const algo of requiredAlgorithms) {
        const found = health.algorithms.some(a => a.includes(algo));
        this.assertTrue(
          found,
          `Algorithm available: ${algo}`
        );
      }

      this.assertTrue(
        health.standards.includes('FIPS 203'),
        'FIPS 203 compliance'
      );
      this.assertTrue(
        health.standards.includes('FIPS 204'),
        'FIPS 204 compliance'
      );
    } catch (e) {
      this.log(`Algorithm stack test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  async testErrorHandling() {
    console.log(`\n${BLUE}=== TEST 9: Error Handling ===${RESET}`);

    // Test with null/undefined
    try {
      this.proxy.encryptModern(null, 'aad');
      this.log('Error handling: null plaintext should throw', 'fail');
      this.results.failed++;
    } catch (e) {
      this.assertTrue(true, 'Null plaintext rejected');
    }

    // Test with invalid packet format
    try {
      this.proxy.decryptModern({ invalid: 'packet' }, 'aad');
      this.log('Error handling: invalid packet should throw', 'fail');
      this.results.failed++;
    } catch (e) {
      this.assertTrue(true, 'Invalid packet rejected');
    }
  }

  async testKeyPersistence() {
    console.log(`\n${BLUE}=== TEST 10: Key Persistence ===${RESET}`);

    try {
      const keyPath = `${process.env.HOME}/.proxy-encryption/quantum-master-key.json`;
      
      if (fs.existsSync(keyPath)) {
        this.assertTrue(true, 'Master key file exists');

        const keyData = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
        this.assertExists(keyData.kyberPrivate, 'Kyber private key stored');
        this.assertExists(keyData.dilithiumPrivate, 'Dilithium private key stored');
        this.assertExists(keyData.x25519Private, 'X25519 private key stored');

        // Check file permissions (should be 0600)
        const stats = fs.statSync(keyPath);
        const mode = (stats.mode & parseInt('777', 8)).toString(8);
        this.assertTrue(
          mode === '600',
          `Key file permissions secure (${mode})`
        );
      } else {
        this.log('Key file not yet created (will be on first use)', 'warn');
      }
    } catch (e) {
      this.log(`Key persistence test error: ${e.message}`, 'fail');
      this.results.failed++;
    }
  }

  printResults() {
    console.log(`\n${BLUE}${'='.repeat(60)}${RESET}`);
    console.log(`${BLUE}TEST RESULTS${RESET}`);
    console.log(`${BLUE}${'='.repeat(60)}${RESET}`);
    console.log(
      `${GREEN}✅ Passed: ${this.results.passed}${RESET}`
    );
    console.log(
      `${RED}❌ Failed: ${this.results.failed}${RESET}`
    );
    console.log(
      `${YELLOW}⚠️  Skipped: ${this.results.skipped}${RESET}`
    );
    console.log(
      `${BLUE}📊 Total: ${this.results.passed + this.results.failed + this.results.skipped}${RESET}`
    );
    console.log(`${BLUE}${'='.repeat(60)}${RESET}\n`);

    if (this.results.failed === 0) {
      console.log(
        `${GREEN}✅ ALL TESTS PASSED - MODERN QUANTUM-SAFE ENCRYPTION READY${RESET}`
      );
    } else {
      console.log(
        `${RED}❌ SOME TESTS FAILED - REVIEW ABOVE FOR DETAILS${RESET}`
      );
    }
  }

  async runAll() {
    console.log(`${BLUE}${'='.repeat(60)}${RESET}`);
    console.log(
      `${BLUE}MODERN 2024 QUANTUM-SAFE ENCRYPTION TEST SUITE${RESET}`
    );
    console.log(`${BLUE}${'='.repeat(60)}${RESET}\n`);

    if (!(await this.initialize())) {
      console.log(
        `${RED}Failed to initialize proxy. Tests cannot run.${RESET}`
      );
      process.exit(1);
    }

    await this.testRoundTripEncryption();
    await this.testSignatureVerification();
    await this.testTamperingDetection();
    await this.testStatisticsTracking();
    await this.testHealthStatus();
    await this.testPacketStructure();
    await this.testKeyRotation();
    await this.testAlgorithmStack();
    await this.testErrorHandling();
    await this.testKeyPersistence();

    this.printResults();

    process.exit(this.results.failed > 0 ? 1 : 0);
  }
}

// Run tests
const suite = new TestSuite();
suite.runAll().catch(e => {
  console.error(`${RED}Fatal test error: ${e.message}${RESET}`);
  process.exit(1);
});
