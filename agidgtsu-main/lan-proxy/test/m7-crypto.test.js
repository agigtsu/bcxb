const test = require('node:test');
const assert = require('node:assert/strict');
const m7Crypto = require('../m7-crypto');

test('decodeEncryptionKey accepts 32-byte hex keys', () => {
    const key = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const decoded = m7Crypto.decodeEncryptionKey(key);

    assert.ok(Buffer.isBuffer(decoded));
    assert.equal(decoded.length, 32);
    assert.deepStrictEqual(decoded, Buffer.from(key, 'hex'));
});

test('decodeEncryptionKey rejects unsupported or invalid key formats', () => {
    assert.equal(m7Crypto.decodeEncryptionKey('not-a-hex-key'), null);
    assert.equal(m7Crypto.decodeEncryptionKey('00112233445566778899aabbccddeeff00112233445566778899aabbccddeef'), null);
});

test('createHmacSignature produces lowercase hex and verifies correctly', () => {
    const signature = m7Crypto.createHmacSignature('secret', 'payload');
    assert.match(signature, /^[0-9a-f]{64}$/);
    assert.equal(m7Crypto.verifyHmacSignature(signature, 'payload', 'secret'), true);
    assert.equal(m7Crypto.verifyHmacSignature(signature, 'different', 'secret'), false);
});
