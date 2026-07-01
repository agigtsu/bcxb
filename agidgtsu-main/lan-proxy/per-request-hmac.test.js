const assert = require('assert');
const { createPerRequestSignature, verifyPerRequestSignature } = require('./m7-crypto');

function main() {
    const masterSecret = 'container-master-secret';
    const payload = JSON.stringify({ action: 'proxy', url: 'https://example.com' });

    const first = createPerRequestSignature(masterSecret, payload, { nonce: Buffer.from('a'.repeat(32)), timestamp: 1710000000000 });
    const second = createPerRequestSignature(masterSecret, payload, { nonce: Buffer.from('b'.repeat(32)), timestamp: 1710000001000 });

    assert.ok(first.signature, 'signature should be generated');
    assert.notStrictEqual(first.signature, second.signature, 'every request should use a unique signature');
    assert.strictEqual(verifyPerRequestSignature(first.signature, payload, masterSecret, first.metadata), true);
    assert.strictEqual(verifyPerRequestSignature(second.signature, payload, masterSecret, second.metadata), true);
    assert.strictEqual(verifyPerRequestSignature(first.signature, 'tampered', masterSecret, first.metadata), false);
    console.log('per-request hmac test passed');
}

main();
