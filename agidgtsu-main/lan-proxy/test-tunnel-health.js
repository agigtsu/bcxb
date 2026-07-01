const assert = require('assert');
const http = require('http');
const { createTunnelHealthController } = require('./tunnel-health');
const { buildHealthPayload } = require('./health-response');
const { getEchRuntimeStatus } = require('./ech-status');

async function run() {
    const controller = createTunnelHealthController({
        enabled: true,
        gateway: 'host.docker.internal:8888',
        timeoutMs: 1000,
        maxFailures: 3
    });

    const normalized = controller.normalizeGateway('host.docker.internal:8888');
    assert.strictEqual(normalized, '127.0.0.1:8888');

    const stubServer = http.createServer((req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('ok');
    });

    await new Promise((resolve) => stubServer.listen(0, '127.0.0.1', resolve));
    const address = stubServer.address();
    const port = typeof address === 'object' && address ? address.port : 8888;
    const gateway = `127.0.0.1:${port}`;

    const snapshot = await controller.checkHealth({ gateway, timeoutMs: 1000 });
    assert.strictEqual(snapshot.tunnelHealthy, true);
    assert.strictEqual(snapshot.lastError, null);

    const healthPayload = await buildHealthPayload({
        initQuantumProxy: async () => {},
        checkTunnelHealth: async () => controller.checkHealth({ gateway, timeoutMs: 1000 }),
        getEncryptionCapabilitySummary: () => ({ mode: 'hybrid' }),
        req: {
            secure: true,
            protocol: 'https',
            socket: {
                getProtocol: () => 'TLSv1.3',
                getCipher: () => ({ name: 'TLS_AES_256_GCM_SHA384' })
            }
        },
        serviceName: 'lan-proxy'
    });

    assert.strictEqual(healthPayload.tunnel.healthy, true);
    assert.strictEqual(healthPayload.tunnel.gateway, gateway);
    assert.strictEqual(healthPayload.transport.https, true);
    assert.strictEqual(healthPayload.transport.tlsHandshakeOk, true);
    assert.strictEqual(healthPayload.transport.tlsProtocol, 'TLSv1.3');

    const echStatus = getEchRuntimeStatus();
    assert.strictEqual(echStatus.supported, false);
    assert.strictEqual(echStatus.enabled, false);
    assert.strictEqual(echStatus.status, 'unsupported');

    await new Promise((resolve) => stubServer.close(resolve));

    console.log('Tunnel health regression checks passed');
}

run().catch((err) => {
    console.error('Tunnel health regression failed:', err.message);
    process.exit(1);
});
