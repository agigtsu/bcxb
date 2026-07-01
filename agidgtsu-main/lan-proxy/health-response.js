const { getEchRuntimeStatus } = require('./ech-status');

function buildTransportStatus(req) {
    const socket = req?.socket || {};
    const forwardedProto = (req?.headers?.['x-forwarded-proto'] || '').toString().toLowerCase();
    const isSecure = Boolean(req?.secure || socket.encrypted || forwardedProto === 'https');

    return {
        scheme: isSecure ? 'https' : (req?.protocol || 'http'),
        https: isSecure,
        tlsHandshakeOk: isSecure,
        tlsProtocol: socket.getProtocol?.() || null,
        tlsCipher: socket.getCipher?.()?.name || null,
        httpStatus: 200
    };
}

async function buildHealthPayload({
    initQuantumProxy,
    checkTunnelHealth,
    getEncryptionCapabilitySummary,
    req,
    serviceName = 'lan-proxy'
}) {
    await initQuantumProxy();
    const tunnelSnapshot = await checkTunnelHealth();

    return {
        status: 'ok',
        service: serviceName,
        timestamp: new Date().toISOString(),
        tunnel: {
            enabled: tunnelSnapshot.tunnelEnabled,
            healthy: tunnelSnapshot.tunnelHealthy,
            gateway: tunnelSnapshot.gateway,
            lastError: tunnelSnapshot.lastError,
            lastHealthCheck: tunnelSnapshot.lastHealthCheck
        },
        transport: buildTransportStatus(req),
        ech: getEchRuntimeStatus(),
        crypto: getEncryptionCapabilitySummary(req)
    };
}

module.exports = { buildHealthPayload };
