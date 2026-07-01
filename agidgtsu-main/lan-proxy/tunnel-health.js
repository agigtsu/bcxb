const http = require('http');
const net = require('net');

function normalizeTunnelGateway(rawGateway, fallbackPort = 8888) {
    if (!rawGateway) {
        return `127.0.0.1:${fallbackPort}`;
    }

    let gateway = String(rawGateway).trim();
    if (!gateway) {
        return `127.0.0.1:${fallbackPort}`;
    }

    if (/^https?:\/\//i.test(gateway) || /^socks(?:4|5)?:\/\//i.test(gateway)) {
        try {
            const parsed = new URL(gateway);
            let host = parsed.hostname;
            const port = parsed.port || fallbackPort;

            if (/^host\.docker\.internal$/i.test(host)) {
                host = '127.0.0.1';
            }

            return `${parsed.protocol}//${host}:${port}`;
        } catch (error) {
            return gateway;
        }
    }

    if (/^host\.docker\.internal$/i.test(gateway)) {
        return `127.0.0.1:${fallbackPort}`;
    }

    if (/^host\.docker\.internal:(\d+)$/i.test(gateway)) {
        const port = gateway.split(':').pop();
        return `127.0.0.1:${port}`;
    }

    return gateway;
}

function createTunnelHealthController(initial = {}) {
    const state = {
        enabled: Boolean(initial.enabled),
        mode: initial.mode || 'disabled',
        gateway: normalizeTunnelGateway(initial.gateway || '127.0.0.1:8888'),
        lastHealthCheck: null,
        isHealthy: false,
        failureCount: 0,
        maxFailures: initial.maxFailures || 3,
        timeoutMs: initial.timeoutMs || 5000,
        lastError: null
    };

    function normalizeGateway(gateway = state.gateway) {
        return normalizeTunnelGateway(gateway, state.timeoutMs ? 8888 : 8888);
    }

    function getStatusSnapshot() {
        return {
            tunnelEnabled: state.enabled,
            tunnelHealthy: state.isHealthy,
            lastError: state.lastError,
            gateway: state.gateway,
            mode: state.mode,
            lastHealthCheck: state.lastHealthCheck,
            failureCount: state.failureCount,
            enabled: state.enabled,
            healthy: state.isHealthy
        };
    }

    async function checkHealth({ gateway = state.gateway, timeoutMs = state.timeoutMs } = {}) {
        const normalizedGateway = normalizeGateway(gateway);
        state.gateway = normalizedGateway;
        state.timeoutMs = timeoutMs;

        if (!state.enabled) {
            state.isHealthy = false;
            state.lastError = 'tunnel_disabled';
            state.lastHealthCheck = new Date().toISOString();
            return getStatusSnapshot();
        }

        const defaultPort = 8888;
        const isSocksGateway = /^socks(?:4|5)?:\/\//i.test(normalizedGateway);
        let host;
        let port;

        if (isSocksGateway) {
            const parsed = new URL(normalizedGateway);
            host = parsed.hostname;
            port = Number.parseInt(parsed.port || `${defaultPort}`, 10) || defaultPort;
        } else {
            host = String(normalizedGateway).split(':')[0];
            port = Number.parseInt(String(normalizedGateway).split(':')[1] || `${defaultPort}`, 10) || defaultPort;
        }

        return new Promise((resolve) => {
            const onSuccess = () => {
                state.isHealthy = true;
                state.lastError = null;
                state.failureCount = 0;
                state.lastHealthCheck = new Date().toISOString();
                resolve(getStatusSnapshot());
            };

            const onFailure = (error) => {
                state.isHealthy = false;
                state.lastError = error?.message || 'gateway_unreachable';
                state.failureCount += 1;
                state.lastHealthCheck = new Date().toISOString();
                resolve(getStatusSnapshot());
            };

            if (isSocksGateway) {
                const socket = net.connect({ host, port, timeout: timeoutMs }, () => {
                    socket.end();
                    onSuccess();
                });

                socket.on('error', onFailure);
                socket.on('timeout', () => {
                    socket.destroy(new Error('timeout'));
                });
                return;
            }

            const req = http.request(
                {
                    hostname: host,
                    port,
                    path: '/',
                    method: 'HEAD',
                    timeout: timeoutMs
                },
                (res) => {
                    const responded = res.statusCode >= 200 && res.statusCode < 600;
                    state.isHealthy = responded;
                    state.lastError = responded ? null : 'gateway_unexpected_status';
                    if (state.isHealthy) {
                        state.failureCount = 0;
                    }
                    state.lastHealthCheck = new Date().toISOString();
                    resolve(getStatusSnapshot());
                }
            );

            req.on('error', (err) => {
                onFailure(err);
            });

            req.on('timeout', () => {
                req.destroy(new Error('timeout'));
            });

            req.setTimeout(timeoutMs);
            req.end();
        });
    }

    return {
        state,
        normalizeGateway,
        getStatusSnapshot,
        checkHealth
    };
}

module.exports = { createTunnelHealthController, normalizeTunnelGateway };
