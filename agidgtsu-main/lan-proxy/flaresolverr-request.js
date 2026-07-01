function buildFlareSolverrRequest(reqOrBody, options = {}) {
    const body = reqOrBody?.body || reqOrBody;

    if (!body || typeof body !== 'object') {
        return body;
    }

    if (body.cmd && (body.cmd === 'request.get' || body.cmd === 'request.post')) {
        return body;
    }

    // SOCKS5 proxy configuration for Cloudflare tunnel (ISP privacy)
    const socksProxyUrl = process.env.SOCKS_PROXY_URL || 'socks5://127.0.0.1:8888';
    const socksEnabled = process.env.SOCKS_ENABLED !== 'false';
    const proxyConfig = socksEnabled ? { url: socksProxyUrl } : undefined;

    if (body.encrypted && body.packet) {
        let targetUrl = body.url || body.targetUrl || body.target || 'https://imei.info';

        const tunnelConfig = options.tunnelEnabled && options.tunnelHealthy
            ? {
                'x-tunnel-enabled': 'true',
                'x-tunnel-gateway': options.tunnelGateway || '127.0.0.1:8888',
                'x-tunnel-mode': options.tunnelMode || 'disabled'
            }
            : {};

        const socksConfig = socksEnabled
            ? {
                'x-socks-proxy': socksProxyUrl,
                'x-socks-enabled': 'true'
            }
            : {};

        const fieldName = body.formFieldName || body.fieldName || 'm7Envelope';
        const envelopeJson = JSON.stringify(body);
        const postData = `${fieldName}=${encodeURIComponent(envelopeJson)}`;

        return {
            cmd: 'request.post',
            url: targetUrl,
            postData,
            maxTimeout: body.maxTimeout || 120000,
            returnOnlyCookies: body.returnOnlyCookies !== false,
            proxy: proxyConfig,
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
                ...tunnelConfig,
                ...socksConfig
            }
        };
    }

    const targetUrl = body.url || body.targetUrl || body.target || body.destination;
    if (!targetUrl) {
        return body;
    }

    const method = String(body.method || 'GET').toUpperCase();
    const socksConfig = socksEnabled
        ? {
            'x-socks-proxy': socksProxyUrl,
            'x-socks-enabled': 'true'
        }
        : {};

    const request = {
        cmd: method === 'POST' ? 'request.post' : 'request.get',
        url: targetUrl,
        maxTimeout: body.maxTimeout || 120000,
        returnOnlyCookies: body.returnOnlyCookies !== false,
        proxy: proxyConfig,
        headers: {
            ...body.headers ? { ...body.headers } : {},
            ...socksConfig
        }
    };

    if (method === 'POST') {
        request.postData = body.postData || body.data || body.payload || '';
    }

    return request;
}

module.exports = { buildFlareSolverrRequest };
