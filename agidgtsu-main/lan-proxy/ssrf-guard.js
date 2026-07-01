function validateRequestURL(url) {
    if (typeof url !== 'string' || !url.trim()) {
        throw new Error('URL validation failed: missing URL');
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch (error) {
        throw new Error(`URL validation failed: invalid URL (${error.message})`);
    }

    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const port = parseInt(parsed.port || (protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : '0'), 10);

    if (['file:', 'gopher:', 'dict:', 'sftp:', 'ldap:', 'telnet:'].includes(protocol)) {
        throw new Error(`SSRF: ${protocol} protocol blocked`);
    }

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        const octets = hostname.split('.').map((value) => parseInt(value, 10));
        if (octets[0] === 127) throw new Error('SSRF: Localhost blocked');
        if (octets[0] === 10) throw new Error('SSRF: Private range 10.x.x.x blocked');
        if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) throw new Error('SSRF: Private range 172.16-31.x.x blocked');
        if (octets[0] === 192 && octets[1] === 168) throw new Error('SSRF: Private range 192.168.x.x blocked');
        if (octets[0] === 169 && octets[1] === 254) throw new Error('SSRF: Link-local/metadata server blocked');
        if (octets[0] === 0) throw new Error('SSRF: Broadcast range blocked');
        if (octets[0] === 255) throw new Error('SSRF: Broadcast range blocked');
    }

    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '0.0.0.0') {
        throw new Error('SSRF: localhost variant blocked');
    }

    if (hostname.startsWith('fc00:') || hostname.startsWith('fd00:') || hostname === '::1') {
        throw new Error('SSRF: IPv6 private range blocked');
    }

    const dangerousPorts = [22, 23, 25, 53, 110, 143, 3306, 5432, 6379, 27017, 8001, 8002, 8003, 8888, 9000, 9001, 9090, 5555, 5556, 5557];
    if (dangerousPorts.includes(port)) {
        throw new Error(`SSRF: Dangerous port ${port} blocked`);
    }

    return true;
}

module.exports = { validateRequestURL };
