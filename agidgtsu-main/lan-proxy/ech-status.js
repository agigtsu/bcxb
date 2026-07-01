function getEchRuntimeStatus() {
    return {
        supported: false,
        enabled: false,
        status: 'unsupported',
        note: 'ECH is not available in this Node/Express/TLS runtime'
    };
}

function applyEchHeaders(res) {
    const echStatus = getEchRuntimeStatus();
    res.setHeader('X-ECH-Supported', echStatus.supported ? 'true' : 'false');
    res.setHeader('X-ECH-Enabled', echStatus.enabled ? 'true' : 'false');
    res.setHeader('X-ECH-Status', echStatus.status);
    return echStatus;
}

module.exports = {
    getEchRuntimeStatus,
    applyEchHeaders
};
