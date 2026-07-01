# ═══════════════════════════════════════════════════════════════════════════
# M7 QUANTUM-SAFE PROXY + FLARESOLVERR + TUNNEL INTEGRATION
# Production-Ready Docker Build with Persistent TLS
# ═══════════════════════════════════════════════════════════════════════════

# Extract cloudflared binary from official image
FROM cloudflare/cloudflared:latest AS cloudflared-bin

FROM python:3.11-slim-bullseye

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 1: Install System Dependencies (Minimal, Security-Focused)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl wget gnupg ca-certificates openssl sqlite3 iproute2 \
    chromium chromium-sandbox \
    fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 libcups2 \
    libdbus-1-3 libexpat1 libgcc1 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 \
    libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \
    libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 \
    libxrender1 libxslt1.1 xdg-utils git \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && node --version && npm --version

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 2: Setup Application Structure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WORKDIR /app

# Create directory structure with proper permissions
# NOTE: /app/certs will be a VOLUME → persists across restarts
RUN mkdir -p /app/lan-proxy /app/flaresolverr /app/config /app/logs /app/audit-logs /app/cloudflare-tunnel \
    && chmod 755 /app /app/logs /app/audit-logs \
    && chmod 700 /app/config

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 3: Copy Application Files & Install Dependencies
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# PERFORMANCE CACHE FIX: Copy requirements.txt before full directory
COPY flaresolverr/requirements* /app/flaresolverr/
WORKDIR /app/flaresolverr
RUN if [ -f requirements.txt ]; then python3 -m pip install --no-cache-dir -r requirements.txt; fi

# Copy LAN Proxy package files for dependency caching
COPY core-service/lan-proxy/package*.json /app/lan-proxy/

# Install Node dependencies
WORKDIR /app/lan-proxy
RUN npm install --production && npm cache clean --force

# Copy LAN Proxy source code
COPY core-service/lan-proxy/ /app/lan-proxy/

# Ensure m7-crypto.js and security modules are available
COPY lan-proxy/m7-crypto.js /app/lan-proxy/m7-crypto.js
COPY lan-proxy/sanitizer.js lan-proxy/ssrf-guard.js lan-proxy/sql-detector.js /app/lan-proxy/
COPY lan-proxy/path-validator.js lan-proxy/key-manager.js lan-proxy/rbac.js /app/lan-proxy/
COPY lan-proxy/error-handler.js lan-proxy/email-based-mfa.js /app/lan-proxy/
COPY lan-proxy/quantum-safe-modern.js lan-proxy/key-rotation-manager.js /app/lan-proxy/

# Copy full FlareSolverr tree
WORKDIR /app
COPY flaresolverr/ /app/flaresolverr/

# Copy entrypoint script
COPY docker/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy Cloudflare tunnel manager
COPY core-service/cloudflare-tunnel/ /app/cloudflare-tunnel/
COPY core-service/cloudflare-tunnel/ /app/core-service/cloudflare-tunnel/
RUN chmod -R 755 /app/cloudflare-tunnel /app/core-service/cloudflare-tunnel \
    && test -f /app/core-service/cloudflare-tunnel/Cloudflare-Tunnel.sh || (echo "ERROR: Tunnel script not found" && exit 1) \
    && test -x /app/core-service/cloudflare-tunnel/Cloudflare-Tunnel.sh || chmod +x /app/core-service/cloudflare-tunnel/Cloudflare-Tunnel.sh

# Copy legacy FlareSolverr launcher
COPY core-service/flare-solverr/ /app/core-service/flare-solverr/
RUN chmod +x /app/core-service/flare-solverr/FlareSolverr.sh

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 4: Copy cloudflared Binary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COPY --from=cloudflared-bin /usr/local/bin/cloudflared /usr/local/bin/cloudflared
RUN chmod +x /usr/local/bin/cloudflared \
    && /usr/local/bin/cloudflared --version

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 5: Final Validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RUN test -f /app/lan-proxy/server.js || (echo "ERROR: /app/lan-proxy/server.js not found" && exit 1) \
    && test -f /app/entrypoint.sh || (echo "ERROR: /app/entrypoint.sh not found" && exit 1) \
    && test -f /app/core-service/cloudflare-tunnel/Cloudflare-Tunnel.sh || (echo "ERROR: Tunnel script not found" && exit 1)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 6: Configuration & Environment
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WORKDIR /app

# Security environment
ENV NODE_ENV=production \
    FLARESOLVERR_PORT=8191 \
    PROXY_PORT=8789 \
    TUNNEL_GATEWAY=127.0.0.1:8888 \
    TLS_CERT_PATH=/app/certs/server.crt \
    TLS_KEY_PATH=/app/certs/server.key \
    LOG_LEVEL=info \
    GODEBUG=tlsmlkem=1,tlsrsakex=0 \
    NODE_OPTIONS="--tls-cipher-list=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384" \
    TUNNEL_TRANSPORT_PROTOCOL=quic \
    TUNNEL_FALLBACK_PROTOCOL=http2 \
    TUNNEL_CONCURRENT_CONNECTIONS=16 \
    TUNNEL_QUIC_CONN_LEVEL=4

# Expose proxy port
EXPOSE 8789

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 7: Health Check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HEALTHCHECK --interval=30s --timeout=10s --start-period=8s --retries=3 \
    CMD curl -k -sf https://localhost:8789/health || exit 1

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 8: Volumes & Startup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# VOLUME declarations: /app/certs persists TLS certificates across restarts
VOLUME ["/app/config", "/app/logs", "/app/audit-logs", "/app/certs"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["start-all"]