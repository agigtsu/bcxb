FROM node:26-alpine

WORKDIR /app

# Copy only package files first (cache layer)
COPY lan-proxy/package*.json ./
RUN npm ci --only=production

# Copy source code
COPY lan-proxy/ ./

# Copy certificates
COPY lan-proxy/certs ./certs

# Environment defaults
ENV NODE_ENV=production
ENV PORT=8789
ENV SOCKS_ENABLED=true
ENV SOCKS_PROXY_URL=socks5://cloudflared-socks:8888

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD node -e "require('https').get('https://localhost:8789/health', {rejectUnauthorized: false}, r => {if(r.statusCode !== 200) throw new Error(r.statusCode)})"

EXPOSE 8789

CMD ["node", "server.js"]
