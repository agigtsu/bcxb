# Multi-stage build: extract cloudflared binary
FROM cloudflare/cloudflared:latest AS cloudflared-bin

# NOTE: this stage is shell-less, so do not run shell commands here.

# FIXED: Use python:3.12-alpine with shell pre-installed
FROM python:3.12-alpine

LABEL description="Cloudflare Tunnel SOCKS5 Gateway"
LABEL purpose="Route all traffic through encrypted Cloudflare tunnel"

# Install base tools, networking utilities, and Python runtime
RUN apk add --no-cache \
    bash \
    ca-certificates \
    openssl \
    curl \
    wget \
    netcat-openbsd \
    net-tools \
    bind-tools \
    iproute2 \
    tcpdump \
    jq \
    tree \
    vim \
    nano \
    htop \
    git \
    sudo \
    shadow \
    supervisor \
    python3 \
    py3-pip

# Copy cloudflared binary
COPY --from=cloudflared-bin /usr/local/bin/cloudflared /usr/local/bin/cloudflared
RUN chmod +x /usr/local/bin/cloudflared \
    && /usr/local/bin/cloudflared --version \
    && /usr/local/bin/cloudflared tunnel --help > /dev/null 2>&1

# Install Python dependencies and extra tools
RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
    pysocks5==0.1.0 \
    pysocks==1.7.1 \
    requests \
    beautifulsoup4 \
    urllib3 \
    pytest && \
    python3 --version

WORKDIR /app

# Create writable directories for persistence and injected scripts
RUN mkdir -p /app/bin /app/scripts /app/config /app/logs /app/data && \
    chmod 755 /app /app/bin /app/scripts /app/config /app/logs /app/data

# Copy scripts
COPY cloudflared-socks/entrypoint.py /app/entrypoint.py
COPY cloudflared-socks/socks5_server.py /app/socks5_server.py
COPY cloudflared-socks/supervisord.conf /etc/supervisord.conf
COPY cloudflared-socks/scripts/probe_tunnel.py /app/scripts/probe_tunnel.py

RUN chmod +x /app/entrypoint.py /app/socks5_server.py /app/scripts/probe_tunnel.py

# Environment
ENV CLOUDFLARE_TUNNEL_TOKEN=""
ENV SOCKS_HOST="0.0.0.0"
ENV SOCKS_PORT="8888"
ENV LOG_LEVEL="info"
ENV PYTHONUNBUFFERED=1

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD nc -z 127.0.0.1 ${SOCKS_PORT} || exit 1

ENTRYPOINT ["/app/entrypoint.py"]
CMD ["start"]