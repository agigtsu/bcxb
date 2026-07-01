FROM python:3.12-alpine

RUN apk add --no-cache tcpdump bash

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY tunnel_tcpdump_to_csv.py /app/tunnel_tcpdump_to_csv.py

RUN chmod +x /app/entrypoint.sh

ENV CSV_PATH="/app/cloudflare-tunnel/tunnels.csv"
ENV CAPTURE_DURATION="20"
ENV CAPTURE_INTERVAL="120"
ENV TCPDUMP_FILTER="tcp port 443 or udp port 7844"

CMD ["/app/entrypoint.sh"]
