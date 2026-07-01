#!/usr/bin/env python3
import os
import socket
import sys

print("Python3 probe for cloudflared-socks")
print(f"Python version: {sys.version}")
print(f"Tunnel token set: {bool(os.getenv('CLOUDFLARE_TUNNEL_TOKEN'))}")
print(f"SOCKS host/port: {os.getenv('SOCKS_HOST', '0.0.0.0')}:{os.getenv('SOCKS_PORT', '8888')}")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", int(os.getenv("SOCKS_PORT", "8888"))))
    print("Local SOCKS port reachable")
except Exception as exc:
    print(f"Local SOCKS port check skipped or failed: {exc}")
