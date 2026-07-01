#!/usr/bin/env python3
"""
Minimal SOCKS5 server that listens on port 8888 and forwards traffic through system routes.
Works with cloudflared tunnel for encrypted egress.
"""

import socket
import struct
import os
import sys
import logging
from concurrent.futures import ThreadPoolExecutor

# Configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'info').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('SOCKS5')

SOCKS_VERSION = 5
SOCKS_HOST = os.getenv('SOCKS_HOST', '0.0.0.0')
SOCKS_PORT = int(os.getenv('SOCKS_PORT', 8888))
MAX_WORKERS = int(os.getenv('SOCKS_MAX_WORKERS', 50))


class SOCKS5Handler:
    """SOCKS5 protocol handler for a single client connection."""
    
    def __init__(self, client_socket, client_addr):
        self.client_socket = client_socket
        self.client_addr = client_addr
        self.server_socket = None
    
    def handle(self):
        """Main handler: negotiate SOCKS5, then relay traffic."""
        try:
            # Step 1: SOCKS5 greeting
            self._handle_greeting()
            
            # Step 2: Authentication (no auth for simplicity)
            self._handle_auth()
            
            # Step 3: Connect request
            self._handle_connect()
            
            # Step 4: Relay traffic bidirectionally
            self._relay_traffic()
        except Exception as e:
            logger.warning(f"Error handling {self.client_addr}: {e}")
        finally:
            self._cleanup()
    
    def _handle_greeting(self):
        """Negotiate SOCKS5 version and auth methods."""
        data = self.client_socket.recv(1024)
        if not data or len(data) < 2:
            raise ValueError("Invalid greeting")
        
        version = data[0]
        if version != SOCKS_VERSION:
            raise ValueError(f"Unsupported SOCKS version: {version}")
        
        # Reply: version 5, no auth required (0x00)
        self.client_socket.sendall(struct.pack('!BB', SOCKS_VERSION, 0x00))
    
    def _handle_auth(self):
        """Handle authentication (we use no auth)."""
        # For simplicity, we don't require authentication
        # In production, implement proper auth here
        pass
    
    def _handle_connect(self):
        """Handle CONNECT request to destination."""
        data = self.client_socket.recv(1024)
        if not data or len(data) < 4:
            raise ValueError("Invalid CONNECT request")
        
        version = data[0]
        command = data[1]
        
        if version != SOCKS_VERSION:
            raise ValueError(f"Unsupported SOCKS version: {version}")
        
        if command != 0x01:  # CONNECT command
            logger.warning(f"Unsupported command: {command}")
            self.client_socket.sendall(struct.pack('!BBBB', SOCKS_VERSION, 0x07, 0, 1))
            raise ValueError(f"Unsupported command: {command}")
        
        # Parse address type
        addr_type = data[3]
        
        if addr_type == 0x01:  # IPv4
            host = '.'.join(map(str, data[4:8]))
            port = struct.unpack('!H', data[8:10])[0]
        elif addr_type == 0x03:  # Domain name
            domain_len = data[4]
            host = data[5:5+domain_len].decode('utf-8')
            port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
        elif addr_type == 0x04:  # IPv6
            host = ':'.join('{:02x}{:02x}'.format(data[4+i], data[5+i]) for i in range(0, 16, 2))
            port = struct.unpack('!H', data[20:22])[0]
        else:
            raise ValueError(f"Unsupported address type: {addr_type}")
        
        logger.info(f"CONNECT request from {self.client_addr} to {host}:{port}")
        
        # Connect to destination
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((host, port))
        except socket.error as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            self.client_socket.sendall(struct.pack('!BBBB', SOCKS_VERSION, 0x01, 0, 1))
            raise
        
        # Reply: success
        self.client_socket.sendall(struct.pack('!BBBB', SOCKS_VERSION, 0x00, 0, 1))
    
    def _relay_traffic(self):
        """Bidirectional relay between client and server."""
        while True:
            # Use select-like behavior with small timeout
            self.client_socket.settimeout(0.5)
            self.server_socket.settimeout(0.5)
            
            try:
                # Client -> Server
                data = self.client_socket.recv(4096)
                if not data:
                    break
                self.server_socket.sendall(data)
            except socket.timeout:
                pass
            except socket.error:
                break
            
            try:
                # Server -> Client
                data = self.server_socket.recv(4096)
                if not data:
                    break
                self.client_socket.sendall(data)
            except socket.timeout:
                pass
            except socket.error:
                break
    
    def _cleanup(self):
        """Close all sockets."""
        try:
            self.client_socket.close()
        except:
            pass
        try:
            if self.server_socket:
                self.server_socket.close()
        except:
            pass


class SOCKS5Server:
    """SOCKS5 server that listens for connections."""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    
    def start(self):
        """Start the SOCKS5 server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            logger.info(f"🚀 SOCKS5 server listening on {self.host}:{self.port}")
            
            while True:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    logger.debug(f"Accepted connection from {client_addr}")
                    
                    handler = SOCKS5Handler(client_socket, client_addr)
                    self.executor.submit(handler.handle)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Failed to start SOCKS5 server: {e}")
            sys.exit(1)
        finally:
            if self.server_socket:
                self.server_socket.close()
            self.executor.shutdown(wait=True)


if __name__ == '__main__':
    try:
        logger.info(f"Starting SOCKS5 server on {SOCKS_HOST}:{SOCKS_PORT}")
        server = SOCKS5Server(SOCKS_HOST, SOCKS_PORT)
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)