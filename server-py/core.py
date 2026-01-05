#!/usr/bin/env python3
"""
Archero TCP Server - Port 12020

Binary protocol server for game client communication.
Uses the protocol module for packet handling.

Run: python tcp_server.py
"""

import socket
import struct
import threading
import signal
import sys
import ssl
from typing import Optional

from protocol.packet_handler import (
    parse_packet,
    handle_packet,
    get_packet_name,
    HEADER_SIZE,
)


TCP_PORT = 12020
BUFFER_SIZE = 65536


class GameClient:
    """Handles a connected game client"""

    def __init__(self, client_socket: socket.socket, address: tuple):
        self.socket = client_socket
        self.address = address
        self.buffer = b""
        self.running = True

    def receive_loop(self):
        """Main receive loop for the client"""
        print(f"[TCP] Client connected: {self.address}")

        try:
            while self.running:
                data = self.socket.recv(BUFFER_SIZE)
                if not data:
                    break

                self.buffer += data
                self.process_buffer()

        except ConnectionResetError:
            print(f"[TCP] Client disconnected: {self.address}")
        except Exception as e:
            print(f"[TCP] Error receiving from {self.address}: {e}")
        finally:
            self.socket.close()
            print(f"[TCP] Connection closed: {self.address}")

    def process_buffer(self):
        """Process complete packets from the buffer"""
        while len(self.buffer) >= HEADER_SIZE:
            # Read packet length from header
            packet_len = struct.unpack("<I", self.buffer[0:4])[0]

            # Check if we have the complete packet
            if len(self.buffer) < packet_len:
                print(
                    f"[TCP] Waiting for more data: have {len(self.buffer)}, need {packet_len}"
                )
                break

            # Extract complete packet
            packet_data = self.buffer[:packet_len]
            self.buffer = self.buffer[packet_len:]

            # Handle packet
            self.handle_packet(packet_data)

    def handle_packet(self, data: bytes):
        """Handle a complete packet"""
        try:
            msg_type, payload = parse_packet(data)
            packet_name = get_packet_name(msg_type)

            # Verbose logging with hex preview
            hex_preview = data[:64].hex() if len(data) >= 64 else data.hex()
            print(
                f"[TCP][C→S] {packet_name} (0x{msg_type:04X}), payload={len(payload)} bytes"
            )
            print(f"[TCP]      Hex: {hex_preview}{'...' if len(data) > 64 else ''}")

            # Get response if any
            response = handle_packet(msg_type, payload)

            if response:
                self.send(response)

        except Exception as e:
            print(f"[TCP] Error handling packet: {e}")
            import traceback

            traceback.print_exc()

    def send(self, data: bytes):
        """Send data to the client"""
        try:
            self.socket.sendall(data)

            # Verbose logging with hex preview
            if len(data) >= HEADER_SIZE:
                msg_type = struct.unpack("<H", data[4:6])[0]
                packet_name = get_packet_name(msg_type)
                hex_preview = data[:64].hex() if len(data) >= 64 else data.hex()
                print(
                    f"[TCP][S→C] {packet_name} (0x{msg_type:04X}), {len(data)} bytes"
                )
                print(f"[TCP]      Hex: {hex_preview}{'...' if len(data) > 64 else ''}")

        except Exception as e:
            print(f"[TCP] Error sending to {self.address}: {e}")


class TCPServer:
    """TCP server for game protocol with optional TLS support"""

    def __init__(self, port: int = TCP_PORT, ssl_context: Optional[ssl.SSLContext] = None):
        self.port = port
        self.socket = None
        self.ssl_context = ssl_context
        self.running = False
        self.clients = []

    def start(self):
        """Start the TCP server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.socket.bind(("0.0.0.0", self.port))
        self.socket.listen(10)

        self.running = True
        tls_status = "🔒 TLS ENABLED" if self.ssl_context else "⚠️  NO TLS"
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║           🎮 Archero TCP Server - Port {self.port}           ║
║           {tls_status:^41}   ║
╚═══════════════════════════════════════════════════════════╝

[TCP] Server listening on 0.0.0.0:{self.port}
[TCP] TLS: {"Enabled" if self.ssl_context else "Disabled"}
[TCP] Waiting for game client connections...
        """)

        try:
            while self.running:
                client_socket, address = self.socket.accept()

                # Wrap with TLS if context provided
                if self.ssl_context:
                    try:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket, server_side=True
                        )
                        print(f"[TCP] TLS handshake completed with {address}")
                    except ssl.SSLError as e:
                        print(f"[TCP] TLS handshake failed with {address}: {e}")
                        client_socket.close()
                        continue

                client = GameClient(client_socket, address)
                self.clients.append(client)

                # Start receive thread
                thread = threading.Thread(target=client.receive_loop, daemon=True)
                thread.start()

        except KeyboardInterrupt:
            print("\n[TCP] Shutting down...")
        finally:
            self.stop()

    def stop(self):
        """Stop the server"""
        self.running = False

        for client in self.clients:
            client.running = False
            try:
                client.socket.close()
            except:
                pass

        if self.socket:
            self.socket.close()

        print("[TCP] Server stopped")


def main():
    server = TCPServer(TCP_PORT)

    # Handle Ctrl+C
    def signal_handler(sig, frame):
        print("\n[TCP] Interrupt received, stopping...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    server.start()


if __name__ == "__main__":
    main()
