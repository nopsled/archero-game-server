#!/usr/bin/env python
# sudo nodemon - -exec python core.py
import random
import socket
import msgpack
from threading import Thread
import time
import ssl
import OpenSSL
import json
import re
import urllib.parse
import base64
import subprocess
from OpenSSL import crypto
import os
from pathlib import Path

from .config import header


def resolve_cert_dir() -> Path:
    override = os.environ.get("ARCHERO_CERT_DIR")
    if override:
        return Path(override)

    preferred = Path(".local/certs")
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_test"
        probe.write_bytes(b"ok")
        probe.unlink()
        return preferred
    except Exception:
        return Path("/tmp/archero-certs")


CERT_DIR = resolve_cert_dir()
CERT_PATH = CERT_DIR / "cert.pem"
KEY_PATH = CERT_DIR / "key.pem"
CA_CERT_PATH = CERT_DIR / "ca.pem"
CA_KEY_PATH = CERT_DIR / "ca.key"


def _try_parse_tls_sni(client_hello: bytes) -> str | None:
    # Minimal TLS ClientHello SNI extractor (best-effort).
    # Supports the common case where peek includes at least the first record.
    try:
        if len(client_hello) < 5:
            return None
        if client_hello[0] != 0x16:  # handshake
            return None
        rec_len = int.from_bytes(client_hello[3:5], "big")
        if len(client_hello) < 5 + rec_len:
            return None
        hs = client_hello[5 : 5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
            return None
        hs_len = int.from_bytes(hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        if len(body) < 42:
            return None
        p = 2  # client_version
        p += 32  # random
        sid_len = body[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(body[p : p + 2], "big")
        p += 2 + cs_len
        comp_len = body[p]
        p += 1 + comp_len
        if p + 2 > len(body):
            return None
        ext_len = int.from_bytes(body[p : p + 2], "big")
        p += 2
        end = min(len(body), p + ext_len)
        while p + 4 <= end:
            etype = int.from_bytes(body[p : p + 2], "big")
            elen = int.from_bytes(body[p + 2 : p + 4], "big")
            p += 4
            if p + elen > end:
                return None
            if etype == 0x0000:  # server_name
                ext = body[p : p + elen]
                if len(ext) < 2:
                    return None
                list_len = int.from_bytes(ext[0:2], "big")
                q = 2
                list_end = min(len(ext), 2 + list_len)
                while q + 3 <= list_end:
                    name_type = ext[q]
                    name_len = int.from_bytes(ext[q + 1 : q + 3], "big")
                    q += 3
                    if q + name_len > list_end:
                        return None
                    if name_type == 0:  # host_name
                        return ext[q : q + name_len].decode("utf-8", errors="replace")
                    q += name_len
                return None
            p += elen
    except Exception:
        return None
    return None


class GameWorldManager:
    instances = []

    def broadcastWorldCommand():
        pass

    def getAllPlayers():
        pass

    def sendChatMessage():
        pass


class GameObject:
    def __init__(
        self,
        id=random.randint(0, 999),
        x=random.randint(0, 300),
        y=random.randint(0, 300),
        scale=random.randint(10, 100),
        type=random.randint(0, 3),
    ):
        pass


class PlayerObject:
    def __init__(
        self,
        socket,
        id=1,
        y=0,
        x=0,
        angle=0.0,
        usingItemID=1,
        unk2=0,
        unk3=0,
        unk4=None,
        clanLeader=0,
        skin=0,
        usingAccessoryID=0,
        showSkull=0,
        unk9=0,
    ):
        pass


def _load_or_generate_key(path: Path, *, bits: int = 2048) -> crypto.PKey:
    if path.exists():
        return crypto.load_privatekey(crypto.FILETYPE_PEM, path.read_bytes())
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)
    path.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    return key


def _load_or_generate_ca() -> tuple[crypto.X509, crypto.PKey]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    ca_key = _load_or_generate_key(CA_KEY_PATH)
    if CA_CERT_PATH.exists():
        ca_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, CA_CERT_PATH.read_bytes()
        )
        return ca_cert, ca_key

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(1)
    ca_subject = ca_cert.get_subject()
    ca_subject.CN = "Archero Local CA"
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    ca_cert.set_issuer(ca_subject)
    ca_cert.set_pubkey(ca_key)
    ca_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=ca_cert
            ),
        ]
    )
    ca_cert.sign(ca_key, "sha256")
    CA_CERT_PATH.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    return ca_cert, ca_key


def generate_cert():
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Keep certs stable across restarts if present.
    if (
        os.environ.get("ARCHERO_REGEN_CERT") != "1"
        and CERT_PATH.exists()
        and KEY_PATH.exists()
        and CA_CERT_PATH.exists()
    ):
        return

    ca_cert, ca_key = _load_or_generate_ca()
    leaf_key = _load_or_generate_key(KEY_PATH)

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(1000)
    subject = cert.get_subject()
    subject.CN = "habby.mobi"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(leaf_key)

    sans = [
        "DNS:habby.mobi",
        "DNS:*.habby.mobi",
        "DNS:receiver.habby.mobi",
        "DNS:hotupdate-archero.habby.com",
        "DNS:*.archerosvc.com",
        "DNS:game-archero-v1.archerosvc.com",
        "DNS:config-archero.archerosvc.com",
    ]
    cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b"keyUsage", False, b"digitalSignature, keyEncipherment"
            ),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(
                b"subjectAltName", False, (", ".join(sans)).encode("ascii")
            ),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert
            ),
        ]
    )
    cert.sign(ca_key, "sha256")

    # Write the certificate to a file
    CERT_PATH.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def parse_socket_data(socket_data):
    delimiter = b"\r\n\r\n"
    idx = socket_data.find(delimiter)
    if idx == -1:
        return {}, socket_data

    head_bytes = socket_data[:idx]
    body = socket_data[idx + len(delimiter) :]
    head = head_bytes.decode("utf-8", errors="replace")

    header_lines = head.split("\r\n")
    header_dict = {}
    if header_lines:
        header_dict[":request-line"] = header_lines[0]
        for line in header_lines[1:]:
            if ": " not in line:
                continue
            key, value = line.split(": ", 1)
            header_dict[key] = value

    return header_dict, body


class NetUtility:
    @staticmethod
    def parse_data(data):
        pass


# Reversed API of Archero.
class API:
    @staticmethod
    def users_x_announcements(request):
        pass

    # Handle requests to: /users/156815953/announcements
    @staticmethod
    def users_x_announcements(request):
        pass


class GameProtocolClient:
    """Handler for binary game protocol on port 12020."""

    def __init__(self, socket, client_address):
        self.socket = socket
        self.client_address = client_address
        self.buffer = bytearray()

    def recv_loop(self):
        """Main receive loop for game protocol."""
        from .protocol import Packet
        from .handlers.login import handle_packet

        print(f"[GameProtocol] Client connected from {self.client_address}")

        try:
            self.socket.settimeout(30.0)  # 30 second timeout for game protocol
        except Exception:
            pass

        while True:
            if self.socket.fileno() == -1:
                print(f"[GameProtocol] Socket closed for {self.client_address}")
                break

            try:
                chunk = self.socket.recv(4096)
            except socket.timeout:
                # Send heartbeat to keep connection alive
                continue
            except Exception as e:
                print(f"[GameProtocol] Recv error from {self.client_address}: {e}")
                break

            if not chunk:
                print(f"[GameProtocol] Client {self.client_address} disconnected")
                break

            self.buffer.extend(chunk)
            print(
                f"[GameProtocol] Received {len(chunk)} bytes, buffer size: {len(self.buffer)}"
            )
            print(
                f"[GameProtocol] Buffer hex: {bytes(self.buffer[:64]).hex()}"
                + ("..." if len(self.buffer) > 64 else "")
            )

            # Try to parse complete packets from buffer
            self._process_buffer(Packet, handle_packet)

        try:
            self.socket.close()
        except Exception:
            pass

    def _process_buffer(self, Packet, handle_packet):
        """Process any complete packets in the buffer."""
        while len(self.buffer) >= 4:
            # Check if we have the complete packet
            packet_len = int.from_bytes(self.buffer[:4], "little")
            if len(self.buffer) < 4 + packet_len:
                # Wait for more data
                print(
                    f"[GameProtocol] Waiting for more data: have {len(self.buffer)}, need {4 + packet_len}"
                )
                break

            try:
                packet, remaining = Packet.from_bytes(bytes(self.buffer))
                self.buffer = bytearray(remaining)

                print(
                    f"[GameProtocol] Parsed packet: type=0x{packet.msg_type:04x}, payload_len={len(packet.payload)}"
                )

                # Handle the packet
                response = handle_packet(packet)
                if response is not None:
                    self._send_packet(response)

            except Exception as e:
                print(f"[GameProtocol] Error parsing packet: {e}")
                print(
                    f"[GameProtocol] Buffer hex at error: {bytes(self.buffer[:128]).hex()}"
                )
                # Clear buffer on parse error to recover
                self.buffer.clear()
                break

    def _send_packet(self, packet):
        """Send a packet to the client."""
        try:
            data = packet.to_bytes()
            print(
                f"[GameProtocol] Sending packet: type=0x{packet.msg_type:04x}, total_len={len(data)}"
            )
            print(
                f"[GameProtocol] Send hex: {data[:64].hex()}"
                + ("..." if len(data) > 64 else "")
            )
            self.socket.sendall(data)
        except Exception as e:
            print(f"[GameProtocol] Send error: {e}")


class Client:
    def __init__(self, socket, alpn: str | None = None, listen_port: int | None = None):
        self.socket = socket
        self.alpn = alpn
        self.listen_port = listen_port
        self.port = -0

    def _send_h2_settings(self):
        # HTTP/2 SETTINGS frame with empty payload:
        # length(3)=0x000000, type(1)=0x04, flags(1)=0x00, stream_id(4)=0x00000000
        self.socket.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")

    def _send_h2_settings_ack(self):
        # SETTINGS ACK: flags=0x01
        self.socket.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")

    def _send_h2_ping_ack(self, opaque8: bytes):
        # PING ACK: length=8 type=0x06 flags=0x01 stream=0
        self.socket.sendall(b"\x00\x00\x08\x06\x01\x00\x00\x00\x00" + opaque8)

    def recv(self):
        h2_buffer = bytearray()
        if self.alpn == "h2":
            try:
                self._send_h2_settings()
                print("[+] Sent HTTP/2 SETTINGS (empty)")
            except Exception as e:
                print(f"[-] Failed to send HTTP/2 SETTINGS: {e}")

        try:
            # Reduce the chance of missing short-lived connections.
            self.socket.settimeout(1.0)
        except Exception:
            pass

        while True:
            if self.socket.fileno() == -1:
                print("[-] Socket is closed")
                break

            try:
                received_data = self.socket.recv(2048)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Cannot recv data on socket, error: {e}")
                break

            if received_data == b"":
                print("[-] Peer closed connection")
                break

            if len(received_data) > 0:
                if self.alpn == "h2":
                    h2_buffer.extend(received_data)
                    # Parse as many HTTP/2 frames as we can.
                    while len(h2_buffer) >= 9:
                        length = (
                            (h2_buffer[0] << 16) | (h2_buffer[1] << 8) | h2_buffer[2]
                        )
                        ftype = h2_buffer[3]
                        flags = h2_buffer[4]
                        stream_id = (
                            ((h2_buffer[5] & 0x7F) << 24)
                            | (h2_buffer[6] << 16)
                            | (h2_buffer[7] << 8)
                            | h2_buffer[8]
                        )
                        if len(h2_buffer) < 9 + length:
                            break
                        payload = bytes(h2_buffer[9 : 9 + length])
                        del h2_buffer[: 9 + length]

                        print(
                            f"[H2] frame type={ftype} flags=0x{flags:02x} stream={stream_id} len={length} payload_hex={payload[:64].hex()}"
                            + (
                                ""
                                if len(payload) <= 64
                                else f"…(+{len(payload) - 64}b)"
                            )
                        )

                        # Respond to SETTINGS / PING so the client keeps talking.
                        try:
                            if ftype == 4 and (flags & 0x1) == 0:
                                self._send_h2_settings_ack()
                                print("[H2] sent SETTINGS ACK")
                            elif ftype == 6 and length == 8 and (flags & 0x1) == 0:
                                self._send_h2_ping_ack(payload)
                                print("[H2] sent PING ACK")
                        except Exception as e:
                            print(f"[-] Failed to respond to H2 control frame: {e}")
                    continue

                headers, body = parse_socket_data(received_data)
                if headers:
                    print("Headers:")
                    for key, value in headers.items():
                        print(f"{key}: {value}")
                if body:
                    snippet = body[:256]
                    print(
                        f"Body: {snippet!r}"
                        + ("" if len(body) <= 256 else f" …(+{len(body) - 256}b)")
                    )

                decodedData = received_data.decode()
                strippedData = decodedData.strip()
                data2 = urllib.parse.parse_qs(strippedData)
                print("")

                for endpoint in header.ENDPOINTS:
                    if endpoint in decodedData:
                        print(
                            f"[+] Client requested: {endpoint}, response sent back to client."
                        )
                        response = header.RESPONSE_HEADER + b"{}"
                        self.socket.send(response)
                        print(response)
                        break

                if "announcements" in decodedData:
                    formatted_time = time.strftime(
                        "%a, %d %b %Y %H:%M:%S GMT", time.gmtime()
                    )
                    response = (
                        b"HTTP/2 200 OK\r\n"
                        b"Content-Type: application/json; charset=UTF-8\r\n"
                        b"Content-length: 29\r\n"
                        b"Connection: close\r\n"
                        b"Date: " + formatted_time.encode("utf-8") + b"\r\n"
                        b"X-Powered-By: Express\r\n"
                        b'ETag: W/"1d-qTxd3JymBGkwYt6o0i73c1lZiUA"\r\n'
                        b"X-Cache: Miss from cloudfront\r\n"
                        b"Via: 1.1 cfd5f3f9049bdb2faa50d6a13e6adb78.cloudfront.net (CloudFront)\r\n"
                        b"X-Amz-Cf-Pop: ARN56-P1\r\n"
                        b"X-Amz-Cf-Id: 0-eFHmiIVp3rpMPZcP8jAo5WLA3f1m-zO5vyG8OyUQGHDqlpyvuUCA==\r\n\r\n"
                        b""" {
                                           "code": 0,
                                           "data": {
                                               "list": []
                                           }
                                       }"""
                    )

                    # response = b'''HTTP/1.1 304 Not Modified
                    # Connection: close
                    # Vary: Accept-Encoding
                    # Date: Mon, 20 Feb 2023 19:17:23 GMT
                    # X-Powered-By: Express
                    # ETag: W/"1d-qTxd3JymBGkwYt6o0i73c1lZiUA"
                    # X-Cache: Miss from cloudfront
                    # Via: 1.1 648da69bb4c2221c403be08a06311d98.cloudfront.net (CloudFront)
                    # X-Amz-Cf-Pop: ARN56-P1
                    # X-Amz-Cf-Id: YSLMFVKf-ZDsrj_ZRkCdupmcUJyeqrh3HdcMryFo8vZIw_mx7frGNQ==\r\n\r\n
                    # {
                    #     "code": 0,
                    #     "data": {
                    #         "list": []
                    #     }
                    # }'''
                    print(
                        "[+] API request: users/<id>/announcements, response sent back to client."
                    )
                    self.socket.send(response)
                    print(response)
                    print("")

                # POST /v1/projects/archero-10b8d/installations HTTP/1.1
                if "v1/projects/archero-10b8d/installations" in decodedData:
                    response = b"""HTTP/2 200 OK
                    Content-Type: application/json; charset=UTF-8
                    Vary: Origin
                    Vary: X-Origin
                    Vary: Referer
                    Date: Mon, 20 Feb 2023 23:29:37 GMT
                    Server: ESF
                    Cache-Control: private
                    Content-Length: 630
                    X-Xss-Protection: 0
                    X-Frame-Options: SAMEORIGIN
                    X-Content-Type-Options: nosniff
                    Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

                    {
                    "name": "projects/828268901162/installations/cxQTspArQ2m_Dl6OsvUfaF",
                    "fid": "cxQTspArQ2m_Dl6OsvUfaF",
                    "refreshToken": "3_AS3qfwJGYt8Al5oYk5R5GrOH5A_iVW4rDi-bTk28SYxQFGJL0jzjUIJ-pG_dYfqsd-2KAZxg03a2rI7o5BGyRYb5PsgDRkbBuBf-qUSSz1TwgJc",
                    "authToken": {
                        "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjE6ODI4MjY4OTAxMTYyOmFuZHJvaWQ6NzliODUyN2ViYzA1M2M2ODhiZTQ1MyIsImV4cCI6MTY3NzU0MDU3NywiZmlkIjoiY3hRVHNwQXJRMm1fRGw2T3N2VWZhRiIsInByb2plY3ROdW1iZXIiOjgyODI2ODkwMTE2Mn0.AB2LPV8wRQIhAOXLJ5-FXc0Vvj7qtFgSLcKLdAthMYPnhvGGpFJ4kibzAiBSd41HdzooTpUzpXK1C0XoY3c13Uw82ZJCDOc4Mhlv2Q",
                        "expiresIn": "604800s"
                    }
                    }"""
                    self.socket.send(response)
                    print(
                        "[+] API request: POST / v1/projects/archero-10b8d/installations"
                    )
                    print("[+] Response: " + response.decode())

                # GET / spi/v2/platforms/android/gmp/1: 828268901162: android: 79b8527ebc053c688be453/settings?instance = 7a16ca6d37f5b937c1687f86d66188f136bb999b & build_version = 1266 & display_version = 4.9.0 & source = 4
                if "/spi/v2/platforms/android/gmp/" in decodedData:
                    response = """HTTP/2 200 OK
                    Content-Type: application/json; charset=utf-8
                    X-Content-Type-Options: nosniff
                    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
                    Pragma: no-cache
                    Expires: Mon, 01 Jan 1990 00:00:00 GMT
                    Date: Mon, 20 Feb 2023 23:29:37 GMT
                    Cross-Origin-Opener-Policy: same-origin-allow-popups
                    Server: ESF
                    X-Xss-Protection: 0
                    X-Frame-Options: SAMEORIGIN
                    Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

                    {"settings_version":3,"cache_duration":86400,"features":{"collect_logged_exceptions":true,"collect_reports":true,"collect_analytics":false,"prompt_enabled":false,"push_enabled":false,"firebase_crashlytics_enabled":false,"collect_anrs":true,"collect_metric_kit":false,"collect_build_ids":false},"app":{"status":"activated","update_required":false,"report_upload_variant":2,"native_report_upload_variant":2},"fabric":{"org_id":"628d0027632d9c0d02e2b976","bundle_id":"com.habby.archero"},"on_demand_upload_rate_per_minute":10.0,"on_demand_backoff_base":1.2,"on_demand_backoff_step_duration_seconds":60,"app_quality":{"sessions_enabled":true,"sampling_rate":1.0,"session_timeout_seconds":1800}}"""
                    self.socket.send(response)
                    print("[+] API request: /sync, responded back to client.")
                    print("[+] Response: " + response.decode())

                # POST /sync HTTP/1.1 (receiver.habby.mobi)
                if "sync" in decodedData:
                    response = b"""HTTP/2 200 OK
                    Date: Mon, 20 Feb 2023 23:05:15 GMT
                    Content-Type: application/json;charset=utf-8
                    Content-Length: 10

                    {"code":0}\r\n\r\n"""
                    self.socket.send(response)
                    print("[+] API request: POST /sync (receiver.habby.mobi)")
                    print("[+] Response: " + response.decode())

                if "config?appid" in decodedData:
                    response = b"""HTTP/2 200 OK
                    Date: Mon, 20 Feb 2023 23:19:00 GMT
                    Content-Type: application/json;charset=utf-8
                    Content-Length: 69

                    {"code":0,"data":{"sync_batch_size":100,"sync_interval":60},"msg":""}\r\n\r\n"""
                    self.socket.send(response)
                    print(
                        "[+] API request: /config?appid=xxxxx, responded back to client."
                    )
                    print("[+] Response: " + response.decode())

                if "session" in decodedData:
                    response = b"""HTTP/1.1 200 OK
                    content-type: application/json; charset=utf-8
                    date: Mon, 20 Feb 2023 23:29:42 GMT
                    content-length: 84
                    strict-transport-security: max-age=31536000; includeSubDomains; preload
                    x-frame-options: SAMEORIGIN
                    x-content-type-options: nosniff
                    x-robots-tag: noindex
                    connection: close

                    {"app_token":"be40xoovkp34","adid":"2e923d233df94bf905a4000937265a52","ask_in":5000}"""
                    self.socket.send(response)
                    print("[+] API request: POST app.adjust.com/session")
                    print("[+] Response: " + response.decode())


def onNewClient(
    clientSocket,
    clientAddress,
    isSSL,
    alpn: str | None = None,
    listen_port: int | None = None,
):
    # Use game protocol handler for port 12020 (game server)
    if listen_port == 12020:
        client = GameProtocolClient(clientSocket, clientAddress)
        Thread(target=client.recv_loop).start()
        print(f"[+]: New GAME client connected on {listen_port}: {clientAddress}")
        return

    # Use HTTP handler for other ports
    client = Client(clientSocket, alpn=alpn, listen_port=listen_port)
    # GameWorldManager.instances.append(client)
    Thread(target=client.recv).start()
    # Thread(target=client.gameLoop).start()
    if listen_port is None:
        print(f"[+]: New HTTP client connected: {clientAddress}")
    else:
        print(f"[+]: New HTTP client connected on {listen_port}: {clientAddress}")


def loop(server_socket, port, isSSL):
    print(f"[+] Server started 0.0.0.0:{port}. Waiting for connections...")
    context: ssl.SSLContext | None = None
    if isSSL or os.environ.get("ARCHERO_PLAIN_DETECT_TLS", "1") == "1":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2", "http/1.1"])
        context.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))

    def handle_client(client_socket, client_address):
        nonlocal context
        alpn = None
        if isSSL and context is not None:
            try:
                if os.environ.get("ARCHERO_LOG_PEEK") == "1":
                    try:
                        client_socket.settimeout(1.0)
                        peek = client_socket.recv(32, socket.MSG_PEEK)
                        if peek:
                            ascii_preview = peek.decode("ascii", errors="replace")
                            print(
                                f"[+] Pre-TLS peek from {client_address}: hex={peek.hex()} ascii={ascii_preview!r}"
                            )
                        else:
                            print(f"[+] Pre-TLS peek from {client_address}: <empty>")
                    except Exception as e:
                        print(f"[-] Pre-TLS peek failed from {client_address}: {e}")

                    try:
                        client_socket.settimeout(1.0)
                        peek_full = client_socket.recv(2048, socket.MSG_PEEK)
                        sni = _try_parse_tls_sni(peek_full)
                        if sni:
                            print(f"[+] TLS SNI from {client_address}: {sni}")
                    except Exception:
                        pass

                # Prevent clients from stalling the accept loop by never completing TLS.
                client_socket.settimeout(2.0)
                client_socket = context.wrap_socket(client_socket, server_side=True)
                client_socket.settimeout(None)
                alpn = client_socket.selected_alpn_protocol()
                print(f"[+] SSL handshake successful: {client_address}")
                if alpn:
                    print(f"[+] ALPN selected: {alpn}")
            except ssl.SSLError as e:
                print(f"[-] SSL handshake failed from {client_address}: {e}")
                client_socket.close()
                return
            except OSError as e:
                print(f"[-] TLS socket error from {client_address}: {e}")
                client_socket.close()
                return
        elif (
            (not isSSL)
            and context is not None
            and os.environ.get("ARCHERO_PLAIN_DETECT_TLS", "1") == "1"
        ):
            # Opportunistically upgrade plain ports (e.g. 12020) if the client is speaking TLS.
            try:
                client_socket.settimeout(1.0)
                peek = client_socket.recv(5, socket.MSG_PEEK)
                if len(peek) >= 3 and peek[0] == 0x16 and peek[1] == 0x03:
                    if os.environ.get("ARCHERO_LOG_PEEK") == "1":
                        print(
                            f"[+] Detected TLS on plain port {port} from {client_address}: hex={peek.hex()}"
                        )
                    client_socket.settimeout(2.0)
                    client_socket = context.wrap_socket(client_socket, server_side=True)
                    client_socket.settimeout(None)
                    alpn = client_socket.selected_alpn_protocol()
                    print(
                        f"[+] TLS handshake successful (plain:{port}): {client_address}"
                    )
                    if alpn:
                        print(f"[+] ALPN selected (plain:{port}): {alpn}")
            except Exception:
                # keep as plain
                try:
                    client_socket.settimeout(None)
                except Exception:
                    pass

        onNewClient(client_socket, client_address, isSSL, alpn=alpn, listen_port=port)

    while True:
        (client_socket, client_address) = server_socket.accept()
        Thread(target=handle_client, args=(client_socket, client_address)).start()


def main():
    # Optional kill-switch (disabled by default).
    # Enable with: ARCHERO_PKILL_PYTHON=1 sudo uv run server
    if os.environ.get("ARCHERO_PKILL_PYTHON") == "1":
        subprocess.run(["pkill", "python"], check=False)

    os.environ["PYTHONASYNCIODEBUG"] = "1"

    generate_cert()

    sslPort = int(os.environ.get("ARCHERO_SSL_PORT", "443"))
    sslSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sslSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sslSocket.bind(("0.0.0.0", sslPort))
    sslSocket.listen(10)
    Thread(
        target=loop,
        args=(
            sslSocket,
            sslPort,
            True,
        ),
    ).start()

    plain_ports_raw = os.environ.get("ARCHERO_PLAIN_PORTS", "12020")
    plain_ports: list[int] = []
    for part in [p.strip() for p in plain_ports_raw.split(",") if p.strip()]:
        try:
            plain_ports.append(int(part))
        except ValueError:
            continue

    for port in plain_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(10)
        except OSError as e:
            print(f"[-] Failed to bind plain port {port}: {e}")
            continue

        Thread(target=loop, args=(s, port, False)).start()


if __name__ == "__main__":
    main()
