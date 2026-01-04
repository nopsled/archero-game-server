"""
Packet Handler for 12020 TCP Protocol

Handles received packets and generates responses based on message type.
"""

import struct
from typing import Optional, Tuple, Callable
from io import BytesIO

from .binary import BinaryReader, BinaryWriter
from .login import (
    read_c_user_login_packet,
    write_c_resp_user_login_packet,
    create_default_login_response,
)
from . import MSG_TYPE_USER_LOGIN, MSG_TYPE_USER_LOGIN_RESP


# Packet header: 4 bytes total length + 2 bytes msg_type
HEADER_SIZE = 6


def parse_packet(data: bytes) -> Tuple[int, bytes]:
    """
    Parse a packet from raw bytes.

    Returns (msg_type, payload_bytes)
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short: {len(data)} < {HEADER_SIZE}")

    # Read header: 4 bytes length (little-endian), 2 bytes msg_type (little-endian)
    total_len = struct.unpack("<I", data[0:4])[0]
    msg_type = struct.unpack("<H", data[4:6])[0]

    payload = data[6:]

    return msg_type, payload


def create_packet(msg_type: int, payload: bytes) -> bytes:
    """
    Create a packet with header.

    Returns complete packet bytes.
    """
    total_len = HEADER_SIZE + len(payload)
    header = struct.pack("<I", total_len) + struct.pack("<H", msg_type)
    return header + payload


def handle_packet(msg_type: int, payload: bytes) -> Optional[bytes]:
    """
    Handle a packet and return response bytes if applicable.

    Returns response packet bytes or None if no response needed.
    """
    print(f"[PacketHandler] Handling msgType=0x{msg_type:04X}")

    if msg_type == MSG_TYPE_USER_LOGIN:
        return handle_login(payload)

    # Unknown packet - log and ignore
    print(
        f"[PacketHandler] Unknown msgType=0x{msg_type:04X}, payload={len(payload)} bytes"
    )
    return None


def handle_login(payload: bytes) -> bytes:
    """Handle login request and return login response."""
    reader = BinaryReader(payload)
    login_req = read_c_user_login_packet(reader)

    print(f"[Login] TransID={login_req.m_nTransID}, Platform={login_req.m_strPlatform}")

    # Create response
    login_resp = create_default_login_response(login_req.m_nTransID)

    # Serialize response
    writer = BinaryWriter()
    write_c_resp_user_login_packet(writer, login_resp)

    return create_packet(MSG_TYPE_USER_LOGIN_RESP, writer.to_bytes())


# Packet type names for logging
PACKET_NAMES = {
    0x0001: "CUserLogin",
    0x0002: "CRespUserLogin",
    # Add more as discovered
    0x014B: "Unknown_0x014b",
    0x014C: "Unknown_0x014c",
    0x014E: "Unknown_0x014e",
}


def get_packet_name(msg_type: int) -> str:
    """Get human-readable packet name."""
    return PACKET_NAMES.get(msg_type, f"Unknown_0x{msg_type:04X}")
