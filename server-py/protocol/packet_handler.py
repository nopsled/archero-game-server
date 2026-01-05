"""
Packet Handler for 12020 TCP Protocol

Handles received packets and generates responses based on message type.
For unhandled packets, returns a generic success response to keep the client happy.
"""

import struct
import time
from typing import Optional, Tuple

from .binary import BinaryReader, BinaryWriter
from .login import (
    read_c_user_login_packet,
    write_c_resp_user_login_packet,
    create_default_login_response,
)
from .common import write_c_common_resp_msg, CCommonRespMsg


# Message type constants
MSG_TYPE_USER_LOGIN = 0x0001
MSG_TYPE_USER_LOGIN_RESP = 0x0002
MSG_TYPE_HEARTBEAT = 0x0003
MSG_TYPE_HEARTBEAT_RESP = 0x0004

# Packet header: 4 bytes total length + 2 bytes msg_type
HEADER_SIZE = 6


def parse_packet(data: bytes) -> Tuple[int, bytes]:
    """Parse a packet from raw bytes. Returns (msg_type, payload_bytes)"""
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short: {len(data)} < {HEADER_SIZE}")

    total_len = struct.unpack("<I", data[0:4])[0]
    msg_type = struct.unpack("<H", data[4:6])[0]
    payload = data[6:]

    return msg_type, payload


def create_packet(msg_type: int, payload: bytes) -> bytes:
    """Create a packet with header. Returns complete packet bytes."""
    total_len = HEADER_SIZE + len(payload)
    header = struct.pack("<I", total_len) + struct.pack("<H", msg_type)
    return header + payload


def create_generic_success_response() -> bytes:
    """Create a minimal success response payload."""
    writer = BinaryWriter()
    write_c_common_resp_msg(writer, CCommonRespMsg(m_unStatusCode=0, m_strInfo=""))
    return writer.to_bytes()


def handle_packet(msg_type: int, payload: bytes) -> Optional[bytes]:
    """Handle a packet and return response bytes if applicable."""
    packet_name = get_packet_name(msg_type)
    print(f"[PacketHandler] << {packet_name} (0x{msg_type:04X}), {len(payload)}B")

    # Login - most important packet
    if msg_type == MSG_TYPE_USER_LOGIN:
        return handle_login(payload)

    # Heartbeat - keep connection alive
    if msg_type == MSG_TYPE_HEARTBEAT:
        return handle_heartbeat(payload)

    # For all other packets, send a generic success response
    # Response msg_type is typically request_type + 1 for Req/Resp pairs
    resp_type = msg_type + 1
    return create_packet(resp_type, create_generic_success_response())


def handle_login(payload: bytes) -> bytes:
    """Handle login request and return login response."""
    reader = BinaryReader(payload)
    login_req = read_c_user_login_packet(reader)

    print(f"[Login] ✓ TransID={login_req.m_nTransID}, Platform={login_req.m_strPlatform}")

    # Create response with player data
    login_resp = create_default_login_response(login_req.m_nTransID)

    # Serialize response
    writer = BinaryWriter()
    write_c_resp_user_login_packet(writer, login_resp)

    return create_packet(MSG_TYPE_USER_LOGIN_RESP, writer.to_bytes())


def handle_heartbeat(payload: bytes) -> bytes:
    """Handle heartbeat and return heartbeat response with server time."""
    writer = BinaryWriter()
    # Heartbeat response contains server time
    writer.write_uint64(int(time.time()))
    return create_packet(MSG_TYPE_HEARTBEAT_RESP, writer.to_bytes())


# Packet type names for logging
PACKET_NAMES = {
    0x0001: "CUserLoginPacket",
    0x0002: "CRespUserLoginPacket",
    0x0003: "CHeartBeatPacket",
    0x0004: "CRespHeartBeatPacket",
    0x0005: "CSyncUserPacket",
    0x0006: "CRespSyncUserPacket",
    # Activities and misc - from captured traffic
    0x000A: "CQueryIAPCount",
    0x000B: "CRespQueryIAPCount",
    0x0010: "CGuildUserLogin",
    0x0011: "CRespGuildUserLogin",
    0x0012: "CGuildTaskInfo",
    0x0013: "CRespGuildTaskInfo",
    0x0020: "CDailyTaskInfo",
    0x0021: "CRespDailyTaskInfo",
    0x0022: "CWeeklyTaskInfo",
    0x0023: "CRespWeeklyTaskInfo",
    0x0030: "CGameAd",
    0x0031: "CRespGameAd",
}


def get_packet_name(msg_type: int) -> str:
    """Get human-readable packet name."""
    return PACKET_NAMES.get(msg_type, f"Packet_0x{msg_type:04X}")
