"""
Packet Handler for 12020 TCP Protocol

Handles received packets and generates responses based on message type.
For unhandled packets, returns a generic success response to keep the client happy.

Message Type Conventions (discovered from game analysis):
- Request packets are usually odd numbers
- Response packets are request + 1
"""

import struct
import time
from typing import Optional, Tuple

from .binary import BinaryReader, BinaryWriter
from .common import (
    CCommonRespMsg,
    write_c_common_resp_msg,
)
from .login import (
    read_c_user_login_packet,
    write_c_resp_user_login_packet,
    create_default_login_response,
)
from .misc import (
    CRespGuildUserLogin,
    write_c_resp_guild_user_login,
)
from .daily import (
    CRespDailyTaskInfo,
    write_c_resp_daily_task_info,
    CRespWeeklyTaskInfo,
    write_c_resp_weekly_task_info,
)
from .battlepass import (
    write_c_resp_battlepass_conf,
    create_default_battlepass_conf,
)
from .activities import (
    write_c_resp_activity_common,
    create_default_activity_response,
)


# =============================================================================
# MESSAGE TYPE CONSTANTS (from game analysis)
# =============================================================================

# Core auth/login
MSG_TYPE_USER_LOGIN = 0x0001
MSG_TYPE_USER_LOGIN_RESP = 0x0002
MSG_TYPE_HEARTBEAT = 0x0003
MSG_TYPE_HEARTBEAT_RESP = 0x0004
MSG_TYPE_SYNC_USER = 0x0005
MSG_TYPE_SYNC_USER_RESP = 0x0006

# Guild
MSG_TYPE_GUILD_USER_LOGIN = 0x0010
MSG_TYPE_GUILD_USER_LOGIN_RESP = 0x0011
MSG_TYPE_GUILD_TASK_INFO = 0x0012
MSG_TYPE_GUILD_TASK_INFO_RESP = 0x0013

# Daily/Weekly tasks
MSG_TYPE_DAILY_TASK_INFO = 0x0020
MSG_TYPE_DAILY_TASK_INFO_RESP = 0x0021
MSG_TYPE_WEEKLY_TASK_INFO = 0x0022
MSG_TYPE_WEEKLY_TASK_INFO_RESP = 0x0023

# Ads
MSG_TYPE_GAME_AD = 0x0030
MSG_TYPE_GAME_AD_RESP = 0x0031

# Battlepass
MSG_TYPE_BATTLEPASS_CONF = 0x014B
MSG_TYPE_BATTLEPASS_CONF_RESP = 0x014C

# Activity
MSG_TYPE_ACTIVITY_COMMON = 0x0150
MSG_TYPE_ACTIVITY_COMMON_RESP = 0x0151


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
    print(f"[Handler] << {packet_name} (0x{msg_type:04X}), {len(payload)}B")

    # === P0: Core Auth ===
    if msg_type == MSG_TYPE_USER_LOGIN:
        return handle_login(payload)
    
    if msg_type == MSG_TYPE_HEARTBEAT:
        return handle_heartbeat(payload)
    
    if msg_type == MSG_TYPE_SYNC_USER:
        return handle_sync_user(payload)

    # === P1: Guild ===
    if msg_type == MSG_TYPE_GUILD_USER_LOGIN:
        return handle_guild_user_login(payload)

    # === P2: Daily/Weekly ===
    if msg_type == MSG_TYPE_DAILY_TASK_INFO:
        return handle_daily_task_info(payload)
    
    if msg_type == MSG_TYPE_WEEKLY_TASK_INFO:
        return handle_weekly_task_info(payload)

    # === P2: Battlepass ===
    if msg_type == MSG_TYPE_BATTLEPASS_CONF:
        return handle_battlepass_conf(payload)

    # === P2: Activity ===
    if msg_type == MSG_TYPE_ACTIVITY_COMMON:
        return handle_activity_common(payload)

    # For all other packets, send a generic success response
    # Response msg_type is typically request_type + 1 for Req/Resp pairs
    resp_type = msg_type + 1
    return create_packet(resp_type, create_generic_success_response())


# =============================================================================
# HANDLER IMPLEMENTATIONS
# =============================================================================


def handle_login(payload: bytes) -> bytes:
    """Handle login request and return full login response."""
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
    writer.write_uint64(int(time.time()))
    return create_packet(MSG_TYPE_HEARTBEAT_RESP, writer.to_bytes())


def handle_sync_user(payload: bytes) -> bytes:
    """Handle user sync - returns minimal success."""
    writer = BinaryWriter()
    write_c_common_resp_msg(writer, CCommonRespMsg(m_unStatusCode=0, m_strInfo=""))
    return create_packet(MSG_TYPE_SYNC_USER_RESP, writer.to_bytes())


def handle_guild_user_login(payload: bytes) -> bytes:
    """Handle guild login - returns no guild membership."""
    writer = BinaryWriter()
    resp = CRespGuildUserLogin(
        m_stRetMsg=CCommonRespMsg(m_unStatusCode=0, m_strInfo=""),
        m_nGuildId=0,  # No guild
        m_strGuildName="",
        m_nGuildLevel=0,
    )
    write_c_resp_guild_user_login(writer, resp)
    return create_packet(MSG_TYPE_GUILD_USER_LOGIN_RESP, writer.to_bytes())


def handle_daily_task_info(payload: bytes) -> bytes:
    """Handle daily task info request."""
    writer = BinaryWriter()
    resp = CRespDailyTaskInfo(
        m_stRetMsg=CCommonRespMsg(m_unStatusCode=0, m_strInfo=""),
        m_nDailyRewardBits=0,
        m_nDailyRewardClaimed=0,
        m_nDailyPoint=0,
        m_vecTasks=[],
        m_vecExtraRewards=[],
    )
    write_c_resp_daily_task_info(writer, resp)
    return create_packet(MSG_TYPE_DAILY_TASK_INFO_RESP, writer.to_bytes())


def handle_weekly_task_info(payload: bytes) -> bytes:
    """Handle weekly task info request."""
    writer = BinaryWriter()
    resp = CRespWeeklyTaskInfo(
        m_stRetMsg=CCommonRespMsg(m_unStatusCode=0, m_strInfo=""),
        m_nWeeklyRewardBits=0,
        m_nWeeklyPoint=0,
        m_vecTasks=[],
    )
    write_c_resp_weekly_task_info(writer, resp)
    return create_packet(MSG_TYPE_WEEKLY_TASK_INFO_RESP, writer.to_bytes())


def handle_battlepass_conf(payload: bytes) -> bytes:
    """Handle battlepass config request."""
    writer = BinaryWriter()
    resp = create_default_battlepass_conf()
    write_c_resp_battlepass_conf(writer, resp)
    return create_packet(MSG_TYPE_BATTLEPASS_CONF_RESP, writer.to_bytes())


def handle_activity_common(payload: bytes) -> bytes:
    """Handle activity common request."""
    writer = BinaryWriter()
    resp = create_default_activity_response()
    write_c_resp_activity_common(writer, resp)
    return create_packet(MSG_TYPE_ACTIVITY_COMMON_RESP, writer.to_bytes())


# =============================================================================
# PACKET NAMES FOR LOGGING
# =============================================================================

PACKET_NAMES = {
    # Core auth
    0x0001: "CUserLoginPacket",
    0x0002: "CRespUserLoginPacket",
    0x0003: "CHeartBeatPacket",
    0x0004: "CRespHeartBeatPacket",
    0x0005: "CSyncUserPacket",
    0x0006: "CRespSyncUserPacket",
    
    # Guild
    0x0010: "CGuildUserLogin",
    0x0011: "CRespGuildUserLogin",
    0x0012: "CGuildTaskInfo",
    0x0013: "CRespGuildTaskInfo",
    
    # Daily/Weekly
    0x0020: "CDailyTaskInfo",
    0x0021: "CRespDailyTaskInfo",
    0x0022: "CWeeklyTaskInfo",
    0x0023: "CRespWeeklyTaskInfo",
    
    # Ads
    0x0030: "CGameAd",
    0x0031: "CRespGameAd",
    
    # Battlepass
    0x014B: "CReqBattlepassConf",
    0x014C: "CRespBattlepassConf",
    
    # Activity  
    0x0150: "CReqActivityCommon",
    0x0151: "CRespActivityCommon",
}


def get_packet_name(msg_type: int) -> str:
    """Get human-readable packet name."""
    return PACKET_NAMES.get(msg_type, f"Packet_0x{msg_type:04X}")
