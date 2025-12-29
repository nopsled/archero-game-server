"""Archero game protocol packet handling.

This module handles parsing and serializing binary packets for the game's
TCP protocol on port 12020.

Packet Structure (assumed based on game analysis):
- 4 bytes: packet length (little-endian uint32)
- 2 bytes: message type (little-endian uint16)
- N bytes: payload (serialized with CustomBinaryWriter format)
"""

from __future__ import annotations

import struct
import io
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class MessageType(IntEnum):
    """Known message types from game protocol."""

    USER_LOGIN = 0x0001  # CUserLoginPacket
    USER_LOGIN_RESPONSE = 0x0002  # SUserLoginResponse (assumed)
    HEARTBEAT = 0x0003  # Keep-alive
    SYNC = 0x0010  # State sync
    # Add more as discovered


@dataclass
class Packet:
    """Base packet structure."""

    msg_type: int
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes with length prefix."""
        # Length = msg_type (2) + payload
        total_len = 2 + len(self.payload)
        return (
            struct.pack("<I", total_len)
            + struct.pack("<H", self.msg_type)
            + self.payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["Packet", bytes]:
        """Parse packet from bytes, return (packet, remaining_bytes)."""
        if len(data) < 4:
            raise ValueError("Insufficient data for packet header")

        length = struct.unpack("<I", data[:4])[0]
        if len(data) < 4 + length:
            raise ValueError(
                f"Incomplete packet: expected {length} bytes, got {len(data) - 4}"
            )

        msg_type = struct.unpack("<H", data[4:6])[0]
        payload = data[6 : 4 + length]
        remaining = data[4 + length :]

        return cls(msg_type=msg_type, payload=payload), remaining


class BinaryReader:
    """Read binary data in CustomBinaryWriter format."""

    def __init__(self, data: bytes):
        self.stream = io.BytesIO(data)

    def read_byte(self) -> int:
        return struct.unpack("<B", self.stream.read(1))[0]

    def read_int16(self) -> int:
        return struct.unpack("<h", self.stream.read(2))[0]

    def read_uint16(self) -> int:
        return struct.unpack("<H", self.stream.read(2))[0]

    def read_int32(self) -> int:
        return struct.unpack("<i", self.stream.read(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.stream.read(4))[0]

    def read_int64(self) -> int:
        return struct.unpack("<q", self.stream.read(8))[0]

    def read_uint64(self) -> int:
        return struct.unpack("<Q", self.stream.read(8))[0]

    def read_float(self) -> float:
        return struct.unpack("<f", self.stream.read(4))[0]

    def read_string(self) -> str:
        """Read length-prefixed UTF-8 string."""
        length = self.read_uint16()
        return self.stream.read(length).decode("utf-8", errors="replace")

    def read_bytes(self, count: int) -> bytes:
        return self.stream.read(count)

    def remaining(self) -> bytes:
        return self.stream.read()

    def position(self) -> int:
        return self.stream.tell()


class BinaryWriter:
    """Write binary data in CustomBinaryWriter format."""

    def __init__(self):
        self.stream = io.BytesIO()

    def write_byte(self, value: int) -> None:
        self.stream.write(struct.pack("<B", value & 0xFF))

    def write_int16(self, value: int) -> None:
        self.stream.write(struct.pack("<h", value))

    def write_uint16(self, value: int) -> None:
        self.stream.write(struct.pack("<H", value))

    def write_int32(self, value: int) -> None:
        self.stream.write(struct.pack("<i", value))

    def write_uint32(self, value: int) -> None:
        self.stream.write(struct.pack("<I", value))

    def write_int64(self, value: int) -> None:
        self.stream.write(struct.pack("<q", value))

    def write_uint64(self, value: int) -> None:
        self.stream.write(struct.pack("<Q", value))

    def write_float(self, value: float) -> None:
        self.stream.write(struct.pack("<f", value))

    def write_string(self, value: str) -> None:
        """Write length-prefixed UTF-8 string."""
        encoded = value.encode("utf-8")
        self.write_uint16(len(encoded))
        self.stream.write(encoded)

    def write_bytes(self, data: bytes) -> None:
        self.stream.write(data)

    def to_bytes(self) -> bytes:
        return self.stream.getvalue()


@dataclass
class UserLoginRequest:
    """Parsed CUserLoginPacket data.

    Fields are estimates based on game analysis.
    Will need refinement once actual packet capture is available.
    """

    device_id: str = ""
    platform: int = 0  # 1=iOS, 2=Android
    version: str = ""
    language: str = ""
    user_id: int = 0
    token: str = ""
    raw_payload: bytes = b""  # Keep raw for debugging

    @classmethod
    def from_payload(cls, payload: bytes) -> "UserLoginRequest":
        """Try to parse login request from payload."""
        request = cls(raw_payload=payload)

        if len(payload) < 4:
            return request

        try:
            reader = BinaryReader(payload)
            # Attempt to decode - structure is speculative
            request.platform = reader.read_int32()
            request.version = reader.read_string()
            request.device_id = reader.read_string()
            request.language = reader.read_string()
            request.user_id = reader.read_int64()
            request.token = reader.read_string()
        except Exception as e:
            print(f"[Protocol] Failed to parse login request: {e}")
            print(f"[Protocol] Raw payload hex: {payload.hex()}")

        return request


@dataclass
class UserLoginResponse:
    """Response to login request with player profile data."""

    result_code: int = 0  # 0 = success
    player_id: int = 170722380
    player_name: str = "Player 170722380"
    coins: int = 199
    gems: int = 120
    level: int = 1
    chapter: int = 1
    exp: int = 100
    talent: int = 0
    server_time: int = 0

    def to_payload(self) -> bytes:
        """Serialize login response to payload bytes."""
        writer = BinaryWriter()
        writer.write_int32(self.result_code)
        writer.write_int64(self.player_id)
        writer.write_string(self.player_name)
        writer.write_int32(self.coins)
        writer.write_int32(self.gems)
        writer.write_int32(self.level)
        writer.write_int32(self.chapter)
        writer.write_int32(self.exp)
        writer.write_int32(self.talent)
        writer.write_int64(self.server_time or int(__import__("time").time()))
        return writer.to_bytes()

    def to_packet(self) -> Packet:
        """Create response packet."""
        return Packet(
            msg_type=MessageType.USER_LOGIN_RESPONSE, payload=self.to_payload()
        )
