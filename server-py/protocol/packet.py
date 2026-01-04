"""
Packet wrapper class for game protocol

Handles the framing of game protocol packets:
- 4-byte little-endian length prefix
- 2-byte little-endian message type
- Variable-length payload
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass
class Packet:
    """Game protocol packet with framing."""

    msg_type: int  # UInt16
    payload: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple["Packet", bytes]:
        """Parse a packet from raw bytes.

        Returns (packet, remaining_bytes).

        Packet format:
        - 4 bytes: total length (little-endian) - includes msg_type + payload
        - 2 bytes: message type (little-endian)
        - N bytes: payload
        """
        if len(data) < 4:
            raise ValueError(f"Not enough data for length prefix: {len(data)} < 4")

        total_len = int.from_bytes(data[:4], "little")

        if len(data) < 4 + total_len:
            raise ValueError(
                f"Incomplete packet: have {len(data)}, need {4 + total_len}"
            )

        if total_len < 2:
            raise ValueError(f"Packet too small: {total_len} < 2")

        msg_type = int.from_bytes(data[4:6], "little")
        payload = data[6 : 4 + total_len]
        remaining = data[4 + total_len :]

        return cls(msg_type=msg_type, payload=payload), remaining

    def to_bytes(self) -> bytes:
        """Serialize packet to bytes.

        Packet format:
        - 4 bytes: total length (little-endian)
        - 2 bytes: message type (little-endian)
        - N bytes: payload
        """
        total_len = 2 + len(self.payload)  # msg_type + payload
        return (
            total_len.to_bytes(4, "little")
            + self.msg_type.to_bytes(2, "little")
            + self.payload
        )
