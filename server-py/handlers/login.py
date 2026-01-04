"""Login handler for Archero game server.

Processes incoming packets on port 12020.
"""

from __future__ import annotations

from protocol import Packet, MSG_TYPE_USER_LOGIN


def handle_packet(packet: Packet) -> Packet | None:
    """Route packet to appropriate handler based on message type.

    Args:
        packet: The received packet

    Returns:
        Response packet, or None if no response needed
    """
    print(
        f"[PacketHandler] Received msg_type=0x{packet.msg_type:04x}, "
        f"payload_len={len(packet.payload)}"
    )
    print(
        f"[PacketHandler] Payload hex: {packet.payload[:128].hex()}"
        + ("..." if len(packet.payload) > 128 else "")
    )

    if packet.msg_type == MSG_TYPE_USER_LOGIN:
        print("[PacketHandler] Login packet detected!")
        # TODO: Parse and respond to login
        # For now, just log it
        return None
    else:
        print(f"[PacketHandler] Unknown message type: 0x{packet.msg_type:04x}")
        return None
