"""Login handler for Archero game server.

Processes CUserLoginPacket and returns player profile data.
"""

from __future__ import annotations

from ..protocol import (
    Packet,
    MessageType,
    UserLoginRequest,
    UserLoginResponse,
    BinaryReader,
)


def handle_login(packet: Packet) -> Packet | None:
    """Handle a login packet and return response.
    
    Args:
        packet: The received login packet
        
    Returns:
        Response packet with player profile data, or None if error
    """
    print(f"[LoginHandler] Received login packet, payload length: {len(packet.payload)}")
    print(f"[LoginHandler] Payload hex: {packet.payload[:64].hex()}" + 
          ("..." if len(packet.payload) > 64 else ""))
    
    # Parse the login request
    request = UserLoginRequest.from_payload(packet.payload)
    print(f"[LoginHandler] Parsed request: platform={request.platform}, "
          f"device_id={request.device_id[:20] if request.device_id else 'N/A'}..., "
          f"user_id={request.user_id}")
    
    # Create mock profile response
    # In a real implementation, this would query a database
    response = UserLoginResponse(
        result_code=0,  # Success
        player_id=170722380,
        player_name="Player 170722380",
        coins=199,
        gems=120,
        level=1,
        chapter=1,
        exp=100,
        talent=0,
    )
    
    response_packet = response.to_packet()
    print(f"[LoginHandler] Sending login response for player {response.player_name}")
    print(f"[LoginHandler] Response payload hex: {response_packet.payload[:64].hex()}")
    
    return response_packet


def handle_packet(packet: Packet) -> Packet | None:
    """Route packet to appropriate handler based on message type.
    
    Args:
        packet: The received packet
        
    Returns:
        Response packet, or None if no response needed
    """
    print(f"[PacketHandler] Received msg_type=0x{packet.msg_type:04x}, "
          f"payload_len={len(packet.payload)}")
    
    if packet.msg_type == MessageType.USER_LOGIN:
        return handle_login(packet)
    elif packet.msg_type == MessageType.HEARTBEAT:
        # Echo heartbeat back
        return Packet(msg_type=MessageType.HEARTBEAT, payload=b"")
    else:
        print(f"[PacketHandler] Unknown message type: 0x{packet.msg_type:04x}")
        # Log payload for analysis
        print(f"[PacketHandler] Unknown payload: {packet.payload.hex()}")
        return None
