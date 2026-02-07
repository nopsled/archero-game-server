## Packet wrapper class for game protocol
##
## Handles the framing of game protocol packets:
## - 4-byte little-endian length prefix
## - 2-byte little-endian message type
## - Variable-length payload

import std/endians

type
  Packet* = object
    msgType*: uint16
    payload*: seq[byte]

proc fromBytes*(T: typedesc[Packet], data: seq[byte]): tuple[packet: Packet, remaining: seq[byte]] =
  ## Parse a packet from raw bytes.
  ## Returns (packet, remaining_bytes).
  ##
  ## Packet format:
  ## - 4 bytes: total length (little-endian) - includes msg_type + payload
  ## - 2 bytes: message type (little-endian)
  ## - N bytes: payload
  if data.len < 4:
    raise newException(ValueError, "Not enough data for length prefix: " & $data.len & " < 4")

  var totalLen: uint32
  littleEndian32(addr totalLen, unsafeAddr data[0])

  if data.len < 4 + totalLen.int:
    raise newException(ValueError, "Incomplete packet: have " & $data.len & ", need " & $(4 + totalLen.int))

  if totalLen < 2:
    raise newException(ValueError, "Packet too small: " & $totalLen & " < 2")

  var msgType: uint16
  littleEndian16(addr msgType, unsafeAddr data[4])

  let payload = data[6 ..< 4 + totalLen.int]
  let remaining = data[4 + totalLen.int .. ^1]

  result = (Packet(msgType: msgType, payload: payload), remaining)

proc toBytes*(p: Packet): seq[byte] =
  ## Serialize packet to bytes.
  ##
  ## Packet format:
  ## - 4 bytes: total length (little-endian)
  ## - 2 bytes: message type (little-endian)
  ## - N bytes: payload
  let totalLen = (2 + p.payload.len).uint32
  result = newSeq[byte](4 + 2 + p.payload.len)

  var leLen: uint32
  littleEndian32(addr leLen, unsafeAddr totalLen)
  copyMem(addr result[0], addr leLen, 4)

  var leMsgType: uint16
  littleEndian16(addr leMsgType, unsafeAddr p.msgType)
  copyMem(addr result[4], addr leMsgType, 2)

  if p.payload.len > 0:
    copyMem(addr result[6], unsafeAddr p.payload[0], p.payload.len)
