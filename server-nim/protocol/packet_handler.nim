## Packet Handler for 12020 TCP Protocol
##
## Handles received packets and generates responses based on message type.
## For unhandled packets, returns a generic success response to keep the client happy.
##
## Message Type Conventions (discovered from game analysis):
## - Request packets are usually odd numbers
## - Response packets are request + 1

import std/[tables, strformat, times, endians]
import binary, common, login, misc, daily, battlepass, activities

# =============================================================================
# MESSAGE TYPE CONSTANTS (from game analysis)
# =============================================================================

const
  # Core auth/login
  MSG_TYPE_USER_LOGIN* = 0x0001'u16
  MSG_TYPE_USER_LOGIN_RESP* = 0x0002'u16
  MSG_TYPE_HEARTBEAT* = 0x0003'u16
  MSG_TYPE_HEARTBEAT_RESP* = 0x0004'u16
  MSG_TYPE_SYNC_USER* = 0x0005'u16
  MSG_TYPE_SYNC_USER_RESP* = 0x0006'u16

  # Guild
  MSG_TYPE_GUILD_USER_LOGIN* = 0x0010'u16
  MSG_TYPE_GUILD_USER_LOGIN_RESP* = 0x0011'u16
  MSG_TYPE_GUILD_TASK_INFO* = 0x0012'u16
  MSG_TYPE_GUILD_TASK_INFO_RESP* = 0x0013'u16

  # Daily/Weekly tasks
  MSG_TYPE_DAILY_TASK_INFO* = 0x0020'u16
  MSG_TYPE_DAILY_TASK_INFO_RESP* = 0x0021'u16
  MSG_TYPE_WEEKLY_TASK_INFO* = 0x0022'u16
  MSG_TYPE_WEEKLY_TASK_INFO_RESP* = 0x0023'u16

  # Ads
  MSG_TYPE_GAME_AD* = 0x0030'u16
  MSG_TYPE_GAME_AD_RESP* = 0x0031'u16

  # Battlepass
  MSG_TYPE_BATTLEPASS_CONF* = 0x014B'u16
  MSG_TYPE_BATTLEPASS_CONF_RESP* = 0x014C'u16

  # Activity
  MSG_TYPE_ACTIVITY_COMMON* = 0x0150'u16
  MSG_TYPE_ACTIVITY_COMMON_RESP* = 0x0151'u16

  # Packet header: 4 bytes total length + 2 bytes msg_type
  HEADER_SIZE* = 6


# =============================================================================
# PACKET NAMES FOR LOGGING
# =============================================================================

let PACKET_NAMES = {
  0x0001'u16: "CUserLoginPacket",
  0x0002'u16: "CRespUserLoginPacket",
  0x0003'u16: "CHeartBeatPacket",
  0x0004'u16: "CRespHeartBeatPacket",
  0x0005'u16: "CSyncUserPacket",
  0x0006'u16: "CRespSyncUserPacket",
  0x0010'u16: "CGuildUserLogin",
  0x0011'u16: "CRespGuildUserLogin",
  0x0012'u16: "CGuildTaskInfo",
  0x0013'u16: "CRespGuildTaskInfo",
  0x0020'u16: "CDailyTaskInfo",
  0x0021'u16: "CRespDailyTaskInfo",
  0x0022'u16: "CWeeklyTaskInfo",
  0x0023'u16: "CRespWeeklyTaskInfo",
  0x0030'u16: "CGameAd",
  0x0031'u16: "CRespGameAd",
  0x014B'u16: "CReqBattlepassConf",
  0x014C'u16: "CRespBattlepassConf",
  0x0150'u16: "CReqActivityCommon",
  0x0151'u16: "CRespActivityCommon",
}.toTable

proc getPacketName*(msgType: uint16): string =
  if msgType in PACKET_NAMES:
    return PACKET_NAMES[msgType]
  return fmt"Packet_0x{msgType:04X}"


# =============================================================================
# PACKET CREATION
# =============================================================================

proc parsePacket*(data: seq[byte]): tuple[msgType: uint16, payload: seq[byte]] =
  ## Parse a packet from raw bytes. Returns (msg_type, payload_bytes)
  if data.len < HEADER_SIZE:
    raise newException(ValueError, fmt"Data too short: {data.len} < {HEADER_SIZE}")

  var totalLen: uint32
  littleEndian32(addr totalLen, unsafeAddr data[0])
  var msgType: uint16
  littleEndian16(addr msgType, unsafeAddr data[4])
  let payload = data[6 .. ^1]
  result = (msgType, payload)

proc createPacket*(msgType: uint16, payload: seq[byte]): seq[byte] =
  ## Create a packet with header. Returns complete packet bytes.
  let totalLen = (2 + payload.len).uint32
  result = newSeq[byte](4 + 2 + payload.len)
  var leLen: uint32
  littleEndian32(addr leLen, unsafeAddr totalLen)
  copyMem(addr result[0], addr leLen, 4)
  var leMsgType: uint16
  littleEndian16(addr leMsgType, unsafeAddr msgType)
  copyMem(addr result[4], addr leMsgType, 2)
  if payload.len > 0:
    copyMem(addr result[6], unsafeAddr payload[0], payload.len)

proc createGenericSuccessResponse(): seq[byte] =
  var writer = newBinaryWriter()
  writer.writeCCommonRespMsg(createSuccessResponse())
  return writer.toBytes()


# =============================================================================
# HANDLER IMPLEMENTATIONS
# =============================================================================

proc handleLogin(payload: seq[byte]): seq[byte] =
  var reader = newBinaryReader(payload)
  let loginReq = readCUserLoginPacket(reader)
  echo fmt"[Login] ✓ TransID={loginReq.m_nTransID}, Platform={loginReq.m_strPlatform}"
  let loginResp = createDefaultLoginResponse(loginReq.m_nTransID)
  var writer = newBinaryWriter()
  writer.writeCRespUserLoginPacket(loginResp)
  return createPacket(MSG_TYPE_USER_LOGIN_RESP, writer.toBytes())

proc handleHeartbeat(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  writer.writeUint64(getTime().toUnix().uint64)
  return createPacket(MSG_TYPE_HEARTBEAT_RESP, writer.toBytes())

proc handleSyncUser(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  writer.writeCCommonRespMsg(createSuccessResponse())
  return createPacket(MSG_TYPE_SYNC_USER_RESP, writer.toBytes())

proc handleGuildUserLogin(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  let resp = CRespGuildUserLogin(
    m_stRetMsg: createSuccessResponse(),
    m_nGuildId: 0, m_strGuildName: "", m_nGuildLevel: 0)
  writer.writeCRespGuildUserLogin(resp)
  return createPacket(MSG_TYPE_GUILD_USER_LOGIN_RESP, writer.toBytes())

proc handleDailyTaskInfo(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  let resp = createDefaultDailyTaskInfo()
  writer.writeCRespDailyTaskInfo(resp)
  return createPacket(MSG_TYPE_DAILY_TASK_INFO_RESP, writer.toBytes())

proc handleWeeklyTaskInfo(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  let now = getTime().toUnix().uint64
  let weekEnd = now + (7 * 86400'u64)
  let resp = CRespWeeklyTaskInfo(
    m_stRetMsg: createSuccessResponse(),
    m_nEndTime: weekEnd, m_nTaskPoint: 0, m_nTaskReward: 0)
  writer.writeCRespWeeklyTaskInfo(resp)
  return createPacket(MSG_TYPE_WEEKLY_TASK_INFO_RESP, writer.toBytes())

proc handleBattlepassConf(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  let resp = createDefaultBattlepassConf()
  writer.writeCRespBattlepassConf(resp)
  return createPacket(MSG_TYPE_BATTLEPASS_CONF_RESP, writer.toBytes())

proc handleActivityCommon(payload: seq[byte]): seq[byte] =
  var writer = newBinaryWriter()
  let resp = createDefaultActivityResponse()
  writer.writeCRespActivityCommon(resp)
  return createPacket(MSG_TYPE_ACTIVITY_COMMON_RESP, writer.toBytes())


# =============================================================================
# MAIN DISPATCH
# =============================================================================

proc handlePacket*(msgType: uint16, payload: seq[byte]): seq[byte] =
  ## Handle a packet and return response bytes.
  let packetName = getPacketName(msgType)
  echo fmt"[Handler] << {packetName} (0x{msgType:04X}), {payload.len}B"

  case msgType
  of MSG_TYPE_USER_LOGIN:
    return handleLogin(payload)
  of MSG_TYPE_HEARTBEAT:
    return handleHeartbeat(payload)
  of MSG_TYPE_SYNC_USER:
    return handleSyncUser(payload)
  of MSG_TYPE_GUILD_USER_LOGIN:
    return handleGuildUserLogin(payload)
  of MSG_TYPE_DAILY_TASK_INFO:
    return handleDailyTaskInfo(payload)
  of MSG_TYPE_WEEKLY_TASK_INFO:
    return handleWeeklyTaskInfo(payload)
  of MSG_TYPE_BATTLEPASS_CONF:
    return handleBattlepassConf(payload)
  of MSG_TYPE_ACTIVITY_COMMON:
    return handleActivityCommon(payload)
  else:
    # Generic success response for unhandled packets
    let respType = msgType + 1
    return createPacket(respType, createGenericSuccessResponse())
