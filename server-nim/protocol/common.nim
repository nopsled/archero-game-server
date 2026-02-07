## Common Protocol Types
##
## Shared data structures used across all GameProtocol packets.
## Based on captured field data from protocol discovery.

import std/times
import binary

# Helper to parse uint from string
proc parseUInt(s: string): uint64 =
  for c in s:
    if c >= '0' and c <= '9':
      result = result * 10 + (c.ord - '0'.ord).uint64

# =============================================================================
# COMMON RESPONSE MESSAGE
# =============================================================================

type
  CCommonRespMsg* = object
    m_unStatusCode*: uint16  ## 0 = success
    m_strInfo*: string       ## error/info message

proc writeCCommonRespMsg*(writer: var BinaryWriter, msg: CCommonRespMsg) =
  writer.writeUint16(msg.m_unStatusCode)
  writer.writeString(msg.m_strInfo)
  # Write minimal STCommonData (m_nChange = false, rest empty)
  writer.writeBool(false)  # m_nChange - client skips other fields if False

proc createSuccessResponse*(): CCommonRespMsg =
  CCommonRespMsg(m_unStatusCode: 0, m_strInfo: "")

# =============================================================================
# EQUIPMENT ITEM
# =============================================================================

type
  CEquipmentItem* = object
    m_nUniqueID*: string   ## unique item ID
    m_nRowID*: uint64
    m_nEquipID*: uint32    ## equipment type (10000 = basic bow)
    m_nLevel*: uint32      ## default 1
    m_nFragment*: uint32   ## default 1
    m_strExtend*: string   ## extension data
    relicEvolutionLevel*: int32
    relicStar*: int32

proc writeCEquipmentItem*(writer: var BinaryWriter, item: CEquipmentItem) =
  writer.writeString(item.m_nUniqueID)
  writer.writeUint64(item.m_nRowID)
  writer.writeUint32(item.m_nEquipID)
  writer.writeUint32(item.m_nLevel)
  writer.writeUint32(item.m_nFragment)
  writer.writeString(item.m_strExtend)
  writer.writeInt32(item.relicEvolutionLevel)
  writer.writeInt32(item.relicStar)

proc createDefaultEquipmentItem*(uniqueId: string, equipId: uint32): CEquipmentItem =
  CEquipmentItem(
    m_nUniqueID: uniqueId,
    m_nRowID: parseUInt(uniqueId).uint64,
    m_nEquipID: equipId,
    m_nLevel: 1,
    m_nFragment: 1,
    m_strExtend: "",
    relicEvolutionLevel: 0,
    relicStar: 0,
  )

# =============================================================================
# HERO ITEM
# =============================================================================

type
  CHeroItem* = object
    m_nHeroId*: uint32   ## 10000 = default hero
    m_nStar*: uint32
    m_nCoopLevel*: uint16  ## default 1

proc writeCHeroItem*(writer: var BinaryWriter, item: CHeroItem) =
  writer.writeUint32(item.m_nHeroId)
  writer.writeUint32(item.m_nStar)
  writer.writeUint16(item.m_nCoopLevel)

proc createDefaultHero*(): CHeroItem =
  CHeroItem(m_nHeroId: 10000, m_nStar: 0, m_nCoopLevel: 1)

# =============================================================================
# RESTORE ITEM
# =============================================================================

type
  CRestoreItem* = object
    m_nMin*: int16
    m_nMax*: uint16
    m_i64Timestamp*: uint64  ## unix timestamp

proc writeCRestoreItem*(writer: var BinaryWriter, item: CRestoreItem) =
  writer.writeInt16(item.m_nMin)
  writer.writeUint16(item.m_nMax)
  writer.writeUint64(item.m_i64Timestamp)

proc createDefaultRestoreItem*(current: int16, maxValue: uint16): CRestoreItem =
  CRestoreItem(
    m_nMin: current,
    m_nMax: maxValue,
    m_i64Timestamp: getTime().toUnix().uint64,
  )

# =============================================================================
# TIMESTAMP ITEM
# =============================================================================

type
  CTimestampItem* = object
    m_nIndex*: uint16
    m_i64Timestamp*: uint64

proc writeCTimestampItem*(writer: var BinaryWriter, item: CTimestampItem) =
  writer.writeUint16(item.m_nIndex)
  writer.writeUint64(item.m_i64Timestamp)

# =============================================================================
# BOX ASSURANCE ITEM
# =============================================================================

type
  CBoxAssuranceItem* = object
    m_nBoxCountLow*: uint16   ## default 10
    m_nBoxCountMid*: uint16   ## default 30
    m_nBoxCountHigh*: uint16  ## default 120

proc writeCBoxAssuranceItem*(writer: var BinaryWriter, item: CBoxAssuranceItem) =
  writer.writeUint16(item.m_nBoxCountLow)
  writer.writeUint16(item.m_nBoxCountMid)
  writer.writeUint16(item.m_nBoxCountHigh)

proc createDefaultBoxAssurance*(): CBoxAssuranceItem =
  CBoxAssuranceItem(m_nBoxCountLow: 10, m_nBoxCountMid: 30, m_nBoxCountHigh: 120)

# =============================================================================
# PET INFO
# =============================================================================

type
  STPetInfo* = object
    m_nPetId*: uint32
    m_nLevel*: uint32
    m_nStar*: uint32

proc writeSTPetInfo*(writer: var BinaryWriter, info: STPetInfo) =
  writer.writeUint32(info.m_nPetId)
  writer.writeUint32(info.m_nLevel)
  writer.writeUint32(info.m_nStar)

# =============================================================================
# HEAD ITEM
# =============================================================================

type
  STHeadItem* = object
    m_nHeadId*: uint32
    m_nTimestamp*: uint64

proc writeSTHeadItem*(writer: var BinaryWriter, item: STHeadItem) =
  writer.writeUint32(item.m_nHeadId)
  writer.writeUint64(item.m_nTimestamp)

# =============================================================================
# ARTIFACT
# =============================================================================

type
  CArtifact* = object
    m_nArtifactId*: uint32
    m_nLevel*: uint32
    m_nStar*: uint32

proc writeCArtifact*(writer: var BinaryWriter, artifact: CArtifact) =
  writer.writeUint32(artifact.m_nArtifactId)
  writer.writeUint32(artifact.m_nLevel)
  writer.writeUint32(artifact.m_nStar)

