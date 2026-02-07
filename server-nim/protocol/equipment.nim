## Equipment Protocol Packets
##
## Equipment, weapons, relics, and related structures.

import binary, common

# =============================================================================
# EQUIPMENT REQUESTS
# =============================================================================

type
  CReqEquipWear* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_nEquipUniqueId*: uint64
    m_nSlotId*: uint16

proc readCReqEquipWear*(reader: var BinaryReader): CReqEquipWear =
  result.m_nTransID = reader.readUint32()
  result.m_nType = reader.readUint16()
  result.m_nEquipUniqueId = reader.readUint64()
  result.m_nSlotId = reader.readUint16()

type
  CReqEquipTotem* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_nTotemId*: uint32

proc readCReqEquipTotem*(reader: var BinaryReader): CReqEquipTotem =
  result.m_nTransID = reader.readUint32()
  result.m_nType = reader.readUint16()
  result.m_nTotemId = reader.readUint32()

type
  CEquipRefine* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nPosId*: uint16
    m_nCarvingId*: uint32
    m_nCarvingIdx*: uint16
    arrayEquipId*: seq[uint64]
    vecCompositeId*: seq[uint32]

proc readCEquipRefine*(reader: var BinaryReader): CEquipRefine =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nPosId = reader.readUint16()
  result.m_nCarvingId = reader.readUint32()
  result.m_nCarvingIdx = reader.readUint16()
  result.arrayEquipId = reader.readArray(proc(r: var BinaryReader): uint64 = r.readUint64())
  result.vecCompositeId = reader.readArray(proc(r: var BinaryReader): uint32 = r.readUint32())

# =============================================================================
# EQUIPMENT RESPONSES
# =============================================================================

type
  CRespEquipWear* = object
    m_stRetMsg*: CCommonRespMsg
    m_nEquipUniqueId*: uint64
    m_nSlotId*: uint16

proc writeCRespEquipWear*(writer: var BinaryWriter, resp: CRespEquipWear) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint64(resp.m_nEquipUniqueId)
  writer.writeUint16(resp.m_nSlotId)

type
  CRespEquipTotem* = object
    m_stRetMsg*: CCommonRespMsg
    m_nTotemId*: uint32

proc writeCRespEquipTotem*(writer: var BinaryWriter, resp: CRespEquipTotem) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint32(resp.m_nTotemId)

type
  CRespEquipRefine* = object
    m_stRetMsg*: CCommonRespMsg
    m_nResult*: uint16

proc writeCRespEquipRefine*(writer: var BinaryWriter, resp: CRespEquipRefine) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint16(resp.m_nResult)

# =============================================================================
# HERO SKIN
# =============================================================================

type
  CReqHeroSkin* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nSkinId*: uint32
    m_nNum*: uint32

proc readCReqHeroSkin*(reader: var BinaryReader): CReqHeroSkin =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nSkinId = reader.readUint32()
  result.m_nNum = reader.readUint32()

type
  CHeroSkin* = object
    m_nSkinId*: uint32
    m_nLevel*: uint16
    m_bIsOwned*: bool

proc writeCHeroSkin*(writer: var BinaryWriter, skin: CHeroSkin) =
  writer.writeUint32(skin.m_nSkinId)
  writer.writeUint16(skin.m_nLevel)
  writer.writeBool(skin.m_bIsOwned)

type
  CRespHeroSkin* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecSkins*: seq[CHeroSkin]

proc writeCRespHeroSkin*(writer: var BinaryWriter, resp: CRespHeroSkin) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeArray(resp.m_vecSkins, proc(w: var BinaryWriter, s: CHeroSkin) = w.writeCHeroSkin(s))

# =============================================================================
# WEAPON SKIN
# =============================================================================

type
  CReqWeaponSkin* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nSkinId*: uint32

proc readCReqWeaponSkin*(reader: var BinaryReader): CReqWeaponSkin =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nSkinId = reader.readUint32()

type
  CRespWeaponSkin* = object
    m_stRetMsg*: CCommonRespMsg
    m_nSkinId*: uint32

proc writeCRespWeaponSkin*(writer: var BinaryWriter, resp: CRespWeaponSkin) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint32(resp.m_nSkinId)

# =============================================================================
# WING
# =============================================================================

type
  CReqWing* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nWingId*: uint32

proc readCReqWing*(reader: var BinaryReader): CReqWing =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nWingId = reader.readUint32()

type
  CRespWing* = object
    m_stRetMsg*: CCommonRespMsg
    m_nWingId*: uint32

proc writeCRespWing*(writer: var BinaryWriter, resp: CRespWing) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint32(resp.m_nWingId)

# =============================================================================
# BOXES
# =============================================================================

type
  CReqOpenDragonBox* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nDiamond*: uint16
    m_nBatchCount*: uint16

proc readCReqOpenDragonBox*(reader: var BinaryReader): CReqOpenDragonBox =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nDiamond = reader.readUint16()
  result.m_nBatchCount = reader.readUint16()

type
  CRespOpenDragonBox* = object
    m_stRetMsg*: CCommonRespMsg
    m_nBoxCount*: uint16
    m_vecRewards*: seq[uint32]

proc writeCRespOpenDragonBox*(writer: var BinaryWriter, resp: CRespOpenDragonBox) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeUint16(resp.m_nBoxCount)
  writer.writeArray(resp.m_vecRewards, proc(w: var BinaryWriter, r: uint32) = w.writeUint32(r))

type
  CReqOpenPetBox* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nCount*: uint16

proc readCReqOpenPetBox*(reader: var BinaryReader): CReqOpenPetBox =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nCount = reader.readUint16()

type
  CRespOpenPetBox* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecRewards*: seq[uint32]

proc writeCRespOpenPetBox*(writer: var BinaryWriter, resp: CRespOpenPetBox) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeArray(resp.m_vecRewards, proc(w: var BinaryWriter, r: uint32) = w.writeUint32(r))

type
  CReqOpenEquipSBox* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nCount*: uint16

proc readCReqOpenEquipSBox*(reader: var BinaryReader): CReqOpenEquipSBox =
  result.m_nType = reader.readUint16()
  result.m_nTransID = reader.readUint32()
  result.m_nCount = reader.readUint16()

type
  CRespOpenEquipSBox* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecRewards*: seq[uint32]

proc writeCRespOpenEquipSBox*(writer: var BinaryWriter, resp: CRespOpenEquipSBox) =
  writer.writeCCommonRespMsg(resp.m_stRetMsg)
  writer.writeArray(resp.m_vecRewards, proc(w: var BinaryWriter, r: uint32) = w.writeUint32(r))
