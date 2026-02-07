## Game Protocol Packets — towers, battles, harvests, achievements, etc.

import binary, common

type
  CGameTowerInfo* = object
    m_nType*: uint16; m_bWin*: bool; m_nTransID*: uint32

proc readCGameTowerInfo*(r: var BinaryReader): CGameTowerInfo =
  result.m_nType = r.readUint16(); result.m_bWin = r.readBool(); result.m_nTransID = r.readUint32()

type
  CPlayTowerInfo* = object
    m_nType*: uint16; m_nTowerId*: uint32; m_nFloor*: uint16; m_nTransID*: uint32

proc readCPlayTowerInfo*(r: var BinaryReader): CPlayTowerInfo =
  result.m_nType = r.readUint16(); result.m_nTowerId = r.readUint32()
  result.m_nFloor = r.readUint16(); result.m_nTransID = r.readUint32()

type
  CRespGameTowerInfo* = object
    m_stRetMsg*: CCommonRespMsg; m_nFloor*, m_nMaxFloor*: uint16

proc writeCRespGameTowerInfo*(w: var BinaryWriter, r: CRespGameTowerInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint16(r.m_nFloor); w.writeUint16(r.m_nMaxFloor)

type
  CRespPlayTowerInfo* = object
    m_stRetMsg*: CCommonRespMsg; m_nTowerId*: uint32; m_nFloor*: uint16

proc writeCRespPlayTowerInfo*(w: var BinaryWriter, r: CRespPlayTowerInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint32(r.m_nTowerId); w.writeUint16(r.m_nFloor)

type
  CReqGameHarvest2* = object
    m_nType*: uint16; m_nTransID*: uint32

proc readCReqGameHarvest2*(r: var BinaryReader): CReqGameHarvest2 =
  result.m_nType = r.readUint16(); result.m_nTransID = r.readUint32()

type
  CRespGameHarvest2* = object
    m_stRetMsg*: CCommonRespMsg; m_nCoins*, m_nExp*: uint32; m_nTimestamp*: uint64; m_nMaxTime*: uint32

proc writeCRespGameHarvest2*(w: var BinaryWriter, r: CRespGameHarvest2) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint32(r.m_nCoins); w.writeUint32(r.m_nExp)
  w.writeUint64(r.m_nTimestamp); w.writeUint32(r.m_nMaxTime)

type
  CGameAchieveInfo* = object
    m_nType*: uint16; m_nId*: uint32; m_nTransID*: uint32

proc readCGameAchieveInfo*(r: var BinaryReader): CGameAchieveInfo =
  result.m_nType = r.readUint16(); result.m_nId = r.readUint32(); result.m_nTransID = r.readUint32()

type
  STCommonAchievementData* = object
    m_nId*: uint32; m_nProgress*: uint32; m_nLevel*: uint16; m_bIsClaimed*: bool

proc writeSTCommonAchievementData*(w: var BinaryWriter, d: STCommonAchievementData) =
  w.writeUint32(d.m_nId); w.writeUint32(d.m_nProgress); w.writeUint16(d.m_nLevel); w.writeBool(d.m_bIsClaimed)

type
  CRespGameAchieveInfo* = object
    m_stRetMsg*: CCommonRespMsg; m_vecAchievements*: seq[STCommonAchievementData]

proc writeCRespGameAchieveInfo*(w: var BinaryWriter, r: CRespGameAchieveInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeArray(r.m_vecAchievements, proc(w: var BinaryWriter, a: STCommonAchievementData) = w.writeSTCommonAchievementData(a))

type
  CGameAd* = object
    m_nType*: uint16; m_nAdId*: uint32; m_nTransID*: uint32

proc readCGameAd*(r: var BinaryReader): CGameAd =
  result.m_nType = r.readUint16(); result.m_nAdId = r.readUint32(); result.m_nTransID = r.readUint32()

type
  CRespGameAd* = object
    m_stRetMsg*: CCommonRespMsg; m_nAdCount*, m_nDailyLimit*: uint16

proc writeCRespGameAd*(w: var BinaryWriter, r: CRespGameAd) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint16(r.m_nAdCount); w.writeUint16(r.m_nDailyLimit)

type
  CReqGameGuide* = object
    m_nType*: uint16; m_nGuideId*: uint32; m_nTransID*: uint32

proc readCReqGameGuide*(r: var BinaryReader): CReqGameGuide =
  result.m_nType = r.readUint16(); result.m_nGuideId = r.readUint32(); result.m_nTransID = r.readUint32()

type
  CRespGameGuide* = object
    m_stRetMsg*: CCommonRespMsg; m_nGuideBits*: uint64

proc writeCRespGameGuide*(w: var BinaryWriter, r: CRespGameGuide) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint64(r.m_nGuideBits)

type
  CReqGameClientData* = object
    m_nType*: uint16; m_strClientData*: string

proc readCReqGameClientData*(r: var BinaryReader): CReqGameClientData =
  result.m_nType = r.readUint16(); result.m_strClientData = r.readString()

type
  CRespGameClientData* = object
    m_stRetMsg*: CCommonRespMsg; m_strClientData*: string

proc writeCRespGameClientData*(w: var BinaryWriter, r: CRespGameClientData) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeString(r.m_strClientData)

type
  CPveSeasonInfo* = object
    m_nType*: uint16; m_nSeasonId*: uint32; m_nTransID*: uint32

proc readCPveSeasonInfo*(r: var BinaryReader): CPveSeasonInfo =
  result.m_nType = r.readUint16(); result.m_nSeasonId = r.readUint32(); result.m_nTransID = r.readUint32()

type
  CRespPveSeasonInfo* = object
    m_stRetMsg*: CCommonRespMsg; m_nSeasonId*, m_nRank*, m_nScore*: uint32

proc writeCRespPveSeasonInfo*(w: var BinaryWriter, r: CRespPveSeasonInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint32(r.m_nSeasonId)
  w.writeUint32(r.m_nRank); w.writeUint32(r.m_nScore)

type
  CReqGameFishing* = object
    m_nType*: uint16; m_nTransID*: uint32

proc readCReqGameFishing*(r: var BinaryReader): CReqGameFishing =
  result.m_nType = r.readUint16(); result.m_nTransID = r.readUint32()

type
  STGameFishingRank* = object
    m_nRank*, m_nScore*: uint32; m_strName*: string

proc writeSTGameFishingRank*(w: var BinaryWriter, r: STGameFishingRank) =
  w.writeUint32(r.m_nRank); w.writeUint32(r.m_nScore); w.writeString(r.m_strName)

type
  CRespGameFishing* = object
    m_stRetMsg*: CCommonRespMsg; m_nScore*: uint32; m_vecRanks*: seq[STGameFishingRank]

proc writeCRespGameFishing*(w: var BinaryWriter, r: CRespGameFishing) =
  w.writeCCommonRespMsg(r.m_stRetMsg); w.writeUint32(r.m_nScore)
  w.writeArray(r.m_vecRanks, proc(w: var BinaryWriter, r: STGameFishingRank) = w.writeSTGameFishingRank(r))
