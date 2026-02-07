## Shop, Guild, VIP, and Miscellaneous Protocol Packets

import binary, common

type
  CRespShopBoxActivity* = object
    m_stRetMsg*: CCommonRespMsg
    m_nActivityId*: uint32
    m_nStartTime*: uint64
    m_nEndTime*: uint64

proc writeCRespShopBoxActivity*(w: var BinaryWriter, r: CRespShopBoxActivity) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint32(r.m_nActivityId)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)

type
  CReqMonthCard* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nPlatformIndex*: uint16

proc readCReqMonthCard*(r: var BinaryReader): CReqMonthCard =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nPlatformIndex = r.readUint16()

type
  CRespMonthCard* = object
    m_stRetMsg*: CCommonRespMsg
    m_nMonthCardEndTime*: uint64
    m_nDoubleCardEndTime*: uint64
    m_nDailyRewardBits*: uint64

proc writeCRespMonthCard*(w: var BinaryWriter, r: CRespMonthCard) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nMonthCardEndTime)
  w.writeUint64(r.m_nDoubleCardEndTime)
  w.writeUint64(r.m_nDailyRewardBits)

type
  CReqPrivilegeCard* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16

proc readCReqPrivilegeCard*(r: var BinaryReader): CReqPrivilegeCard =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()

type
  CRespPrivilegeCard* = object
    m_stRetMsg*: CCommonRespMsg
    m_nEndTime*: uint64
    m_nType*: uint16

proc writeCRespPrivilegeCard*(w: var BinaryWriter, r: CRespPrivilegeCard) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nEndTime)
  w.writeUint16(r.m_nType)

type
  STReqVip* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16

proc readSTReqVip*(r: var BinaryReader): STReqVip =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()

type
  STRespVip* = object
    m_stRetMsg*: CCommonRespMsg
    m_nVipLevel*: uint16
    m_nVipScore*: uint32
    m_nRewardBits*: uint64

proc writeSTRespVip*(w: var BinaryWriter, r: STRespVip) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nVipLevel)
  w.writeUint32(r.m_nVipScore)
  w.writeUint64(r.m_nRewardBits)

# Guild
type
  CGuildTaskInfo* = object
    m_nTaskId*: uint32
    m_nProgress*: uint32
    m_bIsClaimed*: bool

proc writeCGuildTaskInfo*(w: var BinaryWriter, i: CGuildTaskInfo) =
  w.writeUint32(i.m_nTaskId)
  w.writeUint32(i.m_nProgress)
  w.writeBool(i.m_bIsClaimed)

type
  CRespGuildTaskInfo* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecTasks*: seq[CGuildTaskInfo]

proc writeCRespGuildTaskInfo*(w: var BinaryWriter, r: CRespGuildTaskInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeArray(r.m_vecTasks, proc(w: var BinaryWriter, t: CGuildTaskInfo) = w.writeCGuildTaskInfo(t))

type
  CGuildAchInfo* = object
    m_nAchId*: uint32
    m_nProgress*: uint32
    m_nLevel*: uint16

proc writeCGuildAchInfo*(w: var BinaryWriter, i: CGuildAchInfo) =
  w.writeUint32(i.m_nAchId)
  w.writeUint32(i.m_nProgress)
  w.writeUint16(i.m_nLevel)

type
  CRespGuildUserLogin* = object
    m_stRetMsg*: CCommonRespMsg
    m_nGuildId*: uint64
    m_strGuildName*: string
    m_nGuildLevel*: uint16

proc writeCRespGuildUserLogin*(w: var BinaryWriter, r: CRespGuildUserLogin) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nGuildId)
  w.writeString(r.m_strGuildName)
  w.writeUint16(r.m_nGuildLevel)

type
  CRespQueryGuildRedpacket* = object
    m_stRetMsg*: CCommonRespMsg
    m_nRedpacketCount*: uint16

proc writeCRespQueryGuildRedpacket*(w: var BinaryWriter, r: CRespQueryGuildRedpacket) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nRedpacketCount)

# User Back / Login Gift
type
  CReqUserBack* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nRewardType*: uint16
    m_nRewardIndex*: uint16
    m_strExtra*: string

proc readCReqUserBack*(r: var BinaryReader): CReqUserBack =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nRewardType = r.readUint16()
  result.m_nRewardIndex = r.readUint16()
  result.m_strExtra = r.readString()

type
  CRespUserBack* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDays*: uint16
    m_nRewardBits*: uint64

proc writeCRespUserBack*(w: var BinaryWriter, r: CRespUserBack) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDays)
  w.writeUint64(r.m_nRewardBits)

type
  CReqLoginGift* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nRewardIndex*: uint16

proc readCReqLoginGift*(r: var BinaryReader): CReqLoginGift =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nRewardIndex = r.readUint16()

type
  CRespLoginGift* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDays*: uint16
    m_nRewardBits*: uint64

proc writeCRespLoginGift*(w: var BinaryWriter, r: CRespLoginGift) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDays)
  w.writeUint64(r.m_nRewardBits)

type
  CReqWeeklyGift* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16

proc readCReqWeeklyGift*(r: var BinaryReader): CReqWeeklyGift =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()

type
  CRespWeeklyGift* = object
    m_stRetMsg*: CCommonRespMsg
    m_nWeeks*: uint16
    m_nRewardBits*: uint64

proc writeCRespWeeklyGift*(w: var BinaryWriter, r: CRespWeeklyGift) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nWeeks)
  w.writeUint64(r.m_nRewardBits)

type
  CReqFirstCharge* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16

proc readCReqFirstCharge*(r: var BinaryReader): CReqFirstCharge =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()

type
  CRespFirstCharge* = object
    m_stRetMsg*: CCommonRespMsg
    m_nStatus*: uint16
    m_nRewardBits*: uint64

proc writeCRespFirstCharge*(w: var BinaryWriter, r: CRespFirstCharge) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nStatus)
  w.writeUint64(r.m_nRewardBits)

type
  CQueryFirstIAPInfo* = object
    m_nType*: uint16
    m_nTransId*: uint32

proc readCQueryFirstIAPInfo*(r: var BinaryReader): CQueryFirstIAPInfo =
  result.m_nType = r.readUint16()
  result.m_nTransId = r.readUint32()

type
  STReqBindingHabbyID* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_strAuthCode*: string
    m_strLanguage*: string

proc readSTReqBindingHabbyID*(r: var BinaryReader): STReqBindingHabbyID =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()
  result.m_strAuthCode = r.readString()
  result.m_strLanguage = r.readString()

type
  STRespBindingHabbyID* = object
    m_stRetMsg*: CCommonRespMsg
    m_strHabbyID*: string
    m_nStatus*: uint16

proc writeSTRespBindingHabbyID*(w: var BinaryWriter, r: STRespBindingHabbyID) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeString(r.m_strHabbyID)
  w.writeUint16(r.m_nStatus)

# Farm
type
  CReqFarm* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_nSlotId*: uint16

proc readCReqFarm*(r: var BinaryReader): CReqFarm =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()
  result.m_nSlotId = r.readUint16()

type
  CFarmSlot* = object
    m_nSlotId*: uint16
    m_nPlantId*: uint32
    m_nPlantTime*: uint64
    m_nStatus*: uint16

proc writeCFarmSlot*(w: var BinaryWriter, s: CFarmSlot) =
  w.writeUint16(s.m_nSlotId)
  w.writeUint32(s.m_nPlantId)
  w.writeUint64(s.m_nPlantTime)
  w.writeUint16(s.m_nStatus)

type
  CRespFarm* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecSlots*: seq[CFarmSlot]

proc writeCRespFarm*(w: var BinaryWriter, r: CRespFarm) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeArray(r.m_vecSlots, proc(w: var BinaryWriter, s: CFarmSlot) = w.writeCFarmSlot(s))

# Monster Egg / Hatch
type
  CMonsterEgg* = object
    m_nEggId*: uint32
    m_nSlotId*: uint16
    m_nStartTime*: uint64

proc writeCMonsterEgg*(w: var BinaryWriter, e: CMonsterEgg) =
  w.writeUint32(e.m_nEggId)
  w.writeUint16(e.m_nSlotId)
  w.writeUint64(e.m_nStartTime)

type
  CMonsterHatch* = object
    m_nMonsterId*: uint32
    m_nLevel*: uint16
    m_nStar*: uint16

proc writeCMonsterHatch*(w: var BinaryWriter, h: CMonsterHatch) =
  w.writeUint32(h.m_nMonsterId)
  w.writeUint16(h.m_nLevel)
  w.writeUint16(h.m_nStar)

type
  CRespMonsterHatch* = object
    m_stRetMsg*: CCommonRespMsg
    m_vecHatched*: seq[CMonsterHatch]

proc writeCRespMonsterHatch*(w: var BinaryWriter, r: CRespMonsterHatch) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeArray(r.m_vecHatched, proc(w: var BinaryWriter, h: CMonsterHatch) = w.writeCMonsterHatch(h))

# Ship Battle Season
type
  STReqShipBattleSeasonGhostShip* = object
    m_nTransID*: uint32
    m_nType*: uint16

proc readSTReqShipBattleSeasonGhostShip*(r: var BinaryReader): STReqShipBattleSeasonGhostShip =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()

type
  CShipBattleBaseRank* = object
    m_nRank*: uint32
    m_nScore*: uint32
    m_strName*: string

proc writeCShipBattleBaseRank*(w: var BinaryWriter, r: CShipBattleBaseRank) =
  w.writeUint32(r.m_nRank)
  w.writeUint32(r.m_nScore)
  w.writeString(r.m_strName)

type
  STShipBattleSeasonIsLandRankInfo* = object
    m_vecRank*: seq[CShipBattleBaseRank]
    m_nRankValue*: uint64
    m_nRank*: uint32

proc writeSTShipBattleSeasonIsLandRankInfo*(w: var BinaryWriter, i: STShipBattleSeasonIsLandRankInfo) =
  w.writeArray(i.m_vecRank, proc(w: var BinaryWriter, r: CShipBattleBaseRank) = w.writeCShipBattleBaseRank(r))
  w.writeUint64(i.m_nRankValue)
  w.writeUint32(i.m_nRank)

type
  STRespShipBattleSeasonGhostShip* = object
    m_stRetMsg*: CCommonRespMsg
    m_nRemainFreeChallenges*: uint32
    m_nPayChallengeCount*: uint32
    m_nDailyChallengeCount*: uint32
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_nRankEndTime*: uint64
    hasRankInfo*: bool
    mstRankInfo*: STShipBattleSeasonIsLandRankInfo
    m_nChallengeLimit*: uint32

proc writeSTRespShipBattleSeasonGhostShip*(w: var BinaryWriter, r: STRespShipBattleSeasonGhostShip) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint32(r.m_nRemainFreeChallenges)
  w.writeUint32(r.m_nPayChallengeCount)
  w.writeUint32(r.m_nDailyChallengeCount)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)
  w.writeUint64(r.m_nRankEndTime)
  if r.hasRankInfo:
    w.writeSTShipBattleSeasonIsLandRankInfo(r.mstRankInfo)
  w.writeUint32(r.m_nChallengeLimit)

# Daily IAP Gift
type
  CDailyGiftGemData* = object
    m_nGemId*: uint32
    m_nCount*: uint16

proc writeCDailyGiftGemData*(w: var BinaryWriter, d: CDailyGiftGemData) =
  w.writeUint32(d.m_nGemId)
  w.writeUint16(d.m_nCount)

type
  CDailyGiftHeroData* = object
    m_nHeroId*: uint32
    m_nFragments*: uint16

proc writeCDailyGiftHeroData*(w: var BinaryWriter, d: CDailyGiftHeroData) =
  w.writeUint32(d.m_nHeroId)
  w.writeUint16(d.m_nFragments)

type
  CReqDailyIapGift* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nSelectHeroIndex*: uint32

proc readCReqDailyIapGift*(r: var BinaryReader): CReqDailyIapGift =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nSelectHeroIndex = r.readUint32()

type
  CRespDailyIapGift* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDays*: uint16
    m_vecGems*: seq[CDailyGiftGemData]
    m_vecHeroes*: seq[CDailyGiftHeroData]

proc writeCRespDailyIapGift*(w: var BinaryWriter, r: CRespDailyIapGift) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDays)
  w.writeArray(r.m_vecGems, proc(w: var BinaryWriter, g: CDailyGiftGemData) = w.writeCDailyGiftGemData(g))
  w.writeArray(r.m_vecHeroes, proc(w: var BinaryWriter, h: CDailyGiftHeroData) = w.writeCDailyGiftHeroData(h))
