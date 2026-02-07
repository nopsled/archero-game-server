## Battlepass Protocol Packets

import std/times
import binary, common

type
  CBattlePassExtraRewardConf* = object
    nExtraCnt*: uint16
    nExtraCondParam*: uint16
    strReward*: string
    strBigReward*: string

proc writeCBattlePassExtraRewardConf*(w: var BinaryWriter, c: CBattlePassExtraRewardConf) =
  w.writeUint16(c.nExtraCnt)
  w.writeUint16(c.nExtraCondParam)
  w.writeString(c.strReward)
  w.writeString(c.strBigReward)

type
  CBattlePassRewardConf* = object
    nId*: uint32
    nCondType*: uint16
    nParam*: uint16
    m_arrRewardInfo*: seq[string]

proc writeCBattlePassRewardConf*(w: var BinaryWriter, c: CBattlePassRewardConf) =
  w.writeUint32(c.nId)
  w.writeUint16(c.nCondType)
  w.writeUint16(c.nParam)
  w.writeArray(c.m_arrRewardInfo, proc(w: var BinaryWriter, s: string) = w.writeString(s))

type
  CReqBattlepassReward* = object
    m_nTransID*: uint32
    m_nBattleTag*: uint32
    m_nType*: uint16
    m_nKillsOrRewardId*: uint32
    m_nRewardIndex*: uint32
    m_strExtra*: string
    m_strExtend*: string
    m_nBattlePassType*: uint16
    m_nBattlePassId*: uint16
    m_nBattlePassIndex*: uint16

proc readCReqBattlepassReward*(r: var BinaryReader): CReqBattlepassReward =
  result.m_nTransID = r.readUint32()
  result.m_nBattleTag = r.readUint32()
  result.m_nType = r.readUint16()
  result.m_nKillsOrRewardId = r.readUint32()
  result.m_nRewardIndex = r.readUint32()
  result.m_strExtra = r.readString()
  result.m_strExtend = r.readString()
  result.m_nBattlePassType = r.readUint16()
  result.m_nBattlePassId = r.readUint16()
  result.m_nBattlePassIndex = r.readUint16()

type
  CRespBattlepassConf* = object
    m_stRetMsg*: CCommonRespMsg
    nStartTimestamp*: uint64
    nEndTimestamp*: uint64
    m_nBattlepassTag*: uint32
    bIsGin*: bool
    nType*: uint16
    nEventId*: uint16
    stExtraReward*: CBattlePassExtraRewardConf
    hasExtraReward*: bool
    m_arrTagInfo*: seq[CBattlePassRewardConf]
    nMinVersion*: uint16
    nMaxVersion*: uint16
    nSweepAddCnt*: uint16
    nSweepCoinAdd*: uint16
    bIsNew*: bool
    nDropRelicsAdd*: uint16
    nHarvestQuickAdd*: uint16
    nDropBossEggAdd*: uint16
    nRate*: uint16

proc writeCRespBattlepassConf*(w: var BinaryWriter, r: CRespBattlepassConf) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.nStartTimestamp)
  w.writeUint64(r.nEndTimestamp)
  w.writeUint32(r.m_nBattlepassTag)
  w.writeBool(r.bIsGin)
  w.writeUint16(r.nType)
  w.writeUint16(r.nEventId)
  if r.hasExtraReward:
    w.writeCBattlePassExtraRewardConf(r.stExtraReward)
  w.writeArray(r.m_arrTagInfo, proc(w: var BinaryWriter, c: CBattlePassRewardConf) = w.writeCBattlePassRewardConf(c))
  w.writeUint16(r.nMinVersion)
  w.writeUint16(r.nMaxVersion)
  w.writeUint16(r.nSweepAddCnt)
  w.writeUint16(r.nSweepCoinAdd)
  w.writeBool(r.bIsNew)
  w.writeUint16(r.nDropRelicsAdd)
  w.writeUint16(r.nHarvestQuickAdd)
  w.writeUint16(r.nDropBossEggAdd)
  w.writeUint16(r.nRate)
  w.writeUint16(0)  # mapGameActivityBattlePassPhaseConf - empty

type
  CRespBattlepassReward* = object
    m_stRetMsg*: CCommonRespMsg
    m_nKills*: uint32
    m_nRewardBits*: uint64

proc writeCRespBattlepassReward*(w: var BinaryWriter, r: CRespBattlepassReward) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint32(r.m_nKills)
  w.writeUint64(r.m_nRewardBits)

type
  STActivityBattlePassItem* = object
    m_nId*: uint32
    m_nProgress*: uint32
    m_nRewardBits*: uint64

proc writeSTActivityBattlePassItem*(w: var BinaryWriter, i: STActivityBattlePassItem) =
  w.writeUint32(i.m_nId)
  w.writeUint32(i.m_nProgress)
  w.writeUint64(i.m_nRewardBits)

type
  STActivityBattlePass* = object
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_nTag*: uint32
    m_vecItems*: seq[STActivityBattlePassItem]

proc writeSTActivityBattlePass*(w: var BinaryWriter, bp: STActivityBattlePass) =
  w.writeUint64(bp.m_nStartTime)
  w.writeUint64(bp.m_nEndTime)
  w.writeUint32(bp.m_nTag)
  w.writeArray(bp.m_vecItems, proc(w: var BinaryWriter, i: STActivityBattlePassItem) = w.writeSTActivityBattlePassItem(i))

proc createDefaultBattlepassConf*(): CRespBattlepassConf =
  let now = getTime().toUnix().uint64
  CRespBattlepassConf(
    m_stRetMsg: createSuccessResponse(),
    nStartTimestamp: now - 86400,
    nEndTimestamp: now + 86400 * 30,
    m_nBattlepassTag: 165,
    bIsGin: true,
    nType: 2,
    nEventId: 101,
    hasExtraReward: true,
    stExtraReward: CBattlePassExtraRewardConf(
      nExtraCnt: 5, nExtraCondParam: 100,
      strReward: "4,2203,1", strBigReward: "4,2204,1"),
    m_arrTagInfo: @[
      CBattlePassRewardConf(nId: 1, nCondType: 0, nParam: 0,
        m_arrRewardInfo: @["4,2305,1", "4,2306,1", "3,39133,2"]),
      CBattlePassRewardConf(nId: 2, nCondType: 0, nParam: 50,
        m_arrRewardInfo: @["4,2201,1", "4,2204,1", "10,12,1"]),
      CBattlePassRewardConf(nId: 3, nCondType: 0, nParam: 100,
        m_arrRewardInfo: @["4,2203,1", "1,26,1", "1,2,200"]),
      CBattlePassRewardConf(nId: 4, nCondType: 0, nParam: 150,
        m_arrRewardInfo: @["1,2,10", "3,36012,2", "4,2306,1"]),
      CBattlePassRewardConf(nId: 5, nCondType: 0, nParam: 200,
        m_arrRewardInfo: @["1,21,1", "4,2305,1", "4,2204,1"]),
    ],
    nMinVersion: 193,
    nMaxVersion: 999,
    nSweepAddCnt: 10,
    nSweepCoinAdd: 30,
    bIsNew: true,
    nDropRelicsAdd: 10,
    nHarvestQuickAdd: 15,
    nDropBossEggAdd: 15,
    nRate: 20,
  )
