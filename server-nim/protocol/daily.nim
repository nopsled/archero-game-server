## Daily Tasks and Rewards Protocol Packets

import std/times
import binary, common

type
  CRewardItem* = object
    m_nType*: uint16
    m_nId*: uint32
    m_nCount*: uint32

proc writeCRewardItem*(w: var BinaryWriter, item: CRewardItem) =
  w.writeUint16(item.m_nType)
  w.writeUint32(item.m_nId)
  w.writeUint32(item.m_nCount)

type
  CDailyTaskInfo* = object
    m_nType*: uint16
    m_nId*: uint32
    m_nTransID*: uint32

proc readCDailyTaskInfo*(r: var BinaryReader): CDailyTaskInfo =
  result.m_nType = r.readUint16()
  result.m_nId = r.readUint32()
  result.m_nTransID = r.readUint32()

type
  CWeeklyTaskInfo* = object
    m_nType*: uint16
    m_nId*: uint32
    m_nTransID*: uint32

proc readCWeeklyTaskInfo*(r: var BinaryReader): CWeeklyTaskInfo =
  result.m_nType = r.readUint16()
  result.m_nId = r.readUint32()
  result.m_nTransID = r.readUint32()

type
  STDailyTaskExtraRewardData* = object
    m_nId*: uint32
    m_nProgress*: uint32
    m_bIsClaimed*: bool

proc writeSTDailyTaskExtraRewardData*(w: var BinaryWriter, d: STDailyTaskExtraRewardData) =
  w.writeUint32(d.m_nId)
  w.writeUint32(d.m_nProgress)
  w.writeBool(d.m_bIsClaimed)

type
  CRespDailyTaskInfo* = object
    m_stRetMsg*: CCommonRespMsg
    m_nEndTime*: uint64
    m_nTaskPoint*: uint16
    m_nTaskReward*: uint64
    m_nTotalDiamonds*: uint32
    m_nTotalCoins*: uint32
    m_nLife*: uint16
    m_nBattleRebornCount*: uint16
    m_nNormalDiamondItem*: uint16
    m_nLargeDiamondItem*: uint16
    m_nLevel*: uint16
    m_nExperience*: uint32
    m_arrEquipInfo*: seq[CEquipmentItem]
    m_nTowerLife*: uint16
    m_nMixBoxItem*: uint16
    m_nDragonBoxItem*: uint16
    m_nRelicsBoxItem*: uint16
    m_nEquipSBoxItem*: uint16
    m_vecExtraRewardData*: seq[STDailyTaskExtraRewardData]

proc writeCRespDailyTaskInfo*(w: var BinaryWriter, r: CRespDailyTaskInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nEndTime)
  w.writeUint16(r.m_nTaskPoint)
  w.writeUint64(r.m_nTaskReward)
  w.writeUint32(r.m_nTotalDiamonds)
  w.writeUint32(r.m_nTotalCoins)
  w.writeUint16(r.m_nLife)
  w.writeUint16(r.m_nBattleRebornCount)
  w.writeUint16(r.m_nNormalDiamondItem)
  w.writeUint16(r.m_nLargeDiamondItem)
  w.writeUint16(r.m_nLevel)
  w.writeUint32(r.m_nExperience)
  w.writeArray(r.m_arrEquipInfo, proc(w: var BinaryWriter, e: CEquipmentItem) = w.writeCEquipmentItem(e))
  w.writeUint16(r.m_nTowerLife)
  w.writeUint16(r.m_nMixBoxItem)
  w.writeUint16(r.m_nDragonBoxItem)
  w.writeUint16(r.m_nRelicsBoxItem)
  w.writeUint16(r.m_nEquipSBoxItem)
  w.writeArray(r.m_vecExtraRewardData, proc(w: var BinaryWriter, d: STDailyTaskExtraRewardData) = w.writeSTDailyTaskExtraRewardData(d))

type
  CRespWeeklyTaskInfo* = object
    m_stRetMsg*: CCommonRespMsg
    m_nEndTime*: uint64
    m_nTaskPoint*: uint16
    m_nTaskReward*: uint64

proc writeCRespWeeklyTaskInfo*(w: var BinaryWriter, r: CRespWeeklyTaskInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nEndTime)
  w.writeUint16(r.m_nTaskPoint)
  w.writeUint64(r.m_nTaskReward)

type
  CDailyPlay* = object
    m_nType*: uint16
    m_nId*: uint32
    m_nTransID*: uint32
    m_nPartnerUserId*: uint64
    m_nBattleTransID*: uint32
    m_nDailyLevel*: uint32

proc readCDailyPlay*(r: var BinaryReader): CDailyPlay =
  result.m_nType = r.readUint16()
  result.m_nId = r.readUint32()
  result.m_nTransID = r.readUint32()
  result.m_nPartnerUserId = r.readUint64()
  result.m_nBattleTransID = r.readUint32()
  result.m_nDailyLevel = r.readUint32()

type
  CRespDailyPlayInfo* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDailyPlayCount*: uint16
    m_nDailyPlayMax*: uint16

proc writeCRespDailyPlayInfo*(w: var BinaryWriter, r: CRespDailyPlayInfo) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDailyPlayCount)
  w.writeUint16(r.m_nDailyPlayMax)

type
  CReqDailyIapReward* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_strExtra*: string

proc readCReqDailyIapReward*(r: var BinaryReader): CReqDailyIapReward =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()
  result.m_strExtra = r.readString()

type
  CReqWeekIapReward* = object
    m_nTransID*: uint32
    m_nType*: uint16

proc readCReqWeekIapReward*(r: var BinaryReader): CReqWeekIapReward =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()

type
  CReqMonthIapReward* = object
    m_nTransID*: uint32
    m_nType*: uint16

proc readCReqMonthIapReward*(r: var BinaryReader): CReqMonthIapReward =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()

type
  CRespDailyIapReward* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDays*: uint16
    m_nRewardBits*: uint64

proc writeCRespDailyIapReward*(w: var BinaryWriter, r: CRespDailyIapReward) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDays)
  w.writeUint64(r.m_nRewardBits)

type
  CRespWeekIapReward* = object
    m_stRetMsg*: CCommonRespMsg
    m_nWeeks*: uint16
    m_nRewardBits*: uint64

proc writeCRespWeekIapReward*(w: var BinaryWriter, r: CRespWeekIapReward) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nWeeks)
  w.writeUint64(r.m_nRewardBits)

type
  CRespMonthIapReward* = object
    m_stRetMsg*: CCommonRespMsg
    m_nMonths*: uint16
    m_nRewardBits*: uint64

proc writeCRespMonthIapReward*(w: var BinaryWriter, r: CRespMonthIapReward) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nMonths)
  w.writeUint64(r.m_nRewardBits)

proc createDefaultDailyTaskInfo*(): CRespDailyTaskInfo =
  let now = getTime().toUnix().uint64
  let todayEnd = now + (86400'u64 - (now mod 86400'u64))
  CRespDailyTaskInfo(m_stRetMsg: createSuccessResponse(), m_nEndTime: todayEnd)
