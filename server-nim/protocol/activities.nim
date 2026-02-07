## Activity Protocol Packets

import std/times
import binary, common

type
  CActivityCommonData* = object
    m_nActivityId*: uint32
    m_nActivityType*: uint16
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_nStatus*: uint16

proc writeCActivityCommonData*(w: var BinaryWriter, d: CActivityCommonData) =
  w.writeUint32(d.m_nActivityId)
  w.writeUint16(d.m_nActivityType)
  w.writeUint64(d.m_nStartTime)
  w.writeUint64(d.m_nEndTime)
  w.writeUint16(d.m_nStatus)

type
  CActivityInvestCondition* = object
    m_nConditionId*: uint32
    m_nConditionType*: uint16
    m_nCurrentValue*: uint32
    m_nTargetValue*: uint32
    m_bIsComplete*: bool

proc writeCActivityInvestCondition*(w: var BinaryWriter, c: CActivityInvestCondition) =
  w.writeUint32(c.m_nConditionId)
  w.writeUint16(c.m_nConditionType)
  w.writeUint32(c.m_nCurrentValue)
  w.writeUint32(c.m_nTargetValue)
  w.writeBool(c.m_bIsComplete)

type
  CActivityInvestData* = object
    m_nInvestId*: uint32
    m_nLevel*: uint16
    m_bIsBought*: bool
    m_vecConditions*: seq[CActivityInvestCondition]

proc writeCActivityInvestData*(w: var BinaryWriter, d: CActivityInvestData) =
  w.writeUint32(d.m_nInvestId)
  w.writeUint16(d.m_nLevel)
  w.writeBool(d.m_bIsBought)
  w.writeArray(d.m_vecConditions, proc(w: var BinaryWriter, c: CActivityInvestCondition) = w.writeCActivityInvestCondition(c))

# Requests
type
  CReqActivityCommon* = object
    m_nRequestType*: uint16
    m_nType*: uint16
    m_nTransID*: uint32
    m_nRewardId*: uint16
    m_nRewardType*: uint16
    m_strExtra*: string

proc readCReqActivityCommon*(r: var BinaryReader): CReqActivityCommon =
  result.m_nRequestType = r.readUint16()
  result.m_nType = r.readUint16()
  result.m_nTransID = r.readUint32()
  result.m_nRewardId = r.readUint16()
  result.m_nRewardType = r.readUint16()
  result.m_strExtra = r.readString()

type
  CReqActivityShip* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nId*: uint32
    m_strExtra*: string

proc readCReqActivityShip*(r: var BinaryReader): CReqActivityShip =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nId = r.readUint32()
  result.m_strExtra = r.readString()

type
  CReqActivitySuperRoulette* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nTaskIndex*: uint16
    m_nCountRewardIndex*: uint16

proc readCReqActivitySuperRoulette*(r: var BinaryReader): CReqActivitySuperRoulette =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nTaskIndex = r.readUint16()
  result.m_nCountRewardIndex = r.readUint16()

type
  CReqActivityContinueGift* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nRewardIndex*: uint16

proc readCReqActivityContinueGift*(r: var BinaryReader): CReqActivityContinueGift =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nRewardIndex = r.readUint16()

type
  CReqActivityDiamondChoice* = object
    m_nType*: uint16
    m_nTransID*: uint32
    m_nId*: uint16
    m_vecChoiceIndex*: seq[uint16]

proc readCReqActivityDiamondChoice*(r: var BinaryReader): CReqActivityDiamondChoice =
  result.m_nType = r.readUint16()
  result.m_nTransID = r.readUint32()
  result.m_nId = r.readUint16()
  result.m_vecChoiceIndex = r.readArray(proc(r: var BinaryReader): uint16 = r.readUint16())

type
  CReqActivityExchange* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nIndex*: uint16
    m_strExtra*: string

proc readCReqActivityExchange*(r: var BinaryReader): CReqActivityExchange =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nIndex = r.readUint16()
  result.m_strExtra = r.readString()

type
  CReqActivityInvest* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nInvestId*: uint32

proc readCReqActivityInvest*(r: var BinaryReader): CReqActivityInvest =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nInvestId = r.readUint32()

# Responses
type
  CRespActivityCommon* = object
    m_stRetMsg*: CCommonRespMsg
    m_nActivityId*: uint32
    m_nStatus*: uint16

proc writeCRespActivityCommon*(w: var BinaryWriter, r: CRespActivityCommon) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint32(r.m_nActivityId)
  w.writeUint16(r.m_nStatus)

type
  CActivityShipRelicsGift* = object
    m_nGiftId*: uint32
    m_nStatus*: uint16

proc writeCActivityShipRelicsGift*(w: var BinaryWriter, g: CActivityShipRelicsGift) =
  w.writeUint32(g.m_nGiftId)
  w.writeUint16(g.m_nStatus)

type
  CRespActivityShip* = object
    m_stRetMsg*: CCommonRespMsg
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_nScore*: uint32
    m_vecRelicsGifts*: seq[CActivityShipRelicsGift]

proc writeCRespActivityShip*(w: var BinaryWriter, r: CRespActivityShip) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)
  w.writeUint32(r.m_nScore)
  w.writeArray(r.m_vecRelicsGifts, proc(w: var BinaryWriter, g: CActivityShipRelicsGift) = w.writeCActivityShipRelicsGift(g))

type
  CRespActivitySuperRoulette* = object
    m_stRetMsg*: CCommonRespMsg
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_nSpinCount*: uint32
    m_nFreeSpinCount*: uint16

proc writeCRespActivitySuperRoulette*(w: var BinaryWriter, r: CRespActivitySuperRoulette) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)
  w.writeUint32(r.m_nSpinCount)
  w.writeUint16(r.m_nFreeSpinCount)

type
  CRespActivityContinueGift* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDays*: uint16
    m_nRewardBits*: uint64
    m_nStartTime*: uint64
    m_nEndTime*: uint64

proc writeCRespActivityContinueGift*(w: var BinaryWriter, r: CRespActivityContinueGift) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint16(r.m_nDays)
  w.writeUint64(r.m_nRewardBits)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)

type
  CRespActivityInvest* = object
    m_stRetMsg*: CCommonRespMsg
    m_nStartTime*: uint64
    m_nEndTime*: uint64
    m_vecInvestData*: seq[CActivityInvestData]

proc writeCRespActivityInvest*(w: var BinaryWriter, r: CRespActivityInvest) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nEndTime)
  w.writeArray(r.m_vecInvestData, proc(w: var BinaryWriter, d: CActivityInvestData) = w.writeCActivityInvestData(d))

# ST Activity Requests
type
  STReqActivityGiftTower* = object
    m_nTransID*: uint32
    m_nType*: uint16
    m_nId*: uint32
    m_nNum*: uint32

proc readSTReqActivityGiftTower*(r: var BinaryReader): STReqActivityGiftTower =
  result.m_nTransID = r.readUint32()
  result.m_nType = r.readUint16()
  result.m_nId = r.readUint32()
  result.m_nNum = r.readUint32()

type
  STReqActivityBingo* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nId*: uint16

proc readSTReqActivityBingo*(r: var BinaryReader): STReqActivityBingo =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nId = r.readUint16()

type
  STReqActivityMining* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nBlockId*: uint16

proc readSTReqActivityMining*(r: var BinaryReader): STReqActivityMining =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nBlockId = r.readUint16()

type
  STReqActivityPiggyBank* = object
    m_nTransID*: uint32
    m_nRequestType*: uint16
    m_nBankId*: uint16

proc readSTReqActivityPiggyBank*(r: var BinaryReader): STReqActivityPiggyBank =
  result.m_nTransID = r.readUint32()
  result.m_nRequestType = r.readUint16()
  result.m_nBankId = r.readUint16()

# ST Activity Responses
type
  STCommonQuickBuyData* = object
    m_nItemId*: uint32
    m_nBuyTimes*: uint32
    m_nBuyTimesLimit*: uint32
    m_nBuyPrice*: uint32

proc writeSTCommonQuickBuyData*(w: var BinaryWriter, d: STCommonQuickBuyData) =
  w.writeUint32(d.m_nItemId)
  w.writeUint32(d.m_nBuyTimes)
  w.writeUint32(d.m_nBuyTimesLimit)
  w.writeUint32(d.m_nBuyPrice)

type
  STRespActivityGiftTower* = object
    m_stRetMsg*: CCommonRespMsg
    m_nTag*: uint32
    m_nStartTime*: uint64
    m_nGameEndTime*: uint64
    m_nRewardEndTime*: uint64
    m_nEndTime*: uint64
    m_nOpenGameLevel*: uint32
    m_nProgressValue*: uint32
    m_nProgressRewardBits*: uint32
    m_nRewardTowerLayer*: uint32
    m_nTowerHeight*: uint32
    m_nTowerFinishNum*: uint32
    hasQuickBuy*: bool
    m_stQuickBuy*: STCommonQuickBuyData
    m_nDailyTime*: uint64
    m_nTowerGroup*: uint32
    m_nTowerld*: uint32

proc writeSTRespActivityGiftTower*(w: var BinaryWriter, r: STRespActivityGiftTower) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint32(r.m_nTag)
  w.writeUint64(r.m_nStartTime)
  w.writeUint64(r.m_nGameEndTime)
  w.writeUint64(r.m_nRewardEndTime)
  w.writeUint64(r.m_nEndTime)
  w.writeUint32(r.m_nOpenGameLevel)
  w.writeUint32(r.m_nProgressValue)
  w.writeUint32(r.m_nProgressRewardBits)
  w.writeUint32(r.m_nRewardTowerLayer)
  w.writeUint32(r.m_nTowerHeight)
  w.writeUint32(r.m_nTowerFinishNum)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeUint16(0)
  if r.hasQuickBuy:
    w.writeSTCommonQuickBuyData(r.m_stQuickBuy)
  w.writeUint16(0)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeUint64(r.m_nDailyTime)
  w.writeUint32(r.m_nTowerGroup)
  w.writeUint32(r.m_nTowerld)

type
  STRespActivityPiggyBank* = object
    m_stRetMsg*: CCommonRespMsg
    m_nDailyTime*: uint64
    m_nBeginTime*: uint64
    m_nEndTime*: uint64
    m_nFreeRewardStatus*: uint16
    m_nBuyBankID*: uint16
    m_nTotalBattle*: uint32
    m_nTag*: uint16

proc writeSTRespActivityPiggyBank*(w: var BinaryWriter, r: STRespActivityPiggyBank) =
  w.writeCCommonRespMsg(r.m_stRetMsg)
  w.writeUint64(r.m_nDailyTime)
  w.writeUint64(r.m_nBeginTime)
  w.writeUint64(r.m_nEndTime)
  w.writeUint16(r.m_nFreeRewardStatus)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeUint16(r.m_nBuyBankID)
  w.writeUint32(r.m_nTotalBattle)
  w.writeArray(newSeq[uint32](), proc(w: var BinaryWriter, x: uint32) = discard)
  w.writeUint16(r.m_nTag)

# Default factories
proc createDefaultActivityResponse*(): CRespActivityCommon =
  CRespActivityCommon(m_stRetMsg: createSuccessResponse(), m_nActivityId: 0, m_nStatus: 0)

proc createDefaultActivityShipResponse*(): CRespActivityShip =
  let now = getTime().toUnix().uint64
  CRespActivityShip(
    m_stRetMsg: createSuccessResponse(),
    m_nStartTime: now,
    m_nEndTime: now + 86400 * 7,
    m_nScore: 0,
    m_vecRelicsGifts: @[])
