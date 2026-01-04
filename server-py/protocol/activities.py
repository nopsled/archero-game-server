"""
Activity Protocol Packets

Request and response packets for various game activities.
Based on captured field data from protocol discovery.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import time

from .binary import BinaryReader, BinaryWriter
from .common import CCommonRespMsg, write_c_common_resp_msg, create_success_response


# =============================================================================
# ACTIVITY COMMON DATA
# =============================================================================


@dataclass
class CActivityCommonData:
    m_nActivityId: int  # UInt32
    m_nActivityType: int  # UInt16
    m_nStartTime: int  # UInt64
    m_nEndTime: int  # UInt64
    m_nStatus: int  # UInt16


def write_c_activity_common_data(
    writer: BinaryWriter, data: CActivityCommonData
) -> None:
    writer.write_uint32(data.m_nActivityId)
    writer.write_uint16(data.m_nActivityType)
    writer.write_uint64(data.m_nStartTime)
    writer.write_uint64(data.m_nEndTime)
    writer.write_uint16(data.m_nStatus)


# =============================================================================
# ACTIVITY INVEST
# =============================================================================


@dataclass
class CActivityInvestCondition:
    m_nConditionId: int  # UInt32
    m_nConditionType: int  # UInt16
    m_nCurrentValue: int  # UInt32
    m_nTargetValue: int  # UInt32
    m_bIsComplete: bool  # Boolean


def write_c_activity_invest_condition(
    writer: BinaryWriter, cond: CActivityInvestCondition
) -> None:
    writer.write_uint32(cond.m_nConditionId)
    writer.write_uint16(cond.m_nConditionType)
    writer.write_uint32(cond.m_nCurrentValue)
    writer.write_uint32(cond.m_nTargetValue)
    writer.write_bool(cond.m_bIsComplete)


@dataclass
class CActivityInvestData:
    m_nInvestId: int  # UInt32
    m_nLevel: int  # UInt16
    m_bIsBought: bool  # Boolean
    m_vecConditions: List[CActivityInvestCondition] = field(default_factory=list)


def write_c_activity_invest_data(
    writer: BinaryWriter, data: CActivityInvestData
) -> None:
    writer.write_uint32(data.m_nInvestId)
    writer.write_uint16(data.m_nLevel)
    writer.write_bool(data.m_bIsBought)
    writer.write_array(
        data.m_vecConditions, lambda c: write_c_activity_invest_condition(writer, c)
    )


# =============================================================================
# ACTIVITY REQUESTS
# =============================================================================


@dataclass
class CReqActivityCommon:
    m_nRequestType: int  # UInt16
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nRewardId: int  # UInt16
    m_nRewardType: int  # UInt16
    m_strExtra: Optional[str] = None  # String


def read_c_req_activity_common(reader: BinaryReader) -> CReqActivityCommon:
    return CReqActivityCommon(
        m_nRequestType=reader.read_uint16(),
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nRewardId=reader.read_uint16(),
        m_nRewardType=reader.read_uint16(),
        m_strExtra=reader.read_string(),
    )


@dataclass
class CReqActivityShip:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nId: int  # UInt32
    m_strExtra: Optional[str] = None  # String


def read_c_req_activity_ship(reader: BinaryReader) -> CReqActivityShip:
    return CReqActivityShip(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_strExtra=reader.read_string(),
    )


@dataclass
class CReqActivitySuperRoulette:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nTaskIndex: int  # UInt16
    m_nCountRewardIndex: int  # UInt16


def read_c_req_activity_super_roulette(
    reader: BinaryReader,
) -> CReqActivitySuperRoulette:
    return CReqActivitySuperRoulette(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nTaskIndex=reader.read_uint16(),
        m_nCountRewardIndex=reader.read_uint16(),
    )


@dataclass
class CReqActivityContinueGift:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nRewardIndex: int  # UInt16


def read_c_req_activity_continue_gift(reader: BinaryReader) -> CReqActivityContinueGift:
    return CReqActivityContinueGift(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nRewardIndex=reader.read_uint16(),
    )


@dataclass
class CReqActivityDiamondChoice:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nId: int  # UInt16
    m_vecChoiceIndex: List[int] = field(default_factory=list)  # UInt16[]


def read_c_req_activity_diamond_choice(
    reader: BinaryReader,
) -> CReqActivityDiamondChoice:
    return CReqActivityDiamondChoice(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nId=reader.read_uint16(),
        m_vecChoiceIndex=reader.read_array(lambda: reader.read_uint16()),
    )


@dataclass
class CReqActivityExchange:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nIndex: int  # UInt16
    m_strExtra: Optional[str] = None  # String


def read_c_req_activity_exchange(reader: BinaryReader) -> CReqActivityExchange:
    return CReqActivityExchange(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nIndex=reader.read_uint16(),
        m_strExtra=reader.read_string(),
    )


@dataclass
class CReqActivityInvest:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nInvestId: int  # UInt32


def read_c_req_activity_invest(reader: BinaryReader) -> CReqActivityInvest:
    return CReqActivityInvest(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nInvestId=reader.read_uint32(),
    )


# =============================================================================
# ACTIVITY RESPONSES
# =============================================================================


@dataclass
class CRespActivityCommon:
    m_stRetMsg: CCommonRespMsg
    m_nActivityId: int = 0  # UInt32
    m_nStatus: int = 0  # UInt16


def write_c_resp_activity_common(
    writer: BinaryWriter, resp: CRespActivityCommon
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nActivityId)
    writer.write_uint16(resp.m_nStatus)


@dataclass
class CActivityShipRelicsGift:
    m_nGiftId: int  # UInt32
    m_nStatus: int  # UInt16


def write_c_activity_ship_relics_gift(
    writer: BinaryWriter, gift: CActivityShipRelicsGift
) -> None:
    writer.write_uint32(gift.m_nGiftId)
    writer.write_uint16(gift.m_nStatus)


@dataclass
class CRespActivityShip:
    m_stRetMsg: CCommonRespMsg
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nScore: int = 0  # UInt32
    m_vecRelicsGifts: List[CActivityShipRelicsGift] = field(default_factory=list)


def write_c_resp_activity_ship(writer: BinaryWriter, resp: CRespActivityShip) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint32(resp.m_nScore)
    writer.write_array(
        resp.m_vecRelicsGifts, lambda g: write_c_activity_ship_relics_gift(writer, g)
    )


@dataclass
class CRespActivitySuperRoulette:
    m_stRetMsg: CCommonRespMsg
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nSpinCount: int = 0  # UInt32
    m_nFreeSpinCount: int = 0  # UInt16


def write_c_resp_activity_super_roulette(
    writer: BinaryWriter, resp: CRespActivitySuperRoulette
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint32(resp.m_nSpinCount)
    writer.write_uint16(resp.m_nFreeSpinCount)


@dataclass
class CRespActivityContinueGift:
    m_stRetMsg: CCommonRespMsg
    m_nDays: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64


def write_c_resp_activity_continue_gift(
    writer: BinaryWriter, resp: CRespActivityContinueGift
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDays)
    writer.write_uint64(resp.m_nRewardBits)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)


@dataclass
class CRespActivityInvest:
    m_stRetMsg: CCommonRespMsg
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_vecInvestData: List[CActivityInvestData] = field(default_factory=list)


def write_c_resp_activity_invest(
    writer: BinaryWriter, resp: CRespActivityInvest
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_array(
        resp.m_vecInvestData, lambda d: write_c_activity_invest_data(writer, d)
    )


# =============================================================================
# ST ACTIVITY REQUESTS
# =============================================================================


@dataclass
class STReqActivityGiftTower:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nNum: int  # UInt32


def read_st_req_activity_gift_tower(reader: BinaryReader) -> STReqActivityGiftTower:
    return STReqActivityGiftTower(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_nNum=reader.read_uint32(),
    )


@dataclass
class STReqActivityBingo:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nId: int  # UInt16


def read_st_req_activity_bingo(reader: BinaryReader) -> STReqActivityBingo:
    return STReqActivityBingo(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nId=reader.read_uint16(),
    )


@dataclass
class STReqActivityMining:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nBlockId: int  # UInt16


def read_st_req_activity_mining(reader: BinaryReader) -> STReqActivityMining:
    return STReqActivityMining(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nBlockId=reader.read_uint16(),
    )


@dataclass
class STReqActivityPiggyBank:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nBankId: int  # UInt16


def read_st_req_activity_piggy_bank(reader: BinaryReader) -> STReqActivityPiggyBank:
    return STReqActivityPiggyBank(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nBankId=reader.read_uint16(),
    )


# =============================================================================
# ST ACTIVITY RESPONSES
# =============================================================================


@dataclass
class STCommonQuickBuyData:
    m_nItemId: int = 0  # UInt32
    m_nBuyTimes: int = 0  # UInt32
    m_nBuyTimesLimit: int = 0  # UInt32
    m_nBuyPrice: int = 0  # UInt32


def write_st_common_quick_buy_data(
    writer: BinaryWriter, data: STCommonQuickBuyData
) -> None:
    writer.write_uint32(data.m_nItemId)
    writer.write_uint32(data.m_nBuyTimes)
    writer.write_uint32(data.m_nBuyTimesLimit)
    writer.write_uint32(data.m_nBuyPrice)


@dataclass
class STRespActivityGiftTower:
    m_stRetMsg: CCommonRespMsg
    m_nTag: int = 0  # UInt32
    m_nStartTime: int = 0  # UInt64
    m_nGameEndTime: int = 0  # UInt64
    m_nRewardEndTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nOpenGameLevel: int = 0  # UInt32
    m_nProgressValue: int = 0  # UInt32
    m_nProgressRewardBits: int = 0  # UInt32
    m_nRewardTowerLayer: int = 0  # UInt32
    m_nTowerHeight: int = 0  # UInt32
    m_nTowerFinishNum: int = 0  # UInt32
    m_stQuickBuy: Optional[STCommonQuickBuyData] = None
    m_nDailyTime: int = 0  # UInt64
    m_nTowerGroup: int = 0  # UInt32
    m_nTowerld: int = 0  # UInt32


def write_st_resp_activity_gift_tower(
    writer: BinaryWriter, resp: STRespActivityGiftTower
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nTag)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nGameEndTime)
    writer.write_uint64(resp.m_nRewardEndTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint32(resp.m_nOpenGameLevel)
    writer.write_uint32(resp.m_nProgressValue)
    writer.write_uint32(resp.m_nProgressRewardBits)
    writer.write_uint32(resp.m_nRewardTowerLayer)
    writer.write_uint32(resp.m_nTowerHeight)
    writer.write_uint32(resp.m_nTowerFinishNum)
    writer.write_array([], lambda: None)  # m_vecGridDatas
    writer.write_uint16(0)  # m_mapInitItemNum - empty dict
    if resp.m_stQuickBuy:
        write_st_common_quick_buy_data(writer, resp.m_stQuickBuy)
    writer.write_uint16(0)  # m_stAutoDeleteActivityItem
    writer.write_array([], lambda: None)  # m_stGift
    writer.write_array([], lambda: None)  # m_stTask
    writer.write_array([], lambda: None)  # m_stShop
    writer.write_uint64(resp.m_nDailyTime)
    writer.write_uint32(resp.m_nTowerGroup)
    writer.write_uint32(resp.m_nTowerld)


@dataclass
class STRespActivityPiggyBank:
    m_stRetMsg: CCommonRespMsg
    m_nDailyTime: int = 0  # UInt64
    m_nBeginTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nFreeRewardStatus: int = 0  # UInt16
    m_nBuyBankID: int = 0  # UInt16
    m_nTotalBattle: int = 0  # UInt32
    m_nTag: int = 0  # UInt16


def write_st_resp_activity_piggy_bank(
    writer: BinaryWriter, resp: STRespActivityPiggyBank
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nDailyTime)
    writer.write_uint64(resp.m_nBeginTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint16(resp.m_nFreeRewardStatus)
    writer.write_array([], lambda: None)  # m_vecFreeRewards
    writer.write_uint16(resp.m_nBuyBankID)
    writer.write_uint32(resp.m_nTotalBattle)
    writer.write_array([], lambda: None)  # m_vecActivityPiggyBankDatas
    writer.write_uint16(resp.m_nTag)


# =============================================================================
# DEFAULT FACTORIES
# =============================================================================


def create_default_activity_response(trans_id: int) -> CRespActivityCommon:
    return CRespActivityCommon(
        m_stRetMsg=create_success_response(),
        m_nActivityId=trans_id,
        m_nStatus=0,
    )


def create_default_activity_ship_response() -> CRespActivityShip:
    now = int(time.time())
    return CRespActivityShip(
        m_stRetMsg=create_success_response(),
        m_nStartTime=now,
        m_nEndTime=now + 86400 * 7,
        m_nScore=0,
        m_vecRelicsGifts=[],
    )
