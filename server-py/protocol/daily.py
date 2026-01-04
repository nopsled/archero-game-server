"""
Daily Tasks and Rewards Protocol Packets
"""

from dataclasses import dataclass, field
from typing import List, Optional
import time

from .binary import BinaryReader, BinaryWriter
from .common import (
    CCommonRespMsg,
    CEquipmentItem,
    write_c_common_resp_msg,
    write_c_equipment_item,
    create_success_response,
)


# =============================================================================
# REWARD ITEM
# =============================================================================


@dataclass
class CRewardItem:
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nCount: int  # UInt32


def write_c_reward_item(writer: BinaryWriter, item: CRewardItem) -> None:
    writer.write_uint16(item.m_nType)
    writer.write_uint32(item.m_nId)
    writer.write_uint32(item.m_nCount)


# =============================================================================
# DAILY TASK REQUESTS
# =============================================================================


@dataclass
class CDailyTaskInfo:
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_daily_task_info(reader: BinaryReader) -> CDailyTaskInfo:
    return CDailyTaskInfo(
        m_nType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CWeeklyTaskInfo:
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_weekly_task_info(reader: BinaryReader) -> CWeeklyTaskInfo:
    return CWeeklyTaskInfo(
        m_nType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


# =============================================================================
# DAILY TASK RESPONSES
# =============================================================================


@dataclass
class STDailyTaskExtraRewardData:
    m_nId: int  # UInt32
    m_nProgress: int  # UInt32
    m_bIsClaimed: bool  # Boolean


def write_st_daily_task_extra_reward_data(
    writer: BinaryWriter, data: STDailyTaskExtraRewardData
) -> None:
    writer.write_uint32(data.m_nId)
    writer.write_uint32(data.m_nProgress)
    writer.write_bool(data.m_bIsClaimed)


@dataclass
class CRespDailyTaskInfo:
    m_stRetMsg: CCommonRespMsg
    m_nEndTime: int = 0  # UInt64
    m_nTaskPoint: int = 0  # UInt16
    m_nTaskReward: int = 0  # UInt64
    m_nTotalDiamonds: int = 0  # UInt32
    m_nTotalCoins: int = 0  # UInt32
    m_nLife: int = 0  # UInt16
    m_nBattleRebornCount: int = 0  # UInt16
    m_nNormalDiamondItem: int = 0  # UInt16
    m_nLargeDiamondItem: int = 0  # UInt16
    m_nLevel: int = 0  # UInt16
    m_nExperience: int = 0  # UInt32
    m_arrEquipInfo: Optional[List[CEquipmentItem]] = None
    m_nTowerLife: int = 0  # UInt16
    m_nMixBoxItem: int = 0  # UInt16
    m_nDragonBoxItem: int = 0  # UInt16
    m_nRelicsBoxItem: int = 0  # UInt16
    m_nEquipSBoxItem: int = 0  # UInt16
    m_vecExtraRewardData: List[STDailyTaskExtraRewardData] = field(default_factory=list)


def write_c_resp_daily_task_info(
    writer: BinaryWriter, resp: CRespDailyTaskInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint16(resp.m_nTaskPoint)
    writer.write_uint64(resp.m_nTaskReward)
    writer.write_uint32(resp.m_nTotalDiamonds)
    writer.write_uint32(resp.m_nTotalCoins)
    writer.write_uint16(resp.m_nLife)
    writer.write_uint16(resp.m_nBattleRebornCount)
    writer.write_uint16(resp.m_nNormalDiamondItem)
    writer.write_uint16(resp.m_nLargeDiamondItem)
    writer.write_uint16(resp.m_nLevel)
    writer.write_uint32(resp.m_nExperience)
    writer.write_array(
        resp.m_arrEquipInfo or [], lambda e: write_c_equipment_item(writer, e)
    )
    writer.write_uint16(resp.m_nTowerLife)
    writer.write_uint16(resp.m_nMixBoxItem)
    writer.write_uint16(resp.m_nDragonBoxItem)
    writer.write_uint16(resp.m_nRelicsBoxItem)
    writer.write_uint16(resp.m_nEquipSBoxItem)
    writer.write_array(
        resp.m_vecExtraRewardData,
        lambda d: write_st_daily_task_extra_reward_data(writer, d),
    )


@dataclass
class CRespWeeklyTaskInfo:
    m_stRetMsg: CCommonRespMsg
    m_nEndTime: int = 0  # UInt64
    m_nTaskPoint: int = 0  # UInt16
    m_nTaskReward: int = 0  # UInt64


def write_c_resp_weekly_task_info(
    writer: BinaryWriter, resp: CRespWeeklyTaskInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint16(resp.m_nTaskPoint)
    writer.write_uint64(resp.m_nTaskReward)


# =============================================================================
# DAILY PLAY
# =============================================================================


@dataclass
class CDailyPlay:
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nTransID: int  # UInt32
    m_nPartnerUserId: int  # UInt64
    m_nBattleTransID: int  # UInt32
    m_nDailyLevel: int  # UInt32


def read_c_daily_play(reader: BinaryReader) -> CDailyPlay:
    return CDailyPlay(
        m_nType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
        m_nPartnerUserId=reader.read_uint64(),
        m_nBattleTransID=reader.read_uint32(),
        m_nDailyLevel=reader.read_uint32(),
    )


@dataclass
class CRespDailyPlayInfo:
    m_stRetMsg: CCommonRespMsg
    m_nDailyPlayCount: int = 0  # UInt16
    m_nDailyPlayMax: int = 0  # UInt16


def write_c_resp_daily_play_info(
    writer: BinaryWriter, resp: CRespDailyPlayInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDailyPlayCount)
    writer.write_uint16(resp.m_nDailyPlayMax)


# =============================================================================
# IAP REWARDS
# =============================================================================


@dataclass
class CReqDailyIapReward:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_strExtra: Optional[str] = None  # String


def read_c_req_daily_iap_reward(reader: BinaryReader) -> CReqDailyIapReward:
    return CReqDailyIapReward(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_strExtra=reader.read_string(),
    )


@dataclass
class CReqWeekIapReward:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16


def read_c_req_week_iap_reward(reader: BinaryReader) -> CReqWeekIapReward:
    return CReqWeekIapReward(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
    )


@dataclass
class CReqMonthIapReward:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16


def read_c_req_month_iap_reward(reader: BinaryReader) -> CReqMonthIapReward:
    return CReqMonthIapReward(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
    )


@dataclass
class CRespDailyIapReward:
    m_stRetMsg: CCommonRespMsg
    m_nDays: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_daily_iap_reward(
    writer: BinaryWriter, resp: CRespDailyIapReward
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDays)
    writer.write_uint64(resp.m_nRewardBits)


@dataclass
class CRespWeekIapReward:
    m_stRetMsg: CCommonRespMsg
    m_nWeeks: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_week_iap_reward(
    writer: BinaryWriter, resp: CRespWeekIapReward
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nWeeks)
    writer.write_uint64(resp.m_nRewardBits)


@dataclass
class CRespMonthIapReward:
    m_stRetMsg: CCommonRespMsg
    m_nMonths: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_month_iap_reward(
    writer: BinaryWriter, resp: CRespMonthIapReward
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nMonths)
    writer.write_uint64(resp.m_nRewardBits)


# =============================================================================
# DEFAULT FACTORIES
# =============================================================================


def create_default_daily_task_info() -> CRespDailyTaskInfo:
    now = int(time.time())
    today_end = now + (86400 - (now % 86400))

    return CRespDailyTaskInfo(
        m_stRetMsg=create_success_response(),
        m_nEndTime=today_end,
        m_nTaskPoint=0,
        m_nTaskReward=0,
        m_nTotalDiamonds=0,
        m_nTotalCoins=0,
        m_nLife=0,
        m_nBattleRebornCount=0,
        m_nNormalDiamondItem=0,
        m_nLargeDiamondItem=0,
        m_nLevel=0,
        m_nExperience=0,
        m_arrEquipInfo=None,
        m_nTowerLife=0,
        m_nMixBoxItem=0,
        m_nDragonBoxItem=0,
        m_nRelicsBoxItem=0,
        m_nEquipSBoxItem=0,
        m_vecExtraRewardData=[],
    )
