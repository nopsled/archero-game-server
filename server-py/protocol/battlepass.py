"""
Battlepass Protocol Packets

Battle pass related request and response packets.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import time

from .binary import BinaryReader, BinaryWriter
from .common import CCommonRespMsg, write_c_common_resp_msg, create_success_response


# =============================================================================
# BATTLEPASS REWARD CONFIG
# =============================================================================


@dataclass
class CBattlePassExtraRewardConf:
    nExtraCnt: int  # UInt16
    nExtraCondParam: int  # UInt16
    strReward: str  # String (e.g., "4,2203,1")
    strBigReward: str  # String


def write_c_battle_pass_extra_reward_conf(
    writer: BinaryWriter, conf: CBattlePassExtraRewardConf
) -> None:
    writer.write_uint16(conf.nExtraCnt)
    writer.write_uint16(conf.nExtraCondParam)
    writer.write_string(conf.strReward)
    writer.write_string(conf.strBigReward)


@dataclass
class CBattlePassRewardConf:
    nId: int  # UInt32
    nCondType: int  # UInt16
    nParam: int  # UInt16
    m_arrRewardInfo: List[str] = field(default_factory=list)  # String[]


def write_c_battle_pass_reward_conf(
    writer: BinaryWriter, conf: CBattlePassRewardConf
) -> None:
    writer.write_uint32(conf.nId)
    writer.write_uint16(conf.nCondType)
    writer.write_uint16(conf.nParam)
    writer.write_array(conf.m_arrRewardInfo, lambda s: writer.write_string(s))


# =============================================================================
# BATTLEPASS REQUEST
# =============================================================================


@dataclass
class CReqBattlepassReward:
    m_nTransID: int  # UInt32
    m_nBattleTag: int  # UInt32
    m_nType: int  # UInt16
    m_nKillsOrRewardId: int  # UInt32
    m_nRewardIndex: int  # UInt32
    m_strExtra: Optional[str] = None  # String
    m_strExtend: Optional[str] = None  # String
    m_nBattlePassType: int = 0  # UInt16
    m_nBattlePassId: int = 0  # UInt16
    m_nBattlePassIndex: int = 0  # UInt16


def read_c_req_battlepass_reward(reader: BinaryReader) -> CReqBattlepassReward:
    return CReqBattlepassReward(
        m_nTransID=reader.read_uint32(),
        m_nBattleTag=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_nKillsOrRewardId=reader.read_uint32(),
        m_nRewardIndex=reader.read_uint32(),
        m_strExtra=reader.read_string(),
        m_strExtend=reader.read_string(),
        m_nBattlePassType=reader.read_uint16(),
        m_nBattlePassId=reader.read_uint16(),
        m_nBattlePassIndex=reader.read_uint16(),
    )


# =============================================================================
# BATTLEPASS RESPONSE
# =============================================================================


@dataclass
class CRespBattlepassConf:
    m_stRetMsg: CCommonRespMsg
    nStartTimestamp: int = 0  # UInt64
    nEndTimestamp: int = 0  # UInt64
    m_nBattlepassTag: int = 0  # UInt32
    bIsGin: bool = False  # Boolean
    nType: int = 0  # UInt16
    nEventId: int = 0  # UInt16
    stExtraReward: Optional[CBattlePassExtraRewardConf] = None
    m_arrTagInfo: List[CBattlePassRewardConf] = field(default_factory=list)
    nMinVersion: int = 0  # UInt16
    nMaxVersion: int = 0  # UInt16
    nSweepAddCnt: int = 0  # UInt16
    nSweepCoinAdd: int = 0  # UInt16
    bIsNew: bool = False  # Boolean
    nDropRelicsAdd: int = 0  # UInt16
    nHarvestQuickAdd: int = 0  # UInt16
    nDropBossEggAdd: int = 0  # UInt16
    nRate: int = 0  # UInt16


def write_c_resp_battlepass_conf(
    writer: BinaryWriter, resp: CRespBattlepassConf
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.nStartTimestamp)
    writer.write_uint64(resp.nEndTimestamp)
    writer.write_uint32(resp.m_nBattlepassTag)
    writer.write_bool(resp.bIsGin)
    writer.write_uint16(resp.nType)
    writer.write_uint16(resp.nEventId)
    if resp.stExtraReward:
        write_c_battle_pass_extra_reward_conf(writer, resp.stExtraReward)
    writer.write_array(
        resp.m_arrTagInfo, lambda c: write_c_battle_pass_reward_conf(writer, c)
    )
    writer.write_uint16(resp.nMinVersion)
    writer.write_uint16(resp.nMaxVersion)
    writer.write_uint16(resp.nSweepAddCnt)
    writer.write_uint16(resp.nSweepCoinAdd)
    writer.write_bool(resp.bIsNew)
    writer.write_uint16(resp.nDropRelicsAdd)
    writer.write_uint16(resp.nHarvestQuickAdd)
    writer.write_uint16(resp.nDropBossEggAdd)
    writer.write_uint16(resp.nRate)
    # mapGameActivityBattlePassPhaseConf - empty dictionary
    writer.write_uint16(0)


@dataclass
class CRespBattlepassReward:
    m_stRetMsg: CCommonRespMsg
    m_nKills: int = 0  # UInt32
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_battlepass_reward(
    writer: BinaryWriter, resp: CRespBattlepassReward
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nKills)
    writer.write_uint64(resp.m_nRewardBits)


# =============================================================================
# ST ACTIVITY BATTLEPASS
# =============================================================================


@dataclass
class STActivityBattlePassItem:
    m_nId: int  # UInt32
    m_nProgress: int  # UInt32
    m_nRewardBits: int  # UInt64


def write_st_activity_battle_pass_item(
    writer: BinaryWriter, item: STActivityBattlePassItem
) -> None:
    writer.write_uint32(item.m_nId)
    writer.write_uint32(item.m_nProgress)
    writer.write_uint64(item.m_nRewardBits)


@dataclass
class STActivityBattlePass:
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nTag: int = 0  # UInt32
    m_vecItems: List[STActivityBattlePassItem] = field(default_factory=list)


def write_st_activity_battle_pass(
    writer: BinaryWriter, bp: STActivityBattlePass
) -> None:
    writer.write_uint64(bp.m_nStartTime)
    writer.write_uint64(bp.m_nEndTime)
    writer.write_uint32(bp.m_nTag)
    writer.write_array(
        bp.m_vecItems, lambda i: write_st_activity_battle_pass_item(writer, i)
    )


# =============================================================================
# DEFAULT FACTORIES
# =============================================================================


def create_default_battlepass_conf() -> CRespBattlepassConf:
    now = int(time.time())
    return CRespBattlepassConf(
        m_stRetMsg=create_success_response(),
        nStartTimestamp=now - 86400,
        nEndTimestamp=now + 86400 * 30,
        m_nBattlepassTag=165,
        bIsGin=True,
        nType=2,
        nEventId=101,
        stExtraReward=CBattlePassExtraRewardConf(
            nExtraCnt=5,
            nExtraCondParam=100,
            strReward="4,2203,1",
            strBigReward="4,2204,1",
        ),
        m_arrTagInfo=[
            CBattlePassRewardConf(
                nId=1,
                nCondType=0,
                nParam=0,
                m_arrRewardInfo=["4,2305,1", "4,2306,1", "3,39133,2"],
            ),
            CBattlePassRewardConf(
                nId=2,
                nCondType=0,
                nParam=50,
                m_arrRewardInfo=["4,2201,1", "4,2204,1", "10,12,1"],
            ),
            CBattlePassRewardConf(
                nId=3,
                nCondType=0,
                nParam=100,
                m_arrRewardInfo=["4,2203,1", "1,26,1", "1,2,200"],
            ),
            CBattlePassRewardConf(
                nId=4,
                nCondType=0,
                nParam=150,
                m_arrRewardInfo=["1,2,10", "3,36012,2", "4,2306,1"],
            ),
            CBattlePassRewardConf(
                nId=5,
                nCondType=0,
                nParam=200,
                m_arrRewardInfo=["1,21,1", "4,2305,1", "4,2204,1"],
            ),
        ],
        nMinVersion=193,
        nMaxVersion=999,
        nSweepAddCnt=10,
        nSweepCoinAdd=30,
        bIsNew=True,
        nDropRelicsAdd=10,
        nHarvestQuickAdd=15,
        nDropBossEggAdd=15,
        nRate=20,
    )
