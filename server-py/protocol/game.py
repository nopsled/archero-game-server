"""
Game Protocol Packets

Core gameplay structures: towers, battles, harvests, achievements, etc.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .binary import BinaryReader, BinaryWriter
from .common import CCommonRespMsg, write_c_common_resp_msg


# =============================================================================
# GAME TOWER
# =============================================================================


@dataclass
class CGameTowerInfo:
    m_nType: int  # UInt16
    m_bWin: bool  # Boolean
    m_nTransID: int  # UInt32


def read_c_game_tower_info(reader: BinaryReader) -> CGameTowerInfo:
    return CGameTowerInfo(
        m_nType=reader.read_uint16(),
        m_bWin=reader.read_bool(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CPlayTowerInfo:
    m_nType: int  # UInt16
    m_nTowerId: int  # UInt32
    m_nFloor: int  # UInt16
    m_nTransID: int  # UInt32


def read_c_play_tower_info(reader: BinaryReader) -> CPlayTowerInfo:
    return CPlayTowerInfo(
        m_nType=reader.read_uint16(),
        m_nTowerId=reader.read_uint32(),
        m_nFloor=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CRespGameTowerInfo:
    m_stRetMsg: CCommonRespMsg
    m_nFloor: int = 0  # UInt16
    m_nMaxFloor: int = 0  # UInt16


def write_c_resp_game_tower_info(
    writer: BinaryWriter, resp: CRespGameTowerInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nFloor)
    writer.write_uint16(resp.m_nMaxFloor)


@dataclass
class CRespPlayTowerInfo:
    m_stRetMsg: CCommonRespMsg
    m_nTowerId: int = 0  # UInt32
    m_nFloor: int = 0  # UInt16


def write_c_resp_play_tower_info(
    writer: BinaryWriter, resp: CRespPlayTowerInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nTowerId)
    writer.write_uint16(resp.m_nFloor)


# =============================================================================
# HARVEST
# =============================================================================


@dataclass
class CReqGameHarvest2:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32


def read_c_req_game_harvest2(reader: BinaryReader) -> CReqGameHarvest2:
    return CReqGameHarvest2(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CRespGameHarvest2:
    m_stRetMsg: CCommonRespMsg
    m_nCoins: int = 0  # UInt32
    m_nExp: int = 0  # UInt32
    m_nTimestamp: int = 0  # UInt64
    m_nMaxTime: int = 0  # UInt32


def write_c_resp_game_harvest2(writer: BinaryWriter, resp: CRespGameHarvest2) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nCoins)
    writer.write_uint32(resp.m_nExp)
    writer.write_uint64(resp.m_nTimestamp)
    writer.write_uint32(resp.m_nMaxTime)


# =============================================================================
# ACHIEVEMENTS
# =============================================================================


@dataclass
class CGameAchieveInfo:
    m_nType: int  # UInt16
    m_nId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_game_achieve_info(reader: BinaryReader) -> CGameAchieveInfo:
    return CGameAchieveInfo(
        m_nType=reader.read_uint16(),
        m_nId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class STCommonAchievementData:
    m_nId: int  # UInt32
    m_nProgress: int  # UInt32
    m_nLevel: int  # UInt16
    m_bIsClaimed: bool  # Boolean


def write_st_common_achievement_data(
    writer: BinaryWriter, data: STCommonAchievementData
) -> None:
    writer.write_uint32(data.m_nId)
    writer.write_uint32(data.m_nProgress)
    writer.write_uint16(data.m_nLevel)
    writer.write_bool(data.m_bIsClaimed)


@dataclass
class CRespGameAchieveInfo:
    m_stRetMsg: CCommonRespMsg
    m_vecAchievements: List[STCommonAchievementData] = field(default_factory=list)


def write_c_resp_game_achieve_info(
    writer: BinaryWriter, resp: CRespGameAchieveInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(
        resp.m_vecAchievements, lambda a: write_st_common_achievement_data(writer, a)
    )


# =============================================================================
# ADS
# =============================================================================


@dataclass
class CGameAd:
    m_nType: int  # UInt16
    m_nAdId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_game_ad(reader: BinaryReader) -> CGameAd:
    return CGameAd(
        m_nType=reader.read_uint16(),
        m_nAdId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CRespGameAd:
    m_stRetMsg: CCommonRespMsg
    m_nAdCount: int = 0  # UInt16
    m_nDailyLimit: int = 0  # UInt16


def write_c_resp_game_ad(writer: BinaryWriter, resp: CRespGameAd) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nAdCount)
    writer.write_uint16(resp.m_nDailyLimit)


# =============================================================================
# GUIDE
# =============================================================================


@dataclass
class CReqGameGuide:
    m_nType: int  # UInt16
    m_nGuideId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_req_game_guide(reader: BinaryReader) -> CReqGameGuide:
    return CReqGameGuide(
        m_nType=reader.read_uint16(),
        m_nGuideId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CRespGameGuide:
    m_stRetMsg: CCommonRespMsg
    m_nGuideBits: int = 0  # UInt64


def write_c_resp_game_guide(writer: BinaryWriter, resp: CRespGameGuide) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nGuideBits)


# =============================================================================
# GAME CLIENT DATA
# =============================================================================


@dataclass
class CReqGameClientData:
    m_nType: int  # UInt16
    m_strClientData: Optional[str] = None  # String


def read_c_req_game_client_data(reader: BinaryReader) -> CReqGameClientData:
    return CReqGameClientData(
        m_nType=reader.read_uint16(),
        m_strClientData=reader.read_string(),
    )


@dataclass
class CRespGameClientData:
    m_stRetMsg: CCommonRespMsg
    m_strClientData: str = ""  # String


def write_c_resp_game_client_data(
    writer: BinaryWriter, resp: CRespGameClientData
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_string(resp.m_strClientData)


# =============================================================================
# PVE SEASON
# =============================================================================


@dataclass
class CPveSeasonInfo:
    m_nType: int  # UInt16
    m_nSeasonId: int  # UInt32
    m_nTransID: int  # UInt32


def read_c_pve_season_info(reader: BinaryReader) -> CPveSeasonInfo:
    return CPveSeasonInfo(
        m_nType=reader.read_uint16(),
        m_nSeasonId=reader.read_uint32(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class CRespPveSeasonInfo:
    m_stRetMsg: CCommonRespMsg
    m_nSeasonId: int = 0  # UInt32
    m_nRank: int = 0  # UInt32
    m_nScore: int = 0  # UInt32


def write_c_resp_pve_season_info(
    writer: BinaryWriter, resp: CRespPveSeasonInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nSeasonId)
    writer.write_uint32(resp.m_nRank)
    writer.write_uint32(resp.m_nScore)


# =============================================================================
# FISHING
# =============================================================================


@dataclass
class CReqGameFishing:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32


def read_c_req_game_fishing(reader: BinaryReader) -> CReqGameFishing:
    return CReqGameFishing(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
    )


@dataclass
class STGameFishingRank:
    m_nRank: int  # UInt32
    m_nScore: int  # UInt32
    m_strName: str  # String


def write_st_game_fishing_rank(writer: BinaryWriter, rank: STGameFishingRank) -> None:
    writer.write_uint32(rank.m_nRank)
    writer.write_uint32(rank.m_nScore)
    writer.write_string(rank.m_strName)


@dataclass
class CRespGameFishing:
    m_stRetMsg: CCommonRespMsg
    m_nScore: int = 0  # UInt32
    m_vecRanks: List[STGameFishingRank] = field(default_factory=list)


def write_c_resp_game_fishing(writer: BinaryWriter, resp: CRespGameFishing) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nScore)
    writer.write_array(resp.m_vecRanks, lambda r: write_st_game_fishing_rank(writer, r))
