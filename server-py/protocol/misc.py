"""
Shop, Guild, VIP, and Miscellaneous Protocol Packets
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .binary import BinaryReader, BinaryWriter
from .common import CCommonRespMsg, write_c_common_resp_msg


# =============================================================================
# SHOP
# =============================================================================


@dataclass
class CRespShopBoxActivity:
    m_stRetMsg: CCommonRespMsg
    m_nActivityId: int = 0  # UInt32
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64


def write_c_resp_shop_box_activity(
    writer: BinaryWriter, resp: CRespShopBoxActivity
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nActivityId)
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)


# =============================================================================
# MONTH CARD / PRIVILEGE
# =============================================================================


@dataclass
class CReqMonthCard:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nPlatformIndex: int  # UInt16


def read_c_req_month_card(reader: BinaryReader) -> CReqMonthCard:
    return CReqMonthCard(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nPlatformIndex=reader.read_uint16(),
    )


@dataclass
class CRespMonthCard:
    m_stRetMsg: CCommonRespMsg
    m_nMonthCardEndTime: int = 0  # UInt64
    m_nDoubleCardEndTime: int = 0  # UInt64
    m_nDailyRewardBits: int = 0  # UInt64


def write_c_resp_month_card(writer: BinaryWriter, resp: CRespMonthCard) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nMonthCardEndTime)
    writer.write_uint64(resp.m_nDoubleCardEndTime)
    writer.write_uint64(resp.m_nDailyRewardBits)


@dataclass
class CReqPrivilegeCard:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16


def read_c_req_privilege_card(reader: BinaryReader) -> CReqPrivilegeCard:
    return CReqPrivilegeCard(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
    )


@dataclass
class CRespPrivilegeCard:
    m_stRetMsg: CCommonRespMsg
    m_nEndTime: int = 0  # UInt64
    m_nType: int = 0  # UInt16


def write_c_resp_privilege_card(writer: BinaryWriter, resp: CRespPrivilegeCard) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint16(resp.m_nType)


# =============================================================================
# VIP
# =============================================================================


@dataclass
class STReqVip:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16


def read_st_req_vip(reader: BinaryReader) -> STReqVip:
    return STReqVip(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
    )


@dataclass
class STRespVip:
    m_stRetMsg: CCommonRespMsg
    m_nVipLevel: int = 0  # UInt16
    m_nVipScore: int = 0  # UInt32
    m_nRewardBits: int = 0  # UInt64


def write_st_resp_vip(writer: BinaryWriter, resp: STRespVip) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nVipLevel)
    writer.write_uint32(resp.m_nVipScore)
    writer.write_uint64(resp.m_nRewardBits)


# =============================================================================
# GUILD
# =============================================================================


@dataclass
class CGuildTaskInfo:
    m_nTaskId: int  # UInt32
    m_nProgress: int  # UInt32
    m_bIsClaimed: bool  # Boolean


def write_c_guild_task_info(writer: BinaryWriter, info: CGuildTaskInfo) -> None:
    writer.write_uint32(info.m_nTaskId)
    writer.write_uint32(info.m_nProgress)
    writer.write_bool(info.m_bIsClaimed)


@dataclass
class CRespGuildTaskInfo:
    m_stRetMsg: CCommonRespMsg
    m_vecTasks: List[CGuildTaskInfo] = field(default_factory=list)


def write_c_resp_guild_task_info(
    writer: BinaryWriter, resp: CRespGuildTaskInfo
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecTasks, lambda t: write_c_guild_task_info(writer, t))


@dataclass
class CGuildAchInfo:
    m_nAchId: int  # UInt32
    m_nProgress: int  # UInt32
    m_nLevel: int  # UInt16


def write_c_guild_ach_info(writer: BinaryWriter, info: CGuildAchInfo) -> None:
    writer.write_uint32(info.m_nAchId)
    writer.write_uint32(info.m_nProgress)
    writer.write_uint16(info.m_nLevel)


@dataclass
class CRespGuildUserLogin:
    m_stRetMsg: CCommonRespMsg
    m_nGuildId: int = 0  # UInt64
    m_strGuildName: str = ""  # String
    m_nGuildLevel: int = 0  # UInt16


def write_c_resp_guild_user_login(
    writer: BinaryWriter, resp: CRespGuildUserLogin
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nGuildId)
    writer.write_string(resp.m_strGuildName)
    writer.write_uint16(resp.m_nGuildLevel)


@dataclass
class CRespQueryGuildRedpacket:
    m_stRetMsg: CCommonRespMsg
    m_nRedpacketCount: int = 0  # UInt16


def write_c_resp_query_guild_redpacket(
    writer: BinaryWriter, resp: CRespQueryGuildRedpacket
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nRedpacketCount)


# =============================================================================
# USER BACK / LOGIN GIFT
# =============================================================================


@dataclass
class CReqUserBack:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nRewardType: int  # UInt16
    m_nRewardIndex: int  # UInt16
    m_strExtra: Optional[str] = None  # String


def read_c_req_user_back(reader: BinaryReader) -> CReqUserBack:
    return CReqUserBack(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nRewardType=reader.read_uint16(),
        m_nRewardIndex=reader.read_uint16(),
        m_strExtra=reader.read_string(),
    )


@dataclass
class CRespUserBack:
    m_stRetMsg: CCommonRespMsg
    m_nDays: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_user_back(writer: BinaryWriter, resp: CRespUserBack) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDays)
    writer.write_uint64(resp.m_nRewardBits)


@dataclass
class CReqLoginGift:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nRewardIndex: int  # UInt16


def read_c_req_login_gift(reader: BinaryReader) -> CReqLoginGift:
    return CReqLoginGift(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nRewardIndex=reader.read_uint16(),
    )


@dataclass
class CRespLoginGift:
    m_stRetMsg: CCommonRespMsg
    m_nDays: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_login_gift(writer: BinaryWriter, resp: CRespLoginGift) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDays)
    writer.write_uint64(resp.m_nRewardBits)


@dataclass
class CReqWeeklyGift:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16


def read_c_req_weekly_gift(reader: BinaryReader) -> CReqWeeklyGift:
    return CReqWeeklyGift(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
    )


@dataclass
class CRespWeeklyGift:
    m_stRetMsg: CCommonRespMsg
    m_nWeeks: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_weekly_gift(writer: BinaryWriter, resp: CRespWeeklyGift) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nWeeks)
    writer.write_uint64(resp.m_nRewardBits)


# =============================================================================
# FIRST CHARGE
# =============================================================================


@dataclass
class CReqFirstCharge:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16


def read_c_req_first_charge(reader: BinaryReader) -> CReqFirstCharge:
    return CReqFirstCharge(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
    )


@dataclass
class CRespFirstCharge:
    m_stRetMsg: CCommonRespMsg
    m_nStatus: int = 0  # UInt16
    m_nRewardBits: int = 0  # UInt64


def write_c_resp_first_charge(writer: BinaryWriter, resp: CRespFirstCharge) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nStatus)
    writer.write_uint64(resp.m_nRewardBits)


# =============================================================================
# FIRST IAP INFO
# =============================================================================


@dataclass
class CQueryFirstIAPInfo:
    m_nType: int  # UInt16
    m_nTransId: int  # UInt32


def read_c_query_first_iap_info(reader: BinaryReader) -> CQueryFirstIAPInfo:
    return CQueryFirstIAPInfo(
        m_nType=reader.read_uint16(),
        m_nTransId=reader.read_uint32(),
    )


# =============================================================================
# HABBY ID BINDING
# =============================================================================


@dataclass
class STReqBindingHabbyID:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_strAuthCode: Optional[str] = None  # String
    m_strLanguage: str = ""  # String


def read_st_req_binding_habby_id(reader: BinaryReader) -> STReqBindingHabbyID:
    return STReqBindingHabbyID(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_strAuthCode=reader.read_string(),
        m_strLanguage=reader.read_string(),
    )


@dataclass
class STRespBindingHabbyID:
    m_stRetMsg: CCommonRespMsg
    m_strHabbyID: str = ""  # String
    m_nStatus: int = 0  # UInt16


def write_st_resp_binding_habby_id(
    writer: BinaryWriter, resp: STRespBindingHabbyID
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_string(resp.m_strHabbyID)
    writer.write_uint16(resp.m_nStatus)


# =============================================================================
# FARM
# =============================================================================


@dataclass
class CReqFarm:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_nSlotId: int  # UInt16


def read_c_req_farm(reader: BinaryReader) -> CReqFarm:
    return CReqFarm(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_nSlotId=reader.read_uint16(),
    )


@dataclass
class CFarmSlot:
    m_nSlotId: int  # UInt16
    m_nPlantId: int  # UInt32
    m_nPlantTime: int  # UInt64
    m_nStatus: int  # UInt16


def write_c_farm_slot(writer: BinaryWriter, slot: CFarmSlot) -> None:
    writer.write_uint16(slot.m_nSlotId)
    writer.write_uint32(slot.m_nPlantId)
    writer.write_uint64(slot.m_nPlantTime)
    writer.write_uint16(slot.m_nStatus)


@dataclass
class CRespFarm:
    m_stRetMsg: CCommonRespMsg
    m_vecSlots: List[CFarmSlot] = field(default_factory=list)


def write_c_resp_farm(writer: BinaryWriter, resp: CRespFarm) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecSlots, lambda s: write_c_farm_slot(writer, s))


# =============================================================================
# MONSTER EGG / HATCH
# =============================================================================


@dataclass
class CMonsterEgg:
    m_nEggId: int  # UInt32
    m_nSlotId: int  # UInt16
    m_nStartTime: int  # UInt64


def write_c_monster_egg(writer: BinaryWriter, egg: CMonsterEgg) -> None:
    writer.write_uint32(egg.m_nEggId)
    writer.write_uint16(egg.m_nSlotId)
    writer.write_uint64(egg.m_nStartTime)


@dataclass
class CMonsterHatch:
    m_nMonsterId: int  # UInt32
    m_nLevel: int  # UInt16
    m_nStar: int  # UInt16


def write_c_monster_hatch(writer: BinaryWriter, hatch: CMonsterHatch) -> None:
    writer.write_uint32(hatch.m_nMonsterId)
    writer.write_uint16(hatch.m_nLevel)
    writer.write_uint16(hatch.m_nStar)


@dataclass
class CRespMonsterHatch:
    m_stRetMsg: CCommonRespMsg
    m_vecHatched: List[CMonsterHatch] = field(default_factory=list)


def write_c_resp_monster_hatch(writer: BinaryWriter, resp: CRespMonsterHatch) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecHatched, lambda h: write_c_monster_hatch(writer, h))


# =============================================================================
# SHIP BATTLE SEASON
# =============================================================================


@dataclass
class STReqShipBattleSeasonGhostShip:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16


def read_st_req_ship_battle_season_ghost_ship(
    reader: BinaryReader,
) -> STReqShipBattleSeasonGhostShip:
    return STReqShipBattleSeasonGhostShip(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
    )


@dataclass
class CShipBattleBaseRank:
    m_nRank: int  # UInt32
    m_nScore: int  # UInt32
    m_strName: str  # String


def write_c_ship_battle_base_rank(
    writer: BinaryWriter, rank: CShipBattleBaseRank
) -> None:
    writer.write_uint32(rank.m_nRank)
    writer.write_uint32(rank.m_nScore)
    writer.write_string(rank.m_strName)


@dataclass
class STShipBattleSeasonIsLandRankInfo:
    m_vecRank: List[CShipBattleBaseRank] = field(default_factory=list)
    m_nRankValue: int = 0  # UInt64
    m_nRank: int = 0  # UInt32


def write_st_ship_battle_season_island_rank_info(
    writer: BinaryWriter, info: STShipBattleSeasonIsLandRankInfo
) -> None:
    writer.write_array(
        info.m_vecRank, lambda r: write_c_ship_battle_base_rank(writer, r)
    )
    writer.write_uint64(info.m_nRankValue)
    writer.write_uint32(info.m_nRank)


@dataclass
class STRespShipBattleSeasonGhostShip:
    m_stRetMsg: CCommonRespMsg
    m_nRemainFreeChallenges: int = 0  # UInt32
    m_nPayChallengeCount: int = 0  # UInt32
    m_nDailyChallengeCount: int = 0  # UInt32
    m_nStartTime: int = 0  # UInt64
    m_nEndTime: int = 0  # UInt64
    m_nRankEndTime: int = 0  # UInt64
    mstRankInfo: Optional[STShipBattleSeasonIsLandRankInfo] = None
    m_nChallengeLimit: int = 0  # UInt32


def write_st_resp_ship_battle_season_ghost_ship(
    writer: BinaryWriter, resp: STRespShipBattleSeasonGhostShip
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nRemainFreeChallenges)
    writer.write_uint32(resp.m_nPayChallengeCount)
    writer.write_uint32(resp.m_nDailyChallengeCount)
    writer.write_array([], lambda: None)  # m_vecGhostShipData
    writer.write_uint64(resp.m_nStartTime)
    writer.write_uint64(resp.m_nEndTime)
    writer.write_uint64(resp.m_nRankEndTime)
    if resp.mstRankInfo:
        write_st_ship_battle_season_island_rank_info(writer, resp.mstRankInfo)
    writer.write_uint32(resp.m_nChallengeLimit)


# =============================================================================
# DAILY IAP GIFT
# =============================================================================


@dataclass
class CDailyGiftGemData:
    m_nGemId: int  # UInt32
    m_nCount: int  # UInt16


def write_c_daily_gift_gem_data(writer: BinaryWriter, data: CDailyGiftGemData) -> None:
    writer.write_uint32(data.m_nGemId)
    writer.write_uint16(data.m_nCount)


@dataclass
class CDailyGiftHeroData:
    m_nHeroId: int  # UInt32
    m_nFragments: int  # UInt16


def write_c_daily_gift_hero_data(
    writer: BinaryWriter, data: CDailyGiftHeroData
) -> None:
    writer.write_uint32(data.m_nHeroId)
    writer.write_uint16(data.m_nFragments)


@dataclass
class CReqDailyIapGift:
    m_nTransID: int  # UInt32
    m_nRequestType: int  # UInt16
    m_nSelectHeroIndex: int  # UInt32


def read_c_req_daily_iap_gift(reader: BinaryReader) -> CReqDailyIapGift:
    return CReqDailyIapGift(
        m_nTransID=reader.read_uint32(),
        m_nRequestType=reader.read_uint16(),
        m_nSelectHeroIndex=reader.read_uint32(),
    )


@dataclass
class CRespDailyIapGift:
    m_stRetMsg: CCommonRespMsg
    m_nDays: int = 0  # UInt16
    m_vecGems: List[CDailyGiftGemData] = field(default_factory=list)
    m_vecHeroes: List[CDailyGiftHeroData] = field(default_factory=list)


def write_c_resp_daily_iap_gift(writer: BinaryWriter, resp: CRespDailyIapGift) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nDays)
    writer.write_array(resp.m_vecGems, lambda g: write_c_daily_gift_gem_data(writer, g))
    writer.write_array(
        resp.m_vecHeroes, lambda h: write_c_daily_gift_hero_data(writer, h)
    )
