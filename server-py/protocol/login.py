"""
Login Protocol Packets

Request: CUserLoginPacket
Response: CRespUserLoginPacket

Based on captured field data from protocol discovery.
"""

from dataclasses import dataclass, field
from typing import List
import time

from .binary import BinaryReader, BinaryWriter
from .common import (
    CEquipmentItem,
    CHeroItem,
    CRestoreItem,
    CTimestampItem,
    CBoxAssuranceItem,
    STPetInfo,
    STHeadItem,
    CArtifact,
    write_c_equipment_item,
    write_c_hero_item,
    write_c_restore_item,
    write_c_timestamp_item,
    write_c_box_assurance_item,
    write_st_pet_info,
    write_st_head_item,
    write_c_artifact,
    create_default_equipment_item,
    create_default_hero,
    create_default_restore_item,
    create_default_box_assurance,
)


# =============================================================================
# LOGIN REQUEST
# =============================================================================


@dataclass
class CUserLoginPacket:
    """Login request from client"""

    m_nTransID: int  # UInt32
    m_strPlatform: str  # String - "android" or "ios"


def read_c_user_login_packet(reader: BinaryReader) -> CUserLoginPacket:
    return CUserLoginPacket(
        m_nTransID=reader.read_uint32(),
        m_strPlatform=reader.read_string(),
    )


# =============================================================================
# LOGIN RESPONSE
# =============================================================================


@dataclass
class CRespUserLoginPacket:
    """Full login response (50+ fields). Field order based on captured packet data."""

    # Core player data
    m_nTransID: int = 0  # UInt32
    m_nCoins: int = 0  # UInt32
    m_nDiamonds: int = 0  # Int32
    m_nLevel: int = 1  # UInt16
    m_nExperince: int = 0  # UInt32
    m_nUserRawId: int = 0  # UInt64
    m_nNowTime: int = 0  # UInt64 - current server time
    m_nTodayEndTimestamp: int = 0  # UInt64 - end of day

    # Progress data
    m_nMaxLayer: int = 0  # UInt16
    m_nLayerBoxID: int = 0  # UInt16
    m_nTreasureRandomCount: int = 0  # UInt32
    m_nBattleRebornCount: int = 0  # UInt16

    # Account info
    m_strUserAccessToken: str = ""  # String
    m_strNickName: str = ""  # String
    m_nAccountStatus: int = 0  # UInt16

    # Items data
    m_nExtraNormalDiamondItem: int = 0  # UInt16
    m_nExtraLargeDiamondItem: int = 0  # UInt16
    m_nLargeDiamondItemCount: int = 0  # UInt16

    # Game system flags
    m_nGameSystemMask: int = 0  # UInt64

    # Hero layer
    m_nMaxHeroLayer: int = 0  # UInt16
    m_nHeroLayerBoxID: int = 0  # UInt16

    # Cash/monetization
    m_nTotalCash: int = 0  # UInt32
    m_bTalentBackCoin: bool = True  # Boolean

    # Ads
    m_nAdCount: int = 0  # UInt16

    # Email binding
    m_strBindEmailAddress: str = ""  # String

    # Activity recharge
    vecActivityRechargeResetType: List[int] = field(default_factory=list)  # UInt16[]

    # Skins
    m_bHeroSkinItemIsBuy: bool = False  # Boolean
    m_bHeroSkinSeniorItemIsBuy: bool = False  # Boolean
    m_strSkinItemIapProductId: str = "[]"  # String

    # Profile
    m_nHeadIcon: int = 0  # UInt32
    m_nHeadFrame: int = 0  # UInt32
    m_nHeadFrameTimestamp: int = 0  # UInt64

    # IDFA
    m_bOpenIdfa: bool = False  # Boolean

    # Rename
    m_nRemameDiamonds: int = 0  # UInt32
    m_nRenameCount: int = 0  # UInt16

    # Chapter fail counts
    m_nChapFailCnt: int = 0  # UInt16
    m_nHeroChapFailCnt: int = 0  # UInt16

    # Purchase data
    m_nPurcahseInTowWeeks: int = 0  # UInt32
    m_nLatest3PurchaseAvg: int = 0  # UInt32

    # Mix box
    m_nMixBoxItem: int = 0  # UInt16
    m_nMixBoxSingleCount: int = 0  # UInt16
    m_nMixBoxSingleTotalCount: int = 0  # UInt16
    m_nMixBoxTenCount: int = 0  # UInt16

    # Dragon box
    m_nDragonBoxItem: int = 0  # UInt16
    m_nDragonBoxCountLow: int = 0  # UInt16
    m_nDragonBoxCountMid: int = 0  # UInt16
    m_nDragonBoxCountHigh: int = 0  # UInt16

    # Free coin
    m_nFreeCoinTimestamp: int = 0  # UInt64

    # VIP
    m_nVipLevel: int = 0  # UInt16
    m_nVipScore: int = 0  # UInt32

    # Bans
    m_nChapterBanTimestamp: int = 0  # UInt64

    # Relics box
    m_nRelicsBoxItem: int = 0  # UInt16
    m_nRelicsBoxCountLow: int = 0  # UInt16
    m_nRelicsBoxCountHigh: int = 0  # UInt16

    # Offline battle
    m_nOfflineBattleCount: int = 0  # UInt16

    # Equip S box
    m_nEquipSBoxItem: int = 0  # UInt16
    m_nEquipSBoxCountLow: int = 0  # UInt16
    m_nEquipSBoxCountHigh: int = 0  # UInt16

    # Worker box
    m_nWorkerBoxKeyCount: int = 0  # UInt32
    m_nWorkerBoxCountLow: int = 0  # UInt16
    m_nWorkerBoxCountMid: int = 0  # UInt16
    m_nWorkerBoxCountHigh: int = 0  # UInt16

    # Pet box
    m_nPetBoxKeyCount: int = 0  # UInt32
    m_nPetBoxCountLow: int = 0  # UInt16
    m_nPetBoxCountMid: int = 0  # UInt16
    m_nPetBoxCountHigh: int = 0  # UInt16

    # Habby ID
    m_strHabbyID: str = ""  # String

    # Must drop
    m_nMustDropMask: int = 0  # UInt64

    # Guild
    m_nGuildStopTimestamp: int = 0  # UInt64

    # Star diamond
    m_nStarDiamond: int = 0  # UInt32

    # Extended experience/coins
    m_nExperinceInt64: int = 0  # UInt64
    m_nCoinsInt64: int = 0  # Int64

    # Imprint box
    m_nImprintBoxKeyCount: int = 0  # UInt32

    # Hell layer
    m_nMaxHellLayer: int = 0  # UInt16
    m_nHellLayerBoxID: int = 0  # UInt16
    m_nChapHellFailCount: int = 0  # UInt16

    # Other
    m_nUpgradeLevel: int = 0  # UInt16
    m_nCardThemeId: int = 0  # UInt32
    m_nCardThemeTimestamp: int = 0  # UInt64

    # Arrays
    m_arrayEquipData: List[CEquipmentItem] = field(default_factory=list)
    m_arrayRestoreData: List[CRestoreItem] = field(default_factory=list)
    m_arrayTimestampData: List[CTimestampItem] = field(default_factory=list)
    m_arrayHeroData: List[CHeroItem] = field(default_factory=list)
    m_vecHeadItem: List[STHeadItem] = field(default_factory=list)
    m_vecPetInfo: List[STPetInfo] = field(default_factory=list)
    m_arrayAssuranceData: List[CBoxAssuranceItem] = field(default_factory=list)
    m_vecArtifactArray: List[CArtifact] = field(default_factory=list)


def write_c_resp_user_login_packet(
    writer: BinaryWriter, resp: CRespUserLoginPacket
) -> None:
    """Write CRespUserLoginPacket to binary stream. Field order must match client expectations."""

    # Arrays come first in the response
    writer.write_array(
        resp.m_arrayEquipData, lambda item: write_c_equipment_item(writer, item)
    )
    writer.write_array(
        resp.m_arrayRestoreData, lambda item: write_c_restore_item(writer, item)
    )
    writer.write_array(
        resp.m_arrayTimestampData, lambda item: write_c_timestamp_item(writer, item)
    )

    # Core player data
    writer.write_uint32(resp.m_nTransID)
    writer.write_uint32(resp.m_nCoins)
    writer.write_int32(resp.m_nDiamonds)
    writer.write_uint16(resp.m_nMaxLayer)
    writer.write_uint16(resp.m_nLayerBoxID)
    writer.write_uint16(resp.m_nLevel)
    writer.write_uint32(resp.m_nExperince)
    writer.write_uint32(resp.m_nTreasureRandomCount)
    writer.write_uint16(resp.m_nBattleRebornCount)
    writer.write_string(resp.m_strUserAccessToken)
    writer.write_uint64(resp.m_nUserRawId)
    writer.write_uint16(resp.m_nExtraNormalDiamondItem)
    writer.write_uint16(resp.m_nExtraLargeDiamondItem)
    writer.write_uint64(resp.m_nGameSystemMask)
    writer.write_uint16(resp.m_nMaxHeroLayer)
    writer.write_uint16(resp.m_nHeroLayerBoxID)
    writer.write_uint16(resp.m_nLargeDiamondItemCount)
    writer.write_uint64(resp.m_nNowTime)
    writer.write_uint64(resp.m_nTodayEndTimestamp)
    writer.write_uint16(resp.m_nAccountStatus)
    writer.write_uint32(resp.m_nTotalCash)
    writer.write_bool(resp.m_bTalentBackCoin)
    writer.write_uint16(resp.m_nAdCount)

    # Hero array
    writer.write_array(
        resp.m_arrayHeroData, lambda item: write_c_hero_item(writer, item)
    )

    writer.write_string(resp.m_strBindEmailAddress)
    writer.write_array(
        resp.vecActivityRechargeResetType, lambda item: writer.write_uint16(item)
    )
    writer.write_bool(resp.m_bHeroSkinItemIsBuy)
    writer.write_string(resp.m_strNickName)
    writer.write_uint32(resp.m_nHeadIcon)
    writer.write_uint32(resp.m_nHeadFrame)
    writer.write_uint64(resp.m_nHeadFrameTimestamp)
    writer.write_array(
        resp.m_vecHeadItem, lambda item: write_st_head_item(writer, item)
    )
    writer.write_bool(resp.m_bOpenIdfa)
    writer.write_uint32(resp.m_nRemameDiamonds)
    writer.write_uint16(resp.m_nRenameCount)
    writer.write_bool(resp.m_bHeroSkinSeniorItemIsBuy)
    writer.write_string(resp.m_strSkinItemIapProductId)
    writer.write_uint16(resp.m_nChapFailCnt)
    writer.write_uint16(resp.m_nHeroChapFailCnt)
    writer.write_uint32(resp.m_nPurcahseInTowWeeks)
    writer.write_uint32(resp.m_nLatest3PurchaseAvg)
    writer.write_uint16(resp.m_nMixBoxItem)
    writer.write_uint16(resp.m_nMixBoxSingleCount)
    writer.write_uint16(resp.m_nMixBoxSingleTotalCount)
    writer.write_uint16(resp.m_nMixBoxTenCount)
    writer.write_uint16(resp.m_nDragonBoxItem)
    writer.write_uint16(resp.m_nDragonBoxCountLow)
    writer.write_uint16(resp.m_nDragonBoxCountMid)
    writer.write_uint16(resp.m_nDragonBoxCountHigh)
    writer.write_uint64(resp.m_nFreeCoinTimestamp)
    writer.write_uint16(resp.m_nVipLevel)
    writer.write_uint32(resp.m_nVipScore)
    writer.write_uint64(resp.m_nChapterBanTimestamp)
    writer.write_uint16(resp.m_nRelicsBoxItem)
    writer.write_uint16(resp.m_nRelicsBoxCountLow)
    writer.write_uint16(resp.m_nRelicsBoxCountHigh)
    writer.write_uint16(resp.m_nOfflineBattleCount)
    writer.write_uint16(resp.m_nEquipSBoxItem)
    writer.write_uint16(resp.m_nEquipSBoxCountLow)
    writer.write_uint16(resp.m_nEquipSBoxCountHigh)
    writer.write_uint32(resp.m_nWorkerBoxKeyCount)
    writer.write_uint16(resp.m_nWorkerBoxCountLow)
    writer.write_uint16(resp.m_nWorkerBoxCountMid)
    writer.write_uint16(resp.m_nWorkerBoxCountHigh)
    writer.write_array(resp.m_vecPetInfo, lambda item: write_st_pet_info(writer, item))
    writer.write_uint32(resp.m_nPetBoxKeyCount)
    writer.write_uint16(resp.m_nPetBoxCountLow)
    writer.write_uint16(resp.m_nPetBoxCountMid)
    writer.write_uint16(resp.m_nPetBoxCountHigh)
    writer.write_string(resp.m_strHabbyID)
    writer.write_uint64(resp.m_nMustDropMask)
    writer.write_uint64(resp.m_nGuildStopTimestamp)
    writer.write_uint32(resp.m_nStarDiamond)
    writer.write_uint64(resp.m_nExperinceInt64)
    writer.write_int64(resp.m_nCoinsInt64)
    writer.write_uint32(resp.m_nImprintBoxKeyCount)
    writer.write_array(
        resp.m_arrayAssuranceData, lambda item: write_c_box_assurance_item(writer, item)
    )
    writer.write_uint16(resp.m_nMaxHellLayer)
    writer.write_uint16(resp.m_nHellLayerBoxID)
    writer.write_uint16(resp.m_nChapHellFailCount)
    writer.write_array(
        resp.m_vecArtifactArray, lambda item: write_c_artifact(writer, item)
    )
    writer.write_uint16(resp.m_nUpgradeLevel)
    writer.write_uint32(resp.m_nCardThemeId)
    writer.write_uint64(resp.m_nCardThemeTimestamp)


def create_default_login_response(trans_id: int) -> CRespUserLoginPacket:
    """Create a default login response for new players"""
    now = int(time.time())
    today_end = now + (86400 - (now % 86400))

    return CRespUserLoginPacket(
        m_nTransID=trans_id,
        m_nCoins=199,
        m_nDiamonds=120,
        m_nLevel=1,
        m_nExperince=0,
        m_nUserRawId=72276397022577740,  # Random large ID
        m_nNowTime=now,
        m_nTodayEndTimestamp=today_end,
        m_nMaxLayer=0,
        m_nLayerBoxID=0,
        m_nTreasureRandomCount=0,
        m_nBattleRebornCount=0,
        m_strUserAccessToken="",
        m_strNickName="",
        m_nAccountStatus=0,
        m_nExtraNormalDiamondItem=0,
        m_nExtraLargeDiamondItem=0,
        m_nLargeDiamondItemCount=10,
        m_nGameSystemMask=3458764513820540928,
        m_nMaxHeroLayer=0,
        m_nHeroLayerBoxID=0,
        m_nTotalCash=0,
        m_bTalentBackCoin=True,
        m_nAdCount=3,
        m_strBindEmailAddress="",
        vecActivityRechargeResetType=[],
        m_bHeroSkinItemIsBuy=False,
        m_bHeroSkinSeniorItemIsBuy=False,
        m_strSkinItemIapProductId="[]",
        m_nHeadIcon=0,
        m_nHeadFrame=0,
        m_nHeadFrameTimestamp=0,
        m_bOpenIdfa=False,
        m_nRemameDiamonds=0,
        m_nRenameCount=0,
        m_nChapFailCnt=0,
        m_nHeroChapFailCnt=0,
        m_nPurcahseInTowWeeks=0,
        m_nLatest3PurchaseAvg=0,
        m_nMixBoxItem=0,
        m_nMixBoxSingleCount=3,
        m_nMixBoxSingleTotalCount=10,
        m_nMixBoxTenCount=10,
        m_nDragonBoxItem=0,
        m_nDragonBoxCountLow=20,
        m_nDragonBoxCountMid=100,
        m_nDragonBoxCountHigh=220,
        m_nFreeCoinTimestamp=0,
        m_nVipLevel=0,
        m_nVipScore=0,
        m_nChapterBanTimestamp=0,
        m_nRelicsBoxItem=0,
        m_nRelicsBoxCountLow=20,
        m_nRelicsBoxCountHigh=120,
        m_nOfflineBattleCount=0,
        m_nEquipSBoxItem=0,
        m_nEquipSBoxCountLow=10,
        m_nEquipSBoxCountHigh=60,
        m_nWorkerBoxKeyCount=0,
        m_nWorkerBoxCountLow=10,
        m_nWorkerBoxCountMid=20,
        m_nWorkerBoxCountHigh=80,
        m_nPetBoxKeyCount=0,
        m_nPetBoxCountLow=20,
        m_nPetBoxCountMid=100,
        m_nPetBoxCountHigh=300,
        m_strHabbyID="",
        m_nMustDropMask=0,
        m_nGuildStopTimestamp=0,
        m_nStarDiamond=0,
        m_nExperinceInt64=0,
        m_nCoinsInt64=199,
        m_nImprintBoxKeyCount=0,
        m_nMaxHellLayer=0,
        m_nHellLayerBoxID=0,
        m_nChapHellFailCount=0,
        m_nUpgradeLevel=0,
        m_nCardThemeId=0,
        m_nCardThemeTimestamp=0,
        # Arrays - starter equipment and hero
        m_arrayEquipData=[
            create_default_equipment_item("10909050", 10000),  # Basic bow
            create_default_equipment_item("10909051", 1010101),  # Basic armor
        ],
        m_arrayRestoreData=[
            create_default_restore_item(45, 20),  # Keys
            create_default_restore_item(0, 1),
            create_default_restore_item(0, 1),
            create_default_restore_item(4, 4),
            create_default_restore_item(5, 5),
            create_default_restore_item(4, 4),
            create_default_restore_item(5, 5),
            create_default_restore_item(5, 5),
            create_default_restore_item(0, 0),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
            create_default_restore_item(1, 1),
        ],
        m_arrayTimestampData=[
            CTimestampItem(m_nIndex=0, m_i64Timestamp=now),
            CTimestampItem(m_nIndex=1, m_i64Timestamp=now),
            CTimestampItem(m_nIndex=2, m_i64Timestamp=now),
            CTimestampItem(m_nIndex=3, m_i64Timestamp=now),
        ],
        m_arrayHeroData=[create_default_hero()],
        m_vecHeadItem=[],
        m_vecPetInfo=[],
        m_arrayAssuranceData=[create_default_box_assurance()],
        m_vecArtifactArray=[],
    )
