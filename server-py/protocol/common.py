"""
Common Protocol Types

Shared data structures used across all GameProtocol packets.
Based on captured field data from protocol discovery.
"""

from dataclasses import dataclass, field
from typing import Optional, List
import time

from .binary import BinaryWriter


# =============================================================================
# COMMON RESPONSE MESSAGE
# =============================================================================


@dataclass
class CCommonRespMsg:
    """Response wrapper with status code. Every response includes this structure."""

    m_unStatusCode: int = 0  # UInt16 - 0 = success
    m_strInfo: str = ""  # String - error/info message


def write_c_common_resp_msg(writer: BinaryWriter, msg: CCommonRespMsg) -> None:
    writer.write_uint16(msg.m_unStatusCode)
    writer.write_string(msg.m_strInfo)
    # Write minimal STCommonData (m_nChange = false, rest empty)
    writer.write_bool(False)  # m_nChange - client skips other fields if False


def create_success_response() -> CCommonRespMsg:
    return CCommonRespMsg(m_unStatusCode=0, m_strInfo="")


# =============================================================================
# EQUIPMENT ITEM
# =============================================================================


@dataclass
class CEquipmentItem:
    """Equipment/weapon data"""

    m_nUniqueID: str  # String - unique item ID
    m_nRowID: int  # UInt64
    m_nEquipID: int  # UInt32 - equipment type (10000 = basic bow)
    m_nLevel: int = 1  # UInt32
    m_nFragment: int = 1  # UInt32
    m_strExtend: str = ""  # String - extension data
    RelicEvolutionLevel: int = 0  # Int32
    RelicStar: int = 0  # Int32


def write_c_equipment_item(writer: BinaryWriter, item: CEquipmentItem) -> None:
    writer.write_string(item.m_nUniqueID)
    writer.write_uint64(item.m_nRowID)
    writer.write_uint32(item.m_nEquipID)
    writer.write_uint32(item.m_nLevel)
    writer.write_uint32(item.m_nFragment)
    writer.write_string(item.m_strExtend)
    writer.write_int32(item.RelicEvolutionLevel)
    writer.write_int32(item.RelicStar)


def create_default_equipment_item(unique_id: str, equip_id: int) -> CEquipmentItem:
    return CEquipmentItem(
        m_nUniqueID=unique_id,
        m_nRowID=int(unique_id),
        m_nEquipID=equip_id,
        m_nLevel=1,
        m_nFragment=1,
        m_strExtend="",
        RelicEvolutionLevel=0,
        RelicStar=0,
    )


# =============================================================================
# HERO ITEM
# =============================================================================


@dataclass
class CHeroItem:
    """Hero/character data"""

    m_nHeroId: int  # UInt32 (10000 = default hero)
    m_nStar: int = 0  # UInt32
    m_nCoopLevel: int = 1  # UInt16


def write_c_hero_item(writer: BinaryWriter, item: CHeroItem) -> None:
    writer.write_uint32(item.m_nHeroId)
    writer.write_uint32(item.m_nStar)
    writer.write_uint16(item.m_nCoopLevel)


def create_default_hero() -> CHeroItem:
    return CHeroItem(m_nHeroId=10000, m_nStar=0, m_nCoopLevel=1)


# =============================================================================
# RESTORE ITEM
# =============================================================================


@dataclass
class CRestoreItem:
    """Resource restoration/timer data"""

    m_nMin: int  # Int16
    m_nMax: int  # UInt16
    m_i64Timestamp: int = 0  # UInt64 - unix timestamp


def write_c_restore_item(writer: BinaryWriter, item: CRestoreItem) -> None:
    writer.write_int16(item.m_nMin)
    writer.write_uint16(item.m_nMax)
    writer.write_uint64(item.m_i64Timestamp)


def create_default_restore_item(current: int, max_value: int) -> CRestoreItem:
    return CRestoreItem(
        m_nMin=current,
        m_nMax=max_value,
        m_i64Timestamp=int(time.time()),
    )


# =============================================================================
# TIMESTAMP ITEM
# =============================================================================


@dataclass
class CTimestampItem:
    """Timestamp tracking data"""

    m_nIndex: int  # UInt16
    m_i64Timestamp: int  # UInt64


def write_c_timestamp_item(writer: BinaryWriter, item: CTimestampItem) -> None:
    writer.write_uint16(item.m_nIndex)
    writer.write_uint64(item.m_i64Timestamp)


# =============================================================================
# BOX ASSURANCE ITEM
# =============================================================================


@dataclass
class CBoxAssuranceItem:
    """Loot box pity/assurance counts"""

    m_nBoxCountLow: int = 10  # UInt16
    m_nBoxCountMid: int = 30  # UInt16
    m_nBoxCountHigh: int = 120  # UInt16


def write_c_box_assurance_item(writer: BinaryWriter, item: CBoxAssuranceItem) -> None:
    writer.write_uint16(item.m_nBoxCountLow)
    writer.write_uint16(item.m_nBoxCountMid)
    writer.write_uint16(item.m_nBoxCountHigh)


def create_default_box_assurance() -> CBoxAssuranceItem:
    return CBoxAssuranceItem(m_nBoxCountLow=10, m_nBoxCountMid=30, m_nBoxCountHigh=120)


# =============================================================================
# PET INFO
# =============================================================================


@dataclass
class STPetInfo:
    """Pet data"""

    m_nPetId: int  # UInt32
    m_nLevel: int  # UInt32
    m_nStar: int  # UInt32


def write_st_pet_info(writer: BinaryWriter, info: STPetInfo) -> None:
    writer.write_uint32(info.m_nPetId)
    writer.write_uint32(info.m_nLevel)
    writer.write_uint32(info.m_nStar)


# =============================================================================
# HEAD ITEM
# =============================================================================


@dataclass
class STHeadItem:
    """Player head/avatar frame item"""

    m_nHeadId: int  # UInt32
    m_nTimestamp: int  # UInt64


def write_st_head_item(writer: BinaryWriter, item: STHeadItem) -> None:
    writer.write_uint32(item.m_nHeadId)
    writer.write_uint64(item.m_nTimestamp)


# =============================================================================
# ARTIFACT
# =============================================================================


@dataclass
class CArtifact:
    """Artifact data"""

    m_nArtifactId: int  # UInt32
    m_nLevel: int  # UInt32
    m_nStar: int  # UInt32


def write_c_artifact(writer: BinaryWriter, artifact: CArtifact) -> None:
    writer.write_uint32(artifact.m_nArtifactId)
    writer.write_uint32(artifact.m_nLevel)
    writer.write_uint32(artifact.m_nStar)
