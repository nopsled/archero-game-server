"""
Equipment Protocol Packets

Equipment, weapons, relics, and related structures.
"""

from dataclasses import dataclass, field
from typing import List

from .binary import BinaryReader, BinaryWriter
from .common import CCommonRespMsg, write_c_common_resp_msg, create_success_response


# =============================================================================
# EQUIPMENT REQUESTS
# =============================================================================


@dataclass
class CReqEquipWear:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_nEquipUniqueId: int  # UInt64
    m_nSlotId: int  # UInt16


def read_c_req_equip_wear(reader: BinaryReader) -> CReqEquipWear:
    return CReqEquipWear(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_nEquipUniqueId=reader.read_uint64(),
        m_nSlotId=reader.read_uint16(),
    )


@dataclass
class CReqEquipTotem:
    m_nTransID: int  # UInt32
    m_nType: int  # UInt16
    m_nTotemId: int  # UInt32


def read_c_req_equip_totem(reader: BinaryReader) -> CReqEquipTotem:
    return CReqEquipTotem(
        m_nTransID=reader.read_uint32(),
        m_nType=reader.read_uint16(),
        m_nTotemId=reader.read_uint32(),
    )


@dataclass
class CEquipRefine:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nPosId: int  # UInt16
    m_nCarvingId: int  # UInt32
    m_nCarvingIdx: int  # UInt16
    arrayEquipId: List[int] = field(default_factory=list)  # UInt64[]
    vecCompositeId: List[int] = field(default_factory=list)  # UInt32[]


def read_c_equip_refine(reader: BinaryReader) -> CEquipRefine:
    return CEquipRefine(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nPosId=reader.read_uint16(),
        m_nCarvingId=reader.read_uint32(),
        m_nCarvingIdx=reader.read_uint16(),
        arrayEquipId=reader.read_array(lambda: reader.read_uint64()),
        vecCompositeId=reader.read_array(lambda: reader.read_uint32()),
    )


# =============================================================================
# EQUIPMENT RESPONSES
# =============================================================================


@dataclass
class CRespEquipWear:
    m_stRetMsg: CCommonRespMsg
    m_nEquipUniqueId: int  # UInt64
    m_nSlotId: int  # UInt16


def write_c_resp_equip_wear(writer: BinaryWriter, resp: CRespEquipWear) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint64(resp.m_nEquipUniqueId)
    writer.write_uint16(resp.m_nSlotId)


@dataclass
class CRespEquipTotem:
    m_stRetMsg: CCommonRespMsg
    m_nTotemId: int  # UInt32


def write_c_resp_equip_totem(writer: BinaryWriter, resp: CRespEquipTotem) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nTotemId)


@dataclass
class CRespEquipRefine:
    m_stRetMsg: CCommonRespMsg
    m_nResult: int  # UInt16


def write_c_resp_equip_refine(writer: BinaryWriter, resp: CRespEquipRefine) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nResult)


# =============================================================================
# HERO SKIN
# =============================================================================


@dataclass
class CReqHeroSkin:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nSkinId: int  # UInt32
    m_nNum: int  # UInt32


def read_c_req_hero_skin(reader: BinaryReader) -> CReqHeroSkin:
    return CReqHeroSkin(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nSkinId=reader.read_uint32(),
        m_nNum=reader.read_uint32(),
    )


@dataclass
class CHeroSkin:
    m_nSkinId: int  # UInt32
    m_nLevel: int  # UInt16
    m_bIsOwned: bool  # Boolean


def write_c_hero_skin(writer: BinaryWriter, skin: CHeroSkin) -> None:
    writer.write_uint32(skin.m_nSkinId)
    writer.write_uint16(skin.m_nLevel)
    writer.write_bool(skin.m_bIsOwned)


@dataclass
class CRespHeroSkin:
    m_stRetMsg: CCommonRespMsg
    m_vecSkins: List[CHeroSkin] = field(default_factory=list)


def write_c_resp_hero_skin(writer: BinaryWriter, resp: CRespHeroSkin) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecSkins, lambda s: write_c_hero_skin(writer, s))


# =============================================================================
# WEAPON SKIN
# =============================================================================


@dataclass
class CReqWeaponSkin:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nSkinId: int  # UInt32


def read_c_req_weapon_skin(reader: BinaryReader) -> CReqWeaponSkin:
    return CReqWeaponSkin(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nSkinId=reader.read_uint32(),
    )


@dataclass
class CRespWeaponSkin:
    m_stRetMsg: CCommonRespMsg
    m_nSkinId: int  # UInt32


def write_c_resp_weapon_skin(writer: BinaryWriter, resp: CRespWeaponSkin) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nSkinId)


# =============================================================================
# WING
# =============================================================================


@dataclass
class CReqWing:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nWingId: int  # UInt32


def read_c_req_wing(reader: BinaryReader) -> CReqWing:
    return CReqWing(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nWingId=reader.read_uint32(),
    )


@dataclass
class CRespWing:
    m_stRetMsg: CCommonRespMsg
    m_nWingId: int  # UInt32


def write_c_resp_wing(writer: BinaryWriter, resp: CRespWing) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint32(resp.m_nWingId)


# =============================================================================
# BOXES
# =============================================================================


@dataclass
class CReqOpenDragonBox:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nDiamond: int  # UInt16
    m_nBatchCount: int  # UInt16


def read_c_req_open_dragon_box(reader: BinaryReader) -> CReqOpenDragonBox:
    return CReqOpenDragonBox(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nDiamond=reader.read_uint16(),
        m_nBatchCount=reader.read_uint16(),
    )


@dataclass
class CRespOpenDragonBox:
    m_stRetMsg: CCommonRespMsg
    m_nBoxCount: int  # UInt16
    m_vecRewards: List[int] = field(default_factory=list)  # UInt32[]


def write_c_resp_open_dragon_box(
    writer: BinaryWriter, resp: CRespOpenDragonBox
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_uint16(resp.m_nBoxCount)
    writer.write_array(resp.m_vecRewards, lambda r: writer.write_uint32(r))


@dataclass
class CReqOpenPetBox:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nCount: int  # UInt16


def read_c_req_open_pet_box(reader: BinaryReader) -> CReqOpenPetBox:
    return CReqOpenPetBox(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nCount=reader.read_uint16(),
    )


@dataclass
class CRespOpenPetBox:
    m_stRetMsg: CCommonRespMsg
    m_vecRewards: List[int] = field(default_factory=list)  # UInt32[]


def write_c_resp_open_pet_box(writer: BinaryWriter, resp: CRespOpenPetBox) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecRewards, lambda r: writer.write_uint32(r))


@dataclass
class CReqOpenEquipSBox:
    m_nType: int  # UInt16
    m_nTransID: int  # UInt32
    m_nCount: int  # UInt16


def read_c_req_open_equip_s_box(reader: BinaryReader) -> CReqOpenEquipSBox:
    return CReqOpenEquipSBox(
        m_nType=reader.read_uint16(),
        m_nTransID=reader.read_uint32(),
        m_nCount=reader.read_uint16(),
    )


@dataclass
class CRespOpenEquipSBox:
    m_stRetMsg: CCommonRespMsg
    m_vecRewards: List[int] = field(default_factory=list)  # UInt32[]


def write_c_resp_open_equip_s_box(
    writer: BinaryWriter, resp: CRespOpenEquipSBox
) -> None:
    write_c_common_resp_msg(writer, resp.m_stRetMsg)
    writer.write_array(resp.m_vecRewards, lambda r: writer.write_uint32(r))
