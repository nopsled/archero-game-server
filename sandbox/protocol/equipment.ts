/**
 * Equipment Protocol Packets
 *
 * Equipment, weapons, relics, and related structures.
 */

import type { BinaryReader, BinaryWriter } from "./binary";
import { type CCommonRespMsg, writeCCommonRespMsg } from "./common";

// =============================================================================
// EQUIPMENT REQUESTS
// =============================================================================

export interface CReqEquipWear {
  m_nTransID: number; // UInt32
  m_nType: number; // UInt16
  m_nEquipUniqueId: bigint; // UInt64
  m_nSlotId: number; // UInt16
}

export function readCReqEquipWear(reader: BinaryReader): CReqEquipWear {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_nEquipUniqueId: reader.readUInt64(),
    m_nSlotId: reader.readUInt16(),
  };
}

export interface CReqEquipTotem {
  m_nTransID: number; // UInt32
  m_nType: number; // UInt16
  m_nTotemId: number; // UInt32
}

export function readCReqEquipTotem(reader: BinaryReader): CReqEquipTotem {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_nTotemId: reader.readUInt32(),
  };
}

export interface CEquipRefine {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nPosId: number; // UInt16
  m_nCarvingId: number; // UInt32
  m_nCarvingIdx: number; // UInt16
  arrayEquipId: bigint[]; // UInt64[]
  vecCompositeId: number[]; // UInt32[]
}

export function readCEquipRefine(reader: BinaryReader): CEquipRefine {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nPosId: reader.readUInt16(),
    m_nCarvingId: reader.readUInt32(),
    m_nCarvingIdx: reader.readUInt16(),
    arrayEquipId: reader.readArray(() => reader.readUInt64()),
    vecCompositeId: reader.readArray(() => reader.readUInt32()),
  };
}

// =============================================================================
// EQUIPMENT RESPONSES
// =============================================================================

export interface CRespEquipWear {
  m_stRetMsg: CCommonRespMsg;
  m_nEquipUniqueId: bigint; // UInt64
  m_nSlotId: number; // UInt16
}

export function writeCRespEquipWear(writer: BinaryWriter, resp: CRespEquipWear): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nEquipUniqueId);
  writer.writeUInt16(resp.m_nSlotId);
}

export interface CRespEquipTotem {
  m_stRetMsg: CCommonRespMsg;
  m_nTotemId: number; // UInt32
}

export function writeCRespEquipTotem(writer: BinaryWriter, resp: CRespEquipTotem): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nTotemId);
}

export interface CRespEquipRefine {
  m_stRetMsg: CCommonRespMsg;
  m_nResult: number; // UInt16
}

export function writeCRespEquipRefine(writer: BinaryWriter, resp: CRespEquipRefine): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nResult);
}

// =============================================================================
// HERO SKIN
// =============================================================================

export interface CReqHeroSkin {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nSkinId: number; // UInt32
  m_nNum: number; // UInt32
}

export function readCReqHeroSkin(reader: BinaryReader): CReqHeroSkin {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nSkinId: reader.readUInt32(),
    m_nNum: reader.readUInt32(),
  };
}

export interface CHeroSkin {
  m_nSkinId: number; // UInt32
  m_nLevel: number; // UInt16
  m_bIsOwned: boolean; // Boolean
}

export function writeCHeroSkin(writer: BinaryWriter, skin: CHeroSkin): void {
  writer.writeUInt32(skin.m_nSkinId);
  writer.writeUInt16(skin.m_nLevel);
  writer.writeBool(skin.m_bIsOwned);
}

export interface CRespHeroSkin {
  m_stRetMsg: CCommonRespMsg;
  m_vecSkins: CHeroSkin[];
}

export function writeCRespHeroSkin(writer: BinaryWriter, resp: CRespHeroSkin): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecSkins, (s) => writeCHeroSkin(writer, s));
}

// =============================================================================
// WEAPON SKIN
// =============================================================================

export interface CReqWeaponSkin {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nSkinId: number; // UInt32
}

export function readCReqWeaponSkin(reader: BinaryReader): CReqWeaponSkin {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nSkinId: reader.readUInt32(),
  };
}

export interface CRespWeaponSkin {
  m_stRetMsg: CCommonRespMsg;
  m_nSkinId: number; // UInt32
}

export function writeCRespWeaponSkin(writer: BinaryWriter, resp: CRespWeaponSkin): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nSkinId);
}

// =============================================================================
// WING
// =============================================================================

export interface CReqWing {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nWingId: number; // UInt32
}

export function readCReqWing(reader: BinaryReader): CReqWing {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nWingId: reader.readUInt32(),
  };
}

export interface CRespWing {
  m_stRetMsg: CCommonRespMsg;
  m_nWingId: number; // UInt32
}

export function writeCRespWing(writer: BinaryWriter, resp: CRespWing): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nWingId);
}

// =============================================================================
// BOXES
// =============================================================================

export interface CReqOpenDragonBox {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nDiamond: number; // UInt16
  m_nBatchCount: number; // UInt16
}

export function readCReqOpenDragonBox(reader: BinaryReader): CReqOpenDragonBox {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nDiamond: reader.readUInt16(),
    m_nBatchCount: reader.readUInt16(),
  };
}

export interface CRespOpenDragonBox {
  m_stRetMsg: CCommonRespMsg;
  m_nBoxCount: number; // UInt16
  m_vecRewards: number[]; // UInt32[]
}

export function writeCRespOpenDragonBox(writer: BinaryWriter, resp: CRespOpenDragonBox): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nBoxCount);
  writer.writeArray(resp.m_vecRewards, (r) => writer.writeUInt32(r));
}

export interface CReqOpenPetBox {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nCount: number; // UInt16
}

export function readCReqOpenPetBox(reader: BinaryReader): CReqOpenPetBox {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nCount: reader.readUInt16(),
  };
}

export interface CRespOpenPetBox {
  m_stRetMsg: CCommonRespMsg;
  m_vecRewards: number[]; // UInt32[]
}

export function writeCRespOpenPetBox(writer: BinaryWriter, resp: CRespOpenPetBox): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecRewards, (r) => writer.writeUInt32(r));
}

export interface CReqOpenEquipSBox {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nCount: number; // UInt16
}

export function readCReqOpenEquipSBox(reader: BinaryReader): CReqOpenEquipSBox {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nCount: reader.readUInt16(),
  };
}

export interface CRespOpenEquipSBox {
  m_stRetMsg: CCommonRespMsg;
  m_vecRewards: number[]; // UInt32[]
}

export function writeCRespOpenEquipSBox(writer: BinaryWriter, resp: CRespOpenEquipSBox): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecRewards, (r) => writer.writeUInt32(r));
}
