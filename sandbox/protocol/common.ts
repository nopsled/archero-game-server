/**
 * Common Protocol Types
 * 
 * Shared data structures used across all GameProtocol packets.
 * Based on captured field data from protocol discovery.
 */

import { BinaryReader, BinaryWriter } from "./binary";

// =============================================================================
// COMMON RESPONSE MESSAGE
// =============================================================================

/**
 * CCommonRespMsg - Response wrapper with status code
 * Every response includes this structure.
 */
export interface CCommonRespMsg {
  m_unStatusCode: number;   // UInt16 - 0 = success
  m_strInfo: string;        // String - error/info message
  // Note: stCommonData is a large nested structure we'll omit for now
}

export function writeCCommonRespMsg(writer: BinaryWriter, msg: CCommonRespMsg): void {
  writer.writeUInt16(msg.m_unStatusCode);
  writer.writeString(msg.m_strInfo);
  // Write minimal STCommonData (m_nChange = false, rest empty)
  writer.writeBool(false);  // m_nChange
  // The client will skip reading other fields if m_nChange is false
}

export function createSuccessResponse(): CCommonRespMsg {
  return {
    m_unStatusCode: 0,
    m_strInfo: "",
  };
}

// =============================================================================
// EQUIPMENT ITEM
// =============================================================================

/**
 * CEquipmentItem - Equipment/weapon data
 */
export interface CEquipmentItem {
  m_nUniqueID: string;       // String - unique item ID
  m_nRowID: bigint;          // UInt64
  m_nEquipID: number;        // UInt32 - equipment type (10000 = basic bow)
  m_nLevel: number;          // UInt32
  m_nFragment: number;       // UInt32
  m_strExtend: string;       // String - extension data
  RelicEvolutionLevel: number; // Int32
  RelicStar: number;         // Int32
}

export function writeCEquipmentItem(writer: BinaryWriter, item: CEquipmentItem): void {
  writer.writeString(item.m_nUniqueID);
  writer.writeUInt64(item.m_nRowID);
  writer.writeUInt32(item.m_nEquipID);
  writer.writeUInt32(item.m_nLevel);
  writer.writeUInt32(item.m_nFragment);
  writer.writeString(item.m_strExtend);
  writer.writeInt32(item.RelicEvolutionLevel);
  writer.writeInt32(item.RelicStar);
}

export function createDefaultEquipmentItem(uniqueId: string, equipId: number): CEquipmentItem {
  return {
    m_nUniqueID: uniqueId,
    m_nRowID: BigInt(uniqueId),
    m_nEquipID: equipId,
    m_nLevel: 1,
    m_nFragment: 1,
    m_strExtend: "",
    RelicEvolutionLevel: 0,
    RelicStar: 0,
  };
}

// =============================================================================
// HERO ITEM
// =============================================================================

/**
 * CHeroItem - Hero/character data
 */
export interface CHeroItem {
  m_nHeroId: number;    // UInt32 (10000 = default hero)
  m_nStar: number;      // UInt32
  m_nCoopLevel: number; // UInt16
}

export function writeCHeroItem(writer: BinaryWriter, item: CHeroItem): void {
  writer.writeUInt32(item.m_nHeroId);
  writer.writeUInt32(item.m_nStar);
  writer.writeUInt16(item.m_nCoopLevel);
}

export function createDefaultHero(): CHeroItem {
  return {
    m_nHeroId: 10000,  // Default hero
    m_nStar: 0,
    m_nCoopLevel: 1,
  };
}

// =============================================================================
// RESTORE ITEM
// =============================================================================

/**
 * CRestoreItem - Resource restoration/timer data
 */
export interface CRestoreItem {
  m_nMin: number;          // Int16
  m_nMax: number;          // UInt16
  m_i64Timestamp: bigint;  // UInt64 - unix timestamp
}

export function writeCRestoreItem(writer: BinaryWriter, item: CRestoreItem): void {
  writer.writeInt16(item.m_nMin);
  writer.writeUInt16(item.m_nMax);
  writer.writeUInt64(item.m_i64Timestamp);
}

export function createDefaultRestoreItem(current: number, max: number): CRestoreItem {
  return {
    m_nMin: current,
    m_nMax: max,
    m_i64Timestamp: BigInt(Math.floor(Date.now() / 1000)),
  };
}

// =============================================================================
// TIMESTAMP ITEM
// =============================================================================

/**
 * CTimestampItem - Timestamp tracking data
 */
export interface CTimestampItem {
  m_nIndex: number;        // UInt16
  m_i64Timestamp: bigint;  // UInt64
}

export function writeCTimestampItem(writer: BinaryWriter, item: CTimestampItem): void {
  writer.writeUInt16(item.m_nIndex);
  writer.writeUInt64(item.m_i64Timestamp);
}

// =============================================================================
// BOX ASSURANCE ITEM
// =============================================================================

/**
 * CBoxAssuranceItem - Loot box pity/assurance counts
 */
export interface CBoxAssuranceItem {
  m_nBoxCountLow: number;   // UInt16 (10)
  m_nBoxCountMid: number;   // UInt16 (30)
  m_nBoxCountHigh: number;  // UInt16 (120)
}

export function writeCBoxAssuranceItem(writer: BinaryWriter, item: CBoxAssuranceItem): void {
  writer.writeUInt16(item.m_nBoxCountLow);
  writer.writeUInt16(item.m_nBoxCountMid);
  writer.writeUInt16(item.m_nBoxCountHigh);
}

export function createDefaultBoxAssurance(): CBoxAssuranceItem {
  return {
    m_nBoxCountLow: 10,
    m_nBoxCountMid: 30,
    m_nBoxCountHigh: 120,
  };
}

// =============================================================================
// PET INFO
// =============================================================================

/**
 * STPetInfo - Pet data
 */
export interface STPetInfo {
  m_nPetId: number;    // UInt32
  m_nLevel: number;    // UInt32
  m_nStar: number;     // UInt32
}

export function writeSTPetInfo(writer: BinaryWriter, info: STPetInfo): void {
  writer.writeUInt32(info.m_nPetId);
  writer.writeUInt32(info.m_nLevel);
  writer.writeUInt32(info.m_nStar);
}

// =============================================================================
// HEAD ITEM
// =============================================================================

/**
 * STHeadItem - Player head/avatar frame item
 */
export interface STHeadItem {
  m_nHeadId: number;        // UInt32
  m_nTimestamp: bigint;     // UInt64
}

export function writeSTHeadItem(writer: BinaryWriter, item: STHeadItem): void {
  writer.writeUInt32(item.m_nHeadId);
  writer.writeUInt64(item.m_nTimestamp);
}

// =============================================================================
// ARTIFACT
// =============================================================================

/**
 * CArtifact - Artifact data
 */
export interface CArtifact {
  m_nArtifactId: number;  // UInt32
  m_nLevel: number;       // UInt32
  m_nStar: number;        // UInt32
}

export function writeCArtifact(writer: BinaryWriter, artifact: CArtifact): void {
  writer.writeUInt32(artifact.m_nArtifactId);
  writer.writeUInt32(artifact.m_nLevel);
  writer.writeUInt32(artifact.m_nStar);
}
