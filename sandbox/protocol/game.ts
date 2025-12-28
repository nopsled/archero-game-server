/**
 * Game Protocol Packets
 * 
 * Core gameplay structures: towers, battles, harvests, achievements, etc.
 */

import { BinaryReader, BinaryWriter } from "./binary";
import { CCommonRespMsg, writeCCommonRespMsg, createSuccessResponse } from "./common";

// =============================================================================
// GAME TOWER
// =============================================================================

export interface CGameTowerInfo {
  m_nType: number;              // UInt16
  m_bWin: boolean;              // Boolean
  m_nTransID: number;           // UInt32
}

export function readCGameTowerInfo(reader: BinaryReader): CGameTowerInfo {
  return {
    m_nType: reader.readUInt16(),
    m_bWin: reader.readBool(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CPlayTowerInfo {
  m_nType: number;              // UInt16
  m_nTowerId: number;           // UInt32
  m_nFloor: number;             // UInt16
  m_nTransID: number;           // UInt32
}

export function readCPlayTowerInfo(reader: BinaryReader): CPlayTowerInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nTowerId: reader.readUInt32(),
    m_nFloor: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CRespGameTowerInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nFloor: number;             // UInt16
  m_nMaxFloor: number;          // UInt16
}

export function writeCRespGameTowerInfo(writer: BinaryWriter, resp: CRespGameTowerInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nFloor);
  writer.writeUInt16(resp.m_nMaxFloor);
}

export interface CRespPlayTowerInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nTowerId: number;           // UInt32
  m_nFloor: number;             // UInt16
}

export function writeCRespPlayTowerInfo(writer: BinaryWriter, resp: CRespPlayTowerInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nTowerId);
  writer.writeUInt16(resp.m_nFloor);
}

// =============================================================================
// HARVEST
// =============================================================================

export interface CReqGameHarvest2 {
  m_nType: number;              // UInt16
  m_nTransID: number;           // UInt32
}

export function readCReqGameHarvest2(reader: BinaryReader): CReqGameHarvest2 {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CRespGameHarvest2 {
  m_stRetMsg: CCommonRespMsg;
  m_nCoins: number;             // UInt32
  m_nExp: number;               // UInt32
  m_nTimestamp: bigint;         // UInt64
  m_nMaxTime: number;           // UInt32
}

export function writeCRespGameHarvest2(writer: BinaryWriter, resp: CRespGameHarvest2): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nCoins);
  writer.writeUInt32(resp.m_nExp);
  writer.writeUInt64(resp.m_nTimestamp);
  writer.writeUInt32(resp.m_nMaxTime);
}

// =============================================================================
// ACHIEVEMENTS
// =============================================================================

export interface CGameAchieveInfo {
  m_nType: number;              // UInt16
  m_nId: number;                // UInt32
  m_nTransID: number;           // UInt32
}

export function readCGameAchieveInfo(reader: BinaryReader): CGameAchieveInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface STCommonAchievementData {
  m_nId: number;                // UInt32
  m_nProgress: number;          // UInt32
  m_nLevel: number;             // UInt16
  m_bIsClaimed: boolean;        // Boolean
}

export function writeSTCommonAchievementData(writer: BinaryWriter, data: STCommonAchievementData): void {
  writer.writeUInt32(data.m_nId);
  writer.writeUInt32(data.m_nProgress);
  writer.writeUInt16(data.m_nLevel);
  writer.writeBool(data.m_bIsClaimed);
}

export interface CRespGameAchieveInfo {
  m_stRetMsg: CCommonRespMsg;
  m_vecAchievements: STCommonAchievementData[];
}

export function writeCRespGameAchieveInfo(writer: BinaryWriter, resp: CRespGameAchieveInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecAchievements, (a) => writeSTCommonAchievementData(writer, a));
}

// =============================================================================
// ADS
// =============================================================================

export interface CGameAd {
  m_nType: number;              // UInt16
  m_nAdId: number;              // UInt32
  m_nTransID: number;           // UInt32
}

export function readCGameAd(reader: BinaryReader): CGameAd {
  return {
    m_nType: reader.readUInt16(),
    m_nAdId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CRespGameAd {
  m_stRetMsg: CCommonRespMsg;
  m_nAdCount: number;           // UInt16
  m_nDailyLimit: number;        // UInt16
}

export function writeCRespGameAd(writer: BinaryWriter, resp: CRespGameAd): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nAdCount);
  writer.writeUInt16(resp.m_nDailyLimit);
}

// =============================================================================
// GUIDE
// =============================================================================

export interface CReqGameGuide {
  m_nType: number;              // UInt16
  m_nGuideId: number;           // UInt32
  m_nTransID: number;           // UInt32
}

export function readCReqGameGuide(reader: BinaryReader): CReqGameGuide {
  return {
    m_nType: reader.readUInt16(),
    m_nGuideId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CRespGameGuide {
  m_stRetMsg: CCommonRespMsg;
  m_nGuideBits: bigint;         // UInt64
}

export function writeCRespGameGuide(writer: BinaryWriter, resp: CRespGameGuide): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nGuideBits);
}

// =============================================================================
// GAME CLIENT DATA
// =============================================================================

export interface CReqGameClientData {
  m_nType: number;              // UInt16
  m_strClientData: string | null; // String
}

export function readCReqGameClientData(reader: BinaryReader): CReqGameClientData {
  return {
    m_nType: reader.readUInt16(),
    m_strClientData: reader.readString(),
  };
}

export interface CRespGameClientData {
  m_stRetMsg: CCommonRespMsg;
  m_strClientData: string;      // String
}

export function writeCRespGameClientData(writer: BinaryWriter, resp: CRespGameClientData): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeString(resp.m_strClientData);
}

// =============================================================================
// PVE SEASON
// =============================================================================

export interface CPveSeasonInfo {
  m_nType: number;              // UInt16
  m_nSeasonId: number;          // UInt32
  m_nTransID: number;           // UInt32
}

export function readCPveSeasonInfo(reader: BinaryReader): CPveSeasonInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nSeasonId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CRespPveSeasonInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nSeasonId: number;          // UInt32
  m_nRank: number;              // UInt32
  m_nScore: number;             // UInt32
}

export function writeCRespPveSeasonInfo(writer: BinaryWriter, resp: CRespPveSeasonInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nSeasonId);
  writer.writeUInt32(resp.m_nRank);
  writer.writeUInt32(resp.m_nScore);
}

// =============================================================================
// FISHING
// =============================================================================

export interface CReqGameFishing {
  m_nType: number;              // UInt16
  m_nTransID: number;           // UInt32
}

export function readCReqGameFishing(reader: BinaryReader): CReqGameFishing {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface STGameFishingRank {
  m_nRank: number;              // UInt32
  m_nScore: number;             // UInt32
  m_strName: string;            // String
}

export function writeSTGameFishingRank(writer: BinaryWriter, rank: STGameFishingRank): void {
  writer.writeUInt32(rank.m_nRank);
  writer.writeUInt32(rank.m_nScore);
  writer.writeString(rank.m_strName);
}

export interface CRespGameFishing {
  m_stRetMsg: CCommonRespMsg;
  m_nScore: number;             // UInt32
  m_vecRanks: STGameFishingRank[];
}

export function writeCRespGameFishing(writer: BinaryWriter, resp: CRespGameFishing): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nScore);
  writer.writeArray(resp.m_vecRanks, (r) => writeSTGameFishingRank(writer, r));
}
