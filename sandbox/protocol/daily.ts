/**
 * Daily Tasks and Rewards Protocol Packets
 */

import { BinaryReader, BinaryWriter } from "./binary";
import { 
  CCommonRespMsg, 
  writeCCommonRespMsg, 
  createSuccessResponse,
  CEquipmentItem,
  writeCEquipmentItem,
} from "./common";

// =============================================================================
// REWARD ITEM
// =============================================================================

export interface CRewardItem {
  m_nType: number;              // UInt16
  m_nId: number;                // UInt32
  m_nCount: number;             // UInt32
}

export function writeCRewardItem(writer: BinaryWriter, item: CRewardItem): void {
  writer.writeUInt16(item.m_nType);
  writer.writeUInt32(item.m_nId);
  writer.writeUInt32(item.m_nCount);
}

// =============================================================================
// DAILY TASK REQUESTS
// =============================================================================

export interface CDailyTaskInfo {
  m_nType: number;              // UInt16
  m_nId: number;                // UInt32
  m_nTransID: number;           // UInt32
}

export function readCDailyTaskInfo(reader: BinaryReader): CDailyTaskInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

export interface CWeeklyTaskInfo {
  m_nType: number;              // UInt16
  m_nId: number;                // UInt32
  m_nTransID: number;           // UInt32
}

export function readCWeeklyTaskInfo(reader: BinaryReader): CWeeklyTaskInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
  };
}

// =============================================================================
// DAILY TASK RESPONSES
// =============================================================================

export interface STDailyTaskExtraRewardData {
  m_nId: number;                // UInt32
  m_nProgress: number;          // UInt32
  m_bIsClaimed: boolean;        // Boolean
}

export function writeSTDailyTaskExtraRewardData(writer: BinaryWriter, data: STDailyTaskExtraRewardData): void {
  writer.writeUInt32(data.m_nId);
  writer.writeUInt32(data.m_nProgress);
  writer.writeBool(data.m_bIsClaimed);
}

export interface CRespDailyTaskInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nEndTime: bigint;           // UInt64
  m_nTaskPoint: number;         // UInt16
  m_nTaskReward: bigint;        // UInt64
  m_nTotalDiamonds: number;     // UInt32
  m_nTotalCoins: number;        // UInt32
  m_nLife: number;              // UInt16
  m_nBattleRebornCount: number; // UInt16
  m_nNormalDiamondItem: number; // UInt16
  m_nLargeDiamondItem: number;  // UInt16
  m_nLevel: number;             // UInt16
  m_nExperience: number;        // UInt32
  m_arrEquipInfo: CEquipmentItem[] | null;
  m_nTowerLife: number;         // UInt16
  m_nMixBoxItem: number;        // UInt16
  m_nDragonBoxItem: number;     // UInt16
  m_nRelicsBoxItem: number;     // UInt16
  m_nEquipSBoxItem: number;     // UInt16
  m_vecExtraRewardData: STDailyTaskExtraRewardData[];
}

export function writeCRespDailyTaskInfo(writer: BinaryWriter, resp: CRespDailyTaskInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt16(resp.m_nTaskPoint);
  writer.writeUInt64(resp.m_nTaskReward);
  writer.writeUInt32(resp.m_nTotalDiamonds);
  writer.writeUInt32(resp.m_nTotalCoins);
  writer.writeUInt16(resp.m_nLife);
  writer.writeUInt16(resp.m_nBattleRebornCount);
  writer.writeUInt16(resp.m_nNormalDiamondItem);
  writer.writeUInt16(resp.m_nLargeDiamondItem);
  writer.writeUInt16(resp.m_nLevel);
  writer.writeUInt32(resp.m_nExperience);
  writer.writeArray(resp.m_arrEquipInfo || [], (e) => writeCEquipmentItem(writer, e));
  writer.writeUInt16(resp.m_nTowerLife);
  writer.writeUInt16(resp.m_nMixBoxItem);
  writer.writeUInt16(resp.m_nDragonBoxItem);
  writer.writeUInt16(resp.m_nRelicsBoxItem);
  writer.writeUInt16(resp.m_nEquipSBoxItem);
  writer.writeArray(resp.m_vecExtraRewardData, (d) => writeSTDailyTaskExtraRewardData(writer, d));
}

export interface CRespWeeklyTaskInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nEndTime: bigint;           // UInt64
  m_nTaskPoint: number;         // UInt16
  m_nTaskReward: bigint;        // UInt64
}

export function writeCRespWeeklyTaskInfo(writer: BinaryWriter, resp: CRespWeeklyTaskInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt16(resp.m_nTaskPoint);
  writer.writeUInt64(resp.m_nTaskReward);
}

// =============================================================================
// DAILY PLAY
// =============================================================================

export interface CDailyPlay {
  m_nType: number;              // UInt16
  m_nId: number;                // UInt32
  m_nTransID: number;           // UInt32
  m_nPartnerUserId: bigint;     // UInt64
  m_nBattleTransID: number;     // UInt32
  m_nDailyLevel: number;        // UInt32
}

export function readCDailyPlay(reader: BinaryReader): CDailyPlay {
  return {
    m_nType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_nTransID: reader.readUInt32(),
    m_nPartnerUserId: reader.readUInt64(),
    m_nBattleTransID: reader.readUInt32(),
    m_nDailyLevel: reader.readUInt32(),
  };
}

export interface CRespDailyPlayInfo {
  m_stRetMsg: CCommonRespMsg;
  m_nDailyPlayCount: number;    // UInt16
  m_nDailyPlayMax: number;      // UInt16
}

export function writeCRespDailyPlayInfo(writer: BinaryWriter, resp: CRespDailyPlayInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDailyPlayCount);
  writer.writeUInt16(resp.m_nDailyPlayMax);
}

// =============================================================================
// IAP REWARDS
// =============================================================================

export interface CReqDailyIapReward {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
  m_strExtra: string | null;    // String
}

export function readCReqDailyIapReward(reader: BinaryReader): CReqDailyIapReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_strExtra: reader.readString(),
  };
}

export interface CReqWeekIapReward {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
}

export function readCReqWeekIapReward(reader: BinaryReader): CReqWeekIapReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
  };
}

export interface CReqMonthIapReward {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
}

export function readCReqMonthIapReward(reader: BinaryReader): CReqMonthIapReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
  };
}

export interface CRespDailyIapReward {
  m_stRetMsg: CCommonRespMsg;
  m_nDays: number;              // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespDailyIapReward(writer: BinaryWriter, resp: CRespDailyIapReward): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDays);
  writer.writeUInt64(resp.m_nRewardBits);
}

export interface CRespWeekIapReward {
  m_stRetMsg: CCommonRespMsg;
  m_nWeeks: number;             // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespWeekIapReward(writer: BinaryWriter, resp: CRespWeekIapReward): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nWeeks);
  writer.writeUInt64(resp.m_nRewardBits);
}

export interface CRespMonthIapReward {
  m_stRetMsg: CCommonRespMsg;
  m_nMonths: number;            // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespMonthIapReward(writer: BinaryWriter, resp: CRespMonthIapReward): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nMonths);
  writer.writeUInt64(resp.m_nRewardBits);
}

// =============================================================================
// DEFAULT FACTORIES
// =============================================================================

export function createDefaultDailyTaskInfo(): CRespDailyTaskInfo {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const todayEnd = now + BigInt(86400 - (Number(now) % 86400));
  
  return {
    m_stRetMsg: createSuccessResponse(),
    m_nEndTime: todayEnd,
    m_nTaskPoint: 0,
    m_nTaskReward: BigInt(0),
    m_nTotalDiamonds: 0,
    m_nTotalCoins: 0,
    m_nLife: 0,
    m_nBattleRebornCount: 0,
    m_nNormalDiamondItem: 0,
    m_nLargeDiamondItem: 0,
    m_nLevel: 0,
    m_nExperience: 0,
    m_arrEquipInfo: null,
    m_nTowerLife: 0,
    m_nMixBoxItem: 0,
    m_nDragonBoxItem: 0,
    m_nRelicsBoxItem: 0,
    m_nEquipSBoxItem: 0,
    m_vecExtraRewardData: [],
  };
}
