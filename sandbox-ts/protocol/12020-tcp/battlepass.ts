/**
 * Battlepass Protocol Packets
 *
 * Battle pass related request and response packets.
 */

import type { BinaryReader, BinaryWriter } from "./binary";
import { type CCommonRespMsg, createSuccessResponse, writeCCommonRespMsg } from "./common";

// =============================================================================
// BATTLEPASS REWARD CONFIG
// =============================================================================

export interface CBattlePassExtraRewardConf {
  nExtraCnt: number; // UInt16
  nExtraCondParam: number; // UInt16
  strReward: string; // String (e.g., "4,2203,1")
  strBigReward: string; // String
}

export function writeCBattlePassExtraRewardConf(
  writer: BinaryWriter,
  conf: CBattlePassExtraRewardConf,
): void {
  writer.writeUInt16(conf.nExtraCnt);
  writer.writeUInt16(conf.nExtraCondParam);
  writer.writeString(conf.strReward);
  writer.writeString(conf.strBigReward);
}

export interface CBattlePassRewardConf {
  nId: number; // UInt32
  nCondType: number; // UInt16
  nParam: number; // UInt16
  m_arrRewardInfo: string[]; // String[]
}

export function writeCBattlePassRewardConf(
  writer: BinaryWriter,
  conf: CBattlePassRewardConf,
): void {
  writer.writeUInt32(conf.nId);
  writer.writeUInt16(conf.nCondType);
  writer.writeUInt16(conf.nParam);
  writer.writeArray(conf.m_arrRewardInfo, (s) => writer.writeString(s));
}

// =============================================================================
// BATTLEPASS REQUEST
// =============================================================================

export interface CReqBattlepassReward {
  m_nTransID: number; // UInt32
  m_nBattleTag: number; // UInt32
  m_nType: number; // UInt16
  m_nKillsOrRewardId: number; // UInt32
  m_nRewardIndex: number; // UInt32
  m_strExtra: string | null; // String
  m_strExtend: string | null; // String
  m_nBattlePassType: number; // UInt16
  m_nBattlePassId: number; // UInt16
  m_nBattlePassIndex: number; // UInt16
}

export function readCReqBattlepassReward(reader: BinaryReader): CReqBattlepassReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nBattleTag: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_nKillsOrRewardId: reader.readUInt32(),
    m_nRewardIndex: reader.readUInt32(),
    m_strExtra: reader.readString(),
    m_strExtend: reader.readString(),
    m_nBattlePassType: reader.readUInt16(),
    m_nBattlePassId: reader.readUInt16(),
    m_nBattlePassIndex: reader.readUInt16(),
  };
}

// =============================================================================
// BATTLEPASS RESPONSE
// =============================================================================

export interface CRespBattlepassConf {
  m_stRetMsg: CCommonRespMsg;
  nStartTimestamp: bigint; // UInt64
  nEndTimestamp: bigint; // UInt64
  m_nBattlepassTag: number; // UInt32
  bIsGin: boolean; // Boolean
  nType: number; // UInt16
  nEventId: number; // UInt16
  stExtraReward: CBattlePassExtraRewardConf;
  m_arrTagInfo: CBattlePassRewardConf[];
  nMinVersion: number; // UInt16
  nMaxVersion: number; // UInt16
  nSweepAddCnt: number; // UInt16
  nSweepCoinAdd: number; // UInt16
  bIsNew: boolean; // Boolean
  nDropRelicsAdd: number; // UInt16
  nHarvestQuickAdd: number; // UInt16
  nDropBossEggAdd: number; // UInt16
  nRate: number; // UInt16
}

export function writeCRespBattlepassConf(writer: BinaryWriter, resp: CRespBattlepassConf): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.nStartTimestamp);
  writer.writeUInt64(resp.nEndTimestamp);
  writer.writeUInt32(resp.m_nBattlepassTag);
  writer.writeBool(resp.bIsGin);
  writer.writeUInt16(resp.nType);
  writer.writeUInt16(resp.nEventId);
  writeCBattlePassExtraRewardConf(writer, resp.stExtraReward);
  writer.writeArray(resp.m_arrTagInfo, (c) => writeCBattlePassRewardConf(writer, c));
  writer.writeUInt16(resp.nMinVersion);
  writer.writeUInt16(resp.nMaxVersion);
  writer.writeUInt16(resp.nSweepAddCnt);
  writer.writeUInt16(resp.nSweepCoinAdd);
  writer.writeBool(resp.bIsNew);
  writer.writeUInt16(resp.nDropRelicsAdd);
  writer.writeUInt16(resp.nHarvestQuickAdd);
  writer.writeUInt16(resp.nDropBossEggAdd);
  writer.writeUInt16(resp.nRate);
  // mapGameActivityBattlePassPhaseConf - empty dictionary
  writer.writeUInt16(0);
}

export interface CRespBattlepassReward {
  m_stRetMsg: CCommonRespMsg;
  m_nKills: number; // UInt32
  m_nRewardBits: bigint; // UInt64
}

export function writeCRespBattlepassReward(
  writer: BinaryWriter,
  resp: CRespBattlepassReward,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nKills);
  writer.writeUInt64(resp.m_nRewardBits);
}

// =============================================================================
// ST ACTIVITY BATTLEPASS
// =============================================================================

export interface STActivityBattlePassItem {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_nRewardBits: bigint; // UInt64
}

export function writeSTActivityBattlePassItem(
  writer: BinaryWriter,
  item: STActivityBattlePassItem,
): void {
  writer.writeUInt32(item.m_nId);
  writer.writeUInt32(item.m_nProgress);
  writer.writeUInt64(item.m_nRewardBits);
}

export interface STActivityBattlePass {
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nTag: number; // UInt32
  m_vecItems: STActivityBattlePassItem[];
}

export function writeSTActivityBattlePass(writer: BinaryWriter, bp: STActivityBattlePass): void {
  writer.writeUInt64(bp.m_nStartTime);
  writer.writeUInt64(bp.m_nEndTime);
  writer.writeUInt32(bp.m_nTag);
  writer.writeArray(bp.m_vecItems, (i) => writeSTActivityBattlePassItem(writer, i));
}

// =============================================================================
// DEFAULT FACTORIES
// =============================================================================

export function createDefaultBattlepassConf(): CRespBattlepassConf {
  const now = BigInt(Math.floor(Date.now() / 1000));
  return {
    m_stRetMsg: createSuccessResponse(),
    nStartTimestamp: now - BigInt(86400),
    nEndTimestamp: now + BigInt(86400 * 30),
    m_nBattlepassTag: 165,
    bIsGin: true,
    nType: 2,
    nEventId: 101,
    stExtraReward: {
      nExtraCnt: 5,
      nExtraCondParam: 100,
      strReward: "4,2203,1",
      strBigReward: "4,2204,1",
    },
    m_arrTagInfo: [
      { nId: 1, nCondType: 0, nParam: 0, m_arrRewardInfo: ["4,2305,1", "4,2306,1", "3,39133,2"] },
      { nId: 2, nCondType: 0, nParam: 50, m_arrRewardInfo: ["4,2201,1", "4,2204,1", "10,12,1"] },
      { nId: 3, nCondType: 0, nParam: 100, m_arrRewardInfo: ["4,2203,1", "1,26,1", "1,2,200"] },
      { nId: 4, nCondType: 0, nParam: 150, m_arrRewardInfo: ["1,2,10", "3,36012,2", "4,2306,1"] },
      { nId: 5, nCondType: 0, nParam: 200, m_arrRewardInfo: ["1,21,1", "4,2305,1", "4,2204,1"] },
    ],
    nMinVersion: 193,
    nMaxVersion: 999,
    nSweepAddCnt: 10,
    nSweepCoinAdd: 30,
    bIsNew: true,
    nDropRelicsAdd: 10,
    nHarvestQuickAdd: 15,
    nDropBossEggAdd: 15,
    nRate: 20,
  };
}
