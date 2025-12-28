/**
 * Shop, Guild, VIP, and Miscellaneous Protocol Packets
 */

import { BinaryReader, BinaryWriter } from "./binary";
import { CCommonRespMsg, writeCCommonRespMsg, createSuccessResponse } from "./common";

// =============================================================================
// SHOP
// =============================================================================

export interface CRespShopBoxActivity {
  m_stRetMsg: CCommonRespMsg;
  m_nActivityId: number;        // UInt32
  m_nStartTime: bigint;         // UInt64
  m_nEndTime: bigint;           // UInt64
}

export function writeCRespShopBoxActivity(writer: BinaryWriter, resp: CRespShopBoxActivity): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nActivityId);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

// =============================================================================
// MONTH CARD / PRIVILEGE
// =============================================================================

export interface CReqMonthCard {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
  m_nPlatformIndex: number;     // UInt16
}

export function readCReqMonthCard(reader: BinaryReader): CReqMonthCard {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nPlatformIndex: reader.readUInt16(),
  };
}

export interface CRespMonthCard {
  m_stRetMsg: CCommonRespMsg;
  m_nMonthCardEndTime: bigint;  // UInt64
  m_nDoubleCardEndTime: bigint; // UInt64
  m_nDailyRewardBits: bigint;   // UInt64
}

export function writeCRespMonthCard(writer: BinaryWriter, resp: CRespMonthCard): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nMonthCardEndTime);
  writer.writeUInt64(resp.m_nDoubleCardEndTime);
  writer.writeUInt64(resp.m_nDailyRewardBits);
}

export interface CReqPrivilegeCard {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
}

export function readCReqPrivilegeCard(reader: BinaryReader): CReqPrivilegeCard {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface CRespPrivilegeCard {
  m_stRetMsg: CCommonRespMsg;
  m_nEndTime: bigint;           // UInt64
  m_nType: number;              // UInt16
}

export function writeCRespPrivilegeCard(writer: BinaryWriter, resp: CRespPrivilegeCard): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt16(resp.m_nType);
}

// =============================================================================
// VIP
// =============================================================================

export interface STReqVip {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
}

export function readSTReqVip(reader: BinaryReader): STReqVip {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STRespVip {
  m_stRetMsg: CCommonRespMsg;
  m_nVipLevel: number;          // UInt16
  m_nVipScore: number;          // UInt32
  m_nRewardBits: bigint;        // UInt64
}

export function writeSTRespVip(writer: BinaryWriter, resp: STRespVip): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nVipLevel);
  writer.writeUInt32(resp.m_nVipScore);
  writer.writeUInt64(resp.m_nRewardBits);
}

// =============================================================================
// GUILD
// =============================================================================

export interface CGuildTaskInfo {
  m_nTaskId: number;            // UInt32
  m_nProgress: number;          // UInt32
  m_bIsClaimed: boolean;        // Boolean
}

export function writeCGuildTaskInfo(writer: BinaryWriter, info: CGuildTaskInfo): void {
  writer.writeUInt32(info.m_nTaskId);
  writer.writeUInt32(info.m_nProgress);
  writer.writeBool(info.m_bIsClaimed);
}

export interface CRespGuildTaskInfo {
  m_stRetMsg: CCommonRespMsg;
  m_vecTasks: CGuildTaskInfo[];
}

export function writeCRespGuildTaskInfo(writer: BinaryWriter, resp: CRespGuildTaskInfo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecTasks, (t) => writeCGuildTaskInfo(writer, t));
}

export interface CGuildAchInfo {
  m_nAchId: number;             // UInt32
  m_nProgress: number;          // UInt32
  m_nLevel: number;             // UInt16
}

export function writeCGuildAchInfo(writer: BinaryWriter, info: CGuildAchInfo): void {
  writer.writeUInt32(info.m_nAchId);
  writer.writeUInt32(info.m_nProgress);
  writer.writeUInt16(info.m_nLevel);
}

export interface CRespGuildUserLogin {
  m_stRetMsg: CCommonRespMsg;
  m_nGuildId: bigint;           // UInt64
  m_strGuildName: string;       // String
  m_nGuildLevel: number;        // UInt16
}

export function writeCRespGuildUserLogin(writer: BinaryWriter, resp: CRespGuildUserLogin): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nGuildId);
  writer.writeString(resp.m_strGuildName);
  writer.writeUInt16(resp.m_nGuildLevel);
}

export interface CRespQueryGuildRedpacket {
  m_stRetMsg: CCommonRespMsg;
  m_nRedpacketCount: number;    // UInt16
}

export function writeCRespQueryGuildRedpacket(writer: BinaryWriter, resp: CRespQueryGuildRedpacket): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nRedpacketCount);
}

// =============================================================================
// USER BACK / LOGIN GIFT
// =============================================================================

export interface CReqUserBack {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
  m_nRewardType: number;        // UInt16
  m_nRewardIndex: number;       // UInt16
  m_strExtra: string | null;    // String
}

export function readCReqUserBack(reader: BinaryReader): CReqUserBack {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nRewardType: reader.readUInt16(),
    m_nRewardIndex: reader.readUInt16(),
    m_strExtra: reader.readString(),
  };
}

export interface CRespUserBack {
  m_stRetMsg: CCommonRespMsg;
  m_nDays: number;              // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespUserBack(writer: BinaryWriter, resp: CRespUserBack): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDays);
  writer.writeUInt64(resp.m_nRewardBits);
}

export interface CReqLoginGift {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
  m_nRewardIndex: number;       // UInt16
}

export function readCReqLoginGift(reader: BinaryReader): CReqLoginGift {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nRewardIndex: reader.readUInt16(),
  };
}

export interface CRespLoginGift {
  m_stRetMsg: CCommonRespMsg;
  m_nDays: number;              // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespLoginGift(writer: BinaryWriter, resp: CRespLoginGift): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDays);
  writer.writeUInt64(resp.m_nRewardBits);
}

export interface CReqWeeklyGift {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
}

export function readCReqWeeklyGift(reader: BinaryReader): CReqWeeklyGift {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface CRespWeeklyGift {
  m_stRetMsg: CCommonRespMsg;
  m_nWeeks: number;             // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespWeeklyGift(writer: BinaryWriter, resp: CRespWeeklyGift): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nWeeks);
  writer.writeUInt64(resp.m_nRewardBits);
}

// =============================================================================
// FIRST CHARGE
// =============================================================================

export interface CReqFirstCharge {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
}

export function readCReqFirstCharge(reader: BinaryReader): CReqFirstCharge {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface CRespFirstCharge {
  m_stRetMsg: CCommonRespMsg;
  m_nStatus: number;            // UInt16
  m_nRewardBits: bigint;        // UInt64
}

export function writeCRespFirstCharge(writer: BinaryWriter, resp: CRespFirstCharge): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nStatus);
  writer.writeUInt64(resp.m_nRewardBits);
}

// =============================================================================
// FIRST IAP INFO
// =============================================================================

export interface CQueryFirstIAPInfo {
  m_nType: number;              // UInt16
  m_nTransId: number;           // UInt32
}

export function readCQueryFirstIAPInfo(reader: BinaryReader): CQueryFirstIAPInfo {
  return {
    m_nType: reader.readUInt16(),
    m_nTransId: reader.readUInt32(),
  };
}

// =============================================================================
// HABBY ID BINDING
// =============================================================================

export interface STReqBindingHabbyID {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
  m_strAuthCode: string | null; // String
  m_strLanguage: string;        // String
}

export function readSTReqBindingHabbyID(reader: BinaryReader): STReqBindingHabbyID {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_strAuthCode: reader.readString(),
    m_strLanguage: reader.readString(),
  };
}

export interface STRespBindingHabbyID {
  m_stRetMsg: CCommonRespMsg;
  m_strHabbyID: string;         // String
  m_nStatus: number;            // UInt16
}

export function writeSTRespBindingHabbyID(writer: BinaryWriter, resp: STRespBindingHabbyID): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeString(resp.m_strHabbyID);
  writer.writeUInt16(resp.m_nStatus);
}

// =============================================================================
// FARM
// =============================================================================

export interface CReqFarm {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
  m_nSlotId: number;            // UInt16
}

export function readCReqFarm(reader: BinaryReader): CReqFarm {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_nSlotId: reader.readUInt16(),
  };
}

export interface CFarmSlot {
  m_nSlotId: number;            // UInt16
  m_nPlantId: number;           // UInt32
  m_nPlantTime: bigint;         // UInt64
  m_nStatus: number;            // UInt16
}

export function writeCFarmSlot(writer: BinaryWriter, slot: CFarmSlot): void {
  writer.writeUInt16(slot.m_nSlotId);
  writer.writeUInt32(slot.m_nPlantId);
  writer.writeUInt64(slot.m_nPlantTime);
  writer.writeUInt16(slot.m_nStatus);
}

export interface CRespFarm {
  m_stRetMsg: CCommonRespMsg;
  m_vecSlots: CFarmSlot[];
}

export function writeCRespFarm(writer: BinaryWriter, resp: CRespFarm): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecSlots, (s) => writeCFarmSlot(writer, s));
}

// =============================================================================
// MONSTER EGG / HATCH
// =============================================================================

export interface CMonsterEgg {
  m_nEggId: number;             // UInt32
  m_nSlotId: number;            // UInt16
  m_nStartTime: bigint;         // UInt64
}

export function writeCMonsterEgg(writer: BinaryWriter, egg: CMonsterEgg): void {
  writer.writeUInt32(egg.m_nEggId);
  writer.writeUInt16(egg.m_nSlotId);
  writer.writeUInt64(egg.m_nStartTime);
}

export interface CMonsterHatch {
  m_nMonsterId: number;         // UInt32
  m_nLevel: number;             // UInt16
  m_nStar: number;              // UInt16
}

export function writeCMonsterHatch(writer: BinaryWriter, hatch: CMonsterHatch): void {
  writer.writeUInt32(hatch.m_nMonsterId);
  writer.writeUInt16(hatch.m_nLevel);
  writer.writeUInt16(hatch.m_nStar);
}

export interface CRespMonsterHatch {
  m_stRetMsg: CCommonRespMsg;
  m_vecHatched: CMonsterHatch[];
}

export function writeCRespMonsterHatch(writer: BinaryWriter, resp: CRespMonsterHatch): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeArray(resp.m_vecHatched, (h) => writeCMonsterHatch(writer, h));
}

// =============================================================================
// SHIP BATTLE SEASON
// =============================================================================

export interface STReqShipBattleSeasonGhostShip {
  m_nTransID: number;           // UInt32
  m_nType: number;              // UInt16
}

export function readSTReqShipBattleSeasonGhostShip(reader: BinaryReader): STReqShipBattleSeasonGhostShip {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
  };
}

export interface CShipBattleBaseRank {
  m_nRank: number;              // UInt32
  m_nScore: number;             // UInt32
  m_strName: string;            // String
}

export function writeCShipBattleBaseRank(writer: BinaryWriter, rank: CShipBattleBaseRank): void {
  writer.writeUInt32(rank.m_nRank);
  writer.writeUInt32(rank.m_nScore);
  writer.writeString(rank.m_strName);
}

export interface STShipBattleSeasonIsLandRankInfo {
  m_vecRank: CShipBattleBaseRank[];
  m_nRankValue: bigint;         // UInt64
  m_nRank: number;              // UInt32
}

export function writeSTShipBattleSeasonIsLandRankInfo(writer: BinaryWriter, info: STShipBattleSeasonIsLandRankInfo): void {
  writer.writeArray(info.m_vecRank, (r) => writeCShipBattleBaseRank(writer, r));
  writer.writeUInt64(info.m_nRankValue);
  writer.writeUInt32(info.m_nRank);
}

export interface STRespShipBattleSeasonGhostShip {
  m_stRetMsg: CCommonRespMsg;
  m_nRemainFreeChallenges: number; // UInt32
  m_nPayChallengeCount: number;    // UInt32
  m_nDailyChallengeCount: number;  // UInt32
  m_nStartTime: bigint;         // UInt64
  m_nEndTime: bigint;           // UInt64
  m_nRankEndTime: bigint;       // UInt64
  mstRankInfo: STShipBattleSeasonIsLandRankInfo;
  m_nChallengeLimit: number;    // UInt32
}

export function writeSTRespShipBattleSeasonGhostShip(writer: BinaryWriter, resp: STRespShipBattleSeasonGhostShip): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nRemainFreeChallenges);
  writer.writeUInt32(resp.m_nPayChallengeCount);
  writer.writeUInt32(resp.m_nDailyChallengeCount);
  writer.writeArray([], () => {}); // m_vecGhostShipData
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt64(resp.m_nRankEndTime);
  writeSTShipBattleSeasonIsLandRankInfo(writer, resp.mstRankInfo);
  writer.writeUInt32(resp.m_nChallengeLimit);
}

// =============================================================================
// DAILY IAP GIFT
// =============================================================================

export interface CDailyGiftGemData {
  m_nGemId: number;             // UInt32
  m_nCount: number;             // UInt16
}

export function writeCDailyGiftGemData(writer: BinaryWriter, data: CDailyGiftGemData): void {
  writer.writeUInt32(data.m_nGemId);
  writer.writeUInt16(data.m_nCount);
}

export interface CDailyGiftHeroData {
  m_nHeroId: number;            // UInt32
  m_nFragments: number;         // UInt16
}

export function writeCDailyGiftHeroData(writer: BinaryWriter, data: CDailyGiftHeroData): void {
  writer.writeUInt32(data.m_nHeroId);
  writer.writeUInt16(data.m_nFragments);
}

export interface CReqDailyIapGift {
  m_nTransID: number;           // UInt32
  m_nRequestType: number;       // UInt16
  m_nSelectHeroIndex: number;   // UInt32
}

export function readCReqDailyIapGift(reader: BinaryReader): CReqDailyIapGift {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nSelectHeroIndex: reader.readUInt32(),
  };
}

export interface CRespDailyIapGift {
  m_stRetMsg: CCommonRespMsg;
  m_nDays: number;              // UInt16
  m_vecGems: CDailyGiftGemData[];
  m_vecHeroes: CDailyGiftHeroData[];
}

export function writeCRespDailyIapGift(writer: BinaryWriter, resp: CRespDailyIapGift): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDays);
  writer.writeArray(resp.m_vecGems, (g) => writeCDailyGiftGemData(writer, g));
  writer.writeArray(resp.m_vecHeroes, (h) => writeCDailyGiftHeroData(writer, h));
}
