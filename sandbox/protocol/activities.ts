/**
 * Activity Protocol Packets
 *
 * Request and response packets for various game activities.
 * Based on captured field data from protocol discovery.
 */

import type { BinaryReader, BinaryWriter } from "./binary";
import { type CCommonRespMsg, createSuccessResponse, writeCCommonRespMsg } from "./common";

// =============================================================================
// ACTIVITY COMMON DATA
// =============================================================================

export interface CActivityCommonData {
  m_nActivityId: number; // UInt32
  m_nActivityType: number; // UInt16
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nStatus: number; // UInt16
}

export function writeCActivityCommonData(writer: BinaryWriter, data: CActivityCommonData): void {
  writer.writeUInt32(data.m_nActivityId);
  writer.writeUInt16(data.m_nActivityType);
  writer.writeUInt64(data.m_nStartTime);
  writer.writeUInt64(data.m_nEndTime);
  writer.writeUInt16(data.m_nStatus);
}

// =============================================================================
// ACTIVITY INVEST
// =============================================================================

export interface CActivityInvestCondition {
  m_nConditionId: number; // UInt32
  m_nConditionType: number; // UInt16
  m_nCurrentValue: number; // UInt32
  m_nTargetValue: number; // UInt32
  m_bIsComplete: boolean; // Boolean
}

export function writeCActivityInvestCondition(
  writer: BinaryWriter,
  cond: CActivityInvestCondition,
): void {
  writer.writeUInt32(cond.m_nConditionId);
  writer.writeUInt16(cond.m_nConditionType);
  writer.writeUInt32(cond.m_nCurrentValue);
  writer.writeUInt32(cond.m_nTargetValue);
  writer.writeBool(cond.m_bIsComplete);
}

export interface CActivityInvestData {
  m_nInvestId: number; // UInt32
  m_nLevel: number; // UInt16
  m_bIsBought: boolean; // Boolean
  m_vecConditions: CActivityInvestCondition[];
}

export function writeCActivityInvestData(writer: BinaryWriter, data: CActivityInvestData): void {
  writer.writeUInt32(data.m_nInvestId);
  writer.writeUInt16(data.m_nLevel);
  writer.writeBool(data.m_bIsBought);
  writer.writeArray(data.m_vecConditions, (c) => writeCActivityInvestCondition(writer, c));
}

// =============================================================================
// ACTIVITY REQUESTS
// =============================================================================

export interface CReqActivityCommon {
  m_nRequestType: number; // UInt16
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nRewardId: number; // UInt16
  m_nRewardType: number; // UInt16
  m_strExtra: string | null; // String
}

export function readCReqActivityCommon(reader: BinaryReader): CReqActivityCommon {
  return {
    m_nRequestType: reader.readUInt16(),
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nRewardId: reader.readUInt16(),
    m_nRewardType: reader.readUInt16(),
    m_strExtra: reader.readString(),
  };
}

export interface CReqActivityShip {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt32
  m_strExtra: string | null; // String
}

export function readCReqActivityShip(reader: BinaryReader): CReqActivityShip {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_strExtra: reader.readString(),
  };
}

export interface CReqActivitySuperRoulette {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nTaskIndex: number; // UInt16
  m_nCountRewardIndex: number; // UInt16
}

export function readCReqActivitySuperRoulette(reader: BinaryReader): CReqActivitySuperRoulette {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nTaskIndex: reader.readUInt16(),
    m_nCountRewardIndex: reader.readUInt16(),
  };
}

export interface CReqActivityContinueGift {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nRewardIndex: number; // UInt16
}

export function readCReqActivityContinueGift(reader: BinaryReader): CReqActivityContinueGift {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nRewardIndex: reader.readUInt16(),
  };
}

export interface CReqActivityDiamondChoice {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nId: number; // UInt16
  m_vecChoiceIndex: number[]; // UInt16[]
}

export function readCReqActivityDiamondChoice(reader: BinaryReader): CReqActivityDiamondChoice {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nId: reader.readUInt16(),
    m_vecChoiceIndex: reader.readArray(() => reader.readUInt16()),
  };
}

export interface CReqActivityExchange {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nIndex: number; // UInt16
  m_strExtra: string | null; // String
}

export function readCReqActivityExchange(reader: BinaryReader): CReqActivityExchange {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nIndex: reader.readUInt16(),
    m_strExtra: reader.readString(),
  };
}

export interface CReqActivityInvest {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nInvestId: number; // UInt32
}

export function readCReqActivityInvest(reader: BinaryReader): CReqActivityInvest {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nInvestId: reader.readUInt32(),
  };
}

// =============================================================================
// ACTIVITY RESPONSES
// =============================================================================

export interface CRespActivityCommon {
  m_stRetMsg: CCommonRespMsg;
  m_nActivityId: number; // UInt32
  m_nStatus: number; // UInt16
}

export function writeCRespActivityCommon(writer: BinaryWriter, resp: CRespActivityCommon): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nActivityId);
  writer.writeUInt16(resp.m_nStatus);
}

export interface CActivityShipRelicsGift {
  m_nGiftId: number; // UInt32
  m_nStatus: number; // UInt16
}

export function writeCActivityShipRelicsGift(
  writer: BinaryWriter,
  gift: CActivityShipRelicsGift,
): void {
  writer.writeUInt32(gift.m_nGiftId);
  writer.writeUInt16(gift.m_nStatus);
}

export interface CRespActivityShip {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nScore: number; // UInt32
  m_vecRelicsGifts: CActivityShipRelicsGift[];
}

export function writeCRespActivityShip(writer: BinaryWriter, resp: CRespActivityShip): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt32(resp.m_nScore);
  writer.writeArray(resp.m_vecRelicsGifts, (g) => writeCActivityShipRelicsGift(writer, g));
}

export interface CRespActivitySuperRoulette {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nSpinCount: number; // UInt32
  m_nFreeSpinCount: number; // UInt16
}

export function writeCRespActivitySuperRoulette(
  writer: BinaryWriter,
  resp: CRespActivitySuperRoulette,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt32(resp.m_nSpinCount);
  writer.writeUInt16(resp.m_nFreeSpinCount);
}

export interface CRespActivityContinueGift {
  m_stRetMsg: CCommonRespMsg;
  m_nDays: number; // UInt16
  m_nRewardBits: bigint; // UInt64
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityContinueGift(
  writer: BinaryWriter,
  resp: CRespActivityContinueGift,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nDays);
  writer.writeUInt64(resp.m_nRewardBits);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityInvest {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_vecInvestData: CActivityInvestData[];
}

export function writeCRespActivityInvest(writer: BinaryWriter, resp: CRespActivityInvest): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeArray(resp.m_vecInvestData, (d) => writeCActivityInvestData(writer, d));
}

// =============================================================================
// ST ACTIVITY REQUESTS (Alternative naming convention)
// =============================================================================

export interface STReqActivityGiftTower {
  m_nTransID: number; // UInt32
  m_nType: number; // UInt16
  m_nId: number; // UInt32
  m_nNum: number; // UInt32
}

export function readSTReqActivityGiftTower(reader: BinaryReader): STReqActivityGiftTower {
  return {
    m_nTransID: reader.readUInt32(),
    m_nType: reader.readUInt16(),
    m_nId: reader.readUInt32(),
    m_nNum: reader.readUInt32(),
  };
}

export interface STReqActivityBingo {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt16
}

export function readSTReqActivityBingo(reader: BinaryReader): STReqActivityBingo {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt16(),
  };
}

export interface STReqActivityMining {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nBlockId: number; // UInt16
}

export function readSTReqActivityMining(reader: BinaryReader): STReqActivityMining {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nBlockId: reader.readUInt16(),
  };
}

export interface STReqActivityPiggyBank {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nBankId: number; // UInt16
}

export function readSTReqActivityPiggyBank(reader: BinaryReader): STReqActivityPiggyBank {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nBankId: reader.readUInt16(),
  };
}

// =============================================================================
// ST ACTIVITY RESPONSES
// =============================================================================

export interface STCommonQuickBuyData {
  m_nItemId: number; // UInt32
  m_nBuyTimes: number; // UInt32
  m_nBuyTimesLimit: number; // UInt32
  m_nBuyPrice: number; // UInt32
}

export function writeSTCommonQuickBuyData(writer: BinaryWriter, data: STCommonQuickBuyData): void {
  writer.writeUInt32(data.m_nItemId);
  writer.writeUInt32(data.m_nBuyTimes);
  writer.writeUInt32(data.m_nBuyTimesLimit);
  writer.writeUInt32(data.m_nBuyPrice);
}

// biome-ignore lint/complexity/noBannedTypes: Protocol placeholder for unknown structure
export type STAutoDeleteActivityItem = {};

export function writeSTAutoDeleteActivityItem(
  writer: BinaryWriter,
  _item: STAutoDeleteActivityItem,
): void {
  // Write empty dictionary placeholder
  writer.writeUInt16(0); // count = 0
}

export interface STActivityGiftTowerGift {
  m_vecGiftData: unknown[];
}

export function writeSTActivityGiftTowerGift(
  writer: BinaryWriter,
  gift: STActivityGiftTowerGift,
): void {
  writer.writeArray(gift.m_vecGiftData, () => {});
}

export interface STActivityGiftTowerTask {
  m_vecTaskData: unknown[];
}

export function writeSTActivityGiftTowerTask(
  writer: BinaryWriter,
  task: STActivityGiftTowerTask,
): void {
  writer.writeArray(task.m_vecTaskData, () => {});
}

export interface STActivityGiftTowerShop {
  m_vecShopData: unknown[];
}

export function writeSTActivityGiftTowerShop(
  writer: BinaryWriter,
  shop: STActivityGiftTowerShop,
): void {
  writer.writeArray(shop.m_vecShopData, () => {});
}

export interface STRespActivityGiftTower {
  m_stRetMsg: CCommonRespMsg;
  m_nTag: number; // UInt32
  m_nStartTime: bigint; // UInt64
  m_nGameEndTime: bigint; // UInt64
  m_nRewardEndTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nOpenGameLevel: number; // UInt32
  m_nProgressValue: number; // UInt32
  m_nProgressRewardBits: number; // UInt32
  m_nRewardTowerLayer: number; // UInt32
  m_nTowerHeight: number; // UInt32
  m_nTowerFinishNum: number; // UInt32
  m_stQuickBuy: STCommonQuickBuyData;
  m_stAutoDeleteActivityItem: STAutoDeleteActivityItem;
  m_stGift: STActivityGiftTowerGift;
  m_stTask: STActivityGiftTowerTask;
  m_stShop: STActivityGiftTowerShop;
  m_nDailyTime: bigint; // UInt64
  m_nTowerGroup: number; // UInt32
  m_nTowerld: number; // UInt32
}

export function writeSTRespActivityGiftTower(
  writer: BinaryWriter,
  resp: STRespActivityGiftTower,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nTag);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nGameEndTime);
  writer.writeUInt64(resp.m_nRewardEndTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt32(resp.m_nOpenGameLevel);
  writer.writeUInt32(resp.m_nProgressValue);
  writer.writeUInt32(resp.m_nProgressRewardBits);
  writer.writeUInt32(resp.m_nRewardTowerLayer);
  writer.writeUInt32(resp.m_nTowerHeight);
  writer.writeUInt32(resp.m_nTowerFinishNum);
  // Skip complex nested data for now - write empty
  writer.writeArray([], () => {}); // m_vecGridDatas
  writer.writeUInt16(0); // m_mapInitItemNum - empty dictionary
  writeSTCommonQuickBuyData(writer, resp.m_stQuickBuy);
  writeSTAutoDeleteActivityItem(writer, resp.m_stAutoDeleteActivityItem);
  writeSTActivityGiftTowerGift(writer, resp.m_stGift);
  writeSTActivityGiftTowerTask(writer, resp.m_stTask);
  writeSTActivityGiftTowerShop(writer, resp.m_stShop);
  writer.writeUInt64(resp.m_nDailyTime);
  writer.writeUInt32(resp.m_nTowerGroup);
  writer.writeUInt32(resp.m_nTowerld);
}

export interface STRespActivityPiggyBank {
  m_stRetMsg: CCommonRespMsg;
  m_nDailyTime: bigint; // UInt64
  m_nBeginTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nFreeRewardStatus: number; // UInt16
  m_nBuyBankID: number; // UInt16
  m_nTotalBattle: number; // UInt32
  m_nTag: number; // UInt16
}

export function writeSTRespActivityPiggyBank(
  writer: BinaryWriter,
  resp: STRespActivityPiggyBank,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nDailyTime);
  writer.writeUInt64(resp.m_nBeginTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt16(resp.m_nFreeRewardStatus);
  writer.writeArray([], () => {}); // m_vecFreeRewards
  writer.writeUInt16(resp.m_nBuyBankID);
  writer.writeUInt32(resp.m_nTotalBattle);
  writer.writeArray([], () => {}); // m_vecActivityPiggyBankDatas
  writer.writeUInt16(resp.m_nTag);
}

// Default response factories
export function createDefaultActivityResponse(transId: number): CRespActivityCommon {
  return {
    m_stRetMsg: createSuccessResponse(),
    m_nActivityId: transId,
    m_nStatus: 0,
  };
}

export function createDefaultActivityShipResponse(): CRespActivityShip {
  const now = BigInt(Math.floor(Date.now() / 1000));
  return {
    m_stRetMsg: createSuccessResponse(),
    m_nStartTime: now,
    m_nEndTime: now + BigInt(86400 * 7),
    m_nScore: 0,
    m_vecRelicsGifts: [],
  };
}
