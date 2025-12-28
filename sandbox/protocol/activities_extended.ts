/**
 * Additional Activity Protocol Packets
 *
 * Missing request and response packets for various game activities.
 */

import type { BinaryReader, BinaryWriter } from "./binary";
import { type CCommonRespMsg, writeCCommonRespMsg } from "./common";

// =============================================================================
// ADDITIONAL ACTIVITY REQUESTS
// =============================================================================

export interface CReqActivityBackReward {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nRewardId: number; // UInt32
}

export function readCReqActivityBackReward(reader: BinaryReader): CReqActivityBackReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nRewardId: reader.readUInt32(),
  };
}

export interface CReqActivityChainGift {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nGiftId: number; // UInt32
}

export function readCReqActivityChainGift(reader: BinaryReader): CReqActivityChainGift {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nGiftId: reader.readUInt32(),
  };
}

export interface CReqActivityChainGiftNew {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nGiftId: number; // UInt32
}

export function readCReqActivityChainGiftNew(reader: BinaryReader): CReqActivityChainGiftNew {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nGiftId: reader.readUInt32(),
  };
}

export interface CReqActivityDropRate {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readCReqActivityDropRate(reader: BinaryReader): CReqActivityDropRate {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface CReqActivityEmploy {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nEmployId: number; // UInt32
}

export function readCReqActivityEmploy(reader: BinaryReader): CReqActivityEmploy {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nEmployId: reader.readUInt32(),
  };
}

export interface CReqActivityGrowth {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nRewardId: number; // UInt32
  m_nRewardIndex: number; // UInt32
  m_strExtra: string | null; // String
}

export function readCReqActivityGrowth(reader: BinaryReader): CReqActivityGrowth {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nRewardId: reader.readUInt32(),
    m_nRewardIndex: reader.readUInt32(),
    m_strExtra: reader.readString(),
  };
}

export interface CReqActivityLuckyWheel {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nNum: number; // UInt16
}

export function readCReqActivityLuckyWheel(reader: BinaryReader): CReqActivityLuckyWheel {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nNum: reader.readUInt16(),
  };
}

// =============================================================================
// ADDITIONAL ACTIVITY RESPONSES
// =============================================================================

export interface CRespActivityBackReward {
  m_stRetMsg: CCommonRespMsg;
  m_nRewardBits: bigint; // UInt64
}

export function writeCRespActivityBackReward(
  writer: BinaryWriter,
  resp: CRespActivityBackReward,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nRewardBits);
}

export interface CRespActivityChainGift {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityChainGift(
  writer: BinaryWriter,
  resp: CRespActivityChainGift,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityChainGiftNew {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityChainGiftNew(
  writer: BinaryWriter,
  resp: CRespActivityChainGiftNew,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityDiamondChoice {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_vecChoices: number[]; // UInt16[]
}

export function writeCRespActivityDiamondChoice(
  writer: BinaryWriter,
  resp: CRespActivityDiamondChoice,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeArray(resp.m_vecChoices, (c) => writer.writeUInt16(c));
}

export interface CRespActivityDropRate {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityDropRate(
  writer: BinaryWriter,
  resp: CRespActivityDropRate,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityEmploy {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityEmploy(writer: BinaryWriter, resp: CRespActivityEmploy): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityExchange {
  m_stRetMsg: CCommonRespMsg;
  m_nRequestType: number; // UInt16
  m_nEndTime: bigint; // UInt64
  m_strDropItems: string; // String
  m_nIndex: number; // UInt16
  m_nCount: number; // Int16
  m_ntotalCount: number; // UInt16
  m_nStartTime: bigint; // UInt64
  m_nStyleId: number; // UInt32
}

export function writeCRespActivityExchange(
  writer: BinaryWriter,
  resp: CRespActivityExchange,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nRequestType);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeString(resp.m_strDropItems);
  writer.writeArray([], () => {}); // m_vecExchangeData - empty
  writer.writeUInt16(resp.m_nIndex);
  writer.writeInt16(resp.m_nCount);
  writer.writeUInt16(resp.m_ntotalCount);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt32(resp.m_nStyleId);
}

export interface CRespActivityGrowth {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityGrowth(writer: BinaryWriter, resp: CRespActivityGrowth): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface CRespActivityLuckyWheel {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeCRespActivityLuckyWheel(
  writer: BinaryWriter,
  resp: CRespActivityLuckyWheel,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

// =============================================================================
// ST ACTIVITY REQUESTS
// =============================================================================

export interface STReqActivityAnniversary {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nPos: number; // UInt16
  m_nRewardType: number; // UInt16
  m_nTaskId: number; // UInt16
  m_nBoxRewardId: number; // Int32
  m_nExchangeId: number; // UInt16
}

export function readSTReqActivityAnniversary(reader: BinaryReader): STReqActivityAnniversary {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nPos: reader.readUInt16(),
    m_nRewardType: reader.readUInt16(),
    m_nTaskId: reader.readUInt16(),
    m_nBoxRewardId: reader.readInt32(),
    m_nExchangeId: reader.readUInt16(),
  };
}

export interface STReqActivityArtifactTrial {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityArtifactTrial(reader: BinaryReader): STReqActivityArtifactTrial {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityChargeOnce {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityChargeOnce(reader: BinaryReader): STReqActivityChargeOnce {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityChargeReward {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityChargeReward(reader: BinaryReader): STReqActivityChargeReward {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityCircleTreasure {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt16
}

export function readSTReqActivityCircleTreasure(reader: BinaryReader): STReqActivityCircleTreasure {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt16(),
  };
}

export interface STReqActivityCommonTurn {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt16
}

export function readSTReqActivityCommonTurn(reader: BinaryReader): STReqActivityCommonTurn {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt16(),
  };
}

export interface STReqActivityCostDiamond {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityCostDiamond(reader: BinaryReader): STReqActivityCostDiamond {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityCostLife {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityCostLife(reader: BinaryReader): STReqActivityCostLife {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityCrazyMonth {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityCrazyMonth(reader: BinaryReader): STReqActivityCrazyMonth {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityFifthAnniversary {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityFifthAnniversary(
  reader: BinaryReader,
): STReqActivityFifthAnniversary {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityGardenTreasure {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityGardenTreasure(reader: BinaryReader): STReqActivityGardenTreasure {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityLattice {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  vecChoices: number[]; // UInt16[]
  m_nId: number; // UInt16
  m_nExchangeCnt: number; // UInt16
}

export function readSTReqActivityLattice(reader: BinaryReader): STReqActivityLattice {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    vecChoices: reader.readArray(() => reader.readUInt16()),
    m_nId: reader.readUInt16(),
    m_nExchangeCnt: reader.readUInt16(),
  };
}

export interface STReqActivityLoginPackage {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityLoginPackage(reader: BinaryReader): STReqActivityLoginPackage {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityLuckPlinko {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityLuckPlinko(reader: BinaryReader): STReqActivityLuckPlinko {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityMagicCrystal {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt16
  m_nExchangeNum: number; // UInt16
}

export function readSTReqActivityMagicCrystal(reader: BinaryReader): STReqActivityMagicCrystal {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt16(),
    m_nExchangeNum: reader.readUInt16(),
  };
}

export interface STReqActivityMineCar {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityMineCar(reader: BinaryReader): STReqActivityMineCar {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityOpenBox {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nPos: number; // UInt16
  m_nRewardType: number; // UInt16
  m_nTaskId: number; // UInt16
  m_nBoxRewardId: number; // Int32
  m_nExchangeId: number; // UInt16
}

export function readSTReqActivityOpenBox(reader: BinaryReader): STReqActivityOpenBox {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nPos: reader.readUInt16(),
    m_nRewardType: reader.readUInt16(),
    m_nTaskId: reader.readUInt16(),
    m_nBoxRewardId: reader.readInt32(),
    m_nExchangeId: reader.readUInt16(),
  };
}

export interface STReqActivityPayment {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityPayment(reader: BinaryReader): STReqActivityPayment {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityPrivilege {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityPrivilege(reader: BinaryReader): STReqActivityPrivilege {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityPuzzle {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nTaskId: number; // UInt16
  m_nBoxRewardId: number; // Int32
}

export function readSTReqActivityPuzzle(reader: BinaryReader): STReqActivityPuzzle {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nTaskId: reader.readUInt16(),
    m_nBoxRewardId: reader.readInt32(),
  };
}

export interface STReqActivityRebate {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityRebate(reader: BinaryReader): STReqActivityRebate {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivityScratchLottery {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivityScratchLottery(reader: BinaryReader): STReqActivityScratchLottery {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivitySevenDays {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivitySevenDays(reader: BinaryReader): STReqActivitySevenDays {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivitySevenDaysAppend {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
}

export function readSTReqActivitySevenDaysAppend(
  reader: BinaryReader,
): STReqActivitySevenDaysAppend {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
  };
}

export interface STReqActivitySixthAnniversary {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nId: number; // Int32
  m_nNum: number; // UInt16
}

export function readSTReqActivitySixthAnniversary(
  reader: BinaryReader,
): STReqActivitySixthAnniversary {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nId: reader.readInt32(),
    m_nNum: reader.readUInt16(),
  };
}

export interface STReqActivityTreasure {
  m_nType: number; // UInt16
  m_nTransID: number; // UInt32
  m_nId: number; // UInt16
  m_nIndex: number; // UInt16
}

export function readSTReqActivityTreasure(reader: BinaryReader): STReqActivityTreasure {
  return {
    m_nType: reader.readUInt16(),
    m_nTransID: reader.readUInt32(),
    m_nId: reader.readUInt16(),
    m_nIndex: reader.readUInt16(),
  };
}

export interface STReqActivityWish {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // UInt16
}

export function readSTReqActivityWish(reader: BinaryReader): STReqActivityWish {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readUInt16(),
  };
}

// =============================================================================
// COMMON DATA STRUCTURE
// =============================================================================

/**
 * STCommonData - Large state synchronization structure
 * Sent with most responses to update player state
 */
export interface STCommonData {
  m_nChange: boolean; // Boolean - if false, skip reading rest
  // When m_nChange is false, the rest is not serialized
}

export function writeSTCommonData(writer: BinaryWriter, data: STCommonData): void {
  writer.writeBool(data.m_nChange);
  // If m_nChange is false, don't write any more data
}

export function readSTCommonData(reader: BinaryReader): STCommonData {
  const m_nChange = reader.readBool();
  return { m_nChange };
  // If m_nChange is true, there would be more fields, but we handle that separately
}
