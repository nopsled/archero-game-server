/**
 * ST (Status/State) Activity Response Packets
 *
 * These are complex activity response structures for various events.
 */

import type { BinaryReader, BinaryWriter } from "./binary";
import { type CCommonRespMsg, writeCCommonRespMsg } from "./common";

// =============================================================================
// ACTIVITY DATA STRUCTURES
// =============================================================================

export interface STActivityAnniversaryExchange {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityAnniversaryExchange(
  writer: BinaryWriter,
  data: STActivityAnniversaryExchange,
): void {
  writer.writeUInt32(data.m_nId);
  writer.writeUInt16(data.m_nCount);
}

export interface STActivityAnniversaryOpenBox {
  m_nPos: number; // UInt16
  m_bOpened: boolean; // Boolean
}

export function writeSTActivityAnniversaryOpenBox(
  writer: BinaryWriter,
  data: STActivityAnniversaryOpenBox,
): void {
  writer.writeUInt16(data.m_nPos);
  writer.writeBool(data.m_bOpened);
}

export interface STActivityAnniversaryPuzzle {
  m_nId: number; // UInt16
  m_nProgress: number; // UInt32
}

export function writeSTActivityAnniversaryPuzzle(
  writer: BinaryWriter,
  data: STActivityAnniversaryPuzzle,
): void {
  writer.writeUInt16(data.m_nId);
  writer.writeUInt32(data.m_nProgress);
}

export interface STActivityAnniversarySign {
  m_nDay: number; // UInt16
  m_bSigned: boolean; // Boolean
}

export function writeSTActivityAnniversarySign(
  writer: BinaryWriter,
  data: STActivityAnniversarySign,
): void {
  writer.writeUInt16(data.m_nDay);
  writer.writeBool(data.m_bSigned);
}

export interface STActivityAnniversaryTowerDefence {
  m_nLevel: number; // UInt16
  m_nScore: number; // UInt32
}

export function writeSTActivityAnniversaryTowerDefence(
  writer: BinaryWriter,
  data: STActivityAnniversaryTowerDefence,
): void {
  writer.writeUInt16(data.m_nLevel);
  writer.writeUInt32(data.m_nScore);
}

export interface STActivityArtifactTrialRankInfo {
  m_nRank: number; // UInt32
  m_strName: string; // String
  m_nScore: number; // UInt32
}

export function writeSTActivityArtifactTrialRankInfo(
  writer: BinaryWriter,
  info: STActivityArtifactTrialRankInfo,
): void {
  writer.writeUInt32(info.m_nRank);
  writer.writeString(info.m_strName);
  writer.writeUInt32(info.m_nScore);
}

export interface STActivityCircleTreasurePanel {
  m_nId: number; // UInt16
  m_nProgress: number; // UInt32
}

export function writeSTActivityCircleTreasurePanel(
  writer: BinaryWriter,
  panel: STActivityCircleTreasurePanel,
): void {
  writer.writeUInt16(panel.m_nId);
  writer.writeUInt32(panel.m_nProgress);
}

export interface STActivityCircleTreasureTask {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityCircleTreasureTask(
  writer: BinaryWriter,
  task: STActivityCircleTreasureTask,
): void {
  writer.writeUInt32(task.m_nId);
  writer.writeUInt32(task.m_nProgress);
  writer.writeBool(task.m_bClaimed);
}

export interface STActivityCrazyMonth {
  m_nDays: number; // UInt16
  m_nRewardBits: bigint; // UInt64
}

export function writeSTActivityCrazyMonth(writer: BinaryWriter, data: STActivityCrazyMonth): void {
  writer.writeUInt16(data.m_nDays);
  writer.writeUInt64(data.m_nRewardBits);
}

export interface STActivityFifthAnniversaryAward {
  m_nId: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityFifthAnniversaryAward(
  writer: BinaryWriter,
  award: STActivityFifthAnniversaryAward,
): void {
  writer.writeUInt32(award.m_nId);
  writer.writeBool(award.m_bClaimed);
}

export interface STActivityFifthAnniversaryShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityFifthAnniversaryShop(
  writer: BinaryWriter,
  shop: STActivityFifthAnniversaryShop,
): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivityFifthAnniversarySign {
  m_nDay: number; // UInt16
  m_bSigned: boolean; // Boolean
}

export function writeSTActivityFifthAnniversarySign(
  writer: BinaryWriter,
  sign: STActivityFifthAnniversarySign,
): void {
  writer.writeUInt16(sign.m_nDay);
  writer.writeBool(sign.m_bSigned);
}

export interface STActivityGardenTreasurePanel {
  m_nId: number; // UInt16
  m_nProgress: number; // UInt32
}

export function writeSTActivityGardenTreasurePanel(
  writer: BinaryWriter,
  panel: STActivityGardenTreasurePanel,
): void {
  writer.writeUInt16(panel.m_nId);
  writer.writeUInt32(panel.m_nProgress);
}

export interface STActivityGardenTreasureTask {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityGardenTreasureTask(
  writer: BinaryWriter,
  task: STActivityGardenTreasureTask,
): void {
  writer.writeUInt32(task.m_nId);
  writer.writeUInt32(task.m_nProgress);
  writer.writeBool(task.m_bClaimed);
}

export interface STActivityLotteryGift {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityLotteryGift(
  writer: BinaryWriter,
  gift: STActivityLotteryGift,
): void {
  writer.writeUInt32(gift.m_nId);
  writer.writeUInt16(gift.m_nCount);
}

export interface STActivityLotteryShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityLotteryShop(
  writer: BinaryWriter,
  shop: STActivityLotteryShop,
): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivityLuckyPlinkoAchievement {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityLuckyPlinkoAchievement(
  writer: BinaryWriter,
  ach: STActivityLuckyPlinkoAchievement,
): void {
  writer.writeUInt32(ach.m_nId);
  writer.writeUInt32(ach.m_nProgress);
  writer.writeBool(ach.m_bClaimed);
}

export interface STActivityLuckyPlinkoGift {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityLuckyPlinkoGift(
  writer: BinaryWriter,
  gift: STActivityLuckyPlinkoGift,
): void {
  writer.writeUInt32(gift.m_nId);
  writer.writeUInt16(gift.m_nCount);
}

export interface STActivityLuckyPlinkoGrid {
  m_nId: number; // UInt16
  m_bOpened: boolean; // Boolean
}

export function writeSTActivityLuckyPlinkoGrid(
  writer: BinaryWriter,
  grid: STActivityLuckyPlinkoGrid,
): void {
  writer.writeUInt16(grid.m_nId);
  writer.writeBool(grid.m_bOpened);
}

export interface STActivityLuckyPlinkoReward {
  m_nId: number; // UInt32
  m_nCount: number; // UInt32
}

export function writeSTActivityLuckyPlinkoReward(
  writer: BinaryWriter,
  reward: STActivityLuckyPlinkoReward,
): void {
  writer.writeUInt32(reward.m_nId);
  writer.writeUInt32(reward.m_nCount);
}

export interface STActivityLuckyPlinkoShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityLuckyPlinkoShop(
  writer: BinaryWriter,
  shop: STActivityLuckyPlinkoShop,
): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivityLuckyPlinkoTask {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityLuckyPlinkoTask(
  writer: BinaryWriter,
  task: STActivityLuckyPlinkoTask,
): void {
  writer.writeUInt32(task.m_nId);
  writer.writeUInt32(task.m_nProgress);
  writer.writeBool(task.m_bClaimed);
}

export interface STActivityMineCarAchievement {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityMineCarAchievement(
  writer: BinaryWriter,
  ach: STActivityMineCarAchievement,
): void {
  writer.writeUInt32(ach.m_nId);
  writer.writeUInt32(ach.m_nProgress);
  writer.writeBool(ach.m_bClaimed);
}

export interface STActivityMineCarGift {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityMineCarGift(
  writer: BinaryWriter,
  gift: STActivityMineCarGift,
): void {
  writer.writeUInt32(gift.m_nId);
  writer.writeUInt16(gift.m_nCount);
}

export interface STActivityMineCarPanel {
  m_nId: number; // UInt16
  m_nProgress: number; // UInt32
}

export function writeSTActivityMineCarPanel(
  writer: BinaryWriter,
  panel: STActivityMineCarPanel,
): void {
  writer.writeUInt16(panel.m_nId);
  writer.writeUInt32(panel.m_nProgress);
}

export interface STActivityMineCarShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityMineCarShop(
  writer: BinaryWriter,
  shop: STActivityMineCarShop,
): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivityMineCarTask {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityMineCarTask(
  writer: BinaryWriter,
  task: STActivityMineCarTask,
): void {
  writer.writeUInt32(task.m_nId);
  writer.writeUInt32(task.m_nProgress);
  writer.writeBool(task.m_bClaimed);
}

export interface STActivityMiningAchievement {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityMiningAchievement(
  writer: BinaryWriter,
  ach: STActivityMiningAchievement,
): void {
  writer.writeUInt32(ach.m_nId);
  writer.writeUInt32(ach.m_nProgress);
  writer.writeBool(ach.m_bClaimed);
}

export interface STActivityMiningBlockMap {
  m_nX: number; // UInt16
  m_nY: number; // UInt16
  m_nType: number; // UInt16
}

export function writeSTActivityMiningBlockMap(
  writer: BinaryWriter,
  block: STActivityMiningBlockMap,
): void {
  writer.writeUInt16(block.m_nX);
  writer.writeUInt16(block.m_nY);
  writer.writeUInt16(block.m_nType);
}

export interface STActivityMiningGift {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityMiningGift(writer: BinaryWriter, gift: STActivityMiningGift): void {
  writer.writeUInt32(gift.m_nId);
  writer.writeUInt16(gift.m_nCount);
}

export interface STActivityMiningShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityMiningShop(writer: BinaryWriter, shop: STActivityMiningShop): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivityMiningTask {
  m_nId: number; // UInt32
  m_nProgress: number; // UInt32
  m_bClaimed: boolean; // Boolean
}

export function writeSTActivityMiningTask(writer: BinaryWriter, task: STActivityMiningTask): void {
  writer.writeUInt32(task.m_nId);
  writer.writeUInt32(task.m_nProgress);
  writer.writeBool(task.m_bClaimed);
}

export interface STActivityPirateTreasureExchange {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityPirateTreasureExchange(
  writer: BinaryWriter,
  exc: STActivityPirateTreasureExchange,
): void {
  writer.writeUInt32(exc.m_nId);
  writer.writeUInt16(exc.m_nCount);
}

export interface STActivityPirateTreasureGift {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivityPirateTreasureGift(
  writer: BinaryWriter,
  gift: STActivityPirateTreasureGift,
): void {
  writer.writeUInt32(gift.m_nId);
  writer.writeUInt16(gift.m_nCount);
}

export interface STActivityPirateTreasureVault {
  m_nId: number; // UInt16
  m_bOpened: boolean; // Boolean
}

export function writeSTActivityPirateTreasureVault(
  writer: BinaryWriter,
  vault: STActivityPirateTreasureVault,
): void {
  writer.writeUInt16(vault.m_nId);
  writer.writeBool(vault.m_bOpened);
}

export interface STActivitySixthAnniversaryBattlePass {
  m_nLevel: number; // UInt16
  m_nScore: number; // UInt32
  m_nRewardBits: bigint; // UInt64
}

export function writeSTActivitySixthAnniversaryBattlePass(
  writer: BinaryWriter,
  bp: STActivitySixthAnniversaryBattlePass,
): void {
  writer.writeUInt16(bp.m_nLevel);
  writer.writeUInt32(bp.m_nScore);
  writer.writeUInt64(bp.m_nRewardBits);
}

export interface STActivitySixthAnniversaryShop {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTActivitySixthAnniversaryShop(
  writer: BinaryWriter,
  shop: STActivitySixthAnniversaryShop,
): void {
  writer.writeUInt32(shop.m_nId);
  writer.writeUInt16(shop.m_nCount);
}

export interface STActivitySixthAnniversarySign {
  m_nDay: number; // UInt16
  m_bSigned: boolean; // Boolean
}

export function writeSTActivitySixthAnniversarySign(
  writer: BinaryWriter,
  sign: STActivitySixthAnniversarySign,
): void {
  writer.writeUInt16(sign.m_nDay);
  writer.writeBool(sign.m_bSigned);
}

export interface STLuckyPlinkoQuickBuyData {
  m_nId: number; // UInt32
  m_nCount: number; // UInt16
}

export function writeSTLuckyPlinkoQuickBuyData(
  writer: BinaryWriter,
  data: STLuckyPlinkoQuickBuyData,
): void {
  writer.writeUInt32(data.m_nId);
  writer.writeUInt16(data.m_nCount);
}

// =============================================================================
// ST ACTIVITY RESPONSES
// =============================================================================

export interface STRespActivityAnniversary {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityAnniversary(
  writer: BinaryWriter,
  resp: STRespActivityAnniversary,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityArtifactTrial {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityArtifactTrial(
  writer: BinaryWriter,
  resp: STRespActivityArtifactTrial,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityBingo {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityBingo(writer: BinaryWriter, resp: STRespActivityBingo): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityChargeOnce {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityChargeOnce(
  writer: BinaryWriter,
  resp: STRespActivityChargeOnce,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityChargeReward {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityChargeReward(
  writer: BinaryWriter,
  resp: STRespActivityChargeReward,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityCircleTreasure {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityCircleTreasure(
  writer: BinaryWriter,
  resp: STRespActivityCircleTreasure,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityCommonTurn {
  m_stRetMsg: CCommonRespMsg;
  m_nRequestType: number; // UInt16
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
  m_nTaskEndTime: bigint; // UInt64
  m_bIsEnd: boolean; // Boolean
  m_bIsNew: boolean; // Boolean
  m_nOpenGameLevel: number; // UInt32
  m_strItems: string; // String
  m_nTurnCount: number; // UInt16
  m_nDoTurnId: number; // UInt32
  m_nCurrentTurn: number; // UInt16
  m_nMaxTurn: number; // UInt16
  m_strBoxItems: string; // String
  m_nTotalTurn: number; // UInt16
  m_nRewardBoxBits: bigint; // UInt64
  m_nStyleId: number; // UInt32
  m_nTaskRewardBits: bigint; // UInt64
  m_strTasks: string; // String
  m_strTaskCount: string; // String
  m_nKeyItemCount: number; // UInt16
}

export function writeSTRespActivityCommonTurn(
  writer: BinaryWriter,
  resp: STRespActivityCommonTurn,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nRequestType);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
  writer.writeUInt64(resp.m_nTaskEndTime);
  writer.writeBool(resp.m_bIsEnd);
  writer.writeBool(resp.m_bIsNew);
  writer.writeUInt32(resp.m_nOpenGameLevel);
  writer.writeString(resp.m_strItems);
  writer.writeUInt16(resp.m_nTurnCount);
  writer.writeArray([], () => {}); // m_vecTurntableData
  writer.writeUInt32(resp.m_nDoTurnId);
  writer.writeUInt16(resp.m_nCurrentTurn);
  writer.writeUInt16(resp.m_nMaxTurn);
  writer.writeString(resp.m_strBoxItems);
  writer.writeUInt16(resp.m_nTotalTurn);
  writer.writeUInt64(resp.m_nRewardBoxBits);
  writer.writeArray([], () => {}); // m_verRewardItems
  writer.writeUInt32(resp.m_nStyleId);
  writer.writeUInt64(resp.m_nTaskRewardBits);
  writer.writeString(resp.m_strTasks);
  writer.writeString(resp.m_strTaskCount);
  writer.writeUInt16(resp.m_nKeyItemCount);
}

export interface STRespActivityLattice {
  m_stRetMsg: CCommonRespMsg;
  m_nRequestType: number; // UInt16
  m_nLayer: number; // UInt16
  m_nScore: number; // UInt32
  m_nRewardId: number; // UInt32
  m_nLatticeIndex: number; // UInt16
  m_nHitChoiceIndex: number; // UInt16
  m_nId: number; // UInt16
  m_nCount: number; // Int16
  m_ntotalCount: number; // UInt16
  m_nGiftId: number; // UInt32
  m_strGiftBuyCnt: string; // String
}

export function writeSTRespActivityLattice(
  writer: BinaryWriter,
  resp: STRespActivityLattice,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nRequestType);
  writer.writeUInt16(resp.m_nLayer);
  writer.writeUInt32(resp.m_nScore);
  writer.writeUInt32(resp.m_nRewardId);
  writer.writeArray([], () => {}); // m_vecChoices
  writer.writeArray([], () => {}); // m_vecLattices
  writer.writeUInt16(resp.m_nLatticeIndex);
  writer.writeUInt16(resp.m_nHitChoiceIndex);
  writer.writeArray([], () => {}); // m_vecOpenLattices
  writer.writeArray([], () => {}); // m_vecExchangeData
  writer.writeUInt16(resp.m_nId);
  writer.writeInt16(resp.m_nCount);
  writer.writeUInt16(resp.m_ntotalCount);
  writer.writeUInt32(resp.m_nGiftId);
  writer.writeString(resp.m_strGiftBuyCnt);
  writer.writeArray([], () => {}); // m_vecSuperChoices
}

export interface STRespActivityMining {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityMining(writer: BinaryWriter, resp: STRespActivityMining): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityOpenBox {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityOpenBox(
  writer: BinaryWriter,
  resp: STRespActivityOpenBox,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityPiggyBank {
  m_stRetMsg: CCommonRespMsg;
  m_nDiamonds: number; // UInt32
  m_nMaxDiamonds: number; // UInt32
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityPiggyBank(
  writer: BinaryWriter,
  resp: STRespActivityPiggyBank,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt32(resp.m_nDiamonds);
  writer.writeUInt32(resp.m_nMaxDiamonds);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityPirateTreasure {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityPirateTreasure(
  writer: BinaryWriter,
  resp: STRespActivityPirateTreasure,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivitySixthAnniversary {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivitySixthAnniversary(
  writer: BinaryWriter,
  resp: STRespActivitySixthAnniversary,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityTreasure {
  m_stRetMsg: CCommonRespMsg;
  m_nType: number; // UInt16
  m_nStepIndex: number; // UInt16
  m_nProgress: number; // UInt16
  m_nRewardBits: bigint; // UInt64
  m_nBuyCnt: number; // UInt16
  m_nSelectId: number; // UInt16
  m_strTreasureCnt: string; // String
  m_nBPPoint: number; // UInt32
  m_nBPFreeRewardBits: bigint; // UInt64
  m_nBPNormalRewardBits: bigint; // UInt64
  m_nBPBigRewardBits: bigint; // UInt64
  m_nHitId: number; // UInt16
  m_bIapBattlePass: boolean; // Boolean
  m_bIapBigBattlePass: boolean; // Boolean
  m_strPayCount: string; // String
  m_nTag: number; // UInt16
  m_nGuaranteeTimes: number; // UInt16
}

export function writeSTRespActivityTreasure(
  writer: BinaryWriter,
  resp: STRespActivityTreasure,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nType);
  writer.writeUInt16(resp.m_nStepIndex);
  writer.writeUInt16(resp.m_nProgress);
  writer.writeUInt64(resp.m_nRewardBits);
  writer.writeUInt16(resp.m_nBuyCnt);
  writer.writeUInt16(resp.m_nSelectId);
  writer.writeString(resp.m_strTreasureCnt);
  writer.writeUInt32(resp.m_nBPPoint);
  writer.writeUInt64(resp.m_nBPFreeRewardBits);
  writer.writeUInt64(resp.m_nBPNormalRewardBits);
  writer.writeUInt64(resp.m_nBPBigRewardBits);
  writer.writeUInt16(resp.m_nHitId);
  writer.writeBool(resp.m_bIapBattlePass);
  writer.writeBool(resp.m_bIapBigBattlePass);
  writer.writeString(resp.m_strPayCount);
  writer.writeUInt16(resp.m_nTag);
  writer.writeArray([], () => {}); // m_vecHitIds
  writer.writeUInt16(resp.m_nGuaranteeTimes);
}

export interface STRespActivityWish {
  m_stRetMsg: CCommonRespMsg;
  m_nRequestType: number; // UInt16
  m_nDailyTaskRefreshTime: bigint; // UInt64
  m_bIsNew: boolean; // Boolean
  m_nRound: number; // UInt16
  m_nWishId: number; // UInt32
  m_nWishSelectIdx: number; // UInt16
  m_nWishValue: number; // UInt32
  m_nWishRewardBits: bigint; // UInt64
  m_nGiftId: number; // UInt32
  m_strGiftBuyCnt: string; // String
}

export function writeSTRespActivityWish(writer: BinaryWriter, resp: STRespActivityWish): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt16(resp.m_nRequestType);
  writer.writeUInt64(resp.m_nDailyTaskRefreshTime);
  writer.writeBool(resp.m_bIsNew);
  writer.writeUInt16(resp.m_nRound);
  writer.writeUInt32(resp.m_nWishId);
  writer.writeUInt16(resp.m_nWishSelectIdx);
  writer.writeUInt32(resp.m_nWishValue);
  writer.writeUInt64(resp.m_nWishRewardBits);
  writer.writeUInt32(resp.m_nGiftId);
  writer.writeString(resp.m_strGiftBuyCnt);
  writer.writeArray([], () => {}); // m_vecDailyTasks
}

export interface STReqActivityPirateTreasure {
  m_nTransID: number; // UInt32
  m_nRequestType: number; // UInt16
  m_nId: number; // Int32
}

export function readSTReqActivityPirateTreasure(reader: BinaryReader): STReqActivityPirateTreasure {
  return {
    m_nTransID: reader.readUInt32(),
    m_nRequestType: reader.readUInt16(),
    m_nId: reader.readInt32(),
  };
}

// =============================================================================
// REMAINING STRESP ACTIVITY TYPES (for 100% coverage)
// =============================================================================

export interface STRespActivityCostDiamond {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityCostDiamond(
  writer: BinaryWriter,
  resp: STRespActivityCostDiamond,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityCostLife {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityCostLife(
  writer: BinaryWriter,
  resp: STRespActivityCostLife,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityCrazyMonth {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityCrazyMonth(
  writer: BinaryWriter,
  resp: STRespActivityCrazyMonth,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityFifthAnniversary {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityFifthAnniversary(
  writer: BinaryWriter,
  resp: STRespActivityFifthAnniversary,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityGardenTreasure {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityGardenTreasure(
  writer: BinaryWriter,
  resp: STRespActivityGardenTreasure,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityLoginPackage {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityLoginPackage(
  writer: BinaryWriter,
  resp: STRespActivityLoginPackage,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityLuckyPlinko {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityLuckyPlinko(
  writer: BinaryWriter,
  resp: STRespActivityLuckyPlinko,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityMagicCrystal {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityMagicCrystal(
  writer: BinaryWriter,
  resp: STRespActivityMagicCrystal,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityMineCar {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityMineCar(
  writer: BinaryWriter,
  resp: STRespActivityMineCar,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityPayment {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityPayment(
  writer: BinaryWriter,
  resp: STRespActivityPayment,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityPrivilege {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityPrivilege(
  writer: BinaryWriter,
  resp: STRespActivityPrivilege,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityPuzzle {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityPuzzle(writer: BinaryWriter, resp: STRespActivityPuzzle): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityRebate {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityRebate(writer: BinaryWriter, resp: STRespActivityRebate): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivityScratchLottery {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivityScratchLottery(
  writer: BinaryWriter,
  resp: STRespActivityScratchLottery,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivitySevenDays {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivitySevenDays(
  writer: BinaryWriter,
  resp: STRespActivitySevenDays,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}

export interface STRespActivitySevenDaysAppend {
  m_stRetMsg: CCommonRespMsg;
  m_nStartTime: bigint; // UInt64
  m_nEndTime: bigint; // UInt64
}

export function writeSTRespActivitySevenDaysAppend(
  writer: BinaryWriter,
  resp: STRespActivitySevenDaysAppend,
): void {
  writeCCommonRespMsg(writer, resp.m_stRetMsg);
  writer.writeUInt64(resp.m_nStartTime);
  writer.writeUInt64(resp.m_nEndTime);
}
