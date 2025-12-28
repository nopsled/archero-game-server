/**
 * Login Protocol Packets
 * 
 * Request: CUserLoginPacket
 * Response: CRespUserLoginPacket
 * 
 * Based on captured field data from protocol discovery.
 */

import { BinaryReader, BinaryWriter } from "./binary";
import {
  CEquipmentItem,
  writeCEquipmentItem,
  createDefaultEquipmentItem,
  CHeroItem,
  writeCHeroItem,
  createDefaultHero,
  CRestoreItem,
  writeCRestoreItem,
  createDefaultRestoreItem,
  CTimestampItem,
  writeCTimestampItem,
  CBoxAssuranceItem,
  writeCBoxAssuranceItem,
  createDefaultBoxAssurance,
  STPetInfo,
  writeSTPetInfo,
  STHeadItem,
  writeSTHeadItem,
  CArtifact,
  writeCArtifact,
} from "./common";

// =============================================================================
// LOGIN REQUEST
// =============================================================================

/**
 * CUserLoginPacket - Login request from client
 */
export interface CUserLoginPacket {
  m_nTransID: number;      // UInt32
  m_strPlatform: string;   // String - "android" or "ios"
}

export function readCUserLoginPacket(reader: BinaryReader): CUserLoginPacket {
  return {
    m_nTransID: reader.readUInt32(),
    m_strPlatform: reader.readString(),
  };
}

// =============================================================================
// LOGIN RESPONSE
// =============================================================================

/**
 * CRespUserLoginPacket - Full login response (50+ fields)
 * Field order based on captured packet data.
 */
export interface CRespUserLoginPacket {
  // Core player data
  m_nTransID: number;              // UInt32
  m_nCoins: number;                // UInt32
  m_nDiamonds: number;             // Int32
  m_nLevel: number;                // UInt16
  m_nExperince: number;            // UInt32
  m_nUserRawId: bigint;            // UInt64
  m_nNowTime: bigint;              // UInt64 - current server time
  m_nTodayEndTimestamp: bigint;    // UInt64 - end of day

  // Progress data
  m_nMaxLayer: number;             // UInt16
  m_nLayerBoxID: number;           // UInt16
  m_nTreasureRandomCount: number;  // UInt32
  m_nBattleRebornCount: number;    // UInt16
  
  // Account info
  m_strUserAccessToken: string;    // String
  m_strNickName: string;           // String
  m_nAccountStatus: number;        // UInt16
  
  // Items data
  m_nExtraNormalDiamondItem: number;  // UInt16
  m_nExtraLargeDiamondItem: number;   // UInt16
  m_nLargeDiamondItemCount: number;   // UInt16
  
  // Game system flags
  m_nGameSystemMask: bigint;       // UInt64

  // Hero layer
  m_nMaxHeroLayer: number;         // UInt16
  m_nHeroLayerBoxID: number;       // UInt16

  // Cash/monetization
  m_nTotalCash: number;            // UInt32
  m_bTalentBackCoin: boolean;      // Boolean

  // Ads
  m_nAdCount: number;              // UInt16

  // Email binding
  m_strBindEmailAddress: string;   // String

  // Activity recharge
  vecActivityRechargeResetType: number[]; // UInt16[]

  // Skins
  m_bHeroSkinItemIsBuy: boolean;   // Boolean
  m_bHeroSkinSeniorItemIsBuy: boolean; // Boolean
  m_strSkinItemIapProductId: string;   // String

  // Profile
  m_nHeadIcon: number;             // UInt32
  m_nHeadFrame: number;            // UInt32
  m_nHeadFrameTimestamp: bigint;   // UInt64

  // IDFA
  m_bOpenIdfa: boolean;            // Boolean

  // Rename
  m_nRemameDiamonds: number;       // UInt32
  m_nRenameCount: number;          // UInt16

  // Chapter fail counts
  m_nChapFailCnt: number;          // UInt16
  m_nHeroChapFailCnt: number;      // UInt16

  // Purchase data
  m_nPurcahseInTowWeeks: number;   // UInt32
  m_nLatest3PurchaseAvg: number;   // UInt32

  // Mix box
  m_nMixBoxItem: number;           // UInt16
  m_nMixBoxSingleCount: number;    // UInt16
  m_nMixBoxSingleTotalCount: number; // UInt16
  m_nMixBoxTenCount: number;       // UInt16

  // Dragon box
  m_nDragonBoxItem: number;        // UInt16
  m_nDragonBoxCountLow: number;    // UInt16
  m_nDragonBoxCountMid: number;    // UInt16
  m_nDragonBoxCountHigh: number;   // UInt16

  // Free coin
  m_nFreeCoinTimestamp: bigint;    // UInt64

  // VIP
  m_nVipLevel: number;             // UInt16
  m_nVipScore: number;             // UInt32

  // Bans
  m_nChapterBanTimestamp: bigint;  // UInt64

  // Relics box
  m_nRelicsBoxItem: number;        // UInt16
  m_nRelicsBoxCountLow: number;    // UInt16
  m_nRelicsBoxCountHigh: number;   // UInt16

  // Offline battle
  m_nOfflineBattleCount: number;   // UInt16

  // Equip S box
  m_nEquipSBoxItem: number;        // UInt16
  m_nEquipSBoxCountLow: number;    // UInt16
  m_nEquipSBoxCountHigh: number;   // UInt16

  // Worker box
  m_nWorkerBoxKeyCount: number;    // UInt32
  m_nWorkerBoxCountLow: number;    // UInt16
  m_nWorkerBoxCountMid: number;    // UInt16
  m_nWorkerBoxCountHigh: number;   // UInt16

  // Pet box
  m_nPetBoxKeyCount: number;       // UInt32
  m_nPetBoxCountLow: number;       // UInt16
  m_nPetBoxCountMid: number;       // UInt16
  m_nPetBoxCountHigh: number;      // UInt16

  // Habby ID
  m_strHabbyID: string;            // String

  // Must drop
  m_nMustDropMask: bigint;         // UInt64

  // Guild
  m_nGuildStopTimestamp: bigint;   // UInt64

  // Star diamond
  m_nStarDiamond: number;          // UInt32

  // Extended experience/coins
  m_nExperinceInt64: bigint;       // UInt64
  m_nCoinsInt64: bigint;           // Int64

  // Imprint box
  m_nImprintBoxKeyCount: number;   // UInt32

  // Hell layer
  m_nMaxHellLayer: number;         // UInt16
  m_nHellLayerBoxID: number;       // UInt16
  m_nChapHellFailCount: number;    // UInt16

  // Other
  m_nUpgradeLevel: number;         // UInt16
  m_nCardThemeId: number;          // UInt32
  m_nCardThemeTimestamp: bigint;   // UInt64

  // Arrays
  m_arrayEquipData: CEquipmentItem[];
  m_arrayRestoreData: CRestoreItem[];
  m_arrayTimestampData: CTimestampItem[];
  m_arrayHeroData: CHeroItem[];
  m_vecHeadItem: STHeadItem[];
  m_vecPetInfo: STPetInfo[];
  m_arrayAssuranceData: CBoxAssuranceItem[];
  m_vecArtifactArray: CArtifact[];
}

/**
 * Write CRespUserLoginPacket to binary stream
 * Note: Field order must match what the client expects
 */
export function writeCRespUserLoginPacket(writer: BinaryWriter, resp: CRespUserLoginPacket): void {
  // Arrays come first in the response
  writer.writeArray(resp.m_arrayEquipData, (item) => writeCEquipmentItem(writer, item));
  writer.writeArray(resp.m_arrayRestoreData, (item) => writeCRestoreItem(writer, item));
  writer.writeArray(resp.m_arrayTimestampData, (item) => writeCTimestampItem(writer, item));

  // Core player data
  writer.writeUInt32(resp.m_nTransID);
  writer.writeUInt32(resp.m_nCoins);
  writer.writeInt32(resp.m_nDiamonds);
  writer.writeUInt16(resp.m_nMaxLayer);
  writer.writeUInt16(resp.m_nLayerBoxID);
  writer.writeUInt16(resp.m_nLevel);
  writer.writeUInt32(resp.m_nExperince);
  writer.writeUInt32(resp.m_nTreasureRandomCount);
  writer.writeUInt16(resp.m_nBattleRebornCount);
  writer.writeString(resp.m_strUserAccessToken);
  writer.writeUInt64(resp.m_nUserRawId);
  writer.writeUInt16(resp.m_nExtraNormalDiamondItem);
  writer.writeUInt16(resp.m_nExtraLargeDiamondItem);
  writer.writeUInt64(resp.m_nGameSystemMask);
  writer.writeUInt16(resp.m_nMaxHeroLayer);
  writer.writeUInt16(resp.m_nHeroLayerBoxID);
  writer.writeUInt16(resp.m_nLargeDiamondItemCount);
  writer.writeUInt64(resp.m_nNowTime);
  writer.writeUInt64(resp.m_nTodayEndTimestamp);
  writer.writeUInt16(resp.m_nAccountStatus);
  writer.writeUInt32(resp.m_nTotalCash);
  writer.writeBool(resp.m_bTalentBackCoin);
  writer.writeUInt16(resp.m_nAdCount);

  // Hero array
  writer.writeArray(resp.m_arrayHeroData, (item) => writeCHeroItem(writer, item));

  writer.writeString(resp.m_strBindEmailAddress);
  writer.writeArray(resp.vecActivityRechargeResetType, (item) => writer.writeUInt16(item));
  writer.writeBool(resp.m_bHeroSkinItemIsBuy);
  writer.writeString(resp.m_strNickName);
  writer.writeUInt32(resp.m_nHeadIcon);
  writer.writeUInt32(resp.m_nHeadFrame);
  writer.writeUInt64(resp.m_nHeadFrameTimestamp);
  writer.writeArray(resp.m_vecHeadItem, (item) => writeSTHeadItem(writer, item));
  writer.writeBool(resp.m_bOpenIdfa);
  writer.writeUInt32(resp.m_nRemameDiamonds);
  writer.writeUInt16(resp.m_nRenameCount);
  writer.writeBool(resp.m_bHeroSkinSeniorItemIsBuy);
  writer.writeString(resp.m_strSkinItemIapProductId);
  writer.writeUInt16(resp.m_nChapFailCnt);
  writer.writeUInt16(resp.m_nHeroChapFailCnt);
  writer.writeUInt32(resp.m_nPurcahseInTowWeeks);
  writer.writeUInt32(resp.m_nLatest3PurchaseAvg);
  writer.writeUInt16(resp.m_nMixBoxItem);
  writer.writeUInt16(resp.m_nMixBoxSingleCount);
  writer.writeUInt16(resp.m_nMixBoxSingleTotalCount);
  writer.writeUInt16(resp.m_nMixBoxTenCount);
  writer.writeUInt16(resp.m_nDragonBoxItem);
  writer.writeUInt16(resp.m_nDragonBoxCountLow);
  writer.writeUInt16(resp.m_nDragonBoxCountMid);
  writer.writeUInt16(resp.m_nDragonBoxCountHigh);
  writer.writeUInt64(resp.m_nFreeCoinTimestamp);
  writer.writeUInt16(resp.m_nVipLevel);
  writer.writeUInt32(resp.m_nVipScore);
  writer.writeUInt64(resp.m_nChapterBanTimestamp);
  writer.writeUInt16(resp.m_nRelicsBoxItem);
  writer.writeUInt16(resp.m_nRelicsBoxCountLow);
  writer.writeUInt16(resp.m_nRelicsBoxCountHigh);
  writer.writeUInt16(resp.m_nOfflineBattleCount);
  writer.writeUInt16(resp.m_nEquipSBoxItem);
  writer.writeUInt16(resp.m_nEquipSBoxCountLow);
  writer.writeUInt16(resp.m_nEquipSBoxCountHigh);
  writer.writeUInt32(resp.m_nWorkerBoxKeyCount);
  writer.writeUInt16(resp.m_nWorkerBoxCountLow);
  writer.writeUInt16(resp.m_nWorkerBoxCountMid);
  writer.writeUInt16(resp.m_nWorkerBoxCountHigh);
  writer.writeArray(resp.m_vecPetInfo, (item) => writeSTPetInfo(writer, item));
  writer.writeUInt32(resp.m_nPetBoxKeyCount);
  writer.writeUInt16(resp.m_nPetBoxCountLow);
  writer.writeUInt16(resp.m_nPetBoxCountMid);
  writer.writeUInt16(resp.m_nPetBoxCountHigh);
  writer.writeString(resp.m_strHabbyID);
  writer.writeUInt64(resp.m_nMustDropMask);
  writer.writeUInt64(resp.m_nGuildStopTimestamp);
  writer.writeUInt32(resp.m_nStarDiamond);
  writer.writeUInt64(resp.m_nExperinceInt64);
  writer.writeInt64(resp.m_nCoinsInt64);
  writer.writeUInt32(resp.m_nImprintBoxKeyCount);
  writer.writeArray(resp.m_arrayAssuranceData, (item) => writeCBoxAssuranceItem(writer, item));
  writer.writeUInt16(resp.m_nMaxHellLayer);
  writer.writeUInt16(resp.m_nHellLayerBoxID);
  writer.writeUInt16(resp.m_nChapHellFailCount);
  writer.writeArray(resp.m_vecArtifactArray, (item) => writeCArtifact(writer, item));
  writer.writeUInt16(resp.m_nUpgradeLevel);
  writer.writeUInt32(resp.m_nCardThemeId);
  writer.writeUInt64(resp.m_nCardThemeTimestamp);
}

/**
 * Create a default login response for new players
 */
export function createDefaultLoginResponse(transId: number): CRespUserLoginPacket {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const todayEnd = now + BigInt(86400 - (Number(now) % 86400));

  return {
    m_nTransID: transId,
    m_nCoins: 199,
    m_nDiamonds: 120,
    m_nLevel: 1,
    m_nExperince: 0,
    m_nUserRawId: BigInt("72276397022577740"),  // Random large ID
    m_nNowTime: now,
    m_nTodayEndTimestamp: todayEnd,
    m_nMaxLayer: 0,
    m_nLayerBoxID: 0,
    m_nTreasureRandomCount: 0,
    m_nBattleRebornCount: 0,
    m_strUserAccessToken: "",
    m_strNickName: "",
    m_nAccountStatus: 0,
    m_nExtraNormalDiamondItem: 0,
    m_nExtraLargeDiamondItem: 0,
    m_nLargeDiamondItemCount: 10,
    m_nGameSystemMask: BigInt("3458764513820540928"),
    m_nMaxHeroLayer: 0,
    m_nHeroLayerBoxID: 0,
    m_nTotalCash: 0,
    m_bTalentBackCoin: true,
    m_nAdCount: 3,
    m_strBindEmailAddress: "",
    vecActivityRechargeResetType: [],
    m_bHeroSkinItemIsBuy: false,
    m_bHeroSkinSeniorItemIsBuy: false,
    m_strSkinItemIapProductId: "[]",
    m_nHeadIcon: 0,
    m_nHeadFrame: 0,
    m_nHeadFrameTimestamp: BigInt(0),
    m_bOpenIdfa: false,
    m_nRemameDiamonds: 0,
    m_nRenameCount: 0,
    m_nChapFailCnt: 0,
    m_nHeroChapFailCnt: 0,
    m_nPurcahseInTowWeeks: 0,
    m_nLatest3PurchaseAvg: 0,
    m_nMixBoxItem: 0,
    m_nMixBoxSingleCount: 3,
    m_nMixBoxSingleTotalCount: 10,
    m_nMixBoxTenCount: 10,
    m_nDragonBoxItem: 0,
    m_nDragonBoxCountLow: 20,
    m_nDragonBoxCountMid: 100,
    m_nDragonBoxCountHigh: 220,
    m_nFreeCoinTimestamp: BigInt(0),
    m_nVipLevel: 0,
    m_nVipScore: 0,
    m_nChapterBanTimestamp: BigInt(0),
    m_nRelicsBoxItem: 0,
    m_nRelicsBoxCountLow: 20,
    m_nRelicsBoxCountHigh: 120,
    m_nOfflineBattleCount: 0,
    m_nEquipSBoxItem: 0,
    m_nEquipSBoxCountLow: 10,
    m_nEquipSBoxCountHigh: 60,
    m_nWorkerBoxKeyCount: 0,
    m_nWorkerBoxCountLow: 10,
    m_nWorkerBoxCountMid: 20,
    m_nWorkerBoxCountHigh: 80,
    m_nPetBoxKeyCount: 0,
    m_nPetBoxCountLow: 20,
    m_nPetBoxCountMid: 100,
    m_nPetBoxCountHigh: 300,
    m_strHabbyID: "",
    m_nMustDropMask: BigInt(0),
    m_nGuildStopTimestamp: BigInt(0),
    m_nStarDiamond: 0,
    m_nExperinceInt64: BigInt(0),
    m_nCoinsInt64: BigInt(199),
    m_nImprintBoxKeyCount: 0,
    m_nMaxHellLayer: 0,
    m_nHellLayerBoxID: 0,
    m_nChapHellFailCount: 0,
    m_nUpgradeLevel: 0,
    m_nCardThemeId: 0,
    m_nCardThemeTimestamp: BigInt(0),

    // Arrays - starter equipment and hero
    m_arrayEquipData: [
      createDefaultEquipmentItem("10909050", 10000),   // Basic bow
      createDefaultEquipmentItem("10909051", 1010101), // Basic armor
    ],
    m_arrayRestoreData: [
      createDefaultRestoreItem(45, 20),  // Keys
      createDefaultRestoreItem(0, 1),
      createDefaultRestoreItem(0, 1),
      createDefaultRestoreItem(4, 4),
      createDefaultRestoreItem(5, 5),
      createDefaultRestoreItem(4, 4),
      createDefaultRestoreItem(5, 5),
      createDefaultRestoreItem(5, 5),
      createDefaultRestoreItem(0, 0),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
      createDefaultRestoreItem(1, 1),
    ],
    m_arrayTimestampData: [
      { m_nIndex: 0, m_i64Timestamp: now },
      { m_nIndex: 1, m_i64Timestamp: now },
      { m_nIndex: 2, m_i64Timestamp: now },
      { m_nIndex: 3, m_i64Timestamp: now },
    ],
    m_arrayHeroData: [createDefaultHero()],
    m_vecHeadItem: [],
    m_vecPetInfo: [],
    m_arrayAssuranceData: [createDefaultBoxAssurance()],
    m_vecArtifactArray: [],
  };
}
