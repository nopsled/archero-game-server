## Login Protocol Packets
##
## Request: CUserLoginPacket
## Response: CRespUserLoginPacket

import std/times
import binary, common

# =============================================================================
# LOGIN REQUEST
# =============================================================================

type
  CUserLoginPacket* = object
    m_nTransID*: uint32
    m_strPlatform*: string  ## "android" or "ios"

proc readCUserLoginPacket*(reader: var BinaryReader): CUserLoginPacket =
  result.m_nTransID = reader.readUint32()
  result.m_strPlatform = reader.readString()

# =============================================================================
# LOGIN RESPONSE
# =============================================================================

type
  CRespUserLoginPacket* = object
    # Core player data
    m_nTransID*: uint32
    m_nCoins*: uint32
    m_nDiamonds*: int32
    m_nLevel*: uint16
    m_nExperince*: uint32
    m_nUserRawId*: uint64
    m_nNowTime*: uint64
    m_nTodayEndTimestamp*: uint64

    # Progress data
    m_nMaxLayer*: uint16
    m_nLayerBoxID*: uint16
    m_nTreasureRandomCount*: uint32
    m_nBattleRebornCount*: uint16

    # Account info
    m_strUserAccessToken*: string
    m_strNickName*: string
    m_nAccountStatus*: uint16

    # Items data
    m_nExtraNormalDiamondItem*: uint16
    m_nExtraLargeDiamondItem*: uint16
    m_nLargeDiamondItemCount*: uint16

    # Game system flags
    m_nGameSystemMask*: uint64

    # Hero layer
    m_nMaxHeroLayer*: uint16
    m_nHeroLayerBoxID*: uint16

    # Cash/monetization
    m_nTotalCash*: uint32
    m_bTalentBackCoin*: bool

    # Ads
    m_nAdCount*: uint16

    # Email binding
    m_strBindEmailAddress*: string

    # Activity recharge
    vecActivityRechargeResetType*: seq[uint16]

    # Skins
    m_bHeroSkinItemIsBuy*: bool
    m_bHeroSkinSeniorItemIsBuy*: bool
    m_strSkinItemIapProductId*: string

    # Profile
    m_nHeadIcon*: uint32
    m_nHeadFrame*: uint32
    m_nHeadFrameTimestamp*: uint64

    # IDFA
    m_bOpenIdfa*: bool

    # Rename
    m_nRemameDiamonds*: uint32
    m_nRenameCount*: uint16

    # Chapter fail counts
    m_nChapFailCnt*: uint16
    m_nHeroChapFailCnt*: uint16

    # Purchase data
    m_nPurcahseInTowWeeks*: uint32
    m_nLatest3PurchaseAvg*: uint32

    # Mix box
    m_nMixBoxItem*: uint16
    m_nMixBoxSingleCount*: uint16
    m_nMixBoxSingleTotalCount*: uint16
    m_nMixBoxTenCount*: uint16

    # Dragon box
    m_nDragonBoxItem*: uint16
    m_nDragonBoxCountLow*: uint16
    m_nDragonBoxCountMid*: uint16
    m_nDragonBoxCountHigh*: uint16

    # Free coin
    m_nFreeCoinTimestamp*: uint64

    # VIP
    m_nVipLevel*: uint16
    m_nVipScore*: uint32

    # Bans
    m_nChapterBanTimestamp*: uint64

    # Relics box
    m_nRelicsBoxItem*: uint16
    m_nRelicsBoxCountLow*: uint16
    m_nRelicsBoxCountHigh*: uint16

    # Offline battle
    m_nOfflineBattleCount*: uint16

    # Equip S box
    m_nEquipSBoxItem*: uint16
    m_nEquipSBoxCountLow*: uint16
    m_nEquipSBoxCountHigh*: uint16

    # Worker box
    m_nWorkerBoxKeyCount*: uint32
    m_nWorkerBoxCountLow*: uint16
    m_nWorkerBoxCountMid*: uint16
    m_nWorkerBoxCountHigh*: uint16

    # Pet box
    m_nPetBoxKeyCount*: uint32
    m_nPetBoxCountLow*: uint16
    m_nPetBoxCountMid*: uint16
    m_nPetBoxCountHigh*: uint16

    # Habby ID
    m_strHabbyID*: string

    # Must drop
    m_nMustDropMask*: uint64

    # Guild
    m_nGuildStopTimestamp*: uint64

    # Star diamond
    m_nStarDiamond*: uint32

    # Extended experience/coins
    m_nExperinceInt64*: uint64
    m_nCoinsInt64*: int64

    # Imprint box
    m_nImprintBoxKeyCount*: uint32

    # Hell layer
    m_nMaxHellLayer*: uint16
    m_nHellLayerBoxID*: uint16
    m_nChapHellFailCount*: uint16

    # Other
    m_nUpgradeLevel*: uint16
    m_nCardThemeId*: uint32
    m_nCardThemeTimestamp*: uint64

    # Arrays
    m_arrayEquipData*: seq[CEquipmentItem]
    m_arrayRestoreData*: seq[CRestoreItem]
    m_arrayTimestampData*: seq[CTimestampItem]
    m_arrayHeroData*: seq[CHeroItem]
    m_vecHeadItem*: seq[STHeadItem]
    m_vecPetInfo*: seq[STPetInfo]
    m_arrayAssuranceData*: seq[CBoxAssuranceItem]
    m_vecArtifactArray*: seq[CArtifact]


proc writeCRespUserLoginPacket*(writer: var BinaryWriter, resp: CRespUserLoginPacket) =
  ## Write CRespUserLoginPacket to binary stream. Field order must match client expectations.

  # Arrays come first in the response
  writer.writeArray(resp.m_arrayEquipData, proc(w: var BinaryWriter, item: CEquipmentItem) = w.writeCEquipmentItem(item))
  writer.writeArray(resp.m_arrayRestoreData, proc(w: var BinaryWriter, item: CRestoreItem) = w.writeCRestoreItem(item))
  writer.writeArray(resp.m_arrayTimestampData, proc(w: var BinaryWriter, item: CTimestampItem) = w.writeCTimestampItem(item))

  # Core player data
  writer.writeUint32(resp.m_nTransID)
  writer.writeUint32(resp.m_nCoins)
  writer.writeInt32(resp.m_nDiamonds)
  writer.writeUint16(resp.m_nMaxLayer)
  writer.writeUint16(resp.m_nLayerBoxID)
  writer.writeUint16(resp.m_nLevel)
  writer.writeUint32(resp.m_nExperince)
  writer.writeUint32(resp.m_nTreasureRandomCount)
  writer.writeUint16(resp.m_nBattleRebornCount)
  writer.writeString(resp.m_strUserAccessToken)
  writer.writeUint64(resp.m_nUserRawId)
  writer.writeUint16(resp.m_nExtraNormalDiamondItem)
  writer.writeUint16(resp.m_nExtraLargeDiamondItem)
  writer.writeUint64(resp.m_nGameSystemMask)
  writer.writeUint16(resp.m_nMaxHeroLayer)
  writer.writeUint16(resp.m_nHeroLayerBoxID)
  writer.writeUint16(resp.m_nLargeDiamondItemCount)
  writer.writeUint64(resp.m_nNowTime)
  writer.writeUint64(resp.m_nTodayEndTimestamp)
  writer.writeUint16(resp.m_nAccountStatus)
  writer.writeUint32(resp.m_nTotalCash)
  writer.writeBool(resp.m_bTalentBackCoin)
  writer.writeUint16(resp.m_nAdCount)

  # Hero array
  writer.writeArray(resp.m_arrayHeroData, proc(w: var BinaryWriter, item: CHeroItem) = w.writeCHeroItem(item))

  writer.writeString(resp.m_strBindEmailAddress)
  writer.writeArrayInline(resp.vecActivityRechargeResetType)
  writer.writeBool(resp.m_bHeroSkinItemIsBuy)
  writer.writeString(resp.m_strNickName)
  writer.writeUint32(resp.m_nHeadIcon)
  writer.writeUint32(resp.m_nHeadFrame)
  writer.writeUint64(resp.m_nHeadFrameTimestamp)
  writer.writeArray(resp.m_vecHeadItem, proc(w: var BinaryWriter, item: STHeadItem) = w.writeSTHeadItem(item))
  writer.writeBool(resp.m_bOpenIdfa)
  writer.writeUint32(resp.m_nRemameDiamonds)
  writer.writeUint16(resp.m_nRenameCount)
  writer.writeBool(resp.m_bHeroSkinSeniorItemIsBuy)
  writer.writeString(resp.m_strSkinItemIapProductId)
  writer.writeUint16(resp.m_nChapFailCnt)
  writer.writeUint16(resp.m_nHeroChapFailCnt)
  writer.writeUint32(resp.m_nPurcahseInTowWeeks)
  writer.writeUint32(resp.m_nLatest3PurchaseAvg)
  writer.writeUint16(resp.m_nMixBoxItem)
  writer.writeUint16(resp.m_nMixBoxSingleCount)
  writer.writeUint16(resp.m_nMixBoxSingleTotalCount)
  writer.writeUint16(resp.m_nMixBoxTenCount)
  writer.writeUint16(resp.m_nDragonBoxItem)
  writer.writeUint16(resp.m_nDragonBoxCountLow)
  writer.writeUint16(resp.m_nDragonBoxCountMid)
  writer.writeUint16(resp.m_nDragonBoxCountHigh)
  writer.writeUint64(resp.m_nFreeCoinTimestamp)
  writer.writeUint16(resp.m_nVipLevel)
  writer.writeUint32(resp.m_nVipScore)
  writer.writeUint64(resp.m_nChapterBanTimestamp)
  writer.writeUint16(resp.m_nRelicsBoxItem)
  writer.writeUint16(resp.m_nRelicsBoxCountLow)
  writer.writeUint16(resp.m_nRelicsBoxCountHigh)
  writer.writeUint16(resp.m_nOfflineBattleCount)
  writer.writeUint16(resp.m_nEquipSBoxItem)
  writer.writeUint16(resp.m_nEquipSBoxCountLow)
  writer.writeUint16(resp.m_nEquipSBoxCountHigh)
  writer.writeUint32(resp.m_nWorkerBoxKeyCount)
  writer.writeUint16(resp.m_nWorkerBoxCountLow)
  writer.writeUint16(resp.m_nWorkerBoxCountMid)
  writer.writeUint16(resp.m_nWorkerBoxCountHigh)
  writer.writeArray(resp.m_vecPetInfo, proc(w: var BinaryWriter, info: STPetInfo) = w.writeSTPetInfo(info))
  writer.writeUint32(resp.m_nPetBoxKeyCount)
  writer.writeUint16(resp.m_nPetBoxCountLow)
  writer.writeUint16(resp.m_nPetBoxCountMid)
  writer.writeUint16(resp.m_nPetBoxCountHigh)
  writer.writeString(resp.m_strHabbyID)
  writer.writeUint64(resp.m_nMustDropMask)
  writer.writeUint64(resp.m_nGuildStopTimestamp)
  writer.writeUint32(resp.m_nStarDiamond)
  writer.writeUint64(resp.m_nExperinceInt64)
  writer.writeInt64(resp.m_nCoinsInt64)
  writer.writeUint32(resp.m_nImprintBoxKeyCount)
  writer.writeArray(resp.m_arrayAssuranceData, proc(w: var BinaryWriter, item: CBoxAssuranceItem) = w.writeCBoxAssuranceItem(item))
  writer.writeUint16(resp.m_nMaxHellLayer)
  writer.writeUint16(resp.m_nHellLayerBoxID)
  writer.writeUint16(resp.m_nChapHellFailCount)
  writer.writeArray(resp.m_vecArtifactArray, proc(w: var BinaryWriter, item: CArtifact) = w.writeCArtifact(item))
  writer.writeUint16(resp.m_nUpgradeLevel)
  writer.writeUint32(resp.m_nCardThemeId)
  writer.writeUint64(resp.m_nCardThemeTimestamp)


proc createDefaultLoginResponse*(transId: uint32): CRespUserLoginPacket =
  ## Create a default login response matching real server values
  let now = getTime().toUnix().uint64
  let todayEnd = now + (86400'u64 - (now mod 86400'u64))

  result = CRespUserLoginPacket(
    m_nTransID: transId,
    m_nCoins: 199,
    m_nDiamonds: 100,
    m_nLevel: 1,
    m_nExperince: 0,
    m_nUserRawId: 72453418394682577'u64,
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
    m_nGameSystemMask: 3458764513820540928'u64,
    m_nMaxHeroLayer: 0,
    m_nHeroLayerBoxID: 0,
    m_nTotalCash: 0,
    m_bTalentBackCoin: true,
    m_nAdCount: 3,
    m_strBindEmailAddress: "",
    vecActivityRechargeResetType: @[],
    m_bHeroSkinItemIsBuy: false,
    m_bHeroSkinSeniorItemIsBuy: false,
    m_strSkinItemIapProductId: "[]",
    m_nHeadIcon: 0,
    m_nHeadFrame: 0,
    m_nHeadFrameTimestamp: 0,
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
    m_nFreeCoinTimestamp: 0,
    m_nVipLevel: 0,
    m_nVipScore: 0,
    m_nChapterBanTimestamp: 0,
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
    m_nMustDropMask: 0,
    m_nGuildStopTimestamp: 0,
    m_nStarDiamond: 0,
    m_nExperinceInt64: 0,
    m_nCoinsInt64: 199,
    m_nImprintBoxKeyCount: 0,
    m_nMaxHellLayer: 0,
    m_nHellLayerBoxID: 0,
    m_nChapHellFailCount: 0,
    m_nUpgradeLevel: 0,
    m_nCardThemeId: 0,
    m_nCardThemeTimestamp: 0,
    m_arrayEquipData: @[
      createDefaultEquipmentItem("10909050", 10000),  # Basic bow
      createDefaultEquipmentItem("10909051", 1010101),  # Basic armor
    ],
    m_arrayRestoreData: @[
      createDefaultRestoreItem(45, 20),  # Keys
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
    m_arrayTimestampData: @[
      CTimestampItem(m_nIndex: 0, m_i64Timestamp: now),
      CTimestampItem(m_nIndex: 1, m_i64Timestamp: now),
      CTimestampItem(m_nIndex: 2, m_i64Timestamp: now),
      CTimestampItem(m_nIndex: 3, m_i64Timestamp: now),
    ],
    m_arrayHeroData: @[createDefaultHero()],
    m_vecHeadItem: @[],
    m_vecPetInfo: @[],
    m_arrayAssuranceData: @[createDefaultBoxAssurance()],
    m_vecArtifactArray: @[],
  )
