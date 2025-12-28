/**
 * GameProtocol Module
 * 
 * Exports all protocol structures for the Archero sandbox server.
 */

// Binary serialization
export { BinaryReader, BinaryWriter } from "./binary";

// Common types
export {
  type CCommonRespMsg,
  writeCCommonRespMsg,
  createSuccessResponse,
  type CEquipmentItem,
  writeCEquipmentItem,
  createDefaultEquipmentItem,
  type CHeroItem,
  writeCHeroItem,
  createDefaultHero,
  type CRestoreItem,
  writeCRestoreItem,
  createDefaultRestoreItem,
  type CTimestampItem,
  writeCTimestampItem,
  type CBoxAssuranceItem,
  writeCBoxAssuranceItem,
  createDefaultBoxAssurance,
  type STPetInfo,
  writeSTPetInfo,
  type STHeadItem,
  writeSTHeadItem,
  type CArtifact,
  writeCArtifact,
} from "./common";

// Login packets
export {
  type CUserLoginPacket,
  readCUserLoginPacket,
  type CRespUserLoginPacket,
  writeCRespUserLoginPacket,
  createDefaultLoginResponse,
} from "./login";
