/**
 * Login Packet Tests
 * 
 * Run: bun test protocol/login.test.ts
 */

import { expect, test, describe } from "bun:test";
import { BinaryReader, BinaryWriter } from "./binary";
import {
  readCUserLoginPacket,
  writeCRespUserLoginPacket,
  createDefaultLoginResponse,
} from "./login";

describe("CUserLoginPacket", () => {
  test("reads login request correctly", () => {
    const writer = new BinaryWriter();
    writer.writeUInt32(12345);   // m_nTransID
    writer.writeString("android"); // m_strPlatform
    
    const reader = new BinaryReader(writer.toBytes());
    const packet = readCUserLoginPacket(reader);
    
    expect(packet.m_nTransID).toBe(12345);
    expect(packet.m_strPlatform).toBe("android");
  });
});

describe("CRespUserLoginPacket", () => {
  test("creates default response with expected values", () => {
    const resp = createDefaultLoginResponse(12345);
    
    expect(resp.m_nTransID).toBe(12345);
    expect(resp.m_nCoins).toBe(199);
    expect(resp.m_nDiamonds).toBe(120);
    expect(resp.m_nLevel).toBe(1);
    expect(resp.m_arrayEquipData.length).toBe(2);
    expect(resp.m_arrayHeroData.length).toBe(1);
    expect(resp.m_arrayHeroData[0].m_nHeroId).toBe(10000);
  });

  test("serializes to bytes without error", () => {
    const resp = createDefaultLoginResponse(12345);
    const writer = new BinaryWriter();
    
    // Should not throw
    expect(() => writeCRespUserLoginPacket(writer, resp)).not.toThrow();
    
    // Should produce output
    const bytes = writer.toBytes();
    expect(bytes.length).toBeGreaterThan(100);
    console.log(`Login response serialized to ${bytes.length} bytes`);
  });
});
