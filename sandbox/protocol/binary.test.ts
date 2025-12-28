/**
 * Protocol Binary Tests
 * 
 * Run: bun test protocol/binary.test.ts
 */

import { expect, test, describe } from "bun:test";
import { BinaryReader, BinaryWriter } from "./binary";

describe("BinaryWriter", () => {
  test("writes primitives correctly", () => {
    const writer = new BinaryWriter();
    writer.writeByte(0x42);
    writer.writeUInt16(0x1234);
    writer.writeUInt32(0xDEADBEEF);
    writer.writeInt32(-1);
    
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(1 + 2 + 4 + 4);
    expect(bytes[0]).toBe(0x42);
    // Little-endian: 0x1234 => [0x34, 0x12]
    expect(bytes[1]).toBe(0x34);
    expect(bytes[2]).toBe(0x12);
  });

  test("writes uint64 correctly", () => {
    const writer = new BinaryWriter();
    writer.writeUInt64(BigInt("72276397022577740"));
    
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(8);
    
    // Verify by reading back
    const reader = new BinaryReader(bytes);
    expect(reader.readUInt64()).toBe(BigInt("72276397022577740"));
  });

  test("writes strings with length prefix", () => {
    const writer = new BinaryWriter();
    writer.writeString("hello");
    
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(2 + 5); // 2 byte length + "hello"
    expect(bytes[0]).toBe(5);  // length low byte
    expect(bytes[1]).toBe(0);  // length high byte
    expect(bytes[2]).toBe(0x68); // 'h'
    expect(bytes[3]).toBe(0x65); // 'e'
  });

  test("writes null strings as empty", () => {
    const writer = new BinaryWriter();
    writer.writeString(null);
    
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(2); // just length = 0
    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0);
  });

  test("writes arrays with count prefix", () => {
    const writer = new BinaryWriter();
    writer.writeArray([1, 2, 3], (item) => writer.writeUInt32(item));
    
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(2 + 3 * 4); // count (2) + 3 x uint32 (4)
    
    // Verify count
    expect(bytes[0]).toBe(3);
    expect(bytes[1]).toBe(0);
  });
});

describe("BinaryReader", () => {
  test("reads primitives correctly", () => {
    const bytes = new Uint8Array([0x42, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);
    const reader = new BinaryReader(bytes);
    
    expect(reader.readByte()).toBe(0x42);
    expect(reader.readUInt16()).toBe(0x1234);
    expect(reader.readUInt32()).toBe(0xDEADBEEF);
  });

  test("reads strings correctly", () => {
    // "hello" = length 5, then "hello" bytes
    const bytes = new Uint8Array([5, 0, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const reader = new BinaryReader(bytes);
    
    expect(reader.readString()).toBe("hello");
    expect(reader.position).toBe(7);
  });

  test("reads arrays correctly", () => {
    const bytes = new Uint8Array([
      2, 0, // count = 2
      0x01, 0x00, 0x00, 0x00, // item 1 = 1
      0x02, 0x00, 0x00, 0x00, // item 2 = 2
    ]);
    const reader = new BinaryReader(bytes);
    
    const items = reader.readArray(() => reader.readUInt32());
    expect(items).toEqual([1, 2]);
  });
});

describe("Round-trip", () => {
  test("write then read produces same values", () => {
    const writer = new BinaryWriter();
    writer.writeUInt32(12345);
    writer.writeString("test string");
    writer.writeUInt64(BigInt("9876543210"));
    writer.writeBool(true);
    writer.writeInt32(-999);
    
    const reader = new BinaryReader(writer.toBytes());
    expect(reader.readUInt32()).toBe(12345);
    expect(reader.readString()).toBe("test string");
    expect(reader.readUInt64()).toBe(BigInt("9876543210"));
    expect(reader.readBool()).toBe(true);
    expect(reader.readInt32()).toBe(-999);
  });
});
