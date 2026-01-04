#!/usr/bin/env python3
"""
Protocol Verification Test

Generates test binary data and compares Python output with TypeScript output.
"""

import sys
import time

sys.path.insert(0, ".")

from protocol import (
    BinaryWriter,
    BinaryReader,
    create_default_login_response,
    write_c_resp_user_login_packet,
    create_success_response,
    write_c_common_resp_msg,
)


def test_binary_primitives():
    """Test that binary primitives encode correctly"""
    print("=" * 60)
    print("Testing Binary Primitives")
    print("=" * 60)

    writer = BinaryWriter()

    # Write test values
    writer.write_byte(0x42)
    writer.write_bool(True)
    writer.write_bool(False)
    writer.write_int16(-1234)
    writer.write_uint16(5678)
    writer.write_int32(-123456)
    writer.write_uint32(654321)
    writer.write_int64(-9876543210)
    writer.write_uint64(1234567890123)
    writer.write_float(3.14159)
    writer.write_string("Hello, World!")
    writer.write_string("")
    writer.write_array([1, 2, 3], lambda x: writer.write_uint32(x))

    data = writer.to_bytes()
    print(f"Written {len(data)} bytes")
    print(f"Hex: {data.hex()}")

    # Read back and verify
    reader = BinaryReader(data)

    assert reader.read_byte() == 0x42, "byte mismatch"
    assert reader.read_bool() == True, "bool True mismatch"
    assert reader.read_bool() == False, "bool False mismatch"
    assert reader.read_int16() == -1234, "int16 mismatch"
    assert reader.read_uint16() == 5678, "uint16 mismatch"
    assert reader.read_int32() == -123456, "int32 mismatch"
    assert reader.read_uint32() == 654321, "uint32 mismatch"
    assert reader.read_int64() == -9876543210, "int64 mismatch"
    assert reader.read_uint64() == 1234567890123, "uint64 mismatch"

    f = reader.read_float()
    assert abs(f - 3.14159) < 0.0001, f"float mismatch: {f}"

    assert reader.read_string() == "Hello, World!", "string mismatch"
    assert reader.read_string() == "", "empty string mismatch"

    arr = reader.read_array(lambda: reader.read_uint32())
    assert arr == [1, 2, 3], f"array mismatch: {arr}"

    print("✅ All primitive tests passed!")

    return data


def test_login_response():
    """Test login response serialization"""
    print()
    print("=" * 60)
    print("Testing Login Response")
    print("=" * 60)

    # Create response
    resp = create_default_login_response(12345)

    # Serialize
    writer = BinaryWriter()
    write_c_resp_user_login_packet(writer, resp)
    data = writer.to_bytes()

    print(f"Response size: {len(data)} bytes")
    print(f"First 50 bytes: {data[:50].hex()}")
    print(f"Trans ID: {resp.m_nTransID}")
    print(f"Coins: {resp.m_nCoins}")
    print(f"Diamonds: {resp.m_nDiamonds}")
    print(f"Level: {resp.m_nLevel}")
    print(f"Equipment count: {len(resp.m_arrayEquipData)}")
    print(f"Hero count: {len(resp.m_arrayHeroData)}")

    print("✅ Login response serialization complete!")

    return data


def test_common_resp_msg():
    """Test common response message"""
    print()
    print("=" * 60)
    print("Testing CCommonRespMsg")
    print("=" * 60)

    resp = create_success_response()

    writer = BinaryWriter()
    write_c_common_resp_msg(writer, resp)
    data = writer.to_bytes()

    print(f"CCommonRespMsg size: {len(data)} bytes")
    print(f"Hex: {data.hex()}")

    # Expected: uint16(0) + string("") + bool(false)
    # = 2 + 2 + 1 = 5 bytes
    # 0x0000 (status 0) + 0x0000 (empty string len) + 0x00 (m_nChange=false)
    expected = bytes([0x00, 0x00, 0x00, 0x00, 0x00])

    if data == expected:
        print("✅ CCommonRespMsg matches expected bytes!")
    else:
        print(f"❌ Mismatch! Expected: {expected.hex()}, Got: {data.hex()}")

    return data


def generate_ts_comparison_script():
    """Generate TypeScript comparison script"""
    print()
    print("=" * 60)
    print("TypeScript Comparison Script")
    print("=" * 60)

    script = """
// Run with: cd sandbox-ts && bun run ts-verification.ts
import { BinaryWriter, BinaryReader } from "./protocol/12020-tcp/binary";
import { createSuccessResponse, writeCCommonRespMsg } from "./protocol/12020-tcp/common";
import { createDefaultLoginResponse, writeCRespUserLoginPacket } from "./protocol/12020-tcp/login";

// Test primitives
const writer = new BinaryWriter();
writer.writeByte(0x42);
writer.writeBool(true);
writer.writeBool(false);
writer.writeInt16(-1234);
writer.writeUInt16(5678);
writer.writeInt32(-123456);
writer.writeUInt32(654321);
writer.writeInt64(BigInt(-9876543210));
writer.writeUInt64(BigInt(1234567890123));
writer.writeFloat(3.14159);
writer.writeString("Hello, World!");
writer.writeString("");
writer.writeArray([1, 2, 3], (x) => writer.writeUInt32(x));

console.log("Primitives hex:", Buffer.from(writer.toBytes()).toString('hex'));

// Test login response
const writer2 = new BinaryWriter();
const resp = createDefaultLoginResponse(12345);
writeCRespUserLoginPacket(writer2, resp);
console.log("Login response size:", writer2.position);
console.log("Login first 50:", Buffer.from(writer2.toBytes().slice(0, 50)).toString('hex'));

// Test common resp msg
const writer3 = new BinaryWriter();
writeCCommonRespMsg(writer3, createSuccessResponse());
console.log("CCommonRespMsg:", Buffer.from(writer3.toBytes()).toString('hex'));
"""

    print(script)

    # Save to file
    with open("../sandbox-ts/ts-verification.ts", "w") as f:
        f.write(script)

    print("\nSaved to sandbox-ts/ts-verification.ts")
    print("Run: cd sandbox-ts && bun run ts-verification.ts")


if __name__ == "__main__":
    print()
    print("🔍 PROTOCOL VERIFICATION")
    print()

    primitives_data = test_binary_primitives()
    common_data = test_common_resp_msg()
    login_data = test_login_response()

    generate_ts_comparison_script()

    print()
    print("=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"Primitives size: {len(primitives_data)} bytes")
    print(f"CCommonRespMsg size: {len(common_data)} bytes")
    print(f"Login response size: {len(login_data)} bytes")
    print()
    print("✅ Python protocol verification complete!")
    print("Run TypeScript test to compare: cd sandbox-ts && bun run ts-verification.ts")
