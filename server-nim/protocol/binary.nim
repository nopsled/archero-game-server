## Binary Reader/Writer for GameProtocol
##
## Matches the game's CustomBinaryReader/CustomBinaryWriter format:
## - Little-endian encoding
## - Length-prefixed strings (uint16 + utf8 bytes)
## - Array serialization (uint16 count + items)

import std/[streams, endians]

type
  BinaryReader* = object
    data: seq[byte]
    pos: int

  BinaryWriter* = object
    stream: StringStream

# =============================================================================
# BINARY READER
# =============================================================================

proc newBinaryReader*(data: seq[byte]): BinaryReader =
  result.data = data
  result.pos = 0

proc newBinaryReader*(data: openArray[byte]): BinaryReader =
  result.data = @data
  result.pos = 0

proc position*(r: BinaryReader): int = r.pos

proc remaining*(r: BinaryReader): int = r.data.len - r.pos

proc readByte*(r: var BinaryReader): uint8 =
  result = r.data[r.pos]
  r.pos += 1

proc readBool*(r: var BinaryReader): bool =
  result = r.readByte() != 0

proc readInt16*(r: var BinaryReader): int16 =
  var tmp: int16
  littleEndian16(addr tmp, addr r.data[r.pos])
  r.pos += 2
  result = tmp

proc readUint16*(r: var BinaryReader): uint16 =
  var tmp: uint16
  littleEndian16(addr tmp, addr r.data[r.pos])
  r.pos += 2
  result = tmp

proc readInt32*(r: var BinaryReader): int32 =
  var tmp: int32
  littleEndian32(addr tmp, addr r.data[r.pos])
  r.pos += 4
  result = tmp

proc readUint32*(r: var BinaryReader): uint32 =
  var tmp: uint32
  littleEndian32(addr tmp, addr r.data[r.pos])
  r.pos += 4
  result = tmp

proc readInt64*(r: var BinaryReader): int64 =
  var tmp: int64
  littleEndian64(addr tmp, addr r.data[r.pos])
  r.pos += 8
  result = tmp

proc readUint64*(r: var BinaryReader): uint64 =
  var tmp: uint64
  littleEndian64(addr tmp, addr r.data[r.pos])
  r.pos += 8
  result = tmp

proc readFloat32*(r: var BinaryReader): float32 =
  var tmp: float32
  littleEndian32(addr tmp, addr r.data[r.pos])
  r.pos += 4
  result = tmp

proc readFloat64*(r: var BinaryReader): float64 =
  var tmp: float64
  littleEndian64(addr tmp, addr r.data[r.pos])
  r.pos += 8
  result = tmp

proc readString*(r: var BinaryReader): string =
  let length = r.readUint16().int
  if length == 0:
    return ""
  result = newString(length)
  copyMem(addr result[0], addr r.data[r.pos], length)
  r.pos += length

proc readBytes*(r: var BinaryReader, count: int): seq[byte] =
  result = r.data[r.pos ..< r.pos + count]
  r.pos += count

proc readArray*[T](r: var BinaryReader, readItem: proc(r: var BinaryReader): T): seq[T] =
  let count = r.readUint16().int
  result = newSeqOfCap[T](count)
  for _ in 0 ..< count:
    result.add(readItem(r))


# =============================================================================
# BINARY WRITER
# =============================================================================

proc newBinaryWriter*(initialCapacity: int = 1024): BinaryWriter =
  result.stream = newStringStream()

proc position*(w: BinaryWriter): int = w.stream.getPosition()

proc writeByte*(w: var BinaryWriter, value: uint8) =
  w.stream.write(value)

proc writeBool*(w: var BinaryWriter, value: bool) =
  w.writeByte(if value: 1'u8 else: 0'u8)

proc writeInt16*(w: var BinaryWriter, value: int16) =
  var tmp: int16
  littleEndian16(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeUint16*(w: var BinaryWriter, value: uint16) =
  var tmp: uint16
  littleEndian16(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeInt32*(w: var BinaryWriter, value: int32) =
  var tmp: int32
  littleEndian32(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeUint32*(w: var BinaryWriter, value: uint32) =
  var tmp: uint32
  littleEndian32(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeInt64*(w: var BinaryWriter, value: int64) =
  var tmp: int64
  littleEndian64(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeUint64*(w: var BinaryWriter, value: uint64) =
  var tmp: uint64
  littleEndian64(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeFloat32*(w: var BinaryWriter, value: float32) =
  var tmp: float32
  littleEndian32(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeFloat64*(w: var BinaryWriter, value: float64) =
  var tmp: float64
  littleEndian64(addr tmp, unsafeAddr value)
  w.stream.write(tmp)

proc writeString*(w: var BinaryWriter, value: string) =
  w.writeUint16(value.len.uint16)
  if value.len > 0:
    w.stream.writeData(unsafeAddr value[0], value.len)

proc writeBytes*(w: var BinaryWriter, data: seq[byte]) =
  if data.len > 0:
    w.stream.writeData(unsafeAddr data[0], data.len)

proc writeBytes*(w: var BinaryWriter, data: openArray[byte]) =
  if data.len > 0:
    # Copy to avoid const issues
    var d = @data
    w.stream.writeData(addr d[0], d.len)

proc writeArray*[T](w: var BinaryWriter, items: seq[T], writeItem: proc(w: var BinaryWriter, item: T)) =
  w.writeUint16(items.len.uint16)
  for item in items:
    writeItem(w, item)

proc writeArrayInline*(w: var BinaryWriter, items: seq[uint16]) =
  ## Convenience for writing arrays of simple uint16 values
  w.writeUint16(items.len.uint16)
  for item in items:
    w.writeUint16(item)

proc toBytes*(w: var BinaryWriter): seq[byte] =
  w.stream.setPosition(0)
  let s = w.stream.readAll()
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)
