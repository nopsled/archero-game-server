/**
 * Binary Reader/Writer for GameProtocol
 *
 * Matches the game's CustomBinaryReader/CustomBinaryWriter format:
 * - Little-endian encoding
 * - Length-prefixed strings (uint16 + utf8 bytes)
 * - Array serialization (uint16 count + items)
 */

// =============================================================================
// BINARY READER
// =============================================================================

export class BinaryReader {
  private view: DataView;
  private offset: number = 0;

  constructor(buffer: ArrayBuffer | Uint8Array) {
    if (buffer instanceof Uint8Array) {
      this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else {
      this.view = new DataView(buffer);
    }
  }

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.view.byteLength - this.offset;
  }

  readByte(): number {
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  readBool(): boolean {
    return this.readByte() !== 0;
  }

  readInt16(): number {
    const value = this.view.getInt16(this.offset, true);
    this.offset += 2;
    return value;
  }

  readUInt16(): number {
    const value = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return value;
  }

  readInt32(): number {
    const value = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return value;
  }

  readUInt32(): number {
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  readInt64(): bigint {
    const value = this.view.getBigInt64(this.offset, true);
    this.offset += 8;
    return value;
  }

  readUInt64(): bigint {
    const value = this.view.getBigUint64(this.offset, true);
    this.offset += 8;
    return value;
  }

  readFloat(): number {
    const value = this.view.getFloat32(this.offset, true);
    this.offset += 4;
    return value;
  }

  readDouble(): number {
    const value = this.view.getFloat64(this.offset, true);
    this.offset += 8;
    return value;
  }

  readString(): string {
    const length = this.readUInt16();
    if (length === 0) return "";

    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, length);
    this.offset += length;
    return new TextDecoder("utf-8").decode(bytes);
  }

  readBytes(count: number): Uint8Array {
    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, count);
    this.offset += count;
    return bytes;
  }

  /** Read array with length prefix and reader function */
  readArray<T>(reader: () => T): T[] {
    const count = this.readUInt16();
    const items: T[] = [];
    for (let i = 0; i < count; i++) {
      items.push(reader());
    }
    return items;
  }
}

// =============================================================================
// BINARY WRITER
// =============================================================================

export class BinaryWriter {
  private buffer: ArrayBuffer;
  private view: DataView;
  private offset: number = 0;
  private capacity: number;

  constructor(initialCapacity: number = 1024) {
    this.capacity = initialCapacity;
    this.buffer = new ArrayBuffer(initialCapacity);
    this.view = new DataView(this.buffer);
  }

  private ensureCapacity(additionalBytes: number): void {
    if (this.offset + additionalBytes > this.capacity) {
      // Double capacity or add enough for the new data
      const newCapacity = Math.max(this.capacity * 2, this.offset + additionalBytes);
      const newBuffer = new ArrayBuffer(newCapacity);
      new Uint8Array(newBuffer).set(new Uint8Array(this.buffer, 0, this.offset));
      this.buffer = newBuffer;
      this.view = new DataView(this.buffer);
      this.capacity = newCapacity;
    }
  }

  get position(): number {
    return this.offset;
  }

  writeByte(value: number): void {
    this.ensureCapacity(1);
    this.view.setUint8(this.offset, value & 0xff);
    this.offset += 1;
  }

  writeBool(value: boolean): void {
    this.writeByte(value ? 1 : 0);
  }

  writeInt16(value: number): void {
    this.ensureCapacity(2);
    this.view.setInt16(this.offset, value, true);
    this.offset += 2;
  }

  writeUInt16(value: number): void {
    this.ensureCapacity(2);
    this.view.setUint16(this.offset, value, true);
    this.offset += 2;
  }

  writeInt32(value: number): void {
    this.ensureCapacity(4);
    this.view.setInt32(this.offset, value, true);
    this.offset += 4;
  }

  writeUInt32(value: number): void {
    this.ensureCapacity(4);
    this.view.setUint32(this.offset, value, true);
    this.offset += 4;
  }

  writeInt64(value: bigint): void {
    this.ensureCapacity(8);
    this.view.setBigInt64(this.offset, value, true);
    this.offset += 8;
  }

  writeUInt64(value: bigint): void {
    this.ensureCapacity(8);
    this.view.setBigUint64(this.offset, value, true);
    this.offset += 8;
  }

  writeFloat(value: number): void {
    this.ensureCapacity(4);
    this.view.setFloat32(this.offset, value, true);
    this.offset += 4;
  }

  writeDouble(value: number): void {
    this.ensureCapacity(8);
    this.view.setFloat64(this.offset, value, true);
    this.offset += 8;
  }

  writeString(value: string | null): void {
    if (value === null || value === undefined) {
      this.writeUInt16(0);
      return;
    }
    const bytes = new TextEncoder().encode(value);
    this.writeUInt16(bytes.length);
    this.writeBytes(bytes);
  }

  writeBytes(bytes: Uint8Array): void {
    this.ensureCapacity(bytes.length);
    new Uint8Array(this.buffer, this.offset, bytes.length).set(bytes);
    this.offset += bytes.length;
  }

  /** Write array with length prefix and writer function */
  writeArray<T>(items: T[] | null, writer: (item: T) => void): void {
    if (items === null || items === undefined) {
      this.writeUInt16(0);
      return;
    }
    this.writeUInt16(items.length);
    for (const item of items) {
      writer(item);
    }
  }

  /** Get the written bytes as a new Uint8Array */
  toBytes(): Uint8Array {
    return new Uint8Array(this.buffer, 0, this.offset);
  }

  /** Get the written bytes as an ArrayBuffer */
  toArrayBuffer(): ArrayBuffer {
    return this.buffer.slice(0, this.offset);
  }
}
