"""
Binary Reader/Writer for GameProtocol

Matches the game's CustomBinaryReader/CustomBinaryWriter format:
- Little-endian encoding
- Length-prefixed strings (uint16 + utf8 bytes)
- Array serialization (uint16 count + items)
"""

import struct
from typing import Callable, TypeVar, List, Optional
from io import BytesIO

T = TypeVar("T")


class BinaryReader:
    """Binary reader with little-endian encoding"""

    def __init__(self, data: bytes):
        self._buffer = BytesIO(data)
        self._length = len(data)

    @property
    def position(self) -> int:
        return self._buffer.tell()

    @property
    def remaining(self) -> int:
        return self._length - self._buffer.tell()

    def read_byte(self) -> int:
        """Read unsigned 8-bit integer"""
        return struct.unpack("<B", self._buffer.read(1))[0]

    def read_bool(self) -> bool:
        """Read boolean (1 byte)"""
        return self.read_byte() != 0

    def read_int16(self) -> int:
        """Read signed 16-bit integer"""
        return struct.unpack("<h", self._buffer.read(2))[0]

    def read_uint16(self) -> int:
        """Read unsigned 16-bit integer"""
        return struct.unpack("<H", self._buffer.read(2))[0]

    def read_int32(self) -> int:
        """Read signed 32-bit integer"""
        return struct.unpack("<i", self._buffer.read(4))[0]

    def read_uint32(self) -> int:
        """Read unsigned 32-bit integer"""
        return struct.unpack("<I", self._buffer.read(4))[0]

    def read_int64(self) -> int:
        """Read signed 64-bit integer"""
        return struct.unpack("<q", self._buffer.read(8))[0]

    def read_uint64(self) -> int:
        """Read unsigned 64-bit integer"""
        return struct.unpack("<Q", self._buffer.read(8))[0]

    def read_float(self) -> float:
        """Read 32-bit float"""
        return struct.unpack("<f", self._buffer.read(4))[0]

    def read_double(self) -> float:
        """Read 64-bit float"""
        return struct.unpack("<d", self._buffer.read(8))[0]

    def read_string(self) -> str:
        """Read length-prefixed UTF-8 string"""
        length = self.read_uint16()
        if length == 0:
            return ""
        data = self._buffer.read(length)
        return data.decode("utf-8")

    def read_bytes(self, count: int) -> bytes:
        """Read raw bytes"""
        return self._buffer.read(count)

    def read_array(self, reader: Callable[[], T]) -> List[T]:
        """Read array with length prefix and reader function"""
        count = self.read_uint16()
        return [reader() for _ in range(count)]


class BinaryWriter:
    """Binary writer with little-endian encoding"""

    def __init__(self, initial_capacity: int = 1024):
        self._buffer = BytesIO()

    @property
    def position(self) -> int:
        return self._buffer.tell()

    def write_byte(self, value: int) -> None:
        """Write unsigned 8-bit integer"""
        self._buffer.write(struct.pack("<B", value & 0xFF))

    def write_bool(self, value: bool) -> None:
        """Write boolean (1 byte)"""
        self.write_byte(1 if value else 0)

    def write_int16(self, value: int) -> None:
        """Write signed 16-bit integer"""
        self._buffer.write(struct.pack("<h", value))

    def write_uint16(self, value: int) -> None:
        """Write unsigned 16-bit integer"""
        self._buffer.write(struct.pack("<H", value))

    def write_int32(self, value: int) -> None:
        """Write signed 32-bit integer"""
        self._buffer.write(struct.pack("<i", value))

    def write_uint32(self, value: int) -> None:
        """Write unsigned 32-bit integer"""
        self._buffer.write(struct.pack("<I", value))

    def write_int64(self, value: int) -> None:
        """Write signed 64-bit integer"""
        self._buffer.write(struct.pack("<q", value))

    def write_uint64(self, value: int) -> None:
        """Write unsigned 64-bit integer"""
        self._buffer.write(struct.pack("<Q", value))

    def write_float(self, value: float) -> None:
        """Write 32-bit float"""
        self._buffer.write(struct.pack("<f", value))

    def write_double(self, value: float) -> None:
        """Write 64-bit float"""
        self._buffer.write(struct.pack("<d", value))

    def write_string(self, value: Optional[str]) -> None:
        """Write length-prefixed UTF-8 string"""
        if value is None:
            self.write_uint16(0)
            return
        data = value.encode("utf-8")
        self.write_uint16(len(data))
        self._buffer.write(data)

    def write_bytes(self, data: bytes) -> None:
        """Write raw bytes"""
        self._buffer.write(data)

    def write_array(
        self, items: Optional[List[T]], writer: Callable[[T], None]
    ) -> None:
        """Write array with length prefix and writer function"""
        if items is None:
            self.write_uint16(0)
            return
        self.write_uint16(len(items))
        for item in items:
            writer(item)

    def to_bytes(self) -> bytes:
        """Get the written bytes"""
        return self._buffer.getvalue()
