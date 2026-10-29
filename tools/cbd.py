"""Reads FM15 .dbc/.cbd rule data (e.g. data/comps.dbc) into Python values.

A .dbc file is a 27-byte header followed by back-to-back zlib streams. Each stream is a .cbd
record: a 12-byte header, a typed record id, then a field list. A field is a 4-char tag
(stored byte-reversed), a type byte and a value. See reports/rules/README.md.

Usage: python cbd.py <file.dbc> [tag ...]   prints every value stored under the given tag names
"""

import pathlib
import struct
import sys
import zlib

TAGS_FILE = pathlib.Path(__file__).parent.parent / "reports" / "rules" / "tags.txt"


def load_tag_names():
    names = {}
    for line in TAGS_FILE.read_text("utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            names[parts[0]] = parts[2]
    return names


TAG_NAMES = load_tag_names()


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def take(self, n):
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def tag(self):
        return self.take(4)[::-1].decode("latin-1")

    def value(self, kind):
        if kind == 0x11:
            return self.u8()
        if kind == 0x12:
            return struct.unpack("<H", self.take(2))[0]
        if kind == 0x03:
            return bool(self.u8())
        if kind in (0x01, 0x02):
            return self.u32()
        if kind == 0x04:
            return struct.unpack("<i", self.take(4))[0]
        if kind == 0x0F:  # pair of u32 (seen on draw-rule fields)
            return struct.unpack("<II", self.take(8))
        if kind == 0x00:
            return ""
        if kind == 0x06:  # UTF-16, char count excludes the terminator
            n = self.u32()
            return self.take(n * 2 + 2)[:-2].decode("utf-16-le")  # null-terminated
        if kind == 0x0A:
            return self.struct()
        if kind == 0x0B:
            n = self.u32()
            return [self.value(self.u8()) for _ in range(n)]
        raise ValueError(f"unknown type byte {kind:#x} at {self.i - 1:#x}")

    def struct(self):
        fields = []
        for _ in range(self.u32()):
            t = self.tag()
            fields.append((TAG_NAMES.get(t, t), self.value(self.u8())))
        return fields


def streams(path):
    data = pathlib.Path(path).read_bytes()
    rest = data[27:]
    while rest:
        if rest.startswith(b"\x02\x01fmf."):  # sub-header before the last stream
            rest = rest[9:]
        z = zlib.decompressobj()
        yield z.decompress(rest)
        rest = z.unused_data


def records(path):
    """Yields (stream index, record id, fields) for every record in a .dbc file."""
    for n, raw in enumerate(streams(path)):
        r = Reader(raw)
        r.take(12)
        try:
            rid = r.value(r.u8())
            yield n, rid, r.struct()
        except (ValueError, struct.error, UnicodeDecodeError) as e:
            print(f"stream {n}: {e}", file=sys.stderr)


def find(fields, tag, path=()):
    """Yields (path, value) for every occurrence of `tag` in nested fields."""
    for name, value in fields:
        here = path + (name,)
        if name == tag:
            yield here, value
        if isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, list) and item and isinstance(item[0], tuple):
                    yield from find(item, tag, here + (i,))


if __name__ == "__main__":
    for n, rid, fields in records(sys.argv[1]):
        for tag in sys.argv[2:]:
            for path, value in find(fields, tag):
                print(n, rid, "/".join(map(str, path)), value)
