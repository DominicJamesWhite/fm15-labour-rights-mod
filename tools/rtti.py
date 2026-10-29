"""Finds MSVC (32-bit) vftables for classes by RTTI name in fm.exe and lists their virtual functions.

Usage: python rtti.py <fm.exe> <class name substring> [...]
"""

import re
import struct
import sys


class PE:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        count = struct.unpack_from("<H", self.data, pe + 6)[0]
        opt = struct.unpack_from("<H", self.data, pe + 20)[0]
        self.base = struct.unpack_from("<I", self.data, pe + 24 + 28)[0]
        self.sections = []
        for i in range(count):
            o = pe + 24 + opt + 40 * i
            name = self.data[o:o + 8].rstrip(b"\0").decode()
            vsize, rva, rawsize, raw = struct.unpack_from("<IIII", self.data, o + 8)
            self.sections.append((name, rva, max(vsize, rawsize), raw, rawsize))

    def off_to_va(self, off):
        for _, rva, _, raw, rawsize in self.sections:
            if raw <= off < raw + rawsize:
                return self.base + rva + off - raw
        return None

    def va_to_off(self, va):
        for _, rva, size, raw, rawsize in self.sections:
            if self.base + rva <= va < self.base + rva + rawsize:
                return va - self.base - rva + raw
        return None

    def is_code(self, va):
        name, rva, size, _, _ = self.sections[0]
        return self.base + rva <= va < self.base + rva + size

    def u32(self, va):
        return struct.unpack_from("<I", self.data, self.va_to_off(va))[0]


def vftables(pe, name_re):
    out = []
    for m in re.finditer(rb"\.\?AV([A-Za-z0-9_@?$]+)@@\0", pe.data):
        cls = m.group(1).decode()
        if not re.search(name_re, cls):
            continue
        td = pe.off_to_va(m.start()) - 8
        # Complete object locators: signature 0, offset, cdOffset, pTypeDescriptor
        for c in re.finditer(re.escape(struct.pack("<I", td)), pe.data):
            col_off = c.start() - 12
            sig, offset = struct.unpack_from("<II", pe.data, col_off)
            if sig != 0:
                continue
            col = pe.off_to_va(col_off)
            for v in re.finditer(re.escape(struct.pack("<I", col)), pe.data):
                vft = pe.off_to_va(v.start()) + 4
                entries = []
                while True:
                    target = pe.u32(vft + 4 * len(entries))
                    if not pe.is_code(target):
                        break
                    entries.append(target)
                out.append((cls, offset, vft, entries))
    return out


def main(argv):
    pe = PE(argv[1])
    for pattern in argv[2:]:
        for cls, offset, vft, entries in vftables(pe, pattern):
            print(f"{cls} (subobject +{offset:#x}) vftable {vft:#010x}, {len(entries)} entries")
            for i, e in enumerate(entries):
                print(f"\t[{i}] +{4 * i:#x} -> {e:#010x}")


if __name__ == "__main__":
    main(sys.argv)
