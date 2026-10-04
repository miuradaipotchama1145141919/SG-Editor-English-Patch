from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple, Union

from .errors import TranslationError
from .textutil import align


class Leaf:
    def __init__(self, data: bytes, codepage: int = 0, reserved: int = 0):
        self.data = data
        self.codepage = codepage
        self.reserved = reserved


class Dir:
    def __init__(self, meta: Tuple[int, int, int, int]):
        self.meta = meta
        self.entries: List[Tuple[Union[str, int], Union["Dir", Leaf]]] = []


# Parse
def parseRsrc(pe, rsrcRva: int, rsrcSize: int) -> Dir:
    buffer = pe.get_data(rsrcRva, rsrcSize)

    if len(buffer) < 16:
        raise TranslationError("The resource directory is too small to parse")

    def readName(offset: int) -> str:
        if offset + 2 > len(buffer):
            raise TranslationError("Bad resource name offset")

        length = struct.unpack_from("<H", buffer, offset)[0]
        end = offset + 2 + 2 * length

        if end > len(buffer):
            raise TranslationError("Bad resource name length")

        return buffer[offset + 2 : end].decode("utf-16le")

    visited = set()

    def readDir(offset: int) -> Dir:
        if offset in visited:
            raise TranslationError("Recursive resource directory detected")

        visited.add(offset)

        if offset + 16 > len(buffer):
            raise TranslationError("Bad resource directory offset")

        characteristics, timestamp, major, minor, namedCount, idCount = (
            struct.unpack_from("<IIHHHH", buffer, offset)
        )
        directory = Dir((characteristics, timestamp, major, minor))

        for i in range(namedCount + idCount):
            entryOffset = offset + 16 + 8 * i

            if entryOffset + 8 > len(buffer):
                raise TranslationError("Bad resource directory entry")

            nameField, target = struct.unpack_from("<II", buffer, entryOffset)
            key = (
                readName(nameField & 0x7FFFFFFF)
                if nameField & 0x80000000
                else nameField
            )

            if target & 0x80000000:
                child = readDir(target & 0x7FFFFFFF)
            else:
                if target + 16 > len(buffer):
                    raise TranslationError("Bad resource data entry")

                rva, size, codepage, reserved = struct.unpack_from(
                    "<IIII", buffer, target
                )
                child = Leaf(pe.get_data(rva, size), codepage, reserved)

            directory.entries.append((key, child))

        visited.remove(offset)

        return directory

    return readDir(0)


# Build
def buildRsrc(root: Dir, baseRva: int) -> bytes:
    directories: List[Dir] = []
    queue = [root]

    while queue:
        current = queue.pop(0)
        directories.append(current)
        queue.extend(child for _, child in current.entries if isinstance(child, Dir))

    offsets: Dict[object, int] = {}
    position = 0

    for directory in directories:
        offsets[id(directory)] = position
        position += 16 + 8 * len(directory.entries)

    leaves = [
        child
        for directory in directories
        for _, child in directory.entries
        if isinstance(child, Leaf)
    ]

    for leaf in leaves:
        offsets[id(leaf)] = position
        position += 16

    nameOffsets: Dict[str, int] = {}

    for directory in directories:
        for key, _ in directory.entries:
            if isinstance(key, str) and key not in nameOffsets:
                nameOffsets[key] = position
                position += 2 + 2 * len(key)

    position = align(position, 4)

    for leaf in leaves:
        offsets[("data", id(leaf))] = position
        position += align(len(leaf.data), 4)

    out = bytearray(position)

    for directory in directories:
        base = offsets[id(directory)]
        named = sum(1 for key, _ in directory.entries if isinstance(key, str))
        numeric = len(directory.entries) - named
        struct.pack_into("<IIHHHH", out, base, *directory.meta, named, numeric)

        for i, (key, child) in enumerate(directory.entries):
            nameField = (0x80000000 | nameOffsets[key]) if isinstance(key, str) else key
            target = (
                (0x80000000 | offsets[id(child)])
                if isinstance(child, Dir)
                else offsets[id(child)]
            )
            struct.pack_into("<II", out, base + 16 + 8 * i, nameField, target)

    for leaf in leaves:
        dataOffset = offsets[("data", id(leaf))]
        struct.pack_into(
            "<IIII",
            out,
            offsets[id(leaf)],
            baseRva + dataOffset,
            len(leaf.data),
            leaf.codepage,
            leaf.reserved,
        )
        out[dataOffset : dataOffset + len(leaf.data)] = leaf.data

    for name, offset in nameOffsets.items():
        struct.pack_into("<H", out, offset, len(name))
        out[offset + 2 : offset + 2 + 2 * len(name)] = name.encode("utf-16le")

    return bytes(out)


# Lookup
def findType(root: Dir, typeId: int) -> Optional[Dir]:
    for key, child in root.entries:
        if key == typeId:
            return child if isinstance(child, Dir) else None

    return None


def iterLeaves(typeDir: Optional[Dir]):
    if typeDir is None:
        return

    for resourceKey, resourceDir in typeDir.entries:
        if not isinstance(resourceDir, Dir):
            continue

        for language, leaf in resourceDir.entries:
            if isinstance(leaf, Leaf):
                yield resourceKey, language, leaf
