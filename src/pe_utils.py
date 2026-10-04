from __future__ import annotations

import struct
from collections import defaultdict
from typing import Dict, List, Tuple

from .constants import (
    BASERELOC_DIRECTORY_INDEX,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SECTION_HEADER_SIZE,
    OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET_PE32,
    PE32_MAGIC,
)
from .errors import TranslationError
from .textutil import align


def sectionName(section) -> str:
    return section.Name.rstrip(b"\0").decode("ascii", errors="ignore")


# Headers
def peHeaderOffsets(pe) -> Tuple[int, int, int, int, int]:
    fileHeader = pe.DOS_HEADER.e_lfanew + 4
    optional = fileHeader + 20
    sectionTable = optional + pe.FILE_HEADER.SizeOfOptionalHeader

    return sectionTable, fileHeader + 2, optional + 56, optional + 64, optional


def nextSectionVa(pe) -> int:
    end = max(
        (
            s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
            for s in pe.sections
        ),
        default=0,
    )

    return align(end, pe.OPTIONAL_HEADER.SectionAlignment)


def appendSection(
    raw: bytearray, pe, name: str, data: bytes, va: int, characteristics: int
) -> Tuple[int, int]:
    if len(name) > 8:
        raise ValueError("PE section name must be <= 8 bytes")

    fileAlign = pe.OPTIONAL_HEADER.FileAlignment
    sectionAlign = pe.OPTIONAL_HEADER.SectionAlignment
    rawPtr = align(len(raw), fileAlign)
    rawSize = align(len(data), fileAlign)
    raw.extend(b"\0" * (rawPtr - len(raw)))
    raw.extend(data)
    raw.extend(b"\0" * (rawSize - len(data)))

    sectionTable, numberSectionsOffset, sizeOfImageOffset, _checksum, _optional = (
        peHeaderOffsets(pe)
    )
    oldCount = pe.FILE_HEADER.NumberOfSections
    headerOffset = sectionTable + oldCount * IMAGE_SECTION_HEADER_SIZE
    headersEnd = pe.OPTIONAL_HEADER.SizeOfHeaders

    if headerOffset + IMAGE_SECTION_HEADER_SIZE > headersEnd:
        raise TranslationError(
            f"No room for another PE section header: need "
            f"0x{headerOffset + IMAGE_SECTION_HEADER_SIZE:X}, headers end at 0x{headersEnd:X}"
        )

    header = bytearray(IMAGE_SECTION_HEADER_SIZE)
    header[:8] = name.encode("ascii").ljust(8, b"\0")
    struct.pack_into("<I", header, 8, len(data))
    struct.pack_into("<I", header, 12, va)
    struct.pack_into("<I", header, 16, rawSize)
    struct.pack_into("<I", header, 20, rawPtr)
    struct.pack_into("<I", header, 36, characteristics)
    raw[headerOffset : headerOffset + IMAGE_SECTION_HEADER_SIZE] = header
    struct.pack_into("<H", raw, numberSectionsOffset, oldCount + 1)
    pe.FILE_HEADER.NumberOfSections = oldCount + 1
    oldImage = struct.unpack_from("<I", raw, sizeOfImageOffset)[0]
    newImage = max(oldImage, align(va + len(data), sectionAlign))
    struct.pack_into("<I", raw, sizeOfImageOffset, newImage)
    pe.OPTIONAL_HEADER.SizeOfImage = newImage

    return rawPtr, rawSize


def directoryEntryOffset(pe, index: int) -> int:
    if pe.OPTIONAL_HEADER.Magic != PE32_MAGIC:
        raise TranslationError("This patcher requires PE32/x86 DLLs")

    return (
        peHeaderOffsets(pe)[4] + OPTIONAL_HEADER_DATA_DIRECTORY_OFFSET_PE32 + index * 8
    )


def setDirectoryEntry(raw: bytearray, pe, index: int, rva: int, size: int) -> None:
    struct.pack_into("<II", raw, directoryEntryOffset(pe, index), rva, size)


# Pointers
def collectRelocPointers(pe, raw: bytes) -> Dict[int, List[int]]:
    pointers: Dict[int, List[int]] = defaultdict(list)

    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        try:
            pe.parse_data_directories(directories=[BASERELOC_DIRECTORY_INDEX])
        except Exception:
            return pointers

    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if entry.type != IMAGE_REL_BASED_HIGHLOW:
                continue

            try:
                offset = pe.get_offset_from_rva(entry.rva)

                if offset + 4 <= len(raw):
                    pointers[struct.unpack_from("<I", raw, offset)[0]].append(entry.rva)
            except Exception:
                continue

    return pointers


def buildDirectPointerIndex(
    pe, raw: bytes, vaLow: int, vaHigh: int
) -> Dict[int, List[int]]:
    # Some builds hold absolute pointers missing from the relocation table.
    # Only offsets whose high 16 bits fall in the range are inspected.
    index: Dict[int, List[int]] = defaultdict(list)

    if vaHigh <= vaLow:
        return index

    highWords = range(vaLow >> 16, ((vaHigh - 1) >> 16) + 1)

    for section in pe.sections:
        if sectionName(section).lower() in (".reloc", ".rsrc"):
            continue

        base = section.PointerToRawData
        end = min(base + section.SizeOfRawData, len(raw))

        for highWord in highWords:
            needle = struct.pack("<H", highWord)
            position = raw.find(needle, base + 2, end)

            while position >= 0:
                offset = position - 2
                value = struct.unpack_from("<I", raw, offset)[0]

                if vaLow <= value < vaHigh:
                    index[value].append(offset)

                position = raw.find(needle, position + 1, end)

    return index


def sectionNameAtOffset(pe, fileOffset: int) -> str:
    for section in pe.sections:
        start = section.PointerToRawData

        if start <= fileOffset < start + section.SizeOfRawData:
            return sectionName(section)

    return ""
