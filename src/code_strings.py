from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .pe_utils import (
    buildDirectPointerIndex,
    collectRelocPointers,
    sectionName,
    sectionNameAtOffset,
)
from .textutil import nfkc, printfTokens

STRING_SECTION_PREFIXES = (b".data", b".rdata")
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020
ENC_NARROW = "cp932"
ENC_WIDE = "utf-16le"


# Lookup
def looseKey(text: str) -> str:
    text = nfkc(text).replace("\r\n", "\n").replace("\r", "\n").replace("。", "")

    return text.strip().rstrip(".").strip()


class Lookup:
    def __init__(self, mapping: Dict[str, str]):
        self.exact: Dict[str, str] = dict(mapping)
        self.nfkc: Dict[str, Tuple[str, str]] = {}
        self.loose: Dict[str, List[Tuple[str, str]]] = {}

        for key, translation in mapping.items():
            self.nfkc.setdefault(nfkc(key), (key, translation))
            loose = looseKey(key)

            if loose:
                self.loose.setdefault(loose, []).append((key, translation))

    def find(self, text: str) -> Optional[Tuple[str, str, str]]:
        if text in self.exact:
            return text, self.exact[text], "exact"

        folded = nfkc(text)

        if folded in self.nfkc:
            key, translation = self.nfkc[folded]

            return key, translation, "nfkc"

        loose = looseKey(text)
        candidates = self.loose.get(loose)

        if loose and candidates and len(candidates) == 1:
            key, translation = candidates[0]

            return key, translation, "loose"

        return None


# Scanning
@dataclass
class Entry:
    section: str
    fileOffset: int
    rva: int
    data: bytes
    text: str
    encoding: str


@dataclass
class Ref:
    fileOffset: int
    delta: int
    kind: str


def _stringSections(pe):
    return [
        s
        for s in pe.sections
        if s.Name.rstrip(b"\0").lower().startswith(STRING_SECTION_PREFIXES)
    ]


def _iterNarrow(blob: bytes):
    position = 0

    for piece in blob.split(b"\x00"):
        if len(piece) >= 2:
            yield position, piece

        position += len(piece) + 1


def _iterWide(blob: bytes):
    limit = len(blob) // 2 * 2
    start = 0

    while start < limit:
        end = start

        while end < limit and blob[end : end + 2] != b"\x00\x00":
            end += 2

        if end - start >= 4:
            yield start, blob[start:end]

        start = end + 2


def scanEntries(pe, raw: bytes) -> List[Entry]:
    entries: List[Entry] = []

    for section in _stringSections(pe):
        name = sectionName(section)
        base = section.PointerToRawData
        blob = raw[base : base + min(section.SizeOfRawData, len(raw) - base)]

        for iterate, encoding in ((_iterNarrow, ENC_NARROW), (_iterWide, ENC_WIDE)):
            for position, piece in iterate(blob):
                try:
                    text = piece.decode(encoding)
                except UnicodeDecodeError:
                    continue

                entries.append(
                    Entry(
                        name,
                        base + position,
                        section.VirtualAddress + position,
                        piece,
                        text,
                        encoding,
                    )
                )

    return entries


class PointerFinder:
    def __init__(self, pe, raw: bytes, entries: List[Entry]):
        self.pe = pe
        self.imageBase = pe.OPTIONAL_HEADER.ImageBase
        self.reloc = collectRelocPointers(pe, raw)

        if entries:
            low = min(self.imageBase + e.rva for e in entries)
            high = max(self.imageBase + e.rva + len(e.data) for e in entries)
            self.direct = buildDirectPointerIndex(pe, raw, low, high)
        else:
            self.direct = {}

        self.codeRanges = [
            (s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData)
            for s in pe.sections
            if s.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
        ]

    def _isInCode(self, fileOffset: int) -> bool:
        return any(start <= fileOffset < end for start, end in self.codeRanges)

    def refs(self, entry: Entry, rawLength: int) -> List[Ref]:
        va = self.imageBase + entry.rva
        found: Dict[Tuple[int, int], Ref] = {}

        for delta in range(len(entry.data)):
            pointer = va + delta

            for siteRva in self.reloc.get(pointer, ()):
                try:
                    offset = self.pe.get_offset_from_rva(siteRva)
                except Exception:
                    continue

                if offset + 4 <= rawLength:
                    found.setdefault((offset, delta), Ref(offset, delta, "reloc"))

            for offset in self.direct.get(pointer, ()):
                if not self._isInCode(offset) and offset % 4:
                    continue

                found.setdefault((offset, delta), Ref(offset, delta, "direct"))

        return list(found.values())


# Helpers
def _encode(text: str, encoding: str) -> Tuple[bytes, bytes]:
    return text.encode(encoding), (b"\x00\x00" if encoding == ENC_WIDE else b"\x00")


def _shorten(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _classifyUnmatched(
    key: str, pe, raw: bytes, entries: List[Entry]
) -> Tuple[str, str]:
    folded = nfkc(key)
    containing = [
        e
        for e in entries
        if e.encoding == ENC_NARROW
        and folded in nfkc(e.text)
        and nfkc(e.text) != folded
    ]

    if containing:
        shortest = min(containing, key=lambda e: len(e.text))

        return (
            "substring_only",
            f"only occurs inside longer string {_shorten(shortest.text)!r}",
        )

    sections = set()

    for encoding in (ENC_NARROW, ENC_WIDE):
        try:
            needle = key.encode(encoding)
        except UnicodeEncodeError:
            continue

        position = raw.find(needle)

        while position >= 0:
            sections.add(sectionNameAtOffset(pe, position))
            position = raw.find(needle, position + 1)

    if sections and sections <= {".rsrc"}:
        return "resource_only", "present only in .rsrc (handled by the resource pass)"

    if sections:
        return "elsewhere", "found only in " + ", ".join(
            sorted(s or "?" for s in sections)
        )

    return "not_in_binary", "not present in this DLL build"


def _interiorTarget(entry: Entry, delta: int, lookup: Lookup):
    if entry.encoding == ENC_WIDE and delta % 2:
        return None

    try:
        entry.data[:delta].decode(entry.encoding)
        suffix = entry.data[delta:].decode(entry.encoding)
    except UnicodeDecodeError:
        return None

    hit = lookup.find(suffix)

    return None if hit is None else (suffix, hit[0], hit[1])


def _newStats() -> Dict:
    return {
        "patched": 0,
        "moved": [],
        "in_place": [],
        "interior": [],
        "skipped": [],
        "info": {
            "resource_only": [],
            "substring_only": [],
            "elsewhere": [],
            "not_in_binary": [],
        },
        "warnings": [],
    }


# Patching
def patchHardcodedStrings(
    pe, raw: bytearray, dllName: str, config: Dict, caveRva: int
) -> Tuple[bytes, Dict]:
    mapping = dict(config.get("code_strings", {}).get(dllName, {}))

    if config.get("_include_risky", False):
        mapping.update(config.get("code_strings_risky", {}).get("all", {}))

    stats = _newStats()

    if not mapping:
        return b"", stats

    if not _stringSections(pe):
        stats["skipped"] = [(key, "no .data/.rdata section") for key in mapping]

        return b"", stats

    lookup = Lookup(mapping)
    rawBytes = bytes(raw)
    entries = scanEntries(pe, rawBytes)
    matches = [
        (e, hit) for e in entries for hit in [lookup.find(e.text)] if hit is not None
    ]
    finder = PointerFinder(pe, rawBytes, [e for e, _ in matches])

    imageBase = pe.OPTIONAL_HEADER.ImageBase
    cave = bytearray()
    caveIndex: Dict[Tuple[str, str], int] = {}
    patchedSites: Set[int] = set()
    matchedKeys: Set[str] = set()

    def allocate(text: str, encoding: str) -> Optional[int]:
        cacheKey = (encoding, text)

        if cacheKey in caveIndex:
            return caveIndex[cacheKey]

        try:
            payload, terminator = _encode(text, encoding)
        except UnicodeEncodeError:
            return None

        if encoding == ENC_WIDE and len(cave) % 2:
            cave.append(0)

        va = imageBase + caveRva + len(cave)
        cave.extend(payload + terminator)
        caveIndex[cacheKey] = va

        return va

    def skip(label: str, reason: str) -> None:
        stats["skipped"].append((label, reason))

    for entry, (key, translation, tier) in sorted(
        matches, key=lambda m: m[0].fileOffset
    ):
        label = entry.text

        if printfTokens(nfkc(entry.text)) != printfTokens(translation):
            skip(label, "printf format specifiers changed")
            continue

        try:
            payload, _terminator = _encode(translation, entry.encoding)
        except UnicodeEncodeError:
            skip(label, f"translated text is not {entry.encoding} encodable")
            continue

        if entry.text.count("\n") != translation.count("\n"):
            stats["warnings"].append(
                f"{_shorten(label)!r}: newline count differs from translation"
            )

        matchedKeys.add(key)

        refs = finder.refs(entry, len(raw))

        if not refs:
            if len(payload) > len(entry.data):
                skip(
                    label,
                    "no pointer references and the translation is longer than "
                    f"the original ({len(payload)} > {len(entry.data)} bytes)",
                )
                continue

            padding = b"\x00" * (len(entry.data) - len(payload))
            raw[entry.fileOffset : entry.fileOffset + len(entry.data)] = (
                payload + padding
            )
            stats["in_place"].append(
                {
                    "from": label,
                    "to": translation,
                    "tier": tier,
                    "encoding": entry.encoding,
                    "file_offset": hex(entry.fileOffset),
                }
            )
            continue

        for ref in sorted(refs, key=lambda r: (r.delta, r.fileOffset)):
            if ref.fileOffset in patchedSites:
                continue

            if ref.delta == 0:
                targetText = translation
            else:
                interior = _interiorTarget(entry, ref.delta, lookup)

                if interior is None:
                    skip(
                        label,
                        f"pointer into the middle of the string (+{ref.delta}) "
                        "and its tail has no translation; left unchanged",
                    )
                    continue

                suffix, tailKey, targetText = interior
                matchedKeys.add(tailKey)
                stats["interior"].append(
                    {"in": label, "delta": ref.delta, "tail": suffix, "to": targetText}
                )

            va = allocate(targetText, entry.encoding)

            if va is None:
                skip(label, f"translated text is not {entry.encoding} encodable")
                continue

            struct.pack_into("<I", raw, ref.fileOffset, va)
            patchedSites.add(ref.fileOffset)
            stats["patched"] += 1

        stats["moved"].append(
            {
                "from": label,
                "to": translation,
                "tier": tier,
                "encoding": entry.encoding,
                "refs": len(refs),
                "ref_kinds": sorted({r.kind for r in refs}),
                "new_va": hex(caveIndex.get((entry.encoding, translation), 0)),
            }
        )

    for key in mapping:
        if key in matchedKeys:
            continue

        code, reason = _classifyUnmatched(key, pe, rawBytes, entries)

        if code in stats["info"]:
            stats["info"][code].append((key, reason))
        else:
            skip(key, reason)

    return bytes(cave), stats
