from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict, Optional

import pefile

from .code_strings import patchHardcodedStrings
from .constants import (
    MACHINE_I386,
    NEW_SECTION_CHARACTERISTICS,
    PE32_MAGIC,
    RESOURCE_DIRECTORY_INDEX,
)
from .errors import TranslationError
from .pe_utils import appendSection, nextSectionVa, peHeaderOffsets, setDirectoryEntry
from .resources import loadTranslations, patchResourceTree
from .rsrc import buildRsrc, parseRsrc
from .textutil import align


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patchDll(
    src: Path,
    dst: Path,
    translationsPath: Path,
    args,
    profileName: Optional[str] = None,
) -> Dict:
    config = dict(loadTranslations(translationsPath))
    config["_include_risky"] = bool(args.includeRisky)
    raw = bytearray(src.read_bytes())
    srcSha = _sha256(raw)

    try:
        pe = pefile.PE(data=bytes(raw), fast_load=False)
    except Exception as error:
        raise TranslationError(f"Could not parse {src}: {error}") from error

    if pe.OPTIONAL_HEADER.Magic != PE32_MAGIC:
        raise TranslationError("Only 32-bit PE32 DLLs are supported")

    if pe.FILE_HEADER.Machine != MACHINE_I386:
        raise TranslationError("Only x86 (i386) DLLs are supported")

    dllName = profileName or src.name
    resourceEntry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[RESOURCE_DIRECTORY_INDEX]

    if resourceEntry.VirtualAddress == 0 or resourceEntry.Size == 0:
        raise TranslationError(f"{src.name} has no resource directory")

    root = parseRsrc(pe, resourceEntry.VirtualAddress, resourceEntry.Size)
    stats = patchResourceTree(
        pe,
        dllName,
        root,
        config,
        Path(args.bitmapPatches) if args.bitmapPatches else None,
        not args.noBitmaps,
    )

    # Sections
    newSections = []
    nextVa = nextSectionVa(pe)
    codeStats = {"patched": 0, "skipped": [], "moved": []}

    if not args.noCode:
        caveData, codeStats = patchHardcodedStrings(pe, raw, dllName, config, nextVa)

        if caveData:
            newSections.append(
                (b".sgtrn", caveData, nextVa, NEW_SECTION_CHARACTERISTICS)
            )
            nextVa = align(nextVa + len(caveData), pe.OPTIONAL_HEADER.SectionAlignment)

    newSections.append(
        (b".rsrc2", buildRsrc(root, nextVa), nextVa, NEW_SECTION_CHARACTERISTICS)
    )

    for name, data, va, characteristics in newSections:
        appendSection(raw, pe, name.decode("ascii"), data, va, characteristics)

    _name, rsrcData, rsrcVa, _chars = newSections[-1]
    setDirectoryEntry(raw, pe, RESOURCE_DIRECTORY_INDEX, rsrcVa, len(rsrcData))

    # Checksum
    checksumOffset = peHeaderOffsets(pe)[3]
    struct.pack_into("<I", raw, checksumOffset, 0)

    try:
        checksum = pefile.PE(data=bytes(raw), fast_load=False).generate_checksum()
        struct.pack_into("<I", raw, checksumOffset, checksum)
    except Exception:
        pass

    # Output
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(raw)

    verify = pefile.PE(str(dst), fast_load=False)
    outputResource = verify.OPTIONAL_HEADER.DATA_DIRECTORY[RESOURCE_DIRECTORY_INDEX]

    if outputResource.VirtualAddress != rsrcVa:
        raise TranslationError("Output resource directory was not updated correctly")

    verify.close()
    pe.close()

    return {
        "profile": dllName,
        "input": str(src),
        "output": str(dst),
        "input_sha256": srcSha,
        "output_sha256": _sha256(dst.read_bytes()),
        "resource": {k: v for k, v in stats.items() if k != "missing"},
        "missing_resource_translations": {
            k: sorted(set(v)) for k, v in stats["missing"].items()
        },
        "code": codeStats,
        "new_sections": [
            {"name": name.decode("ascii"), "rva": hex(va), "size": len(data)}
            for name, data, va, _chars in newSections
        ],
        "include_risky": bool(args.includeRisky),
    }
