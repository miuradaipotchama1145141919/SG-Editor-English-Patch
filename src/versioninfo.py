from __future__ import annotations

from pathlib import Path
from typing import Dict

import pefile

from .constants import RESOURCE_DIRECTORY_INDEX


def readVersionInfo(path: Path) -> Dict[str, str]:
    pe = pefile.PE(str(path), fast_load=True)

    try:
        pe.parse_data_directories(directories=[RESOURCE_DIRECTORY_INDEX])
        info: Dict[str, str] = {}

        for fileInfo in getattr(pe, "FileInfo", None) or []:
            for entry in fileInfo:
                for table in getattr(entry, "StringTable", []):
                    for key, value in table.entries.items():
                        info[key.decode(errors="replace")] = value.decode(
                            errors="replace"
                        )

        fixed = getattr(pe, "VS_FIXEDFILEINFO", None)
        fixed = fixed[0] if isinstance(fixed, list) and fixed else fixed

        if fixed:
            ms, ls = fixed.FileVersionMS, fixed.FileVersionLS
            info["version"] = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        elif "FileVersion" in info:
            info["version"] = info["FileVersion"].replace(", ", ".").replace(",", ".")
    finally:
        pe.close()

    return info


def profileKey(info: Dict[str, str]) -> str:
    return f"{info.get('InternalName', '')}@{info.get('version', '')}"
