from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import INI_NAME_FIELD
from .errors import TranslationError
from .textutil import hasJapanese


def _splitLine(line: bytes) -> Tuple[bytes, bytes]:
    body = line.rstrip(b"\r\n")

    return body, line[len(body) :]


def _sectionName(body: bytes) -> Optional[str]:
    if not (body.startswith(b"[") and body.endswith(b"]")):
        return None

    try:
        return body[1:-1].decode("cp932")
    except UnicodeDecodeError:
        return ""


def _writeResult(
    src: Path, dst: Path, lines: List[bytes], changed: List, unknown: List
) -> Dict:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(b"".join(lines))

    return {
        "input": str(src),
        "output": str(dst),
        "changed": changed,
        "unknown_japanese": unknown,
    }


# sge.ini
def translateSgeIni(src: Path, dst: Path, displayTranslations: Dict[str, str]) -> Dict:
    # Coefficient records are hex: a 12-byte CP932 name field, parameter bytes,
    # then a one-byte checksum. Only the name and checksum are rewritten.
    out: List[bytes] = []
    changed: List[Dict] = []
    unknown: List[str] = []
    inCoefficients = False

    for line in src.read_bytes().splitlines(keepends=True):
        body, ending = _splitLine(line)
        section = _sectionName(body)

        if section is not None:
            inCoefficients = section == "係数"
            out.append(line)
            continue

        if not inCoefficients or b"=" not in body:
            out.append(line)
            continue

        key, value = body.split(b"=", 1)

        try:
            textKey = key.decode("cp932")
            record = bytearray(bytes.fromhex(value.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            out.append(line)
            continue

        if len(record) < 2:
            out.append(line)
            continue

        payload = record[:-1]

        try:
            oldText = payload[:INI_NAME_FIELD].split(b"\x00", 1)[0].decode("cp932")
        except UnicodeDecodeError:
            out.append(line)
            continue

        newText = displayTranslations.get(oldText)

        if newText is None:
            if hasJapanese(oldText):
                unknown.append(f"{textKey}: {oldText}")

            out.append(line)
            continue

        newBytes = newText.encode("cp932")
        capacity = INI_NAME_FIELD - 1

        if len(newBytes) > capacity:
            raise TranslationError(
                f"sge.ini {textKey}: translated display name {newText!r} is too long "
                f"({len(newBytes)} > {capacity} bytes)"
            )

        payload[:INI_NAME_FIELD] = newBytes.ljust(INI_NAME_FIELD, b"\x00")
        record[:-1] = payload
        record[-1] = sum(record[:-1]) & 0xFF
        out.append(key + b"=" + record.hex().upper().encode("ascii") + ending)
        changed.append({"key": textKey, "from": oldText, "to": newText})

    return _writeResult(src, dst, out, changed, unknown)


# SGvce.ini
def translateVceIni(src: Path, dst: Path, categoryTranslations: Dict[str, str]) -> Dict:
    # Lines look like "key=name:11,12,13". Only the name is replaced.
    out: List[bytes] = []
    changed: List[Dict] = []
    unknown: List[str] = []
    inCategories = False

    for line in src.read_bytes().splitlines(keepends=True):
        body, ending = _splitLine(line)
        section = _sectionName(body)

        if section is not None:
            inCategories = section == "カテゴリ名"
            out.append(line)
            continue

        if not inCategories or b"=" not in body:
            out.append(line)
            continue

        key, value = body.split(b"=", 1)
        nameBytes, separator, rest = value.partition(b":")

        try:
            oldName = nameBytes.decode("cp932")
            textKey = key.decode("cp932")
        except UnicodeDecodeError:
            out.append(line)
            continue

        newName = categoryTranslations.get(oldName)

        if newName is None:
            if hasJapanese(oldName):
                unknown.append(f"{textKey}: {oldName}")

            out.append(line)
            continue

        out.append(key + b"=" + newName.encode("cp932") + separator + rest + ending)
        changed.append({"key": textKey, "from": oldName, "to": newName})

    return _writeResult(src, dst, out, changed, unknown)
