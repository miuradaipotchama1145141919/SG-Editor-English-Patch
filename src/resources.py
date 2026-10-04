from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Optional, Sequence

from .constants import RT_BITMAP, RT_DIALOG, RT_MENU, RT_STRING
from .errors import TranslationError
from .rsrc import Dir, findType, iterLeaves
from .textutil import hasJapanese, normKey, translateText
from .winres import (
    decodeDialog,
    decodeMenu,
    decodeStringBlock,
    encodeDialog,
    encodeMenu,
    encodeStringBlock,
    walkMenu,
)

IGNORED_FONT_NAME = "MSゴシック"


def loadTranslations(path: Path) -> Dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise TranslationError(f"Could not read translations file {path}: {error}")

    for key in ("resources", "code_strings"):
        if not isinstance(data.get(key), dict):
            raise TranslationError(f"translations.json is missing {key}")

    return data


# Geometry
def applyGeometry(
    dllName: str, resourceKey, dialog: Dict, geometry: Sequence[Dict]
) -> int:
    changed = 0

    for rule in geometry:
        if rule.get("dll") != dllName or str(rule.get("dialog")) != str(resourceKey):
            continue

        if "id" in rule:
            matched = [c for c in dialog["controls"] if c["id"] == int(rule["id"])]
        elif "text" in rule:
            wanted = normKey(str(rule["text"]))
            matched = [
                c
                for c in dialog["controls"]
                if c["text"][0] == "str" and normKey(c["text"][1]) == wanted
            ]
        else:
            matched = []

        for control in matched:
            for field in ("x", "y", "cx", "cy"):
                if field in rule:
                    control[field] = int(rule[field])

            changed += 1

    return changed


# Bitmaps
def loadBitmapPatches(path: Path) -> Dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise TranslationError(
            f"Could not read bitmap patches {path}: {error}. "
            "Use --no-bitmaps to disable bitmap replacement."
        )


def applyBitmapPatch(dib: bytes, patch: Dict) -> bytes:
    if hashlib.sha256(dib).hexdigest() != patch["sha256"]:
        raise TranslationError("bitmap does not match the expected original")

    buffer = bytearray(dib)

    for offset, hexData in patch["runs"]:
        data = bytes.fromhex(hexData)

        if offset < 0 or offset + len(data) > len(buffer):
            raise TranslationError("bitmap patch run is out of range")

        buffer[offset : offset + len(data)] = data

    return bytes(buffer)


def _patchBitmaps(
    root: Dir,
    dllName: str,
    bitmapConfig: Dict,
    patchesPath: Optional[Path],
    stats: Dict,
) -> None:
    byKey = {
        str(key): leaf for key, _lang, leaf in iterLeaves(findType(root, RT_BITMAP))
    }
    patches = loadBitmapPatches(patchesPath) if patchesPath else {}

    for resourceKey, patchId in bitmapConfig.items():
        if patchId not in patches:
            raise TranslationError(
                f"Bitmap patch missing for {dllName}:{resourceKey}: {patchId}. "
                "Use --no-bitmaps to disable bitmap replacement."
            )

        if str(resourceKey) not in byKey:
            raise TranslationError(
                f"Required bitmap resource missing from {dllName}: "
                f"{resourceKey} (patch {patchId})."
            )

        leaf = byKey[str(resourceKey)]

        try:
            leaf.data = applyBitmapPatch(leaf.data, patches[patchId])
        except Exception as error:
            raise TranslationError(
                f"Could not patch bitmap {dllName}:{resourceKey}: {error}"
            ) from error

        stats["bitmaps"] += 1


# Resource tree
def _wrapError(dllName: str, kind: str, resourceKey, error: TranslationError):
    return TranslationError(f"{dllName}: {kind} resource {resourceKey}: {error}")


def _collectUiStrings(root: Dir, keepNorm: set) -> list:
    seen = set()

    for typeId in (RT_MENU, RT_DIALOG, RT_STRING):
        for _key, _lang, leaf in iterLeaves(findType(root, typeId)):
            if typeId == RT_MENU:
                values = [
                    item["text"] for item in walkMenu(decodeMenu(leaf.data)["items"])
                ]
            elif typeId == RT_DIALOG:
                dialog = decodeDialog(leaf.data)
                values = [dialog["title"]] + [
                    c["text"][1] for c in dialog["controls"] if c["text"][0] == "str"
                ]
            else:
                values = decodeStringBlock(leaf.data)[0]

            seen.update(
                text
                for text in values
                if hasJapanese(text)
                and normKey(text) not in keepNorm
                and normKey(text) != IGNORED_FONT_NAME
            )

    return sorted(seen)


def patchResourceTree(
    pe,
    dllName: str,
    root: Dir,
    config: Dict,
    bitmapPatchesPath: Optional[Path],
    includeBitmaps: bool,
) -> Dict:
    resources = config.get("resources", {})
    keep = config.get("keep", [])
    geometry = config.get("geometry", [])
    keepNorm = {normKey(item) for item in keep}
    stats = {
        "strings": 0,
        "menus": 0,
        "dialogs": 0,
        "geometry": 0,
        "bitmaps": 0,
        "bitmap_missing": [],
        "missing": defaultdict(list),
        "remaining": [],
    }

    def translate(text: str) -> str:
        translated, changed = translateText(text, resources, keep)

        if changed:
            stats["strings"] += 1
        elif (
            hasJapanese(text)
            and normKey(text) not in keepNorm
            and normKey(text) not in resources
        ):
            stats["missing"]["resources"].append(text)

        return translated

    for resourceKey, _lang, leaf in iterLeaves(findType(root, RT_MENU)):
        try:
            menu = decodeMenu(leaf.data)
            changed = False

            for item in walkMenu(menu["items"]):
                translated = translate(item["text"])

                if translated != item["text"]:
                    item["text"] = translated
                    changed = True

            if changed:
                leaf.data = encodeMenu(menu)
                stats["menus"] += 1
        except TranslationError as error:
            raise _wrapError(dllName, "MENU", resourceKey, error) from error

    for resourceKey, _lang, leaf in iterLeaves(findType(root, RT_DIALOG)):
        try:
            dialog = decodeDialog(leaf.data)
            translatedTitle = translate(dialog["title"])
            changed = translatedTitle != dialog["title"]
            dialog["title"] = translatedTitle
            geometryChanges = applyGeometry(dllName, resourceKey, dialog, geometry)
            stats["geometry"] += geometryChanges
            changed = changed or geometryChanges > 0

            for control in dialog["controls"]:
                if control["text"][0] != "str":
                    continue

                translated = translate(control["text"][1])

                if translated != control["text"][1]:
                    control["text"] = ("str", translated)
                    changed = True

            if changed:
                leaf.data = encodeDialog(dialog)
                stats["dialogs"] += 1
        except TranslationError as error:
            raise _wrapError(dllName, "DIALOG", resourceKey, error) from error

    for resourceKey, _lang, leaf in iterLeaves(findType(root, RT_STRING)):
        try:
            strings, tail = decodeStringBlock(leaf.data)
            translatedStrings = [translate(text) for text in strings]

            if translatedStrings != strings:
                leaf.data = encodeStringBlock(translatedStrings, tail)
        except TranslationError as error:
            raise _wrapError(dllName, "STRING", resourceKey, error) from error

    bitmapConfig = config.get("bitmaps", {}).get(dllName, {})

    if includeBitmaps and bitmapConfig:
        _patchBitmaps(root, dllName, bitmapConfig, bitmapPatchesPath, stats)

    stats["remaining"] = _collectUiStrings(root, keepNorm)

    return stats
