from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional, Sequence, Tuple

from .constants import JP, PRINTF


def hasJapanese(text: str) -> bool:
    return bool(JP.search(text))


def normKey(text: str) -> str:
    return unicodedata.normalize("NFKC", text.strip())


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def preserveEdgeSpace(original: str, translated: str) -> str:
    prefix = re.match(r"^\s*", original).group(0)
    suffix = re.search(r"\s*$", original).group(0)

    return prefix + translated.strip() + suffix


def printfTokens(text: str) -> List[str]:
    return PRINTF.findall(text)


# Translation
def translateText(
    original: str, resources: Dict[str, str], keep: Sequence[str]
) -> Tuple[str, bool]:
    keepNorm = {normKey(item) for item in keep}

    if normKey(original) in keepNorm:
        return original, False

    def lookup(text: str) -> Optional[str]:
        key = normKey(text)

        return text if key in keepNorm else resources.get(key)

    def finish(result: str) -> Tuple[str, bool]:
        return result, result != original

    whole = lookup(original)

    if whole is not None:
        return finish(preserveEdgeSpace(original, whole))

    if "\t" in original:
        base, tail = original.split("\t", 1)
        baseHit = lookup(base)

        if baseHit is not None:
            return finish(preserveEdgeSpace(base, baseHit) + "\t" + tail)

    if "\n" in original:
        parts = re.split(r"(\r?\n)", original)
        translatedParts = []

        for part in parts:
            hit = None if part in ("\n", "\r\n") else lookup(part)
            translatedParts.append(
                part if hit is None else preserveEdgeSpace(part, hit)
            )

        result = "".join(translatedParts)

        if result != original:
            return finish(result)

    return original, False
