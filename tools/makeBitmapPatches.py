import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

import pefile

from src.constants import RT_BITMAP
from src.rsrc import findType, iterLeaves, parseRsrc

warnDistance = 300


# Bitmap reading
def readBitmaps(dllPath):
    pe = pefile.PE(str(dllPath))
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
    tree = parseRsrc(pe, entry.VirtualAddress, entry.Size)

    return {
        str(key): leaf.data
        for key, _lang, leaf in iterLeaves(findType(tree, RT_BITMAP))
    }


def readInfo(dib):
    _size, width, height, _planes, bitCount, compression = struct.unpack_from(
        "<IiiHHI", dib, 0
    )

    if compression != 0 or bitCount not in (4, 8):
        raise ValueError("only uncompressed 4 and 8 bit bitmaps are supported")

    colorCount = struct.unpack_from("<I", dib, 32)[0] or (1 << bitCount)

    return {
        "width": width,
        "height": height,
        "bitCount": bitCount,
        "palette": [tuple(dib[40 + 4 * i : 43 + 4 * i]) for i in range(colorCount)],
        "pixelStart": 40 + 4 * colorCount,
        "stride": ((width * bitCount + 31) // 32) * 4,
    }


def indexAt(row, x, bitCount):
    if bitCount == 8:
        return row[x]

    return row[x // 2] >> 4 if x % 2 == 0 else row[x // 2] & 15


def readRows(dib, info):
    def readRow(rowIndex):
        start = info["pixelStart"] + rowIndex * info["stride"]
        row = dib[start : start + info["stride"]]

        return [
            info["palette"][indexAt(row, x, info["bitCount"])]
            for x in range(info["width"])
        ]

    return [readRow(i) for i in range(abs(info["height"]))]


# Snapping
def snapToOriginal(originalDib, editedBytes):
    info = readInfo(originalDib)
    editedDib = editedBytes[14:]
    editedInfo = readInfo(editedDib)

    if info["bitCount"] != editedInfo["bitCount"]:
        raise ValueError("edited bitmap bit depth differs from the original")

    if (info["width"], abs(info["height"])) != (
        editedInfo["width"],
        abs(editedInfo["height"]),
    ):
        raise ValueError("edited bitmap size differs from the original")

    editedRows = readRows(editedDib, editedInfo)

    if (info["height"] > 0) != (editedInfo["height"] > 0):
        editedRows = editedRows[::-1]

    buffer = bytearray(originalDib)
    palette = info["palette"]
    distanceCache = {}
    distances = []

    def distancesFor(color):
        if color not in distanceCache:
            distanceCache[color] = [
                sum((a - b) ** 2 for a, b in zip(color, entry)) for entry in palette
            ]

        return distanceCache[color]

    for y in range(abs(info["height"])):
        rowStart = info["pixelStart"] + y * info["stride"]

        for x in range(info["width"]):
            offset = rowStart + (x if info["bitCount"] == 8 else x // 2)
            originalIndex = indexAt(
                originalDib[rowStart : rowStart + info["stride"]], x, info["bitCount"]
            )
            colorDistances = distancesFor(editedRows[y][x])
            nearest = min(colorDistances)
            newIndex = (
                originalIndex
                if colorDistances[originalIndex] == nearest
                else colorDistances.index(nearest)
            )
            distances.append(nearest)

            if info["bitCount"] == 8:
                buffer[offset] = newIndex
            elif x % 2 == 0:
                buffer[offset] = (buffer[offset] & 0x0F) | (newIndex << 4)
            else:
                buffer[offset] = (buffer[offset] & 0xF0) | newIndex

    return bytes(buffer), distances


def findRuns(original, patched, gap=8):
    runs = []
    i = 0

    while i < len(original):
        if original[i] == patched[i]:
            i += 1
            continue

        end = i
        j = i

        while j < len(original) and j - end <= gap:
            if original[j] != patched[j]:
                end = j

            j += 1

        runs.append([i, patched[i : end + 1].hex()])
        i = end + 1

    return runs


# Main
def collectOriginals(dllDir, translations):
    profiles = translations["binary_profiles"]
    originals = {}

    for dllPath in sorted(dllDir.glob("*.dll")):
        sha = hashlib.sha256(dllPath.read_bytes()).hexdigest()

        if sha not in profiles:
            print(f"Skipped unrecognised DLL: {dllPath.name}")
            continue

        bitmaps = readBitmaps(dllPath)
        profile = profiles[sha]["profile"]

        for resourceKey, patchId in translations["bitmaps"].get(profile, {}).items():
            originals.setdefault(patchId, []).append((profile, bitmaps[resourceKey]))

    return originals


def buildPatch(patchId, candidates, bmpDir):
    first = candidates[0][1]

    if any(dib != first for _profile, dib in candidates):
        raise SystemExit(f"{patchId}: original bitmaps differ between DLL versions")

    folder, name = patchId.split("/")
    editedPath = bmpDir / f"{folder}BMP" / f"{name}.bmp"

    if not editedPath.exists():
        raise SystemExit(f"Missing edited bitmap: {editedPath}")

    patched, distances = snapToOriginal(first, editedPath.read_bytes())
    runs = findRuns(first, patched)
    snapped = sum(1 for d in distances if d)
    far = sum(1 for d in distances if d > warnDistance)
    byteCount = sum(len(data) // 2 for _offset, data in runs)
    warning = (
        f"  WARNING: {far} pixels snapped far from any palette color" if far else ""
    )

    print(
        f"{patchId}: {len(runs)} runs, {byteCount} bytes, {snapped} pixels snapped{warning}"
    )

    return {"sha256": hashlib.sha256(first).hexdigest(), "runs": runs}


def main():
    parser = argparse.ArgumentParser(
        description="Build bitmap_patches.json from edited bitmaps."
    )
    parser.add_argument(
        "bmpDir",
        help="folder holding SGeeditorBMP and SGlyricBMP with the edited bitmaps",
    )
    parser.add_argument(
        "--dll-dir",
        dest="dllDir",
        default=str(root / "input"),
        help="folder with the original DLLs (default: input)",
    )
    parser.add_argument("-t", "--translations", default=str(root / "translations.json"))
    parser.add_argument("-o", "--output", default=str(root / "bitmap_patches.json"))
    args = parser.parse_args()
    translations = json.loads(Path(args.translations).read_text(encoding="utf-8"))
    originals = collectOriginals(Path(args.dllDir), translations)
    wanted = sorted(
        {
            pid
            for mapping in translations["bitmaps"].values()
            for pid in mapping.values()
        }
    )
    missing = [pid for pid in wanted if pid not in originals]

    if missing:
        raise SystemExit(f"No original DLL found for: {', '.join(missing)}")

    patches = {
        pid: buildPatch(pid, originals[pid], Path(args.bmpDir)) for pid in wanted
    }
    lines = [
        f"  {json.dumps(key)}: {json.dumps(value, separators=(',', ':'))}"
        for key, value in patches.items()
    ]
    Path(args.output).write_text("{\n" + ",\n".join(lines) + "\n}\n", encoding="utf-8")

    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
