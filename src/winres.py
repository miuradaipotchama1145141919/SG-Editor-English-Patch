from __future__ import annotations

import struct
from typing import Dict, List, Sequence, Tuple

from .constants import DS_SETFONT, MF_END, MF_POPUP
from .errors import TranslationError
from .textutil import align


# String table
def decodeStringBlock(data: bytes) -> Tuple[List[str], bytes]:
    strings: List[str] = []
    position = 0

    for _ in range(16):
        if position + 2 > len(data):
            raise TranslationError("Malformed RT_STRING block")

        length = struct.unpack_from("<H", data, position)[0]
        position += 2
        end = position + 2 * length

        if end > len(data):
            raise TranslationError("Malformed RT_STRING string")

        strings.append(data[position:end].decode("utf-16le"))
        position = end

    return strings, data[position:]


def encodeStringBlock(strings: Sequence[str], tail: bytes = b"") -> bytes:
    out = bytearray()

    for text in strings:
        if len(text) > 0xFFFF:
            raise TranslationError("RT_STRING value is too long")

        out += struct.pack("<H", len(text)) + text.encode("utf-16le")

    return bytes(out) + tail


# Primitives
def _readString(data: bytes, position: int) -> Tuple[str, int]:
    if position & 1:
        raise TranslationError("Unaligned UTF-16 string")

    end = position

    while end + 2 <= len(data):
        if data[end : end + 2] == b"\0\0":
            return data[position:end].decode("utf-16le"), end + 2

        end += 2

    raise TranslationError("Unterminated UTF-16 string")


def _encodeString(text: str) -> bytes:
    return text.encode("utf-16le") + b"\0\0"


def _readOrdinalOrString(data: bytes, position: int):
    if position + 2 > len(data):
        raise TranslationError("Malformed ordinal/string field")

    word = struct.unpack_from("<H", data, position)[0]

    if word == 0:
        return ("none", None), position + 2

    if word == 0xFFFF:
        if position + 4 > len(data):
            raise TranslationError("Malformed ordinal field")

        return ("ord", struct.unpack_from("<H", data, position + 2)[0]), position + 4

    text, nextPosition = _readString(data, position)

    return ("str", text), nextPosition


def _encodeOrdinalOrString(value) -> bytes:
    kind, content = value

    if kind == "none":
        return b"\0\0"

    if kind == "ord":
        return struct.pack("<HH", 0xFFFF, content)

    return _encodeString(content)


# Menu
def decodeMenu(data: bytes) -> Dict:
    if len(data) < 4:
        raise TranslationError("Malformed MENU resource")

    version, headerSize = struct.unpack_from("<HH", data)

    if version != 0:
        raise TranslationError("MENUEX is not supported by this patcher")

    def readItems(position: int):
        items = []

        while True:
            if position + 2 > len(data):
                raise TranslationError("Malformed MENU item flags")

            flags = struct.unpack_from("<H", data, position)[0]
            position += 2
            item = {"flags": flags}

            if flags & MF_POPUP:
                item["text"], position = _readString(data, position)
                item["children"], position = readItems(position)
            else:
                if position + 2 > len(data):
                    raise TranslationError("Malformed MENU item id")

                item["id"] = struct.unpack_from("<H", data, position)[0]
                position += 2
                item["text"], position = _readString(data, position)

            items.append(item)

            if flags & MF_END:
                return items, position

    tree, end = readItems(4 + headerSize)

    return {"hdr": data[: 4 + headerSize], "items": tree, "tail": data[end:]}


def encodeMenu(menu: Dict) -> bytes:
    out = bytearray(menu["hdr"])

    def emit(items):
        for item in items:
            out.extend(struct.pack("<H", item["flags"]))

            if item["flags"] & MF_POPUP:
                out.extend(_encodeString(item["text"]))
                emit(item["children"])
            else:
                out.extend(struct.pack("<H", item["id"]))
                out.extend(_encodeString(item["text"]))

    emit(menu["items"])

    return bytes(out) + menu["tail"]


def walkMenu(items):
    for item in items:
        yield item

        if item["flags"] & MF_POPUP:
            yield from walkMenu(item["children"])


# Dialog
def decodeDialog(data: bytes) -> Dict:
    if len(data) < 18:
        raise TranslationError("Malformed DIALOG resource")

    version, signature = struct.unpack_from("<HH", data)
    extended = version == 1 and signature == 0xFFFF
    dialog = {"ex": extended}

    if extended:
        if len(data) < 26:
            raise TranslationError("Malformed DLGTEMPLATEEX header")

        (
            dialog["help"],
            dialog["exstyle"],
            dialog["style"],
            controlCount,
            dialog["x"],
            dialog["y"],
            dialog["cx"],
            dialog["cy"],
        ) = struct.unpack_from("<IIIHhhhh", data, 4)
        position = 26
    else:
        (
            dialog["style"],
            dialog["exstyle"],
            controlCount,
            dialog["x"],
            dialog["y"],
            dialog["cx"],
            dialog["cy"],
        ) = struct.unpack_from("<IIHhhhh", data)
        position = 18

    dialog["menu"], position = _readOrdinalOrString(data, position)
    dialog["class"], position = _readOrdinalOrString(data, position)
    dialog["title"], position = _readString(data, position)

    if dialog["style"] & DS_SETFONT:
        fontSize = 6 if extended else 2

        if position + fontSize > len(data):
            raise TranslationError("Malformed dialog font")

        if extended:
            dialog["pt"], dialog["weight"], dialog["italic"], dialog["charset"] = (
                struct.unpack_from("<HHBB", data, position)
            )
        else:
            dialog["pt"] = struct.unpack_from("<H", data, position)[0]

        position += fontSize
        dialog["face"], position = _readString(data, position)

    controls = []

    for _ in range(controlCount):
        position = align(position, 4)
        control = {}

        if extended:
            if position + 24 > len(data):
                raise TranslationError("Malformed DLGTEMPLATEEX control")

            (
                control["help"],
                control["exstyle"],
                control["style"],
                control["x"],
                control["y"],
                control["cx"],
                control["cy"],
                control["id"],
            ) = struct.unpack_from("<IIIhhhhI", data, position)
            position += 24
        else:
            if position + 18 > len(data):
                raise TranslationError("Malformed DLGTEMPLATE control")

            (
                control["style"],
                control["exstyle"],
                control["x"],
                control["y"],
                control["cx"],
                control["cy"],
                control["id"],
            ) = struct.unpack_from("<IIhhhhH", data, position)
            position += 18

        control["class"], position = _readOrdinalOrString(data, position)
        control["text"], position = _readOrdinalOrString(data, position)

        if position + 2 > len(data):
            raise TranslationError("Malformed dialog control extra-size")

        extraSize = struct.unpack_from("<H", data, position)[0]
        position += 2

        if position + extraSize > len(data):
            raise TranslationError("Malformed dialog control extra data")

        control["extra"] = data[position : position + extraSize]
        position += extraSize
        controls.append(control)

    dialog["controls"] = controls
    dialog["tail"] = data[position:]

    return dialog


def encodeDialog(dialog: Dict) -> bytes:
    extended = dialog["ex"]
    geometry = (dialog["x"], dialog["y"], dialog["cx"], dialog["cy"])

    if extended:
        out = bytearray(
            struct.pack(
                "<HHIIIHhhhh",
                1,
                0xFFFF,
                dialog["help"],
                dialog["exstyle"],
                dialog["style"],
                len(dialog["controls"]),
                *geometry,
            )
        )
    else:
        out = bytearray(
            struct.pack(
                "<IIHhhhh",
                dialog["style"],
                dialog["exstyle"],
                len(dialog["controls"]),
                *geometry,
            )
        )

    out += _encodeOrdinalOrString(dialog["menu"])
    out += _encodeOrdinalOrString(dialog["class"])
    out += _encodeString(dialog["title"])

    if dialog["style"] & DS_SETFONT:
        if extended:
            out += struct.pack(
                "<HHBB",
                dialog["pt"],
                dialog["weight"],
                dialog["italic"],
                dialog["charset"],
            )
        else:
            out += struct.pack("<H", dialog["pt"])

        out += _encodeString(dialog["face"])

    for control in dialog["controls"]:
        while len(out) % 4:
            out.append(0)

        controlGeometry = (control["x"], control["y"], control["cx"], control["cy"])

        if extended:
            out += struct.pack(
                "<IIIhhhhI",
                control["help"],
                control["exstyle"],
                control["style"],
                *controlGeometry,
                control["id"],
            )
        else:
            out += struct.pack(
                "<IIhhhhH",
                control["style"],
                control["exstyle"],
                *controlGeometry,
                control["id"],
            )

        out += _encodeOrdinalOrString(control["class"])
        out += _encodeOrdinalOrString(control["text"])
        extra = control["extra"]

        if len(extra) > 0xFFFF:
            raise TranslationError("Dialog extra data too large")

        out += struct.pack("<H", len(extra)) + extra

    return bytes(out) + dialog["tail"]
