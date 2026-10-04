from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .errors import CliError
from .ini_files import translateSgeIni, translateVceIni
from .patcher import patchDll
from .versioninfo import profileKey, readVersionInfo

INPUT_DIRNAME = "input"
CODE_INFO_LABELS = {
    "resource_only": "only in resources (already handled by the resource pass)",
    "substring_only": "only part of a longer string (not patched on their own)",
    "elsewhere": "found outside the string sections",
    "not_in_binary": "not present in this DLL build",
}


# Identification
def _profileFromVersion(src: Path, versionInfo: Dict, profiles: Dict) -> Dict:
    key = profileKey(versionInfo)
    entry = profiles.get(key)

    if not isinstance(entry, dict):
        raise ValueError(
            f"no known build for {src.name} "
            f"(internal name {versionInfo.get('InternalName', '?')!r}, "
            f"version {versionInfo.get('version', '?')})"
        )

    return {"profile": key, **entry}


def identifyDll(src: Path, translationData: Dict, skipHash: bool = False):
    sha256 = hashlib.sha256(src.read_bytes()).hexdigest().lower()
    binaryProfiles = translationData.get("binary_profiles", {})

    if not isinstance(binaryProfiles, dict):
        raise ValueError("translations.json [binary_profiles] must be an object")

    versionInfo = readVersionInfo(src)
    info = binaryProfiles.get(sha256)

    if isinstance(info, dict):
        return sha256, info, "sha256", versionInfo

    if skipHash:
        profiles = translationData.get("profiles", {})

        return (
            sha256,
            _profileFromVersion(src, versionInfo, profiles),
            "version",
            versionInfo,
        )

    raise ValueError(
        f"unsupported SG DLL hash for {src.name}: {sha256}. "
        "Use --skip-hash to match by internal name and file version instead."
    )


# Arguments
def parseArgs(argv=None):
    parser = argparse.ArgumentParser(
        description="Patch SG Easy/Lyric Editor DLL UI into English"
    )
    parser.add_argument(
        "dll",
        nargs="*",
        help=(
            "DLL(s) to patch. DLLs are identified by SHA-256 signatures, not filenames; "
            "with no arguments, supported DLLs in the input/ folder are discovered automatically."
        ),
    )
    parser.add_argument(
        "-t",
        "--translations",
        help="translation JSON (default: translations.json beside this script)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="outputDir",
        help="output directory (default: output/; split into one folder per file version)",
    )
    parser.add_argument(
        "--bitmap-patches",
        dest="bitmapPatches",
        help="bitmap patch JSON (default: bitmap_patches.json beside this script)",
    )
    parser.add_argument(
        "--no-bitmaps",
        dest="noBitmaps",
        action="store_true",
        help="skip bitmap replacement",
    )
    parser.add_argument(
        "--no-ini",
        dest="noIni",
        action="store_true",
        help="do not translate runtime sge.ini display names",
    )
    parser.add_argument(
        "--no-code",
        dest="noCode",
        action="store_true",
        help="do not patch hard-coded strings",
    )
    parser.add_argument(
        "--include-risky",
        dest="includeRisky",
        action="store_true",
        help="also patch the strings marked risky",
    )
    parser.add_argument(
        "--dump-missing",
        dest="dumpMissing",
        metavar="FILE",
        help="write a JSON report of missing/untranslated resource strings",
    )
    parser.add_argument(
        "--report", metavar="FILE", help="write a full JSON patch report"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="list every string that is not a hard-coded string in the DLL build",
    )
    parser.add_argument(
        "--skip-hash",
        dest="skipHash",
        action="store_true",
        help="do not require a known SHA-256; identify unrecognised DLLs by internal name and file version",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow output files to overwrite existing files",
    )

    return parser.parse_args(argv)


def _resolve(pathText: str, base: Path) -> Path:
    path = Path(pathText)

    return path if path.is_absolute() else base / path


# Setup
def _loadTranslationData(path: Path) -> Dict:
    if not path.exists():
        raise CliError(f"translations file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise CliError(f"cannot read translations JSON: {error}")

    if not isinstance(data.get("profiles", {}), dict):
        raise CliError("translations.json [profiles] must be an object")

    return data


def _discoverDlls(
    inputDir: Path, knownHashes: Dict, profiles: Dict, args
) -> List[Path]:
    found = []

    for candidate in sorted(inputDir.glob("*.dll")):
        try:
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest().lower()
        except OSError:
            continue

        if digest in knownHashes:
            found.append(candidate)
        elif args.skipHash:
            try:
                _profileFromVersion(candidate, readVersionInfo(candidate), profiles)
            except Exception:
                continue

            found.append(candidate)

    if not found:
        raise CliError(
            f"no supported SG DLLs found in {inputDir}. Copy the original "
            "DLLs into that folder. Identification is SHA-256 based, so a "
            "filename alone is not accepted."
        )

    return found


# Reports
def printCodeReport(code: Dict, verbose: bool = False) -> None:
    print(f"  Hard-coded pointer patches: {code['patched']}")

    if code.get("in_place"):
        print(f"  Hard-coded strings patched in place: {len(code['in_place'])}")

    if code.get("interior"):
        print(f"  Tail-shared string pointers retargeted: {len(code['interior'])}")

    if code["skipped"]:
        print("  Hard-coded strings skipped:")

        for text, reason in code["skipped"]:
            print(f"    - {text!r}: {reason}")

    for warning in code.get("warnings", []):
        print(f"  Warning: {warning}")

    counts = [(CODE_INFO_LABELS[k], v) for k, v in code.get("info", {}).items() if v]

    if not counts:
        return

    print(
        "  Not hard-coded strings in this build: "
        + ", ".join(f"{len(items)} {label}" for label, items in counts)
    )

    if verbose:
        for label, items in counts:
            print(f"    {label}:")

            for key, reason in items:
                print(f"      - {key!r}: {reason}")


def _printIdentity(
    src: Path, binaryInfo: Dict, versionInfo: Dict, detectedBy: str
) -> None:
    print(
        f"Identified: {src.name} as {binaryInfo.get('product')} {binaryInfo['version']} (by {detectedBy})"
    )
    print(f"  {versionInfo.get('LegalCopyright', 'no copyright string')}")

    if versionInfo.get("version") and versionInfo["version"] != binaryInfo["version"]:
        print(
            f"  Warning: file version is {versionInfo['version']}, profile expects {binaryInfo['version']}"
        )


def _printDllReport(src: Path, dst: Path, report: Dict, verbose: bool) -> None:
    resource = report["resource"]
    print(f"Patched: {src} -> {dst}")
    print(f"  Resource replacements: {resource['strings']}")
    print(f"  Menu resources changed: {resource['menus']}")
    print(f"  Dialog resources changed: {resource['dialogs']}")
    printCodeReport(report["code"], verbose=verbose)

    if resource["remaining"]:
        print("  Remaining Japanese UI strings:")

        for text in resource["remaining"]:
            print(f"    - {text!r}")

    if resource["bitmaps"]:
        print(f"  Bitmap resources replaced: {resource['bitmaps']}")

    if resource["bitmap_missing"]:
        print("  Bitmap assets not applied:")

        for text in resource["bitmap_missing"]:
            print(f"    - {text}")


def _writeJson(path: str, data: Dict) -> None:
    Path(path).write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _writeReports(args, reports: List[Dict], iniReports: List[Dict]) -> None:
    if args.dumpMissing:
        missing = {
            v
            for r in reports
            for vals in r.get("missing_resource_translations", {}).values()
            for v in vals
        }
        remaining = {
            v for r in reports for v in r.get("resource", {}).get("remaining", [])
        }
        _writeJson(
            args.dumpMissing,
            {"resources": sorted(missing), "remaining_after_patch": sorted(remaining)},
        )

    if args.report:
        _writeJson(args.report, {"dlls": reports, "inis": iniReports})


# Ini files
def _writeInis(versionDirs, inputDir: Path, translationData: Dict, args) -> List[Dict]:
    iniMaps = translationData.get("ini", {})

    if not isinstance(iniMaps, dict):
        iniMaps = {}

    jobs = (
        ("sge.ini", translateSgeIni, "Runtime parameter names changed"),
        ("SGvce.ini", translateVceIni, "Category names changed"),
    )
    reports = []

    for name, translate, label in jobs:
        src = inputDir / name

        if not src.exists():
            continue

        table = iniMaps.get(name, {})

        if not isinstance(table, dict):
            raise CliError(f"translations.json [ini][{name}] must be an object")

        for versionDir in sorted(versionDirs):
            dst = versionDir / name

            if dst.exists() and not args.force:
                raise CliError(f"output exists: {dst} (use --force)")

            try:
                report = translate(src, dst, table)
            except Exception as error:
                raise CliError(f"{name}: {error}", 1)

            reports.append(report)
            print(f"Translated: {src} -> {dst}")
            print(f"  {label}: {len(report['changed'])}")

            for item in report["unknown_japanese"]:
                print(f"    untranslated: {item}")

    return reports


# Main
def _run(args, root: Path) -> int:
    inputDir = root / INPUT_DIRNAME
    translations = (
        _resolve(args.translations, root)
        if args.translations
        else root / "translations.json"
    )
    translationData = _loadTranslationData(translations)

    if args.dll:
        dllPaths = [_resolve(item, root) for item in args.dll]
    else:
        dllPaths = _discoverDlls(
            inputDir,
            translationData.get("binary_profiles", {}),
            translationData.get("profiles", {}),
            args,
        )

    outputDir = _resolve(args.outputDir, root) if args.outputDir else root / "output"
    args.bitmapPatches = str(
        _resolve(args.bitmapPatches, root)
        if args.bitmapPatches
        else root / "bitmap_patches.json"
    )

    if args.dumpMissing:
        args.dumpMissing = str(_resolve(args.dumpMissing, root))

    if args.report:
        args.report = str(_resolve(args.report, root))

    reports = []
    versionDirs = set()

    for dll in dllPaths:
        src = dll.resolve()

        if not src.exists():
            raise CliError(f"DLL not found: {src}")

        try:
            sha256, binaryInfo, detectedBy, versionInfo = identifyDll(
                src, translationData, skipHash=args.skipHash
            )
            profileName = binaryInfo["profile"]
            version = str(binaryInfo["version"])
        except Exception as error:
            raise CliError(f"{src.name}: {error}")

        versionDir = outputDir / version
        dst = versionDir / src.name

        if dst.exists() and not args.force:
            raise CliError(f"output exists: {dst} (use --force)")

        try:
            report = patchDll(src, dst, translations, args, profileName=profileName)
        except Exception as error:
            raise CliError(f"{src.name}: {error}", 1)

        report.update(
            {
                "input_sha256": sha256,
                "version": version,
                "file_version": versionInfo.get("version"),
                "copyright": versionInfo.get("LegalCopyright"),
                "detected_by": detectedBy,
            }
        )
        reports.append(report)
        versionDirs.add(versionDir)
        _printIdentity(src, binaryInfo, versionInfo, detectedBy)
        _printDllReport(src, dst, report, args.verbose)

    iniReports = (
        [] if args.noIni else _writeInis(versionDirs, inputDir, translationData, args)
    )
    _writeReports(args, reports, iniReports)

    return 0


def main(argv=None, root: Optional[Path] = None) -> int:
    args = parseArgs(argv)
    projectRoot = (root or Path(__file__).resolve().parent.parent).resolve()

    try:
        return _run(args, projectRoot)
    except CliError as error:
        print(f"ERROR: {error}", file=sys.stderr)

        return error.exitCode
