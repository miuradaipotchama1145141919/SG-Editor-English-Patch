# SG Editor English Patch

Patches Yamaha SG Easy Editor and SG Lyric Editor DLLs (file versions 1.0.2.0 and 1.1.1.11) so their interface is in English.

## Installation

Requires Windows and Python 3.

```
py -m pip install pefile
```

Copy the original DLLs, plus `sge.ini` and `SGvce.ini` if you have them, into the `input` folder. They are commonly found in one of these installation folders:

```
C:\Program Files (x86)\YAMAHA\OPT Tools\SG Easy Editor\Modules
C:\Program Files (x86)\YAMAHA\OPT Tools\SG Lyric Editor\Modules
C:\Program Files (x86)\YAMAHA\XGWORKS_XXXX\XGworks (XXXX is the XGworks version number.)
```

The file `bitmap_patches.json` must stay next to `main.py`. It contains only the changed pixels and is applied to the bitmaps inside your original DLLs.

## Usage

Run with no arguments to patch every supported DLL in `input`, or double click `translate_sg.cmd`.

```
py main.py
```

You can also name specific DLLs.

```
py main.py SGLyric.dll SGEasyEditor.dll
```

DLLs are identified by SHA-256 hash, not filename. Patched copies are written to a subfolder of `output` named after the file version, for example `output\1.1.1.11`, and the originals are not changed. Translated INI files are written beside the patched DLLs.

## Options

```
-t FILE                 Use a different translation JSON
--bitmap-patches FILE   Use a different bitmap patch JSON
-o DIR                  Write output to DIR instead of output
--skip-hash             Identify unrecognised DLLs by internal name and file version
--force                 Overwrite existing output
--no-code               Skip hard-coded string patching
--no-bitmaps            Skip bitmap replacement
--no-ini                Skip sge.ini and SGvce.ini
--include-risky         Also patch strings that may be internal keys
--report FILE           Save a JSON patch report
--dump-missing FILE     Save a JSON list of untranslated strings
-v                      List strings that are not hard-coded in the build
```

## Supported builds

| SHA-256 | Product | File version | Filename |
|---|---|---|---|
| `38d39d2521f42b2b752db093e72cda46b51f72a60f8c2cf8b87191c4b4e2e65c` | SG Easy Editor | 1.0.2.0 | `SGeeditor.dll` |
| `9e9d648017383a72ec66aa10551b5d7e4433aecaac6a7977faef4ee997f1ea5f` | SG Lyric Editor | 1.0.2.0 | `SGlyric.dll` |
| `17fe75729c663e38e2549a5291432f9003e777c7ded6e2501d87db9496dcf839` | SG Easy Editor | 1.1.1.11 | `SGEasyEditor.dll` |
| `35d90e348c0b3a59ade0663b3f0b06f5df5bc8f959f82a81e06d0aae623748db` | SG Lyric Editor | 1.1.1.11 | `SGLyric.dll` |

To check a hash on Windows:

```
certutil -hashfile SGLyric.dll SHA256
```

Translations and the hash list are stored in `translations.json`.

## Tools

The `makeBitmapPatches.py` tool generates `bitmap_patches.json` from edited bitmaps. Put the original DLLs in `input` and the edited bitmaps in folders named `SGeeditorBMP` and `SGlyricBMP`, with each file named after its resource, then run:

```
py tools/makeBitmapPatches.py path\to\bitmaps
```

Edited bitmaps must use the same bit depth (4-bit or 8-bit) as the original. Pixels are mapped to the nearest color in the original palette.

## Tests

```
py -m unittest discover tests
```
