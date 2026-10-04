#!/usr/bin/env python3
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    sys.exit("This script needs pefile:  py -m pip install pefile")

from src.cli import main

if __name__ == "__main__":
    raise SystemExit(main(root=Path(__file__).resolve().parent))
