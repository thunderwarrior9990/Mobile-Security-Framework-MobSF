#!/usr/bin/env python3
"""Scan decompiled app contents for specific patterns.

This script extracts an APK or IPA file and searches for
opcodes, profanity, unexpected file types, BRID IDs,
credit card numbers and email addresses.
Lists for opcodes, profanity and unexpected file types
can be provided via text files (one entry per line).
"""

import argparse
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterable, List, Tuple


def read_wordlist(path: str) -> List[str]:
    """Read newline separated entries from a file."""
    if not path:
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def compile_word_regex(words: Iterable[str]) -> re.Pattern:
    """Compile a regex that matches any of the given words."""
    escaped = [re.escape(w) for w in words if w]
    if not escaped:
        return re.compile(r"^$a")  # never matches
    return re.compile(r"(" + "|".join(escaped) + r")", re.IGNORECASE)


CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BRID_RE = re.compile(r"\b[A-Za-z]\d{8}\b")


def extract_archive(app_path: Path, out_dir: Path) -> None:
    """Extract APK or IPA using zipfile."""
    with zipfile.ZipFile(app_path, "r") as zf:
        zf.extractall(out_dir)


def iter_text_files(root: Path) -> Iterable[Path]:
    """Yield text files under root."""
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def scan_file(
    path: Path,
    patterns: List[Tuple[str, re.Pattern]],
) -> List[Tuple[str, int, str]]:
    """Scan single file and return matches as (pattern_name, line, value)."""
    matches = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                for name, regex in patterns:
                    for m in regex.finditer(line):
                        matches.append((name, lineno, m.group().strip()))
    except Exception:
        pass
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan app contents for patterns")
    parser.add_argument("app", help="Path to APK or IPA")
    parser.add_argument("--opcodes", help="File containing opcodes to search")
    parser.add_argument("--profanity", help="File with profanity words")
    parser.add_argument("--filetypes", help="File with unexpected file extensions")
    args = parser.parse_args()

    app_path = Path(args.app).resolve()
    if not app_path.is_file():
        print(f"App not found: {app_path}", file=sys.stderr)
        return 1

    temp_dir = Path("./_extracted")
    if temp_dir.exists():
        for p in temp_dir.rglob("*"):
            if p.is_file():
                p.unlink()
            else:
                p.rmdir()
    else:
        temp_dir.mkdir()

    extract_archive(app_path, temp_dir)

    opcode_words = read_wordlist(args.opcodes)
    profanity_words = read_wordlist(args.profanity)
    unexpected_ext = [e.lower().lstrip('.') for e in read_wordlist(args.filetypes)]

    patterns = [
        ("BRID", BRID_RE),
        ("CreditCard", CREDIT_CARD_RE),
        ("Email", EMAIL_RE),
    ]
    if opcode_words:
        patterns.append(("Opcode", compile_word_regex(opcode_words)))
    if profanity_words:
        patterns.append(("Profanity", compile_word_regex(profanity_words)))

    report = []
    for file in iter_text_files(temp_dir):
        rel = file.relative_to(temp_dir)
        if unexpected_ext and file.suffix.lower().lstrip('.') in unexpected_ext:
            report.append(("UnexpectedFile", 0, str(rel)))
        for name, line, value in scan_file(file, patterns):
            report.append((name, f"{rel}:{line}", value))

    for name, loc, value in report:
        print(f"[{name}] {loc} -> {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
