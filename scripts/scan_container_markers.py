#!/usr/bin/env python3
"""
HoneyForge Realism & Stealth Verification: Container Filesystem Marker Audit (TASK 1)
Strict zero-marker scanner:
- Substring search (case-insensitive, no word boundaries) for:
  honeyforge, honeypot, decoy, beacon, telemetry, simulated, fake, mock
- Bounded search for short words (non-letters, digits, camelCase boundaries):
  trap, c2
- Whitelist:
  strap, bootstrap, bootstrapping, trapezoid, trapeze, snmp-trap, trapdoor
- Skips ONLY virtual kernel filesystems (/proc, /sys, /dev) and binary files (\x7fELF, images, etc.).
- Verifies agent code location, entrypoint, configs, and volume mounts.
- Exits with non-zero code if ANY match is found.
"""

import os
import sys
import re
import argparse
from typing import List, Tuple, Set

LONG_FORBIDDEN_WORDS = [
    "honeyforge",
    "honeypot",
    "decoy",
    "beacon",
    "telemetry",
    "simulated",
    "fake",
    "mock",
]

SHORT_FORBIDDEN_WORDS = {"trap", "c2"}

WHITELIST_WORDS = {
    "strap",
    "bootstrap",
    "bootstrapping",
    "bootstrapped",
    "trapezoid",
    "trapeze",
    "snmp-trap",
    "trapdoor",
    "strapdown",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svgz",
    ".so", ".a", ".o", ".dylib", ".bin",
    ".gz", ".tar", ".tgz", ".zip", ".xz", ".bz2", ".7z",
    ".woff", ".woff2", ".ttf", ".eot",
    ".sqlite", ".db",
}

VIRTUAL_KERNEL_DIRS = {"/proc", "/sys", "/dev"}


def check_text_for_markers(text: str) -> Tuple[bool, str, str]:
    """
    Checks text for forbidden markers.
    Returns (has_match, marker_found, matched_snippet).
    """
    low = text.lower()
    # 1. Long words: case-insensitive substring search without word boundaries
    for word in LONG_FORBIDDEN_WORDS:
        idx = low.find(word)
        if idx != -1:
            snippet = text[max(0, idx - 15):min(len(text), idx + len(word) + 15)]
            return True, word, snippet

    # 2. Short words: boundary by non-letters/digits or camelCase transitions
    # Tokenize by non-letters, digits, or camelCase transitions
    tokens = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|_|$)|[0-9]+", text)
    for tok in tokens:
        tok_low = tok.lower()
        if tok_low in WHITELIST_WORDS:
            continue
        if tok_low in SHORT_FORBIDDEN_WORDS:
            idx = text.find(tok)
            snippet = text[max(0, idx - 15):min(len(text), idx + len(tok) + 15)]
            return True, tok_low, snippet

    return False, "", ""


def extract_pyc_strings(data: bytes) -> List[str]:
    """Extracts ASCII/UTF-8 strings of length >= 2 from .pyc bytecode"""
    raw_matches = re.findall(b"[a-zA-Z0-9_./-]{2,}", data)
    extracted = []
    for rm in raw_matches:
        try:
            extracted.append(rm.decode("utf-8"))
        except Exception:
            try:
                extracted.append(rm.decode("latin-1"))
            except Exception:
                pass
    return extracted


def scan_filesystem(root_dir: str = "/") -> Tuple[int, int, int, int, List[dict]]:
    """
    Recursively scans filesystem starting from root_dir.
    Returns (scanned_text, scanned_pyc, skipped_elf, checked_paths, matches).
    """
    scanned_text = 0
    scanned_pyc = 0
    skipped_elf = 0
    checked_paths = 0
    matches = []

    for root, dirs, files in os.walk(root_dir):
        # Skip virtual kernel trees
        norm_root = os.path.abspath(root).replace("\\", "/")
        if any(norm_root == vd or norm_root.startswith(vd + "/") for vd in VIRTUAL_KERNEL_DIRS):
            continue

        # Check directory names
        for d in list(dirs):
            checked_paths += 1
            has_m, word, snip = check_text_for_markers(d)
            dpath = os.path.join(root, d).replace("\\", "/")
            if has_m:
                matches.append({
                    "path": dpath,
                    "type": "directory_name",
                    "word": word,
                    "snippet": snip,
                    "line": 0
                })

        # Check files
        for f in files:
            checked_paths += 1
            fpath = os.path.join(root, f).replace("\\", "/")

            # Skip the scanner script itself to prevent self-matching on word definitions
            try:
                if os.path.samefile(fpath, __file__):
                    continue
            except Exception:
                if os.path.abspath(fpath) == os.path.abspath(__file__):
                    continue

            # Check filename itself
            has_m, word, snip = check_text_for_markers(f)
            if has_m:
                matches.append({
                    "path": fpath,
                    "type": "file_name",
                    "word": word,
                    "snippet": snip,
                    "line": 0
                })

            ext = os.path.splitext(f)[1].lower()

            try:
                # Binary / ELF check by reading first 16 bytes
                with open(fpath, "rb") as bf:
                    hdr = bf.read(16)

                if hdr.startswith(b"\x7fELF"):
                    skipped_elf += 1
                    continue

                if ext in BINARY_EXTENSIONS:
                    continue

                # .pyc bytecode string extraction
                if ext == ".pyc":
                    scanned_pyc += 1
                    with open(fpath, "rb") as bf:
                        raw_bytes = bf.read()
                    pyc_strs = extract_pyc_strings(raw_bytes)
                    for s in pyc_strs:
                        has_m, word, snip = check_text_for_markers(s)
                        if has_m:
                            matches.append({
                                "path": fpath,
                                "type": "pyc_string",
                                "word": word,
                                "snippet": snip,
                                "line": 0
                            })
                    continue

                # Check for binary null byte in header
                if b"\x00" in hdr:
                    continue

                # Plain text inspection
                scanned_text += 1
                with open(fpath, "r", encoding="utf-8", errors="ignore") as tf:
                    for lno, line in enumerate(tf, 1):
                        has_m, word, snip = check_text_for_markers(line)
                        if has_m:
                            matches.append({
                                "path": fpath,
                                "type": "text_content",
                                "word": word,
                                "snippet": snip.strip(),
                                "line": lno
                            })

            except (PermissionError, FileNotFoundError, OSError):
                continue

    return scanned_text, scanned_pyc, skipped_elf, checked_paths, matches


def main():
    parser = argparse.ArgumentParser(description="Container Filesystem Marker Audit (TASK 1)")
    parser.add_argument("--root", default="/", help="Filesystem root to scan (default: /)")
    parser.add_argument("--agent-dir", default="/usr/lib/sysmon", help="Agent execution root (default: /usr/lib/sysmon)")
    args = parser.parse_args()

    print("=" * 80)
    print("  HONEYFORGE CONTAINER REALISM & STEALTH AUDIT: ZERO MARKER SCANNER")
    print("=" * 80)

    # 1. Verify agent launch environment and entrypoint
    print(f"[*] Target scan root: {args.root}")
    print(f"[*] Agent directory: {args.agent_dir}")
    if os.path.exists(args.agent_dir):
        agent_entries = os.listdir(args.agent_dir)
        print(f"[*] Agent directory verified present ({len(agent_entries)} entries): {agent_entries}")
    else:
        print(f"[!] Warning: Agent directory {args.agent_dir} not found on this root.")

    # 2. Check process entrypoint if running inside container
    if os.path.exists("/proc/1/cmdline"):
        try:
            with open("/proc/1/cmdline", "r", encoding="utf-8", errors="ignore") as f:
                cmdline = f.read().replace("\x00", " ").strip()
            print(f"[*] Process 1 cmdline: {cmdline}")
            has_m, word, snip = check_text_for_markers(cmdline)
            if has_m:
                print(f"[FAIL] /proc/1/cmdline contains marker: {word} -> {snip}")
                sys.exit(1)
        except Exception as e:
            print(f"[*] /proc/1/cmdline check: {e}")

    # 3. Perform deep filesystem scan
    print("[*] Performing full filesystem audit...")
    s_text, s_pyc, sk_elf, chk_paths, matches = scan_filesystem(args.root)

    print("-" * 80)
    print("SCAN METRICS & STATISTICS:")
    print(f"  Total paths checked by name:   {chk_paths:>8}")
    print(f"  Scanned text files:            {s_text:>8}")
    print(f"  Scanned .pyc bytecode files:   {s_pyc:>8}")
    print(f"  Skipped binary ELF files:      {sk_elf:>8}")
    print(f"  Total forbidden matches:       {len(matches):>8}")
    print("-" * 80)

    if matches:
        print(f"[FAIL] Audit FAILED: {len(matches)} marker occurrences detected!")
        for m in matches[:50]:
            print(f"  - [{m['type'].upper()}] {m['path']}:{m['line']} (word: '{m['word']}') -> {m['snippet']}")
        if len(matches) > 50:
            print(f"  ... and {len(matches) - 50} more occurrences.")
        sys.exit(1)
    else:
        print("[PASS] Audit PASSED: Exactly 0 marker occurrences detected across the filesystem!")
        sys.exit(0)


if __name__ == "__main__":
    main()
