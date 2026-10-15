#!/usr/bin/env python3
"""
scripts/check_matrix_refs.py
Automated validation of all file:line references in docs/compliance_matrix.md.
Ensures zero broken links, exact line existence, and verifiable code evidence.
"""

import os
import re
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_FILE = REPO_ROOT / "docs" / "compliance_matrix.md"

def normalize_path(raw_url: str) -> Path:
    # Strip file:/// or file://
    url = raw_url.split("#")[0]
    if url.startswith("file:///"):
        path_str = url[8:]
    elif url.startswith("file://"):
        path_str = url[7:]
    else:
        path_str = url
    
    path_str = urllib.parse.unquote(path_str)
    
    # If path starts with Windows drive like c:/, c:/умир/...
    p = Path(path_str)
    if not p.is_absolute():
        p = REPO_ROOT / p
    elif not p.exists():
        # Try resolving relative to REPO_ROOT if path was absolute from another mount
        parts = p.parts
        # find 'умир' or repo folder
        for i, part in enumerate(parts):
            if part.lower() in ["умир", "umirhack"]:
                rel = Path(*parts[i+1:])
                cand = REPO_ROOT / rel
                if cand.exists():
                    return cand
    return p

def extract_references(md_path: Path):
    if not md_path.exists():
        print(f"[ERROR] Matrix file not found: {md_path}")
        sys.exit(1)
        
    content = md_path.read_text(encoding="utf-8")
    # Matches [`label`](url) or [label](url)
    pattern = r'\[`?([^`\]]+)`?\]\((file:///[^)]+|[^)]+)\)'
    matches = re.findall(pattern, content)
    
    refs = []
    for label, url in matches:
        # Ignore external or generic links
        if url.startswith("http://") or url.startswith("https://") or "mailto:" in url:
            continue
        
        # Extract target line number from fragment (#L123) or label (file.py:123)
        line_num = None
        if "#L" in url:
            try:
                line_num = int(url.split("#L")[1].split("-")[0])
            except ValueError:
                pass
        if line_num is None and ":" in label:
            parts = label.split(":")
            if parts[-1].isdigit():
                line_num = int(parts[-1])
                
        file_path = normalize_path(url)
        refs.append({
            "label": label,
            "url": url,
            "file_path": file_path,
            "line_num": line_num
        })
    return refs

def main():
    print(f"[*] Validating compliance matrix references: {MATRIX_FILE}")
    refs = extract_references(MATRIX_FILE)
    print(f"[*] Found {len(refs)} references to check\n")
    
    header = f"{'Status':<8} | {'Label':<28} | {'File Exists':<11} | {'Line':<6} | {'Total':<6} | {'Snippet'}"
    print(header)
    print("-" * len(header))
    
    passed = 0
    failed = 0
    
    for r in refs:
        fp = r["file_path"]
        target_line = r["line_num"]
        
        if not fp.exists():
            print(f"{'FAIL':<8} | {r['label']:<28} | {'MISSING':<11} | {'-':<6} | {'-':<6} | File not found: {fp}")
            failed += 1
            continue
            
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            print(f"{'FAIL':<8} | {r['label']:<28} | {'READ_ERR':<11} | {'-':<6} | {'-':<6} | {e}")
            failed += 1
            continue
            
        total_lines = len(lines)
        if target_line is not None:
            if target_line < 1 or target_line > total_lines:
                print(f"{'FAIL':<8} | {r['label']:<28} | {'EXISTS':<11} | {target_line:<6} | {total_lines:<6} | Line out of range!")
                failed += 1
                continue
            
            snippet = lines[target_line - 1].strip()
            if not snippet:
                snippet = "<blank line>"
            print(f"{'PASS':<8} | {r['label']:<28} | {'EXISTS':<11} | {target_line:<6} | {total_lines:<6} | {snippet[:45]}")
            passed += 1
        else:
            print(f"{'PASS':<8} | {r['label']:<28} | {'EXISTS':<11} | {'-':<6} | {total_lines:<6} | <whole file>")
            passed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED out of {len(refs)} references.")
    print("=" * 60)
    
    if failed > 0:
        print("[!] Validation FAILED. Please correct broken references in docs/compliance_matrix.md.")
        sys.exit(1)
    else:
        print("[+] All compliance matrix references verified successfully (100% PASS).")
        sys.exit(0)

if __name__ == "__main__":
    main()
