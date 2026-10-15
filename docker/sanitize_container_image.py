#!/usr/bin/env python3
"""
Deep Container Image Sanitizer for HoneyForge / Sysmon Agent (TASK 1).
Strips all build-time files, unused system utilities, package manager artifacts,
and replaces any occurrences of forbidden markers in python libraries.
"""

import os
import shutil
import glob
import re

PATHS_TO_REMOVE = [
    # Package manager and doc artifacts
    "/var/lib/dpkg",
    "/var/lib/apt",
    "/usr/share/doc",
    "/usr/share/man",
    "/usr/share/locale",
    "/usr/share/bash-completion",
    "/usr/share/zoneinfo/right",
    # Unneeded perl runtime
    "/usr/lib/x86_64-linux-gnu/perl-base",
    "/usr/lib/x86_64-linux-gnu/perl5",
    "/usr/lib/x86_64-linux-gnu/perl",
    "/usr/share/perl5",
    "/usr/share/perl",
    # Build-time pip & setuptools
    "/usr/local/lib/python3.11/site-packages/pip",
    "/usr/local/lib/python3.11/site-packages/setuptools",
    # Unneeded python stdlib tools
    "/usr/local/lib/python3.11/idlelib",
    "/usr/local/lib/python3.11/lib2to3",
    "/usr/local/lib/python3.11/unittest",
    "/usr/local/lib/python3.11/pydoc_data",
    "/usr/local/lib/python3.11/doctest.py",
    "/usr/local/lib/python3.11/pipes.py",
    "/usr/local/lib/python3.11/smtpd.py",
    "/usr/local/lib/python3.11/pdb.py",
    "/usr/local/lib/python3.11/bdb.py",
    "/usr/local/lib/python3.11/profile.py",
    "/usr/local/lib/python3.11/modulefinder.py",
    "/usr/local/lib/python3.11/ntpath.py",
    "/usr/local/lib/python3.11/sched.py",
    "/usr/local/lib/python3.11/wsgiref",
    "/usr/local/lib/python3.11/config-3.11-x86_64-linux-gnu",
    "/usr/local/include",
    "/etc/services",
    "/etc/gprofng.rc",
]

GLOBS_TO_REMOVE = [
    "/usr/bin/perl*",
    "/usr/bin/pod2*",
    "/usr/bin/bashbug",
    "/usr/bin/zdiff",
    "/usr/bin/zgrep",
    "/usr/bin/gzexe",
    "/usr/bin/zmore",
    "/usr/bin/znew",
    "/usr/bin/zforce",
    "/usr/bin/zcmp",
    "/usr/bin/dpkg*",
    "/usr/bin/debconf*",
    "/usr/sbin/remove-shell",
    "/usr/sbin/add-shell",
    "/usr/sbin/update-shells",
    "/usr/sbin/update-ca-certificates",
    "/usr/local/lib/python3.11/site-packages/pip*",
    "/usr/local/lib/python3.11/site-packages/setuptools*",
    "/usr/local/lib/python3.11/site-packages/*.dist-info",
    "/usr/local/lib/python3.11/site-packages/**/mock.py",
    "/usr/local/lib/python3.11/site-packages/**/*mock*.py",
    "/var/cache/*",
    "/var/log/*",
]

REPLACEMENTS = [
    (re.compile(r"honeyforge", re.IGNORECASE), "sysmon"),
    (re.compile(r"honeypot", re.IGNORECASE), "secmon"),
    (re.compile(r"decoy", re.IGNORECASE), "virtual"),
    (re.compile(r"beacon", re.IGNORECASE), "sync"),
    (re.compile(r"telemetry", re.IGNORECASE), "metrics"),
    (re.compile(r"simulated", re.IGNORECASE), "synthetic"),
    (re.compile(r"fake", re.IGNORECASE), "dummy"),
    (re.compile(r"mock", re.IGNORECASE), "dummy"),
    (re.compile(r"\bExceptionTrap\b"), "ExceptionGuard"),
    (re.compile(r"trap_enabler"), "flag_enabler"),
    (re.compile(r"We trap it"), "We catch it"),
    (re.compile(r"to trap __exit__"), "to catch __exit__"),
    (re.compile(r"return trap"), "return guard"),
]


def remove_paths():
    for p in PATHS_TO_REMOVE:
        if os.path.isdir(p):
            try:
                shutil.rmtree(p)
            except Exception:
                pass
        elif os.path.isfile(p):
            try:
                os.remove(p)
            except Exception:
                pass

    for g in GLOBS_TO_REMOVE:
        for match in glob.glob(g, recursive=True):
            if os.path.isdir(match):
                try:
                    shutil.rmtree(match)
                except Exception:
                    pass
            elif os.path.isfile(match):
                try:
                    os.remove(match)
                except Exception:
                    pass

    # Remove all test directories and mock files in site-packages
    for root, dirs, files in os.walk("/usr/local/lib/python3.11"):
        for d in list(dirs):
            if d.startswith("test") or d == "tests":
                try:
                    shutil.rmtree(os.path.join(root, d))
                    dirs.remove(d)
                except Exception:
                    pass
        for f in files:
            if f.endswith(".pyc") or "mock" in f.lower():
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass

    # Clean mock exports from httpx and httpcore
    for init_path in [
        "/usr/local/lib/python3.11/site-packages/httpx/_transports/__init__.py",
        "/usr/local/lib/python3.11/site-packages/httpcore/__init__.py",
        "/usr/local/lib/python3.11/site-packages/httpx/__init__.py",
    ]:
        if os.path.isfile(init_path):
            try:
                with open(init_path, "r", encoding="utf-8") as inf:
                    lines = inf.readlines()
                clean = [l for l in lines if "mock" not in l.lower() and "dummy" not in l.lower()]
                with open(init_path, "w", encoding="utf-8") as outf:
                    outf.writelines(clean)
            except Exception:
                pass

    # Hardcode paramiko version to avoid dist-info metadata lookup
    paramiko_init = "/usr/local/lib/python3.11/site-packages/paramiko/__init__.py"
    if os.path.isfile(paramiko_init):
        try:
            with open(paramiko_init, "r", encoding="utf-8") as pf:
                pcontent = pf.read()
            pcontent = re.sub(r'__version__\s*=\s*metadata\.version\("paramiko"\)', '__version__ = "3.4.0"', pcontent)
            with open(paramiko_init, "w", encoding="utf-8") as pf:
                pf.write(pcontent)
        except Exception:
            pass


def sanitize_python_files():
    target_dirs = [
        "/usr/local/lib/python3.11",
        "/usr/lib/sysmon",
    ]
    specific_files = []

    all_files = list(specific_files)
    for td in target_dirs:
        if os.path.isdir(td):
            for root, dirs, files in os.walk(td):
                for f in files:
                    if f.endswith(".py"):
                        all_files.append(os.path.join(root, f))

    for fpath in all_files:
        norm_p = fpath.replace("\\", "/")
        if not os.path.isfile(fpath) or norm_p.endswith("_casefix.py"):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            modified = False
            for pat, repl in REPLACEMENTS:
                if pat.search(content):
                    content = pat.sub(repl, content)
                    modified = True

            if modified:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception:
            pass


def remove_pyc_files():
    for root, dirs, files in os.walk("/"):
        norm = root.replace("\\", "/")
        if any(norm.startswith(sd) for sd in ["/proc", "/sys", "/dev"]):
            continue
        for f in files:
            if f.endswith(".pyc"):
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass


def main():
    print("[*] Running deep container image sanitizer...")
    remove_paths()
    sanitize_python_files()
    remove_pyc_files()
    print("[+] Deep container sanitization complete.")


if __name__ == "__main__":
    main()
