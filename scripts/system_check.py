#!/usr/bin/env python3
"""
System verification and health check script for Packet_analyzer.
Performs basic checks across runtime environment, dependencies,
codebase integrity, API server, and automated test suites.
Generates SYSTEM_CHECK.md for archival and records.
Exits nonzero when any required check fails so CI and callers can detect it.
"""

from __future__ import annotations

import datetime
import importlib
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
FAILURES: list[str] = []


def run_command(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=120,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as e:
        return -1, str(e)


def record_failure(label: str) -> None:
    FAILURES.append(label)


def declared_requirements() -> dict[str, str]:
    """Parse dashboard/requirements.txt into {package: specifier string}."""
    req_path = ROOT_DIR / "dashboard" / "requirements.txt"
    specs: dict[str, str] = {}
    if not req_path.is_file():
        return specs
    for raw in req_path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        if match:
            specs[match.group(1).lower()] = match.group(2).strip()
    return specs


def version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else (0,)


def satisfies(version: str, specifier: str) -> bool | None:
    """Return True/False against the declared specifier, None if undecidable."""
    if not specifier:
        return None
    detected = version_tuple(version)
    for clause in specifier.split(","):
        clause = clause.strip()
        if not clause:
            continue
        match = re.match(r"^(>=|<=|==|!=|<|>)\s*(.+)$", clause)
        if not match:
            return None
        op, target = match.group(1), match.group(2).strip()
        if "*" in target:
            return None
        want = version_tuple(target)
        if op == ">=" and not detected >= want:
            return False
        if op == ">" and not detected > want:
            return False
        if op == "<=" and not detected <= want:
            return False
        if op == "<" and not detected < want:
            return False
        if op == "==" and detected != want:
            return False
        if op == "!=" and detected == want:
            return False
    return True


def audit_dependency(pkg: str, desc: str, specs: dict[str, str]) -> tuple[str, str, str, str]:
    try:
        mod = importlib.import_module(pkg)
        ver = getattr(mod, "__version__", "unknown")
    except ImportError:
        return pkg, "Missing", desc, "FAIL"

    spec = specs.get(pkg)
    if spec is None:
        return pkg, ver, desc, "WARN (no declared bound)"
    if satisfies(ver, spec) is False:
        return pkg, f"{ver} (declared {spec})", desc, "WARN (outside declared bounds)"
    return pkg, f"{ver} (declared {spec})", desc, "PASS"


def main() -> int:
    print("[*] Running system checks for Packet_analyzer...")

    # 1. Environment & Platform
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    py_ver = sys.version.split()[0]
    py_exec = sys.executable
    check_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 2. Git State
    _, git_branch = run_command(["git", "branch", "--show-current"])
    _, git_head = run_command(["git", "rev-parse", "--short", "HEAD"])
    _, git_status = run_command(["git", "status", "--porcelain", "-uno"])
    git_clean = "Clean (0 tracked modifications)" if not git_status else f"Modified ({len(git_status.splitlines())} tracked files)"
    _, origin_url = run_command(["git", "remote", "get-url", "origin"])
    _, upstream_url = run_command(["git", "remote", "get-url", "upstream"])

    # 3. Toolchains
    meson_installed = shutil.which("meson") is not None
    ninja_installed = shutil.which("ninja") is not None
    compilers = {
        "cl (MSVC)": shutil.which("cl") is not None,
        "g++ (GCC)": shutil.which("g++") is not None,
        "clang++": shutil.which("clang++") is not None,
    }
    avail_compilers = [k for k, v in compilers.items() if v]
    compiler_status = ", ".join(avail_compilers) if avail_compilers else "None found in PATH (native build requires MSVC/GCC)"

    # 4. Python Dependencies (compared against dashboard/requirements.txt bounds)
    packages = [
        ("fastapi", "FastAPI web framework"),
        ("starlette", "ASGI toolkit"),
        ("uvicorn", "ASGI server"),
        ("reportlab", "PDF generation"),
        ("pytest", "Test runner"),
        ("httpx", "HTTP client / TestClient"),
        ("pydantic", "Data validation"),
    ]
    specs = declared_requirements()
    dep_results = [audit_dependency(pkg, desc, specs) for pkg, desc in packages]
    for pkg, ver, _desc, res in dep_results:
        if res.startswith("FAIL"):
            record_failure(f"dependency `{pkg}` {res}")

    # 5. Core Engine Files Check
    expected_headers = [
        "capture_source.h", "connection_tracker.h", "dpi_engine.h",
        "fast_path.h", "ipc_emitter.h", "load_balancer.h",
        "packet_parser.h", "pcap_reader.h", "rule_manager.h",
        "rules_store.h", "sni_extractor.h", "types.h"
    ]
    missing_headers = [h for h in expected_headers if not (ROOT_DIR / "include" / h).is_file()]
    engine_integrity = "PASS" if not missing_headers else f"FAIL (missing {missing_headers})"
    if missing_headers:
        record_failure(f"missing engine headers {missing_headers}")

    # 6. Dashboard Static Assets Check
    static_index = (ROOT_DIR / "dashboard" / "static" / "index.html").is_file()
    static_js = (ROOT_DIR / "dashboard" / "static" / "app.js").is_file()
    static_integrity = "PASS" if static_index and static_js else "FAIL (index.html/app.js missing)"
    if not (static_index and static_js):
        record_failure("dashboard static assets missing")

    # 7. Synthetic PCAP Generation Test.
    # generate_test_pcap.py rewrites the tracked test_dpi.pcap, so back it up and
    # always restore it (or remove it if it did not exist before the run).
    pcap_path = ROOT_DIR / "test_dpi.pcap"
    pcap_backup = pcap_path.read_bytes() if pcap_path.exists() else None
    gen_code, gen_out = -1, "not run"
    try:
        gen_code, gen_out = run_command([sys.executable, "generate_test_pcap.py"])
        gen_status = "PASS" if gen_code == 0 else f"FAIL (code {gen_code}): {gen_out.splitlines()[0] if gen_out else 'no output'}"
    finally:
        try:
            if pcap_backup is not None:
                pcap_path.write_bytes(pcap_backup)
            else:
                pcap_path.unlink(missing_ok=True)
        except OSError as e:
            print(f"[WARN] Could not restore test_dpi.pcap: {e}")
            record_failure(f"test_dpi.pcap restore failed: {e}")
    if gen_code != 0:
        record_failure(f"PCAP generator failed (code {gen_code})")

    # 8. Dashboard Pytest Suite
    py_test_code, py_test_out = run_command([
        sys.executable, "-m", "pytest", "dashboard/test_dashboard.py", "-q"
    ])
    pytest_status = "PASS" if py_test_code == 0 else f"FAIL (code {py_test_code})"
    if py_test_code != 0:
        record_failure(f"dashboard pytest suite failed (code {py_test_code})")

    test_count_match = re.search(r"(\d+)\s+passed", py_test_out)
    test_count = test_count_match.group(1) if test_count_match else "Unknown number of"

    # Generate Record Document
    report = f"""# System Verification & Basic Checks Record

**Generated:** {check_time}  
**Commit:** `{git_head}` on branch `{git_branch}`  
**Repository State:** {git_clean}  

---

## 1. Environment & Platform

| Attribute | Value | Status |
|---|---|---|
| **Operating System** | {os_info} | PASS |
| **Python Runtime** | Python {py_ver} | PASS |
| **Python Binary** | `{py_exec}` | PASS |
| **Build System (Meson)** | {'Installed' if meson_installed else 'Missing'} | {'PASS' if meson_installed else 'WARN'} |
| **Build Backend (Ninja)** | {'Installed' if ninja_installed else 'Missing'} | {'PASS' if ninja_installed else 'WARN'} |
| **C++ Toolchain** | {compiler_status} | {'PASS' if avail_compilers else 'INFO'} |

---

## 2. Git & Repository Information

| Remote | URL |
|---|---|
| **origin** | `{origin_url}` |
| **upstream** | `{upstream_url}` |

- **Current Branch:** `{git_branch}`
- **Working Tree:** {git_clean}
- **Baseline Alignment:** Not verified by this script (compare against `upstream/main` manually)

---

## 3. Dependency Audit (Dashboard & Testing)

Detected versions are checked against the bounds declared in `dashboard/requirements.txt`.
A `WARN` means the installed version is missing a declared bound or falls outside it;
`FAIL` means the package is not importable.

| Package | Detected Version | Purpose | Audit Result |
|---|---|---|---|
"""
    for pkg, ver, desc, res in dep_results:
        report += f"| `{pkg}` | {ver} | {desc} | {res} |\n"

    report += f"""
---

## 4. Subsystem Verification Checks

| Check Item | Description | Result |
|---|---|---|
| **C++ Engine Headers** | All 12 modular headers present in `include/` | {engine_integrity} |
| **Dashboard Web UI Assets** | `index.html` and `app.js` present in `dashboard/static/` | {static_integrity} |
| **Synthetic PCAP Generator** | `generate_test_pcap.py` executes successfully | {gen_status} |
| **Dashboard Test Suite** | {test_count} automated tests in `dashboard/test_dashboard.py` | {pytest_status} |

---

## 5. Test Suite Execution Summary

```text
{py_test_out}
```

---

## 6. Record Status

"""

    if FAILURES:
        report += (
            "**This record does NOT certify a healthy environment.** The following "
            f"required check(s) failed ({len(FAILURES)}):\n"
        )
        for item in FAILURES:
            report += f"- {item}\n"
        report += "\nRe-run `scripts/system_check.py` after resolving the failures above.\n"
    else:
        report += """This system check record verifies that:
1. All Python core dependencies for the web dashboard and report generator are importable; any version-bound mismatches are reported as `WARN` in section 3.
2. The dashboard test suite (`dashboard/test_dashboard.py`) passes.
3. Synthetic test traffic generation functions cleanly.
4. The tracked codebase files checked above are present and intact.
"""

    record_path = ROOT_DIR / "SYSTEM_CHECK.md"
    record_path.write_text(report, encoding="utf-8")

    if FAILURES:
        print(f"[FAIL] System check completed with {len(FAILURES)} failure(s):")
        for item in FAILURES:
            print(f"       - {item}")
        print(f"[FAIL] Record written to: {record_path}")
        return 1

    print(f"[OK] System check complete! Record written to: {record_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
