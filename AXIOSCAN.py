#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  AXIOSCAN v1.1  —  Axios Supply Chain Attack Detector & Remediator      ║
║  NEATLABS™  |  Security 360, LLC  |  SDVOSB                             ║
║  Incident: axios npm compromise — March 31, 2026                         ║
║  Affected: axios@1.14.1  |  axios@0.30.4  |  plain-crypto-js@4.2.1      ║
║  C2 Server: sfrclak.com:8000                                             ║
╚══════════════════════════════════════════════════════════════════════════╝

Usage:  python AXIOSCAN.py   (or python3 AXIOSCAN.py on Linux/macOS)
Deps:   pip install customtkinter
MIT License — https://github.com/Security360LLC/axioscan
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os, json, zipfile, platform, shutil, datetime, tempfile
from pathlib import Path

# ─── App Identity ─────────────────────────────────────────────────────────────
APP_TITLE   = "AXIOSCAN"
APP_VERSION = "v1.1"
COMPANY     = "NEATLABS™  |  Security 360, LLC  |  SDVOSB"

# ─── Threat Intel ─────────────────────────────────────────────────────────────
AFFECTED_AXIOS = {"1.14.1", "0.30.4"}
MALICIOUS_PKG  = "plain-crypto-js"
MALICIOUS_VER  = "4.2.1"
C2_HOST        = "sfrclak.com"
SAFE_1X        = "1.14.0"
SAFE_0X        = "0.30.3"
RAT_ARTIFACTS  = {
    "Darwin":  ["/Library/Caches/com.apple.act.mond"],
    "Windows": [os.path.join(os.environ.get("PROGRAMDATA","C:\\ProgramData"), "wt.exe")],
    "Linux":   ["/tmp/ld.py"],
}

SYSTEM = platform.system()
MONO   = "Courier New" if SYSTEM == "Windows" else "Courier"
HOSTS  = (r"C:\Windows\System32\drivers\etc\hosts"
          if SYSTEM == "Windows" else "/etc/hosts")

# Dirs to never recurse into during filesystem walk
SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".cache",
    ".next", ".nuxt", "dist", "build", "out", "target",
    ".venv", "venv", "env", ".tox", "coverage",
    ".nyc_output", ".tmp", "tmp",
}
# Top-level OS system dirs to skip (not worth scanning)
SKIP_OS_TOP = {
    "Windows": {"Windows","Program Files","Program Files (x86)",
                "ProgramData","Recovery","System Volume Information"},
    "Darwin":  {"System","private","cores","dev"},
    "Linux":   {"proc","sys","dev","run","snap"},
}.get(SYSTEM, set())

# ─── Theme ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

RED    = "#FF3B30"
ORANGE = "#FF9F0A"
GREEN  = "#32D74B"
BLUE   = "#0A84FF"
BG     = "#0A0A0C"
PANEL  = "#111113"
CARD   = "#1A1A1C"
CARD2  = "#222226"
BORDER = "#2C2C2E"
TEXT   = "#F5F5F7"
MUTED  = "#8E8E93"


# ─────────────────────────────────────────────────────────────────────────────
#  Color-coded Log Widget  (tk.Text with tagged colors)
# ─────────────────────────────────────────────────────────────────────────────

class ColorLog(tk.Frame):
    """A scrollable, color-coded log using native tk.Text tags."""

    LEVELS = {
        "SYS":  ("#6E6E73", "[ SYS ]"),
        "INFO": ("#0A84FF", "[INFO ]"),
        "OK":   ("#32D74B", "[ OK  ]"),
        "WARN": ("#FF9F0A", "[WARN ]"),
        "HIT":  ("#FF3B30", "[HIT! ]"),
        "ERR":  ("#FF3B30", "[ ERR ]"),
        "FIX":  ("#32D74B", "[ FIX ]"),
        "NUM":  ("#FF9F0A", "  ➤   "),
        "CMD":  ("#32D74B", "       "),
        "SEP":  ("#2C2C2E", "       "),
        "STEP": ("#F5F5F7", "       "),
    }

    def __init__(self, master, **kwargs):
        bg = kwargs.pop("bg", PANEL)
        super().__init__(master, bg=bg, **kwargs)

        sb = tk.Scrollbar(self, orient="vertical", bg=PANEL,
                          troughcolor=BG, activebackground=CARD2,
                          relief="flat", bd=0, width=10)
        self._t = tk.Text(
            self, bg=PANEL, fg=TEXT,
            insertbackground=TEXT,
            selectbackground=CARD2, selectforeground=TEXT,
            relief="flat", bd=0, padx=12, pady=8,
            font=(MONO, 14), wrap="word",
            state="disabled", highlightthickness=0,
            yscrollcommand=sb.set,
        )
        sb.config(command=self._t.yview)
        sb.pack(side="right", fill="y", padx=(0, 2), pady=2)
        self._t.pack(side="left", fill="both", expand=True)

        # Configure color tags
        self._t.tag_configure("TS",    foreground="#3C3C3E")
        self._t.tag_configure("PATH",  foreground="#4D9DE0")
        self._t.tag_configure("HITBG", background="#1A0505")
        for lvl, (col, _) in self.LEVELS.items():
            self._t.tag_configure(lvl, foreground=col)

    def log(self, level: str, msg: str, path: str = ""):
        """Append a colored log line. Must be called from the main thread."""
        self._t.configure(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        _, prefix = self.LEVELS.get(level, (MUTED, "       "))
        line = f"{ts} {prefix} {msg}\n"
        tags = (level, "HITBG") if level == "HIT" else (level,)
        self._t.insert("end", line, tags)
        if path:
            self._t.insert("end", f"           → {path}\n", "PATH")
        self._t.configure(state="disabled")
        self._t.see("end")

    def clear(self):
        self._t.configure(state="normal")
        self._t.delete("1.0", "end")
        self._t.configure(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────
#  Scan Engine
# ─────────────────────────────────────────────────────────────────────────────

class ScanEngine:
    """
    Pure detection logic. log_cb must be thread-safe (use after() wrappers).
    All methods return (findings_list, files_checked_count).
    """

    def __init__(self, log_cb):
        self._log = log_cb
        self.findings: list = []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _finding(self, severity, kind, path, detail):
        entry = {"severity": severity, "kind": kind,
                 "path": str(path), "detail": detail,
                 "ts": datetime.datetime.now().isoformat(timespec="seconds")}
        self.findings.append(entry)
        return entry

    @staticmethod
    def _parse_json(text: str) -> dict:
        try:
            return json.loads(text)
        except Exception:
            return {}

    @staticmethod
    def _bare_version(spec: str) -> str:
        """Strip semver range operators: ^1.14.1 → 1.14.1"""
        return spec.strip().lstrip("^~>=< ")

    # ── Package.json inspection ───────────────────────────────────────────────

    def _check_pkg_dict(self, pkg: dict, source: str):
        """Scan a parsed package.json for IOCs."""
        name    = pkg.get("name", "")
        version = pkg.get("version", "")
        deps    = {**pkg.get("dependencies", {}),
                   **pkg.get("devDependencies", {}),
                   **pkg.get("peerDependencies", {})}

        # Is THIS the axios package and is it compromised?
        if name == "axios" and version in AFFECTED_AXIOS:
            f = self._finding("CRITICAL", "AXIOS_INSTALLED", source,
                f"axios@{version} — COMPROMISED version installed")
            self._log("HIT", f["detail"], path=source)

        # Does this package depend on a compromised axios version?
        if "axios" in deps:
            raw  = deps["axios"]
            bare = self._bare_version(raw)
            if bare in AFFECTED_AXIOS:
                f = self._finding("CRITICAL", "AXIOS_DEP", source,
                    f'"axios": "{raw}" resolves to COMPROMISED version')
                self._log("HIT", f["detail"], path=source)

        # Does this package list plain-crypto-js as any kind of dependency?
        if MALICIOUS_PKG in deps:
            f = self._finding("CRITICAL", "MALICIOUS_DEP", source,
                f"{MALICIOUS_PKG} listed as dependency — RAT dropper package")
            self._log("HIT", f["detail"], path=source)

    # ── package-lock.json inspection ─────────────────────────────────────────

    def _check_lockfile(self, fpath: str):
        """
        Parse package-lock.json for resolved axios / plain-crypto-js entries.
        Handles npm lockfile v1 (dependencies{}) and v2/v3 (packages{}).
        """
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                lock = self._parse_json(f.read())
            if not lock:
                return

            # npm v2/v3 lockfile: "packages": {"node_modules/axios": {...}}
            for pkg_key, info in lock.get("packages", {}).items():
                if not isinstance(info, dict):
                    continue
                # Strip the "node_modules/" prefix to get the bare name
                bare_name = pkg_key.split("node_modules/")[-1].strip("/")
                ver = info.get("version", "")
                if bare_name == "axios" and ver in AFFECTED_AXIOS:
                    f2 = self._finding("CRITICAL", "LOCKFILE_AXIOS", fpath,
                        f"package-lock.json resolves axios@{ver} — COMPROMISED")
                    self._log("HIT", f2["detail"], path=fpath)
                if bare_name == MALICIOUS_PKG:
                    f2 = self._finding("CRITICAL", "LOCKFILE_RAT", fpath,
                        f"package-lock.json references {MALICIOUS_PKG} — RAT dropper")
                    self._log("HIT", f2["detail"], path=fpath)

            # npm v1 lockfile: "dependencies": {"axios": {"version": "..."}}
            v1_deps = lock.get("dependencies", {})
            if v1_deps:
                self._walk_lock_v1(v1_deps, fpath)

        except Exception:
            pass  # unreadable lockfiles are silently skipped

    def _walk_lock_v1(self, deps: dict, fpath: str):
        """Recursively check v1 lockfile dependency tree."""
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version", "")
            if name == "axios" and ver in AFFECTED_AXIOS:
                f = self._finding("CRITICAL", "LOCKFILE_AXIOS", fpath,
                    f"package-lock.json (v1) resolves axios@{ver} — COMPROMISED")
                self._log("HIT", f["detail"], path=fpath)
            if name == MALICIOUS_PKG:
                f = self._finding("CRITICAL", "LOCKFILE_RAT", fpath,
                    f"package-lock.json (v1) references {MALICIOUS_PKG}")
                self._log("HIT", f["detail"], path=fpath)
            nested = info.get("dependencies", {})
            if nested:
                self._walk_lock_v1(nested, fpath)

    # ── Local System Scan ─────────────────────────────────────────────────────

    def scan_local(self, root_dirs: list, stop_event) -> tuple:
        """
        Walk the filesystem for IOCs.
        Returns (findings, files_checked).

        node_modules traversal strategy (depth-based):
          depth 0  →  project dir: check package.json + package-lock.json
          depth 1  →  inside node_modules: check only plain-crypto-js
                       and axios/package.json; do NOT recurse further
          depth 2+ →  skip entirely (transitive deps, no value)

        This avoids the O(n*n) slow walk through thousands of
        transitive npm packages.
        """
        self.findings.clear()
        checked = 0

        self._log("SYS", f"Platform: {SYSTEM} {platform.release()}")
        self._log("SYS", f"Scanning {len(root_dirs)} root path(s)…")

        for root_dir in root_dirs:
            root_dir = root_dir.strip()
            if not os.path.isdir(root_dir):
                self._log("WARN", f"Not found, skipping: {root_dir}")
                continue

            self._log("INFO", f"Walking: {root_dir}")
            root_path = Path(root_dir).resolve()

            for dirpath, dirnames, filenames in os.walk(root_dir, topdown=True):
                if stop_event.is_set():
                    self._log("WARN", "Scan stopped by user.")
                    return self.findings, checked

                # Compute how many node_modules levels deep we are
                try:
                    rel_parts = Path(dirpath).resolve().relative_to(root_path).parts
                except ValueError:
                    rel_parts = ()
                nm_depth = sum(1 for p in rel_parts if p == "node_modules")

                # ── Depth 0: normal project directory ─────────────────────
                if nm_depth == 0:
                    dirnames[:] = [
                        d for d in dirnames
                        if d not in SKIP_DIRS and d not in SKIP_OS_TOP
                    ]

                    if "package.json" in filenames:
                        fpath = os.path.join(dirpath, "package.json")
                        try:
                            with open(fpath, encoding="utf-8",
                                      errors="ignore") as fh:
                                pkg = self._parse_json(fh.read())
                            if pkg:
                                self._check_pkg_dict(pkg, fpath)
                                checked += 1
                        except Exception:
                            pass

                    if "package-lock.json" in filenames:
                        self._check_lockfile(
                            os.path.join(dirpath, "package-lock.json"))

                # ── Depth 1: directly inside node_modules ─────────────────
                elif nm_depth == 1:
                    # Check for plain-crypto-js directory (RAT executed if present)
                    if MALICIOUS_PKG in dirnames:
                        rat_dir = os.path.join(dirpath, MALICIOUS_PKG)
                        f = self._finding("CRITICAL", "RAT_DIR", rat_dir,
                            "plain-crypto-js in node_modules — "
                            "RAT dropper likely has already executed")
                        self._log("HIT", f["detail"], path=rat_dir)

                    # Check installed axios version
                    if "axios" in dirnames:
                        axios_pkg = os.path.join(dirpath, "axios", "package.json")
                        if os.path.isfile(axios_pkg):
                            try:
                                with open(axios_pkg, encoding="utf-8",
                                          errors="ignore") as fh:
                                    pkg = self._parse_json(fh.read())
                                ver = pkg.get("version", "")
                                if ver in AFFECTED_AXIOS:
                                    f = self._finding("CRITICAL",
                                        "AXIOS_INSTALLED", axios_pkg,
                                        f"INSTALLED: axios@{ver} in node_modules "
                                        f"— COMPROMISED version")
                                    self._log("HIT", f["detail"], path=axios_pkg)
                                checked += 1
                            except Exception:
                                pass

                    # Do not recurse further into node_modules
                    dirnames[:] = []

                # ── Depth 2+: nested node_modules — skip entirely ─────────
                else:
                    dirnames[:] = []

        self._log("INFO", f"Checked {checked} package file(s).")

        # ── Platform RAT artifact check ───────────────────────────────────
        self._log("INFO", "Checking for platform-specific RAT artifacts…")
        for art in RAT_ARTIFACTS.get(SYSTEM, []):
            if os.path.exists(art):
                f = self._finding("CRITICAL", "RAT_ARTIFACT", art,
                    "RAT artifact file present — system likely compromised")
                self._log("HIT", f["detail"], path=art)
            else:
                self._log("OK", f"Not present: {art}")

        # ── Hosts file C2 check ───────────────────────────────────────────
        self._log("INFO", f"Checking hosts file for {C2_HOST}…")
        try:
            lines = Path(HOSTS).read_text(errors="ignore").splitlines()
            c2_found = any(
                C2_HOST in ln and not ln.strip().startswith("#")
                for ln in lines
            )
            if c2_found:
                f = self._finding("WARNING", "C2_HOSTS", HOSTS,
                    f"{C2_HOST} found in hosts file")
                self._log("WARN", f["detail"], path=HOSTS)
            else:
                self._log("OK", f"No {C2_HOST} entry in hosts file")
        except PermissionError:
            self._log("WARN",
                "Cannot read hosts file — re-run as Administrator/sudo for full check")
        except Exception as e:
            self._log("WARN", f"Hosts file check error: {e}")

        crits = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        self._log("SYS",
            f"Scan complete — {crits} critical, "
            f"{len(self.findings)} total finding(s).")
        return self.findings, checked

    # ── Archive Scan ──────────────────────────────────────────────────────────

    def scan_archive(self, zip_path: str, stop_event) -> tuple:
        """
        Inspect a .zip archive for IOCs without extracting to disk.
        Lockfiles are written to a temp file, checked, then deleted.
        Returns (findings, pkg_json_count).
        """
        self.findings.clear()
        pkg_count = 0

        if not os.path.isfile(zip_path):
            self._log("ERR", f"File not found: {zip_path}")
            return self.findings, 0

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                entries = zf.namelist()
                self._log("SYS", f"Archive: {os.path.basename(zip_path)}")
                self._log("INFO", f"{len(entries):,} total entries")

                # Separate project-level files from node_modules internals
                pkg_jsons = [
                    e for e in entries
                    if e.endswith("package.json")
                    and "node_modules/" not in e
                    and "node_modules\\" not in e
                ]
                lock_jsons = [
                    e for e in entries
                    if e.endswith("package-lock.json")
                    and "node_modules/" not in e
                    and "node_modules\\" not in e
                ]
                # Check for plain-crypto-js presence inside the zip
                rat_entries = [
                    e for e in entries
                    if f"node_modules/{MALICIOUS_PKG}/" in e
                    or f"node_modules\\{MALICIOUS_PKG}\\" in e
                ]
                # Check for installed axios inside the zip
                axios_nm = [
                    e for e in entries
                    if e.endswith("node_modules/axios/package.json")
                    or e.endswith("node_modules\\axios\\package.json")
                ]

                self._log("INFO",
                    f"{len(pkg_jsons)} package.json / "
                    f"{len(lock_jsons)} lockfile(s) to inspect")

                # ── Project package.json files ─────────────────────────────
                for entry in pkg_jsons:
                    if stop_event.is_set():
                        self._log("WARN", "Scan stopped.")
                        return self.findings, pkg_count
                    try:
                        with zf.open(entry) as fh:
                            pkg = self._parse_json(
                                fh.read().decode("utf-8", errors="ignore"))
                        if pkg:
                            self._check_pkg_dict(pkg, f"[ZIP] {entry}")
                            pkg_count += 1
                    except Exception:
                        pass

                # ── Lockfiles (write to temp, check, delete) ───────────────
                for entry in lock_jsons:
                    if stop_event.is_set():
                        break
                    try:
                        with zf.open(entry) as fh:
                            raw = fh.read()
                        fd, tmp_path = tempfile.mkstemp(suffix=".json")
                        try:
                            with os.fdopen(fd, "wb") as tmp:
                                tmp.write(raw)
                            before = len(self.findings)
                            self._check_lockfile(tmp_path)
                            # Re-label findings: temp path → zip entry path
                            for f in self.findings[before:]:
                                if f["path"] == tmp_path:
                                    f["path"] = f"[ZIP] {entry}"
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except Exception:
                                pass
                    except Exception:
                        pass

                # ── RAT dropper directory in zip ───────────────────────────
                if rat_entries:
                    f = self._finding("CRITICAL", "RAT_DIR_ZIP",
                        f"[ZIP] {rat_entries[0]}",
                        f"plain-crypto-js present in archive "
                        f"({len(rat_entries)} entries) — RAT dropper present")
                    self._log("HIT", f["detail"], path=f"[ZIP] {rat_entries[0]}")

                # ── Installed axios version in zip's node_modules ──────────
                for entry in axios_nm:
                    try:
                        with zf.open(entry) as fh:
                            pkg = self._parse_json(
                                fh.read().decode("utf-8", errors="ignore"))
                        ver = pkg.get("version", "")
                        if ver in AFFECTED_AXIOS:
                            f = self._finding("CRITICAL", "AXIOS_INSTALLED_ZIP",
                                f"[ZIP] {entry}",
                                f"INSTALLED axios@{ver} in archive — COMPROMISED")
                            self._log("HIT", f["detail"], path=f"[ZIP] {entry}")
                    except Exception:
                        pass

        except zipfile.BadZipFile:
            self._log("ERR", "File is not a valid zip archive.")
        except Exception as e:
            self._log("ERR", f"Archive error: {e}")

        crits = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        self._log("SYS",
            f"Archive scan complete — {crits} critical, "
            f"{len(self.findings)} total finding(s).")
        return self.findings, pkg_count


# ─────────────────────────────────────────────────────────────────────────────
#  Remediation Engine
# ─────────────────────────────────────────────────────────────────────────────

class RemediationEngine:

    def __init__(self, findings: list, log_cb):
        self.findings = findings
        self._log = log_cb

    def auto_remediate(self, stop_event) -> tuple:
        removed, failed = 0, 0

        for f in self.findings:
            if stop_event.is_set():
                break
            kind, path = f["kind"], f["path"]

            if path.startswith("[ZIP]"):
                self._log("WARN",
                    f"Archive finding — manual fix required: {path}")
                continue

            # ── Remove plain-crypto-js directory ──────────────────────────
            if kind in ("RAT_DIR", "MALICIOUS_DEP") and os.path.isdir(path):
                try:
                    shutil.rmtree(path)
                    self._log("FIX", f"Removed directory: {path}")
                    removed += 1
                except PermissionError:
                    self._log("ERR",
                        f"Permission denied: {path} — re-run as admin/sudo")
                    failed += 1
                except Exception as e:
                    self._log("ERR", f"Could not remove {path}: {e}")
                    failed += 1

            # ── Delete RAT artifact file ───────────────────────────────────
            elif kind == "RAT_ARTIFACT" and os.path.isfile(path):
                try:
                    os.remove(path)
                    self._log("FIX", f"Deleted: {path}")
                    removed += 1
                except PermissionError:
                    self._log("ERR",
                        f"Permission denied: {path} — re-run as admin/sudo")
                    failed += 1
                except Exception as e:
                    self._log("ERR", f"Could not delete {path}: {e}")
                    failed += 1

            # ── npm downgrade axios ────────────────────────────────────────
            elif kind in ("AXIOS_INSTALLED", "AXIOS_DEP",
                          "LOCKFILE_AXIOS", "AXIOS_VERSION"):
                proj = _find_project_root(path)
                if proj:
                    # Pick safe version based on detected branch
                    safe = SAFE_0X if "0.30" in f["detail"] else SAFE_1X
                    self._log("INFO",
                        f"Running npm install axios@{safe} in: {proj}")
                    ok = _run_cmd(
                        ["npm", "install", f"axios@{safe}", "--save"],
                        cwd=proj)
                    if ok is not None:
                        self._log("FIX",
                            f"axios downgraded → @{safe}  ({proj})")
                        removed += 1
                    else:
                        self._log("WARN",
                            f"npm install failed in {proj} — downgrade manually")
                        failed += 1
                else:
                    self._log("WARN",
                        f"Could not locate project root for: {path}")
                    failed += 1

        self._log("SYS",
            f"Auto-remediation complete — "
            f"{removed} action(s) applied, {failed} failed/skipped.")
        return removed, failed

    # ── HTML Report ───────────────────────────────────────────────────────────

    def generate_report(self, mode: str = "local") -> str:
        now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        crits = [f for f in self.findings if f["severity"] == "CRITICAL"]
        warns = [f for f in self.findings if f["severity"] == "WARNING"]
        sc    = RED if crits else (ORANGE if warns else GREEN)
        st    = "⛔ COMPROMISED" if crits else ("⚠ WARNINGS" if warns else "✅ CLEAN")

        rows = "".join(
            f'<tr>'
            f'<td><span class="badge" style="background:'
            f'{"#FF3B30" if f["severity"]=="CRITICAL" else "#FF9F0A"}">'
            f'{f["severity"]}</span></td>'
            f'<td>{_esc(f["kind"])}</td>'
            f'<td class="mono">{_esc(f["path"])}</td>'
            f'<td>{_esc(f["detail"])}</td></tr>'
            for f in self.findings
        )

        step_data = [
            ("1","Downgrade axios in all affected projects",
             f"npm install axios@{SAFE_1X} --save     # 1.x\n"
             f"npm install axios@{SAFE_0X} --save     # 0.x"),
            ("2","Remove plain-crypto-js from node_modules",
             "rm -rf ./node_modules/plain-crypto-js\n"
             "Remove-Item .\\node_modules\\plain-crypto-js -Recurse -Force  # Windows PS"),
            ("3","Delete platform-specific RAT artifact files",
             "sudo rm -f /Library/Caches/com.apple.act.mond        # macOS\n"
             "Remove-Item \"$env:PROGRAMDATA\\wt.exe\" -Force          # Windows Admin\n"
             "rm -f /tmp/ld.py                                      # Linux"),
            ("4","ROTATE ALL CREDENTIALS — treat exposed machine as fully compromised",
             "npm tokens  ·  AWS IAM keys  ·  SSH keys\n"
             "GitHub/GitLab PATs  ·  CI/CD secrets  ·  .env API keys"),
            ("5","Block the C2 domain at network level",
             "# Add to /etc/hosts (or Windows hosts file):\n"
             "0.0.0.0 sfrclak.com\n"
             "# Also block in firewall / DNS resolver / EDR"),
            ("6","Pin axios and enforce lockfile integrity in CI/CD",
             '# package.json — exact pin (no caret):\n'
             '"axios": "1.14.0"\n'
             "# CI/CD — always use npm ci:\n"
             "npm ci\n"
             "# Block postinstall scripts in CI:\n"
             "npm install --ignore-scripts"),
            ("7","Audit CI/CD logs for the compromise window",
             "Window: 2026-03-30 23:59 UTC → 2026-03-31 04:26 UTC\n"
             "Any pipeline running npm/yarn/pnpm install in this window = exposed"),
            ("8","Run npm audit and blocklist plain-crypto-js",
             "npm audit && npm audit fix\n"
             "# Add to .npmrc:\n"
             "//registry.npmjs.org/plain-crypto-js:disallow=true"),
        ]

        steps_html = "".join(
            f'<div class="step"><div class="sn">{n}</div>'
            f'<div class="sb"><strong>{t}</strong>'
            f'<code>{_esc(c)}</code></div></div>'
            for n, t, c in step_data
        )

        findings_html = (
            f'<table><thead><tr><th>Severity</th><th>Type</th>'
            f'<th>Path</th><th>Detail</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            if self.findings else
            '<p style="color:#32D74B;font-size:1.05rem">'
            '✅ No compromised packages detected.</p>'
        )

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>AXIOSCAN {APP_VERSION} Report — {now}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#080810;color:#F5F5F7;font-family:'Inter',sans-serif;
  padding:40px;line-height:1.6;max-width:1100px;margin:0 auto}}
.hdr{{border-left:4px solid {RED};padding-left:20px;margin-bottom:30px}}
.hdr h1{{font-size:1.9rem;font-weight:700;letter-spacing:2px;color:{RED}}}
.hdr p{{color:{MUTED};margin-top:4px;font-size:.85rem}}
.status{{display:inline-block;padding:10px 22px;border-radius:6px;
  font-size:1.15rem;font-weight:700;margin:14px 0;
  color:{sc};border:1px solid {sc};background:rgba(255,59,48,.1)}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:22px 0}}
.card{{background:#141416;border:1px solid #2C2C2E;border-radius:8px;
  padding:16px;text-align:center}}
.card .n{{font-size:2rem;font-weight:700}}
.card .l{{color:{MUTED};font-size:.72rem;text-transform:uppercase;
  letter-spacing:1px;margin-top:2px}}
h2{{font-size:.85rem;font-weight:600;letter-spacing:1px;text-transform:uppercase;
  color:{MUTED};border-bottom:1px solid #2C2C2E;padding-bottom:8px;margin:26px 0 12px}}
table{{width:100%;border-collapse:collapse;background:#141416;
  border-radius:8px;overflow:hidden;margin-bottom:8px}}
th{{background:#1C1C1E;color:{MUTED};font-size:.7rem;text-transform:uppercase;
  letter-spacing:1px;padding:10px 12px;text-align:left}}
td{{padding:10px 12px;border-bottom:1px solid #1C1C1E;
  font-size:.82rem;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.badge{{display:inline-block;padding:2px 8px;border-radius:3px;
  font-size:.7rem;font-weight:700;color:#fff}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:.76rem;
  color:#4D9DE0;word-break:break-all}}
.ioc{{background:#180A0A;border:1px solid {RED};border-radius:8px;
  padding:16px;margin:14px 0}}
.ioc h3{{color:{RED};margin-bottom:10px;font-size:.82rem;
  text-transform:uppercase;letter-spacing:1px}}
.ioc li{{margin:4px 0;font-size:.88rem}}
code{{font-family:'JetBrains Mono',monospace;color:#FF9F0A;font-size:.82rem}}
.step{{background:#141416;border:1px solid #2C2C2E;border-radius:6px;
  padding:14px 16px;margin:8px 0;display:flex;gap:12px;align-items:flex-start}}
.sn{{background:{RED};color:#fff;width:26px;height:26px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.8rem;flex-shrink:0;margin-top:2px}}
.sb strong{{display:block;margin-bottom:6px;font-size:.92rem}}
.sb code{{background:#0A0A0C;border:1px solid #2C2C2E;border-radius:4px;
  padding:8px 10px;display:block;margin-top:6px;color:#32D74B;
  font-size:.78rem;white-space:pre}}
.footer{{margin-top:44px;text-align:center;color:#3C3C3E;font-size:.74rem}}
</style></head><body>
<div class="hdr">
  <h1>⬡ AXIOSCAN {APP_VERSION}</h1>
  <p>{COMPANY}</p>
  <p>Generated: {now} &nbsp;|&nbsp; Mode: {mode.upper()} &nbsp;|&nbsp; Platform: {SYSTEM}</p>
</div>
<div class="status">{st}</div>
<div class="grid">
  <div class="card">
    <div class="n" style="color:{RED}">{len(crits)}</div>
    <div class="l">Critical</div></div>
  <div class="card">
    <div class="n" style="color:{ORANGE}">{len(warns)}</div>
    <div class="l">Warnings</div></div>
  <div class="card">
    <div class="n">{len(self.findings)}</div>
    <div class="l">Total Findings</div></div>
</div>
<div class="ioc">
  <h3>⚠ Indicators of Compromise</h3>
  <ul>
    <li>Compromised packages: <code>axios@1.14.1</code> &nbsp; <code>axios@0.30.4</code></li>
    <li>RAT dropper: <code>plain-crypto-js@4.2.1</code></li>
    <li>C2 server: <code>sfrclak.com:8000</code></li>
    <li>macOS artifact: <code>/Library/Caches/com.apple.act.mond</code></li>
    <li>Windows artifact: <code>%PROGRAMDATA%\\wt.exe</code></li>
    <li>Linux artifact: <code>/tmp/ld.py</code></li>
    <li>Attacker emails: <code>ifstap@proton.me</code> &nbsp; <code>nrwise@proton.me</code></li>
    <li>Compromise window: <code>2026-03-30 23:59 UTC → 2026-03-31 04:26 UTC</code></li>
  </ul>
</div>
<h2>Findings</h2>
{findings_html}
<h2>Remediation Playbook</h2>
{steps_html}
<div class="footer">
  <p>AXIOSCAN {APP_VERSION} &nbsp;|&nbsp; {COMPANY} &nbsp;|&nbsp; {now}</p>
  <p style="margin-top:4px">MIT License — Open Source</p>
</div>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def _run_cmd(cmd: list, cwd: str = None):
    """Run a command; return stdout string on success, None on failure."""
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           cwd=cwd, timeout=60)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None

def _find_project_root(start: str) -> str | None:
    """Walk up the directory tree to find the nearest package.json."""
    cur = Path(start)
    if cur.is_file():
        cur = cur.parent
    for _ in range(10):
        if (cur / "package.json").is_file():
            return str(cur)
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return None

def _default_roots() -> list:
    home = str(Path.home())
    extras = {
        "Windows": [r"C:\Users", r"C:\projects", r"C:\dev",
                    r"C:\repos", r"C:\work", r"C:\inetpub"],
        "Darwin":  ["/Users", "/usr/local/lib", "/opt/homebrew/lib",
                    "/var/www", "/opt"],
        "Linux":   ["/home", "/var/www", "/opt", "/srv",
                    "/usr/local/lib"],
    }.get(SYSTEM, [])
    roots = [home]
    for e in extras:
        if os.path.isdir(e) and e not in roots:
            roots.append(e)
    return roots

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _save_report(html: str, prefix: str = "axioscan_report") -> str:
    desktop = Path.home() / "Desktop"
    base = desktop if desktop.is_dir() else Path.home()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = base / f"{prefix}_{ts}.html"
    out.write_text(html, encoding="utf-8")
    return str(out)


# ─────────────────────────────────────────────────────────────────────────────
#  GUI — Main Application
# ─────────────────────────────────────────────────────────────────────────────

class AxioScanApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title(
            f"{APP_TITLE} {APP_VERSION}  —  "
            "Axios Supply Chain Detector & Remediator")
        self.geometry("1200x920")
        self.minsize(980, 740)
        self.configure(fg_color=BG)

        self._stop_evt      = threading.Event()
        self._rem_stop      = threading.Event()
        self._running       = False
        self._findings:      list = []
        self._arch_findings: list = []

        self._build_ui()

    # ─── Top-level UI ─────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=84)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        hl = ctk.CTkFrame(hdr, fg_color="transparent")
        hl.pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(hl, text="⬡ AXIOSCAN",
                     font=(MONO, 30, "bold"), text_color=RED).pack(side="left")
        ctk.CTkLabel(hl, text=f"  {APP_VERSION}",
                     font=(MONO, 16), text_color=MUTED).pack(side="left", pady=5)
        hr = ctk.CTkFrame(hdr, fg_color="transparent")
        hr.pack(side="right", padx=20)
        ctk.CTkLabel(hr,
            text="Axios Supply Chain Compromise  |  March 31, 2026\n"
                 "axios@1.14.1  ·  axios@0.30.4  ·  plain-crypto-js@4.2.1",
            font=(MONO, 13), text_color=MUTED, justify="right").pack()

        # Alert bar
        ban = ctk.CTkFrame(self, fg_color="#180A0A", corner_radius=0, height=38)
        ban.pack(fill="x")
        ban.pack_propagate(False)
        ctk.CTkLabel(ban,
            text=(f"⚠  C2: {C2_HOST}:8000  |  "
                  f"Safe: axios@{SAFE_1X} (1.x)  ·  axios@{SAFE_0X} (0.x)  |  "
                  "Rotate credentials if exposed"),
            font=(MONO, 13, "bold"), text_color=ORANGE).pack(expand=True)

        # Tab view
        self._tabs = ctk.CTkTabview(
            self, fg_color=PANEL, corner_radius=0,
            segmented_button_fg_color=CARD2,
            segmented_button_selected_color=RED,
            segmented_button_selected_hover_color="#CC2020",
            segmented_button_unselected_color=CARD2,
            segmented_button_unselected_hover_color=CARD,
            text_color=TEXT,
        )
        self._tabs.pack(fill="both", expand=True)

        T_LOCAL  = "  🖥  LOCAL SCAN  "
        T_ARCH   = "  📦  ARCHIVE SCAN  "
        T_REM    = "  🛠  REMEDIATION  "
        T_INTEL  = "  ℹ  THREAT INTEL  "
        for t in (T_LOCAL, T_ARCH, T_REM, T_INTEL):
            self._tabs.add(t)

        self._build_local_tab(self._tabs.tab(T_LOCAL))
        self._build_archive_tab(self._tabs.tab(T_ARCH))
        self._build_rem_tab(self._tabs.tab(T_REM))
        self._build_intel_tab(self._tabs.tab(T_INTEL))

        # Status bar
        sb = ctk.CTkFrame(self, fg_color=CARD2, corner_radius=0, height=34)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._status = ctk.CTkLabel(sb,
            text="Ready — select a scan mode above",
            font=(MONO, 13), text_color=MUTED)
        self._status.pack(side="left", padx=14)
        ctk.CTkLabel(sb, text=COMPANY,
                     font=(MONO, 13), text_color=MUTED).pack(side="right", padx=14)

    # ─── LOCAL SCAN tab ───────────────────────────────────────────────────────

    def _build_local_tab(self, p):
        p.configure(fg_color=BG)

        ctrl = ctk.CTkFrame(p, fg_color=CARD, corner_radius=10)
        ctrl.pack(fill="x", padx=14, pady=(14, 6))

        ctk.CTkLabel(ctrl, text="🖥  LOCAL SYSTEM SCAN",
                     font=(MONO, 16, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(ctrl,
            text="Scans your filesystem for compromised axios versions, plain-crypto-js "
                 "RAT directories,\nplatform-specific RAT artifact files, "
                 "and package-lock.json resolved versions.",
            font=(MONO, 13), text_color=MUTED, justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 8))

        dr = ctk.CTkFrame(ctrl, fg_color="transparent")
        dr.pack(fill="x", padx=14, pady=(0, 8))
        self._dir_var = tk.StringVar(value=", ".join(_default_roots()))
        ctk.CTkEntry(dr, textvariable=self._dir_var,
                     font=(MONO, 13), fg_color=CARD2,
                     border_color=BORDER, text_color=TEXT, height=36
                     ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(dr, text="+ Dir", width=78, height=36,
                      fg_color=CARD2, hover_color=CARD,
                      border_color=BORDER, border_width=1,
                      font=(MONO, 13), text_color=TEXT,
                      command=self._add_dir).pack(side="left", padx=(6, 0))

        br = ctk.CTkFrame(ctrl, fg_color="transparent")
        br.pack(fill="x", padx=14, pady=(0, 12))

        self._local_btn = ctk.CTkButton(br, text="▶  START LOCAL SCAN",
            font=(MONO, 15, "bold"), fg_color=RED, hover_color="#CC2020",
            text_color="#fff", height=42, corner_radius=7,
            command=self._start_local)
        self._local_btn.pack(side="left")

        self._local_stop_btn = ctk.CTkButton(br, text="⏹", width=54, height=42,
            fg_color=CARD2, hover_color=CARD, border_color=BORDER,
            border_width=1, text_color=MUTED, corner_radius=7,
            state="disabled", command=self._stop)
        self._local_stop_btn.pack(side="left", padx=6)

        self._local_export_btn = ctk.CTkButton(br, text="📄 Export Report",
            font=(MONO, 13), width=140, height=42, fg_color=CARD2,
            hover_color=CARD, border_color=BORDER, border_width=1,
            text_color=MUTED, corner_radius=7, state="disabled",
            command=lambda: self._export("local"))
        self._local_export_btn.pack(side="left")

        ctk.CTkButton(br, text="🗑 Clear", width=84, height=42,
            fg_color=CARD2, hover_color=CARD, border_color=BORDER,
            border_width=1, font=(MONO, 13), text_color=MUTED,
            corner_radius=7, command=lambda: self._local_log.clear()
            ).pack(side="left", padx=6)

        # Summary cards
        cf = ctk.CTkFrame(p, fg_color="transparent")
        cf.pack(fill="x", padx=14, pady=(0, 6))
        self._lc = {}
        for lbl, val, col in [("CRITICAL","0",RED),
                               ("WARNINGS","0",ORANGE),
                               ("FILES CHECKED","0",BLUE)]:
            c = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=8,
                             width=190, height=76)
            c.pack(side="left", padx=(0, 8))
            c.pack_propagate(False)
            n = ctk.CTkLabel(c, text=val,
                             font=(MONO, 23, "bold"), text_color=col)
            n.pack(pady=(8, 0))
            ctk.CTkLabel(c, text=lbl, font=(MONO, 11),
                         text_color=MUTED).pack()
            self._lc[lbl] = n

        # Progress bar — indeterminate mode for active scan animation
        self._local_prog = ctk.CTkProgressBar(
            p, mode="indeterminate",
            fg_color=CARD, progress_color=RED, height=4)
        self._local_prog.pack(fill="x", padx=14, pady=(0, 4))
        self._local_prog.set(0)

        self._local_log = ColorLog(p, bg=PANEL)
        self._local_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._llog("SYS", f"AXIOSCAN {APP_VERSION} ready.")
        self._llog("SYS", f"Platform: {SYSTEM} {platform.release()}")
        self._llog("INFO", "Press ▶ START LOCAL SCAN to begin.")

    # ─── ARCHIVE SCAN tab ─────────────────────────────────────────────────────

    def _build_archive_tab(self, p):
        p.configure(fg_color=BG)

        ctrl = ctk.CTkFrame(p, fg_color=CARD, corner_radius=10)
        ctrl.pack(fill="x", padx=14, pady=(14, 6))

        ctk.CTkLabel(ctrl, text="📦  ARCHIVE SCAN",
                     font=(MONO, 16, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(ctrl,
            text="Scans a .zip archive (downloaded SaaS bundle, project backup) "
                 "for compromised packages\n"
                 "and plain-crypto-js RAT dropper files — "
                 "without extracting the archive to disk.",
            font=(MONO, 13), text_color=MUTED, justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 8))

        zr = ctk.CTkFrame(ctrl, fg_color="transparent")
        zr.pack(fill="x", padx=14, pady=(0, 8))
        self._zip_var = tk.StringVar(value="No archive selected…")
        ctk.CTkEntry(zr, textvariable=self._zip_var,
                     font=(MONO, 13), fg_color=CARD2,
                     border_color=BORDER, text_color=MUTED,
                     height=36, state="readonly"
                     ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(zr, text="Browse…", width=98, height=36,
                      fg_color=CARD2, hover_color=CARD,
                      border_color=BORDER, border_width=1,
                      font=(MONO, 13), text_color=TEXT,
                      command=self._browse_zip
                      ).pack(side="left", padx=(6, 0))

        br = ctk.CTkFrame(ctrl, fg_color="transparent")
        br.pack(fill="x", padx=14, pady=(0, 12))

        self._arch_btn = ctk.CTkButton(br, text="▶  SCAN ARCHIVE",
            font=(MONO, 15, "bold"), fg_color=RED, hover_color="#CC2020",
            text_color="#fff", height=42, corner_radius=7,
            command=self._start_archive)
        self._arch_btn.pack(side="left")

        self._arch_stop_btn = ctk.CTkButton(br, text="⏹", width=54, height=42,
            fg_color=CARD2, hover_color=CARD, border_color=BORDER,
            border_width=1, text_color=MUTED, corner_radius=7,
            state="disabled", command=self._stop)
        self._arch_stop_btn.pack(side="left", padx=6)

        self._arch_export_btn = ctk.CTkButton(br, text="📄 Export Report",
            font=(MONO, 13), width=130, height=42, fg_color=CARD2,
            hover_color=CARD, border_color=BORDER, border_width=1,
            text_color=MUTED, corner_radius=7, state="disabled",
            command=lambda: self._export("archive"))
        self._arch_export_btn.pack(side="left")

        ctk.CTkButton(br, text="🗑 Clear", width=76, height=38,
            fg_color=CARD2, hover_color=CARD, border_color=BORDER,
            border_width=1, font=(MONO, 13), text_color=MUTED,
            corner_radius=7, command=lambda: self._arch_log.clear()
            ).pack(side="left", padx=6)

        cf = ctk.CTkFrame(p, fg_color="transparent")
        cf.pack(fill="x", padx=14, pady=(0, 6))
        self._ac = {}
        for lbl, val, col in [("CRITICAL","0",RED),
                               ("WARNINGS","0",ORANGE),
                               ("PKG FILES","0",BLUE)]:
            c = ctk.CTkFrame(cf, fg_color=CARD, corner_radius=8,
                             width=190, height=76)
            c.pack(side="left", padx=(0, 8))
            c.pack_propagate(False)
            n = ctk.CTkLabel(c, text=val,
                             font=(MONO, 23, "bold"), text_color=col)
            n.pack(pady=(8, 0))
            ctk.CTkLabel(c, text=lbl, font=(MONO, 11),
                         text_color=MUTED).pack()
            self._ac[lbl] = n

        self._arch_prog = ctk.CTkProgressBar(
            p, mode="indeterminate",
            fg_color=CARD, progress_color=RED, height=4)
        self._arch_prog.pack(fill="x", padx=14, pady=(0, 4))
        self._arch_prog.set(0)

        self._arch_log = ColorLog(p, bg=PANEL)
        self._arch_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._alog("SYS", f"AXIOSCAN {APP_VERSION} — Archive Scanner ready.")
        self._alog("INFO", "Browse to a .zip archive, then press ▶ SCAN ARCHIVE.")

    # ─── REMEDIATION tab ──────────────────────────────────────────────────────

    def _build_rem_tab(self, p):
        p.configure(fg_color=BG)

        ctrl = ctk.CTkFrame(p, fg_color=CARD, corner_radius=10)
        ctrl.pack(fill="x", padx=14, pady=(14, 6))

        ctk.CTkLabel(ctrl, text="🛠  REMEDIATION CENTER",
                     font=(MONO, 16, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(ctrl,
            text="Run auto-remediation after a scan, or follow the manual playbook below.\n"
                 "Auto-remediation removes plain-crypto-js dirs, "
                 "RAT artifact files, and downgrades axios via npm.",
            font=(MONO, 13), text_color=MUTED, justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 8))

        br = ctk.CTkFrame(ctrl, fg_color="transparent")
        br.pack(fill="x", padx=14, pady=(0, 12))

        self._rem_btn = ctk.CTkButton(br, text="⚡  AUTO-REMEDIATE",
            font=(MONO, 15, "bold"), fg_color=RED, hover_color="#CC2020",
            text_color="#fff", height=42, corner_radius=7,
            command=self._auto_rem)
        self._rem_btn.pack(side="left")

        ctk.CTkButton(br, text="📄 Export Playbook",
            font=(MONO, 13), width=140, height=42, fg_color=CARD2,
            hover_color=CARD, border_color=BORDER, border_width=1,
            text_color=MUTED, corner_radius=7,
            command=lambda: self._export("remediation")
            ).pack(side="left", padx=6)

        ctk.CTkButton(br, text="🗑 Clear", width=76, height=38,
            fg_color=CARD2, hover_color=CARD, border_color=BORDER,
            border_width=1, font=(MONO, 13), text_color=MUTED,
            corner_radius=7, command=lambda: self._rem_log.clear()
            ).pack(side="left")

        self._rem_log = ColorLog(p, bg=PANEL)
        self._rem_log.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._rlog("SYS", "Remediation Engine ready. Run a scan first.")
        self._rlog("SEP", "─" * 58)
        self._rlog("NUM", "MANUAL REMEDIATION PLAYBOOK")
        self._rlog("SEP", "─" * 58)
        playbook = [
            ("1", "Downgrade axios in all affected projects",
             [f"npm install axios@{SAFE_1X} --save   # 1.x projects",
              f"npm install axios@{SAFE_0X} --save   # 0.x projects"]),
            ("2", "Remove plain-crypto-js from node_modules",
             ["rm -rf ./node_modules/plain-crypto-js",
              "Remove-Item .\\node_modules\\plain-crypto-js -Recurse -Force  # Windows"]),
            ("3", "Delete platform-specific RAT artifact files",
             ["sudo rm -f /Library/Caches/com.apple.act.mond       # macOS",
              'Remove-Item "$env:PROGRAMDATA\\wt.exe" -Force         # Windows Admin',
              "rm -f /tmp/ld.py                                     # Linux"]),
            ("4", "ROTATE ALL CREDENTIALS on any exposed machine",
             ["npm tokens  ·  AWS IAM keys  ·  SSH keys",
              "GitHub/GitLab PATs  ·  CI/CD secrets  ·  .env API keys"]),
            ("5", "Block C2 at the network level",
             ["Add to /etc/hosts:   0.0.0.0 sfrclak.com",
              "Block sfrclak.com in firewall / DNS / EDR"]),
            ("6", "Pin axios and enforce lockfiles in CI/CD",
             ['In package.json (exact pin, no caret): "axios": "1.14.0"',
              "In CI/CD pipelines use: npm ci  (never npm install)"]),
            ("7", "Audit CI/CD logs for the compromise window",
             ["Window: 2026-03-30 23:59 UTC  →  2026-03-31 04:26 UTC",
              "Any npm/yarn/pnpm install in this window = credentials exposed"]),
            ("8", "Run npm audit and blocklist plain-crypto-js",
             ["npm audit && npm audit fix",
              "Add to .npmrc:  //registry.npmjs.org/plain-crypto-js:disallow=true"]),
        ]
        for num, title, cmds in playbook:
            self._rlog("SEP", "")
            self._rlog("NUM", f"[STEP {num}] {title}")
            for cmd in cmds:
                self._rlog("CMD", f"  {cmd}")
        self._rlog("SEP", "")
        self._rlog("SEP", "─" * 58)

    # ─── THREAT INTEL tab ─────────────────────────────────────────────────────

    def _build_intel_tab(self, p):
        p.configure(fg_color=BG)
        scroll = ctk.CTkScrollableFrame(p, fg_color=BG, corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=14, pady=14)

        def section(title):
            ctk.CTkLabel(scroll, text=title, font=(MONO, 14, "bold"),
                         text_color=RED, anchor="w").pack(fill="x", pady=(14, 4))
            ctk.CTkFrame(scroll, fg_color=BORDER, height=1).pack(fill="x", pady=(0, 6))

        def row(label, value, col=TEXT):
            f = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=6)
            f.pack(fill="x", pady=2)
            ctk.CTkLabel(f, text=f"  {label}", font=(MONO, 13),
                         text_color=MUTED, width=270, anchor="w"
                         ).pack(side="left", pady=7)
            ctk.CTkLabel(f, text=value, font=(MONO, 13, "bold"),
                         text_color=col, anchor="w"
                         ).pack(side="left", pady=7, padx=8, fill="x", expand=True)

        section("▸ INCIDENT OVERVIEW")
        row("Date / time",          "2026-03-30 23:59 UTC", RED)
        row("Containment",          "2026-03-31 04:26 UTC  (≈4.5 hr window)")
        row("Affected package",     "axios  (npm — 100M+ weekly downloads)")
        row("Compromised versions", "axios@1.14.1  |  axios@0.30.4", RED)
        row("Safe 1.x version",     f"axios@{SAFE_1X}", GREEN)
        row("Safe 0.x version",     f"axios@{SAFE_0X}", GREEN)
        row("Compromised account",  "jasonsaayman (lead axios npm maintainer)")
        row("Attacker emails",      "ifstap@proton.me  |  nrwise@proton.me", ORANGE)
        row("Attack vector",        "Stolen npm access token → manual CLI publish, bypassed CI/CD")

        section("▸ MALICIOUS DEPENDENCY")
        row("Package",              f"{MALICIOUS_PKG}", RED)
        row("Malicious version",    MALICIOUS_VER, RED)
        row("Staging version",      "4.2.0  (clean — published 18 hrs prior to establish legitimacy)")
        row("Disguise",             "Mimics crypto-js: same description, author, repo URL")
        row("Entry point",          "postinstall hook in setup.js")
        row("Detection speed",      "Socket flagged within 6 minutes of publish")
        row("C2 server",            f"{C2_HOST}:8000", RED)

        section("▸ RAT PAYLOAD")
        row("Type",                 "Cross-platform Remote Access Trojan dropper")
        row("Targets",              "macOS  |  Windows  |  Linux")
        row("macOS artifact",       "/Library/Caches/com.apple.act.mond  (mimics Apple process)", ORANGE)
        row("Windows artifact",     "%PROGRAMDATA%\\wt.exe  (disguised PowerShell)", ORANGE)
        row("Linux artifact",       "/tmp/ld.py  (Python script)", ORANGE)
        row("Anti-forensics",       "Self-deletes after exec; replaces package.json with clean copy")
        row("Capabilities",         "Arbitrary exec · credential theft · file enum · persistence")

        section("▸ THREAT ACTOR")
        row("Financial motive",     "None — no ransomware, no crypto miners detected")
        row("Target profile",       "Developer workstations · CI/CD pipelines · build servers")
        row("File targeting",       ".ssh/  |  .aws/  |  .env  |  process monitoring")
        row("Attribution",          "Unconfirmed APT — consistent with intelligence collection")
        row("Sophistication",       "HIGH — pre-staged, double-obfuscated, multi-platform, anti-forensic")

        section("▸ CASCADE PACKAGES")
        row("@shadanai/openclaw",       "Vendors plain-crypto-js payload directly in dist/")
        row("@qqbrowser/openclaw-qbot", "Ships tampered axios@1.14.1 in node_modules/")
        row("Detection sources",        "StepSecurity Harden-Runner · Socket Security · Snyk · OSSMalware")

        section("▸ REFERENCES")
        for ref in [
            "https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html",
            "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan",
            "https://socket.dev/blog/axios-npm-package-compromised",
            "https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/",
            "https://www.techzine.eu/news/security/140082/axios-npm-package-compromised-posing-a-new-supply-chain-threat/",
        ]:
            f = ctk.CTkFrame(scroll, fg_color=CARD, corner_radius=6)
            f.pack(fill="x", pady=2)
            ctk.CTkLabel(f, text=f"  {ref}", font=(MONO, 12),
                         text_color=BLUE, anchor="w"
                         ).pack(side="left", pady=6)

    # ─── Thread-safe log helpers ──────────────────────────────────────────────

    def _llog(self, lvl, msg, path=""):
        self.after(0, self._local_log.log, lvl, msg, path)

    def _alog(self, lvl, msg, path=""):
        self.after(0, self._arch_log.log, lvl, msg, path)

    def _rlog(self, lvl, msg, path=""):
        self.after(0, self._rem_log.log, lvl, msg, path)

    def _set_status(self, msg):
        self.after(0, self._status.configure, {"text": msg})

    # ─── Button handlers ──────────────────────────────────────────────────────

    def _add_dir(self):
        d = filedialog.askdirectory(title="Add directory to scan")
        if d:
            cur = self._dir_var.get().strip().rstrip(",")
            self._dir_var.set(f"{cur}, {d}" if cur else d)

    def _browse_zip(self):
        f = filedialog.askopenfilename(
            title="Select zip archive",
            filetypes=[("Zip Archives", "*.zip"), ("All Files", "*.*")])
        if f:
            self._zip_var.set(f)
            self._alog("INFO", f"Archive selected: {f}")

    def _stop(self):
        self._stop_evt.set()
        self._rem_stop.set()
        self._set_status("Stopping…")

    # ─── Local Scan ───────────────────────────────────────────────────────────

    def _start_local(self):
        if self._running:
            return
        dirs = [d.strip() for d in self._dir_var.get().split(",") if d.strip()]
        if not dirs:
            messagebox.showerror("No Directories",
                "Enter at least one directory to scan.")
            return

        self._stop_evt.clear()
        self._running = True
        self._local_btn.configure(state="disabled", text="⏳ Scanning…")
        self._local_stop_btn.configure(state="normal")
        self._local_export_btn.configure(state="disabled")
        for k in self._lc:
            self._lc[k].configure(text="…")
        self._local_prog.configure(mode="indeterminate")
        self._local_prog.start()

        self._llog("SEP", "─" * 56)
        self._llog("SYS", f"Starting local scan — {len(dirs)} root(s)")
        self._set_status("🔍 Local scan in progress…")

        def run():
            eng = ScanEngine(self._llog)
            findings, checked = eng.scan_local(dirs, self._stop_evt)
            self._findings = findings
            crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
            warns = sum(1 for f in findings if f["severity"] == "WARNING")
            self.after(0, self._local_done, crits, warns, checked)

        threading.Thread(target=run, daemon=True).start()

    def _local_done(self, crits, warns, checked):
        self._running = False
        self._local_prog.stop()
        self._local_prog.configure(mode="determinate")
        self._local_prog.set(0.0 if crits else 1.0)
        self._local_btn.configure(state="normal", text="▶  START LOCAL SCAN")
        self._local_stop_btn.configure(state="disabled")
        self._local_export_btn.configure(state="normal")

        self._lc["CRITICAL"].configure(
            text=str(crits), text_color=RED if crits else GREEN)
        self._lc["WARNINGS"].configure(
            text=str(warns), text_color=ORANGE if warns else MUTED)
        self._lc["FILES CHECKED"].configure(text=str(checked))

        if crits:
            self._llog("HIT",
                f"⛔  {crits} CRITICAL FINDING(S) — system may be compromised!")
            self._llog("HIT", "→ Switch to the REMEDIATION tab immediately")
            self._set_status(f"⛔ {crits} CRITICAL — go to Remediation tab now")
        else:
            self._llog("OK",
                "✅ No compromised axios packages detected — system appears clean")
            self._set_status("✅ Local scan complete — CLEAN")

    # ─── Archive Scan ─────────────────────────────────────────────────────────

    def _start_archive(self):
        zp = self._zip_var.get()
        if not zp or "No archive" in zp:
            messagebox.showerror("No Archive",
                "Please browse to a .zip file first.")
            return
        if not os.path.isfile(zp):
            messagebox.showerror("File Not Found", f"Cannot find:\n{zp}")
            return

        self._stop_evt.clear()
        self._running = True
        self._arch_btn.configure(state="disabled", text="⏳ Scanning…")
        self._arch_stop_btn.configure(state="normal")
        self._arch_export_btn.configure(state="disabled")
        for k in self._ac:
            self._ac[k].configure(text="…")
        self._arch_prog.configure(mode="indeterminate")
        self._arch_prog.start()

        self._alog("SEP", "─" * 56)
        self._alog("SYS", "Starting archive scan…")
        self._set_status("🔍 Archive scan in progress…")

        def run():
            eng = ScanEngine(self._alog)
            findings, pkg_count = eng.scan_archive(zp, self._stop_evt)
            self._arch_findings = findings
            crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
            warns = sum(1 for f in findings if f["severity"] == "WARNING")
            self.after(0, self._arch_done, crits, warns, pkg_count)

        threading.Thread(target=run, daemon=True).start()

    def _arch_done(self, crits, warns, pkg_count):
        self._running = False
        self._arch_prog.stop()
        self._arch_prog.configure(mode="determinate")
        self._arch_prog.set(0.0 if crits else 1.0)
        self._arch_btn.configure(state="normal", text="▶  SCAN ARCHIVE")
        self._arch_stop_btn.configure(state="disabled")
        self._arch_export_btn.configure(state="normal")

        self._ac["CRITICAL"].configure(
            text=str(crits), text_color=RED if crits else GREEN)
        self._ac["WARNINGS"].configure(
            text=str(warns), text_color=ORANGE if warns else MUTED)
        self._ac["PKG FILES"].configure(text=str(pkg_count))

        if crits:
            self._alog("HIT",
                f"⛔  {crits} CRITICAL FINDING(S) — DO NOT deploy this archive")
            self._alog("HIT", "→ Switch to the REMEDIATION tab")
            self._set_status(f"⛔ Archive: {crits} critical findings")
        else:
            self._alog("OK",
                "✅ Archive appears clean — no compromised packages found")
            self._set_status("✅ Archive scan complete — CLEAN")

    # ─── Auto Remediation ─────────────────────────────────────────────────────

    def _auto_rem(self):
        all_f = self._findings + self._arch_findings
        if not all_f:
            messagebox.showinfo("No Findings",
                "No findings loaded.\nRun a Local Scan or Archive Scan first.")
            return
        crits = sum(1 for f in all_f if f["severity"] == "CRITICAL")
        if not messagebox.askyesno("Confirm Auto-Remediation",
            f"{crits} critical finding(s) detected.\n\n"
            "Auto-remediation will:\n"
            "  • Remove plain-crypto-js directories\n"
            "  • Delete RAT artifact files\n"
            "  • Run npm install to downgrade axios\n\n"
            "This modifies your filesystem. Proceed?"):
            return

        self._rem_stop.clear()
        self._rem_btn.configure(state="disabled", text="⏳ Remediating…")
        self._rlog("SEP", "─" * 56)
        self._rlog("SYS", f"Starting auto-remediation on {crits} finding(s)…")
        self._set_status("⚡ Auto-remediation running…")

        def run():
            eng = RemediationEngine(all_f, self._rlog)
            removed, failed = eng.auto_remediate(self._rem_stop)
            self.after(0, self._rem_done, removed, failed)

        threading.Thread(target=run, daemon=True).start()

    def _rem_done(self, removed, failed):
        self._rem_btn.configure(state="normal", text="⚡  AUTO-REMEDIATE")
        if failed:
            self._rlog("WARN",
                f"Done: {removed} fixed, {failed} failed "
                "(may need admin/root — complete manually)")
            self._set_status(f"⚡ {removed} fixed, {failed} need manual action")
        else:
            self._rlog("OK", f"Done: {removed} action(s) applied successfully")
            self._set_status(f"✅ Remediation complete — {removed} action(s)")
        self._rlog("WARN",
            "⚠  CRITICAL: Rotate ALL credentials on any exposed machine — "
            "see Step 4 of the manual playbook above")

    # ─── Export ───────────────────────────────────────────────────────────────

    def _export(self, mode: str):
        findings = (self._findings
                    if mode in ("local", "remediation")
                    else self._arch_findings)
        eng = RemediationEngine(findings, self._rlog)
        html = eng.generate_report(mode)
        try:
            path = _save_report(html, f"axioscan_{mode}_report")
            messagebox.showinfo("Report Saved",
                f"Saved to:\n{path}\n\nOpen in any web browser.")
            self._set_status(f"📄 Report: {path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


# ─────────────────────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = AxioScanApp()
    app.mainloop()
