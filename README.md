# AXIOSCAN v1.0
### Axios Supply Chain Attack Detector & Remediator
**NEATLABS™  |  Security 360, LLC  |  SDVOSB**

---

## ⚠ INCIDENT SUMMARY

On **March 31, 2026**, the popular npm package `axios` was compromised in a
sophisticated supply chain attack. The attacker hijacked the lead maintainer's
npm credentials and published two poisoned versions:

- `axios@1.14.1`  ←  **COMPROMISED**
- `axios@0.30.4`  ←  **COMPROMISED**

Both versions inject `plain-crypto-js@4.2.1` — a hidden dependency that acts
as a **cross-platform Remote Access Trojan (RAT)** dropper calling back to:
**`sfrclak.com:8000`**

**Safe versions:**  `axios@1.14.0` (1.x)  |  `axios@0.30.3` (0.x)

---

## 🚀 QUICK START

### Windows
```
Double-click:  LAUNCH_AXIOSCAN.bat
```

### macOS / Linux
```bash
pip install customtkinter
python3 AXIOSCAN.py
```

---

## 🖥 FEATURES

| Tab | What it does |
|-----|-------------|
| **LOCAL SYSTEM SCAN** | Walks your filesystem for compromised axios package.json files, plain-crypto-js RAT directories, and platform-specific RAT artifacts |
| **ARCHIVE SCAN** | Scans a .zip archive (downloaded SaaS project bundle) without extracting — checks all package.json entries inside |
| **REMEDIATION** | Auto-removes RAT artifacts and directories, attempts npm downgrade, provides full 8-step manual playbook |
| **THREAT INTEL** | Full IOC reference: artifacts, C2, TTPs, attacker details, references |

---

## 🔍 WHAT IT SCANS FOR

- **package.json** files containing `axios@1.14.1` or `axios@0.30.4`
- **Dependencies** listing `plain-crypto-js` (any version)
- **node_modules/plain-crypto-js** directory (RAT dropper may have already run)
- **Platform RAT artifacts:**
  - macOS:   `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\wt.exe`
  - Linux:   `/tmp/ld.py`
- **Hosts file** entries for `sfrclak.com`

---

## 🛠 AUTO-REMEDIATION ACTIONS

When you click **⚡ AUTO-REMEDIATE**:
1. Deletes `node_modules/plain-crypto-js` directories
2. Deletes platform-specific RAT artifact files
3. Attempts `npm install axios@<safe_version>` in affected project roots

> **Note:** Some actions require admin/root privileges. Run as Administrator
> on Windows or with `sudo` on macOS/Linux if remediation fails.

---

## ⚡ IF YOUR SYSTEM WAS EXPOSED

If you installed either affected version between **2026-03-30 23:59 UTC** and
**2026-03-31 04:26 UTC**, assume **full system compromise** and immediately rotate:

- npm access tokens
- AWS IAM access keys
- SSH private keys
- GitHub / GitLab personal access tokens
- CI/CD pipeline secrets
- Any API keys present in the environment

---

## 📋 REQUIREMENTS

- Python 3.8+
- `customtkinter` (`pip install customtkinter`)
- npm (optional — needed for auto-downgrade feature)
- Windows 10+ / macOS 12+ / Ubuntu 20.04+

---

## 📄 EXPORT

Both scan modes and the remediation engine can export a **full HTML report**
to your Desktop including: findings table, IOC reference, and the complete
8-step remediation playbook. Open in any browser. No internet required.

---

*AXIOSCAN is part of the NEATLABS™ tool portfolio.*
*Security 360, LLC — Service-Disabled Veteran-Owned Small Business*
