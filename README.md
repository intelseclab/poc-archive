# 🔐 POC Archive

> A structured archive of Proof-of-Concept security research, organized by category with metadata, reproduction steps, and references.

---

## ⚠️ Disclaimer

This repository is intended **strictly for educational and authorized security research purposes**.  
All POCs are archived for reference and knowledge sharing only.  
**Never use these against systems you do not own or have explicit written permission to test.**  
The maintainers are not responsible for any misuse of the material in this repository.

---

## 📁 Repository Structure

```
pocs-archive/
├── pocs/
│   ├── web/              # XSS, SQLi, SSRF, CSRF, RCE via web, etc.
│   ├── network/          # Protocol exploits, MitM, packet injection, etc.
│   ├── binary/           # Buffer overflows, heap exploits, ROP chains, etc.
│   ├── crypto/           # Weak ciphers, padding oracles, key mismanagement, etc.
│   ├── cloud/            # AWS/GCP/Azure misconfigs, IAM escapes, metadata abuse, etc.
│   ├── hardware/         # Firmware, side-channels, physical attacks, etc.
│   ├── social-engineering/ # Phishing templates, pretexting, etc. (authorized simulations only)
│   └── misc/             # Anything that doesn't fit above
├── templates/
│   └── POC_TEMPLATE.md   # Template for new POC entries
├── scripts/
│   ├── new-poc.sh        # Scaffold a new POC entry interactively
│   └── index.sh          # Generate/update the POC index table
├── .github/
│   └── ISSUE_TEMPLATE/
│       └── poc-submission.md
├── INDEX.md              # Auto-generated index of all POCs
└── README.md             # This file
```

---

## 🗂️ Categories

| Category | Description |
|---|---|
| `web` | Web application vulnerabilities (XSS, SQLi, SSRF, SSTI, RCE, etc.) |
| `network` | Network-level attacks (ARP spoofing, BGP hijacks, protocol flaws, etc.) |
| `binary` | Binary exploitation (BOF, heap, format strings, kernel, etc.) |
| `crypto` | Cryptographic weaknesses (oracles, weak RNG, implementation flaws, etc.) |
| `cloud` | Cloud misconfigurations and privilege escalation |
| `hardware` | Hardware/firmware attacks (JTAG, side-channel, glitching, etc.) |
| `social-engineering` | Authorized phishing / pretexting simulations |
| `misc` | Other research that doesn't fit a main category |

---

## 🚀 Adding a New POC

### Option 1 — Interactive script
```bash
./scripts/new-poc.sh
```

### Option 2 — Manual
1. Copy `templates/POC_TEMPLATE.md` into the appropriate `pocs/<category>/` folder
2. Name the file: `YYYY-MM-DD_vuln-name.md` (e.g. `2024-03-15_log4shell-bypass.md`)
3. Fill in all required fields
4. Add any supporting files (exploit code, screenshots) in the same folder
5. Run `./scripts/index.sh` to update `INDEX.md`

---

## 📋 POC Naming Convention

```
YYYY-MM-DD_short-descriptive-name/
├── README.md        ← The POC write-up (from template)
├── exploit.py       ← PoC code (or .rb, .go, .sh, etc.)
├── screenshots/     ← Evidence / demo captures
└── references/      ← Saved copies of relevant advisories, papers
```

---

## 🔍 Searching the Archive

```bash
# Search by CVE
grep -r "CVE-2024-" pocs/ --include="*.md" -l

# Search by severity
grep -r "Severity: Critical" pocs/ --include="*.md" -l

# Search by technology
grep -r "Apache" pocs/ --include="*.md" -l
```

Or browse the auto-generated **[INDEX.md](./INDEX.md)**.

---

## 📊 Index

See **[INDEX.md](./INDEX.md)** for the full searchable table of all archived POCs.

---

## 🤝 Contributing

1. Use the provided template
2. Keep write-ups factual and reproducible
3. Include CVE / advisory references where applicable
4. Do **not** include active credentials, live endpoints, or victim data
5. Run `./scripts/index.sh` before committing

---

## 📜 License

Research notes and write-ups: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)  
Exploit code: [MIT](https://opensource.org/licenses/MIT)  
