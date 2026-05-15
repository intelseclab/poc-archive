# poc-archive

A structured archive of security research proof-of-concepts, organized by category with metadata, reproduction steps, and references.

---

**Disclaimer:** This repository is intended strictly for educational and authorized security research. All material is archived for reference and knowledge sharing only. Never use these against systems you do not own or have explicit written permission to test.

---

## Structure

```
pocs/
  web/                 XSS, SQLi, SSRF, CSRF, RCE via web
  network/             Protocol exploits, MitM, packet injection
  binary/              Buffer overflows, heap exploits, ROP chains
  crypto/              Weak ciphers, padding oracles, key mismanagement
  cloud/               AWS/GCP/Azure misconfigs, IAM escapes, metadata abuse
  hardware/            Firmware, side-channels, physical attacks
  social-engineering/  Authorized phishing and pretexting simulations
  misc/                Anything that doesn't fit above

templates/
  POC_TEMPLATE.md      Template for new entries

archive/
  YYYY.md              Auto-generated index per CVE year (do not edit manually)

scripts/
  new-poc.sh           Scaffold a new POC entry interactively
  index.sh             Regenerate INDEX.md and archive/YYYY.md

.github/
  ISSUE_TEMPLATE/      Issue forms including URL ingestion form
  copilot-instructions.md

INDEX.md               Current CVE year — auto-generated, do not edit manually
```

---

## Adding a POC

### From a GitHub URL

Open a new issue using the **Ingest POC from GitHub URL** template. Paste the repository URL and submit. The Copilot coding agent will fetch metadata, analyze the repository, fill in the template, and open a PR for review.

### Manual

```bash
./scripts/new-poc.sh
```

Or manually:

1. Copy `templates/POC_TEMPLATE.md` into `pocs/<category>/YYYY-MM-DD_vuln-name/README.md`
2. Fill in all fields
3. Add exploit code, screenshots, and references in the same folder
4. Run `./scripts/index.sh` to update `INDEX.md` and `archive/`

---

## Naming Convention

```
pocs/<category>/YYYY-MM-DD_short-name/
  README.md
  exploit.py
  screenshots/
  references/
```

---

## Searching

```bash
grep -r "CVE-2024-" pocs/ --include="*.md" -l
grep -r "Severity: Critical" pocs/ --include="*.md" -l
grep -r "Apache" pocs/ --include="*.md" -l
```

Or browse [INDEX.md](./INDEX.md).

---

## Contributing

- Use the provided template
- Keep write-ups factual and reproducible
- Include CVE or advisory references where applicable
- Do not include active credentials, live endpoints, or victim data
- Run `./scripts/index.sh` before committing

---

## License

Write-ups and research notes: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)  
Exploit code: [MIT](https://opensource.org/licenses/MIT)
