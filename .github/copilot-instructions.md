# Copilot Instructions — POC Archive

This repository is a structured archive of security research Proof-of-Concept entries.
Each POC lives in `pocs/<category>/<YYYY-MM-DD>_<vuln-name>/` and follows a strict template.

---

## Repository layout

```
pocs/
  web / network / binary / crypto / cloud / hardware / social-engineering / misc
    <YYYY-MM-DD>_<vuln-name>/
      README.md          ← filled-in copy of templates/POC_TEMPLATE.md
      exploit.*          ← copied exploit files from the source repo
      screenshots/
      references/
archive/
  YYYY.md                ← auto-generated, one file per CVE year (do not edit manually)
templates/POC_TEMPLATE.md
scripts/index.sh         ← regenerates INDEX.md and archive/YYYY.md
INDEX.md                 ← current CVE year only, auto-generated, do not edit manually
```

---

## How to ingest a POC from a GitHub URL

When an issue contains a GitHub repository URL (e.g. `https://github.com/owner/repo`),
do the following:

### 1 — Fetch repository information

Use `curl` or Python to call the GitHub API and collect:
- Repository name, description, topics/tags
- README content
- Primary language(s)
- Stars, license

```bash
curl -s https://api.github.com/repos/OWNER/REPO
curl -s https://api.github.com/repos/OWNER/REPO/topics \
  -H "Accept: application/vnd.github.mercy-preview+json"
```

Decode the README:
```bash
curl -s https://api.github.com/repos/OWNER/REPO/readme \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"
```

### 2 — Shallow-clone the repo

```bash
git clone --depth=1 https://github.com/OWNER/REPO /tmp/poc-source
```

List the exploit-relevant files (`.py`, `.sh`, `.go`, `.rb`, `.c`, `.cpp`, `.js`, `.ts`, `.rs`).

### 3 — Determine metadata

From the README, description, topics, and file content, determine:

| Field | How to decide |
|---|---|
| **category** | `web` for HTTP/browser vulns; `network` for protocol/packet; `binary` for BOF/heap/ROP; `crypto` for cipher/oracle flaws; `cloud` for AWS/GCP/Azure; `hardware` for firmware/side-channel; `social-engineering` for phishing; `misc` for anything else |
| **severity** | Critical (CVSS 9-10), High (7-8.9), Medium (4-6.9), Low (1-3.9), Informational |
| **cvss_score** | Extract from README/advisory or estimate. Use "N/A" if unknown |
| **cve** | Extract CVE-YYYY-XXXXX from README/topics. Use "N/A" if none |
| **status** | Weaponized if working exploit code exists; Researched if write-up only; Patched/Unpatched based on advisory; Unknown otherwise |
| **tags** | Comma-separated: exploit technique + affected tech + auth level (e.g. `RCE, unauthenticated, nginx, path-traversal`) |
| **related** | If this is a resurface of a known CVE, set to the path of the original entry (e.g. `pocs/web/2021-12-10_log4shell/`). Otherwise `N/A`. |
| **last_updated** | Date of the most recent commit to the upstream repo that changed exploit code (not just README edits). Use `git log --format="%ad" --date=short -- <exploit-files> \| head -1` on the cloned repo. Use `N/A` if indeterminate. |

### 4 — Create the folder

```
pocs/<category>/YYYY-MM-DD_<vuln-name>/
```

- Date = today's date in `YYYY-MM-DD` format
- `vuln-name` = short kebab-case name derived from the repo name or CVE
  (e.g. `nginx-rift-path-traversal`, `log4shell-bypass`, `openssl-heartbleed`)

### 5 — Write README.md

Copy `templates/POC_TEMPLATE.md` into the folder as `README.md`.
Fill in **every field** in the metadata and affected-target tables.
Write the summary, root cause, attack vector, and impact sections based on what you learned from the source repo.
In the References section, always include the source repo URL.
In the Notes section, add: `Auto-ingested from https://github.com/OWNER/REPO on YYYY-MM-DD.`

### 6 — Copy exploit files

Copy the exploit-relevant files from the cloned repo into the POC folder.
Keep original filenames. Do not copy binaries, lock files, or `.git/` contents.

### 7 — Update INDEX.md and archives

Run the index script:

```bash
bash scripts/index.sh
```

This regenerates `INDEX.md` and `archive/YYYY.md` files, grouped by **CVE year** (not Date Added).
- Entries with a CVE ID go into the file matching that CVE's year (e.g. `CVE-2024-21338` → `archive/2024.md`)
- Entries with no CVE fall back to the Date Added year
- `INDEX.md` contains only the current calendar year's CVEs; all older CVE years live in `archive/`

### 8 — Commit

Stage and commit:

```bash
git add pocs/ INDEX.md archive/ docs/data.json
git commit -m "feat: ingest <vuln-name> from <owner>/<repo>"
```

Then open a PR targeting `main` with:
- **Title:** `[POC] <Display Name> — <CVE or N/A>`
- **Body:** summary table (category, severity, CVE, tags, source URL) + note that human review is needed before merging

---

## How to ingest a resurface PoC (same CVE, new researcher)

A **resurface** is when a new GitHub repository implements a PoC for a CVE that already exists in the archive — written by a different researcher or using a different technique. Treat it as a **new ingest**, not an update.

### 1 — Detect the overlap

Before ingesting, search the archive for the CVE:

```bash
grep -rl "CVE-YYYY-XXXXX" pocs/
```

If one or more existing entries share the same CVE, this is a resurface.

### 2 — Follow the normal ingest flow (Steps 1–7 above)

Proceed exactly as a normal ingest. The only differences are:

- **Folder name** — append a distinguishing suffix to avoid collision, e.g.:
  ```
  pocs/binary/YYYY-MM-DD_<vuln-name>-v2/
  pocs/binary/YYYY-MM-DD_<vuln-name>-<researcher-handle>/
  ```
- **`Related` field** — set to the path of every existing entry for this CVE, comma-separated:
  ```
  pocs/binary/2026-05-15_miniplasma-cve-2020-17103/
  ```
- **`Tags` field** — note any new technique or approach if it differs from the original (e.g. `new-chain`, `different-trigger`, `kernel-6.x-only`).
- **Notes section** — add a line explaining how this differs from the original entry, e.g.:
  ```
  Resurface of CVE-2020-17103. New implementation by <researcher> using <different technique>.
  Original entry: pocs/binary/2026-05-15_miniplasma-cve-2020-17103/
  ```

Do **not** modify the original entry.

### 3 — Commit and PR

```bash
git add pocs/ INDEX.md archive/ docs/data.json
git commit -m "feat: ingest <vuln-name>-v2 from <owner>/<repo> (resurface of CVE-YYYY-XXXXX)"
```

PR title: `[POC] <Display Name> (resurface) - <CVE>`

---

## How to update an existing PoC from a GitHub URL

When an issue uses the **Update Existing PoC** template, follow these steps instead of the ingest flow.

### 1 — Find the existing entry

Search all README files in `pocs/` for the source repo URL in the Notes section:

```bash
grep -rl "https://github.com/OWNER/REPO" pocs/
```

If no match is found, fall back to searching for the repo name or CVE mentioned in the issue. If still no match, comment on the issue asking for clarification — do not create a new entry.

### 2 — Fetch the upstream repo

Shallow-clone the repo and get the latest commit date for exploit-relevant files:

```bash
git clone --depth=1 https://github.com/OWNER/REPO /tmp/poc-update
git -C /tmp/poc-update log --format="%ad" --date=short -- $(git -C /tmp/poc-update ls-files | grep -E '\.(py|sh|go|rb|c|cpp|js|ts|rs|cs|ps1)$') | head -1
```

This gives you the `Last Updated` date — the most recent commit that touched exploit code (not just README edits).

### 3 — Update exploit files

Compare files in the existing POC folder against the cloned repo. Replace any exploit-relevant files (`.py`, `.sh`, `.go`, `.rb`, `.c`, `.cpp`, `.js`, `.ts`, `.rs`, `.cs`, `.ps1`, `.sln`, `.csproj`) that have changed. Keep original filenames. Do not copy binaries, lock files, or `.git/` contents.

### 4 — Update README.md

In the existing entry's README.md, update these fields only:

| Field | What to update |
|---|---|
| `Last Updated` | Set to the date from Step 2 |
| `Status` | Re-evaluate based on new content (e.g. if a working shell was added, upgrade to Weaponized) |
| `Tags` | Add any new techniques introduced in the update |
| `Author / Researcher` | Add any new contributors mentioned in the repo |

Do not change `Date Added`, `CVE`, `Category`, or the folder path.

In the **Notes** section, append a line:
```
Updated YYYY-MM-DD: <brief description of what changed, from the issue body or inferred from commit messages>.
```

### 5 — Run index script

```bash
bash scripts/index.sh
```

### 6 — Commit and open PR

```bash
git add pocs/ INDEX.md archive/ docs/data.json
git commit -m "update: <vuln-name> — <one-line summary of change>"
```

Open a PR with:
- **Title:** `Update: <Display Name>`
- **Body:** what changed, last updated date, source URL, note that human review is needed

---

## Rules

- Never commit real credentials, PII, or live endpoints
- Never overwrite an existing POC folder — create a new one with a different date or suffix
- Always run `scripts/index.sh` before committing
- The `INDEX.md` header says "do not edit manually" — only update it via the script
- Exploit code included here is for authorized research only; add a disclaimer comment to the top of copied files if one is not already present
