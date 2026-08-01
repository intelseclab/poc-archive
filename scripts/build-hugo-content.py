#!/usr/bin/env python3
"""Convert pocs/*/README.md into Hugo content pages under content/pocs/."""

import re, sys, json, datetime, shutil
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
POCS_DIR = REPO_ROOT / "pocs"
CONTENT_DIR = REPO_ROOT / "content" / "pocs"
INTEL_FILE = REPO_ROOT / "data" / "cve-intel.json"


# Vendor/technology tokens used to group free-text affected_product values.
# Order matters: more specific names must precede the generic ones they contain.
VENDOR_TOKENS = [
    'PAN-OS', 'Palo Alto', 'Check Point', 'SonicWall', 'FortiOS', 'Fortinet',
    'ManageEngine', 'SolarWinds', 'Atlassian', 'Confluence', 'Jira', 'MOVEit',
    'SharePoint', 'Exchange', 'Outlook', 'Windows', 'Microsoft', 'Azure',
    'WordPress', 'Joomla', 'Drupal', 'Magento', 'Ghost', 'Craft', 'Sitecore',
    'Next.js', 'Node.js', 'React', 'Laravel', 'Django', 'Rails', 'Spring',
    'Tomcat', 'Struts', 'Log4j', 'Fastjson', 'Jenkins', 'GitLab', 'TeamCity',
    'JetBrains', 'Kubernetes', 'Docker', 'Elastic', 'Grafana', 'Redis',
    'PostgreSQL', 'MySQL', 'MongoDB', 'Apache', 'Nginx', 'OpenSSL',
    'Cisco', 'Ivanti', 'Citrix', 'VMware', 'Veeam', 'Juniper', 'BIG-IP', 'F5',
    'QNAP', 'Synology', 'TP-Link', 'D-Link', 'Netgear', 'Zyxel',
    'Adobe', 'Oracle', 'SAP', 'IBM', 'Zoho', 'Salesforce', 'ServiceNow',
    'Splunk', 'Nagios', 'Zabbix', 'pfSense', 'Zimbra', 'Roundcube',
    'Google', 'Chrome', 'Android', 'Linux', 'Langflow', 'Ollama',
    'PHP', 'Java', 'Python', 'Git',
]


def extract_vendor(product):
    """Collapse a free-text affected_product into a groupable vendor label.

    affected_product is ~97% unique across the archive, so it cannot be
    grouped directly; the vendor prefix concentrates it usefully
    (top-15 vendors cover ~44% of entries).
    """
    if not product:
        return ""
    low = product.lower()
    for v in VENDOR_TOKENS:
        if v.lower() in low:
            return v
    m = re.match(r'[\s"]*([A-Za-z][\w.\-]+)', product)
    return m.group(1) if m else ""


def load_intel():
    """Load the KEV/EPSS snapshot written by scripts/enrich-cve-intel.py.

    Absent or malformed snapshot is not fatal — the site simply builds
    without exploitation signals rather than failing.
    """
    if not INTEL_FILE.exists():
        print("  note: data/cve-intel.json absent — building without KEV/EPSS signals",
              file=sys.stderr)
        return {"kev": {}, "epss": {}, "generated": ""}
    try:
        with INTEL_FILE.open(encoding="utf-8") as f:
            data = json.load(f)
        return {
            "kev": data.get("kev", {}),
            "epss": data.get("epss", {}),
            "generated": data.get("generated", ""),
        }
    except Exception as e:
        print(f"  WARN could not read data/cve-intel.json ({e}) — building without signals",
              file=sys.stderr)
        return {"kev": {}, "epss": {}, "generated": ""}


def compute_priority(kev, kev_ransomware, epss, patched, cvss, date_added):
    """Single 0-230ish urgency score. Every component is shown to the user as
    a signal chip, so the ranking is always self-explaining.

      +100  listed in CISA KEV (confirmed exploited in the wild)
      + 50  known ransomware campaign use
      +  0..60  EPSS probability (score * 60)
      + 25  no vendor patch available
      + 15  CVSS >= 9.0   (+8 for >= 7.0)
      +  0..30  recency, decaying over ~60 days

    Deliberately NOT scored: the CISA remediation deadline. Effectively every
    KEV entry in this archive is already past it (CISA allows ~2 weeks; these
    CVEs are months old), so it is a constant across the KEV cohort and adds
    no discriminating signal. kev_due is still recorded as reference data.
    """
    score = 0
    if kev:
        score += 100
    if kev_ransomware:
        score += 50
    if epss:
        score += round(epss * 60)
    if not patched:
        score += 25
    if cvss is not None:
        if cvss >= 9.0:
            score += 15
        elif cvss >= 7.0:
            score += 8
    if date_added:
        age_days = (datetime.date.today() - date_added).days
        score += max(0, 30 - (age_days // 2))
    return score


def extract_field(text, field_name):
    m = re.search(
        rf'\|\s*\*\*{re.escape(field_name)}\*\*\s*\|\s*(.+?)\s*\|',
        text, re.IGNORECASE
    )
    if m:
        val = re.sub(r'<!--.*?-->', '', m.group(1), flags=re.DOTALL).strip()
        # Strip inline code backticks for display
        val = re.sub(r'`([^`]+)`', r'\1', val)
        return val
    return ""


def extract_title(text):
    m = re.search(r'^#\s+(.+)$', text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def extract_references(text):
    refs = []
    in_refs = False
    for line in text.split('\n'):
        if re.match(r'^#+\s+References', line, re.IGNORECASE):
            in_refs = True
            continue
        if in_refs:
            if re.match(r'^#+\s+', line):
                break
            m = re.search(r'\((https?://[^)]+)\)', line)
            if m:
                refs.append(m.group(1))
    return refs


def parse_cvss(s):
    m = re.search(r'(\d+\.\d+)', s)
    return float(m.group(1)) if m else None


def parse_tags(s):
    return [t.strip() for t in s.split(',') if t.strip()] if s else []


def parse_date(s):
    try:
        return datetime.date.fromisoformat(s.strip())
    except Exception:
        return None


def determine_patched(text):
    lower = text.lower()
    for sig in ('no patch available', 'no patch yet', 'no fix', 'no official patch',
                'no cve or official patch', 'no workaround', 'no patch; no workaround',
                '"future release, no workaround"', 'future release'):
        if sig in lower:
            return False
    for sig in ('fixed in', 'patched in', 'upgrade to', 'update to',
                'apply microsoft', 'apply cisco', 'apply check point',
                'apply the patch', 'install the patch', 'install cisco',
                'security update'):
        if sig in lower:
            return True
    return False


def normalize_severity(sev):
    """Map non-standard severity values to the canonical enum set."""
    if not sev:
        return sev
    # Strip parenthetical suffixes: "Critical (per vendor advisory)" → "Critical"
    s = re.sub(r'\s*\([^)]*\)\s*$', '', sev).strip()
    lower = s.lower()
    # Known non-standard vendor severities → canonical
    if lower.startswith('not disclosed'):
        return 'Info'
    if lower == 'important':
        return 'High'
    if lower == 'moderate':
        return 'Medium'
    # Standard values pass through
    if lower in ('critical', 'high', 'medium', 'low', 'info'):
        return s
    # Unknown — keep as-is but warn
    print(f"  WARN unrecognized severity '{sev}'", file=sys.stderr)
    return sev


def strip_placeholder_sections(text):
    """Remove Screenshots/Evidence sections that contain only placeholder content."""
    # Match: ## Screenshots / Evidence  ... through to the next --- or ## heading
    # Only strip if the body contains only placeholder text (no real images/URLs/evidence)
    lines = text.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^##\s+Screenshots\s*/\s*Evidence\s*$', line, re.IGNORECASE)
        if not m:
            result.append(line)
            i += 1
            continue

        # Collect the section body
        j = i + 1
        body_lines = []
        while j < len(lines):
            if re.match(r'^##\s+', lines[j]) or lines[j].strip() == '---':
                break
            body_lines.append(lines[j])
            j += 1

        body = '\n'.join(body_lines)

        # Heuristic: if the body has no real evidence (image, http link, or file reference), strip
        has_real = bool(
            re.search(r'!\[', body) or                         # markdown image
            re.search(r'https?://', body) or                   # external URL
            re.search(r'\.(png|jpg|jpeg|gif|svg|webp|pdf)', body, re.IGNORECASE)
        )
        # Also check for meaningful text beyond placeholder patterns
        meaningful = re.sub(
            r'<!--.*?-->|screenshots/\s*—.*|`screenshots/`\s*—.*|- N/A|None included.*|'
            r'- `[^`]+` — add authorized.*|- Add authorized.*',
            '', body, flags=re.IGNORECASE | re.DOTALL
        ).strip()
        if not has_real and not meaningful:
            # Skip this section entirely
            i = j
            # Skip trailing --- if present
            if i < len(lines) and lines[i].strip() == '---':
                i += 1
            continue
        else:
            result.append(line)
            result.extend(body_lines)
            i = j

    return '\n'.join(result)


def strip_h1(text):
    """Remove H1 heading and the immediately following --- separator."""
    lines = text.split('\n')
    result = []
    skip_next_hr = False
    for i, line in enumerate(lines):
        if re.match(r'^#\s+', line) and not re.match(r'^##', line):
            skip_next_hr = True
            continue
        if skip_next_hr:
            if line.strip() == '' or line.strip() == '---':
                if line.strip() == '---':
                    skip_next_hr = False
                continue
            skip_next_hr = False
        result.append(line)
    return '\n'.join(result).lstrip('\n')


def yaml_str(s):
    """Emit a YAML string value, quoting if needed."""
    if not s:
        return '""'
    # Quote if starts with a reserved YAML indicator, contains special chars, or embeds a quote
    if s[0] in '@`' or '"' in s or any(c in s for c in ':#{}[]|>&*!,?'):
        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    return s


def write_frontmatter(f, fm):
    f.write('---\n')
    for k, v in fm.items():
        if v is None:
            continue
        if isinstance(v, bool):
            f.write(f'{k}: {"true" if v else "false"}\n')
        elif isinstance(v, (int, float)):
            f.write(f'{k}: {v}\n')
        elif isinstance(v, datetime.date):
            f.write(f'{k}: {v.isoformat()}\n')
        elif isinstance(v, list):
            if not v:
                continue
            f.write(f'{k}:\n')
            for item in v:
                escaped = str(item).replace('\\', '\\\\').replace('"', '\\"')
                f.write(f'  - "{escaped}"\n')
        else:
            f.write(f'{k}: {yaml_str(str(v))}\n')
    f.write('---\n')


def process(readme_path, intel=None):
    intel = intel or {"kev": {}, "epss": {}}
    text = readme_path.read_text(encoding='utf-8', errors='replace')

    title = extract_title(text)
    date_added = parse_date(extract_field(text, "Date Added"))
    last_updated = parse_date(extract_field(text, "Last Updated"))
    author = extract_field(text, "Author / Researcher")
    cve = extract_field(text, "CVE / Advisory")
    category = extract_field(text, "Category")
    severity = normalize_severity(extract_field(text, "Severity"))
    cvss_str = extract_field(text, "CVSS Score")
    status = extract_field(text, "Status")
    tags_str = extract_field(text, "Tags")
    related = extract_field(text, "Related")
    affected_product = extract_field(text, "Software / System")
    affected_versions = extract_field(text, "Versions Affected")

    references = extract_references(text)
    tags = parse_tags(tags_str)
    cvss_score = parse_cvss(cvss_str)
    patched = determine_patched(text)

    fm = {}
    if title:
        fm['title'] = title
    if date_added:
        fm['date'] = date_added
    if last_updated:
        fm['lastmod'] = last_updated
    if author:
        fm['author'] = author
    if cve and cve.upper() != 'N/A':
        fm['cve'] = cve
    if category:
        fm['category'] = category
    if severity:
        fm['severity'] = severity
    if cvss_score is not None:
        fm['cvss_score'] = cvss_score
    if status:
        fm['status'] = status
    if affected_product:
        fm['affected_product'] = affected_product
        vendor = extract_vendor(affected_product)
        if vendor:
            fm['vendor'] = vendor
    if affected_versions:
        fm['affected_versions'] = affected_versions
    if tags:
        fm['tags'] = tags
    if references:
        fm['references'] = references
    if related and related.upper() != 'N/A':
        fm['related'] = related
    fm['patched'] = patched

    # ── Exploitation signals (CISA KEV + FIRST EPSS) ──
    kev_rec = None
    epss_rec = None
    cve_m = re.search(r'CVE-\d{4}-\d{4,7}', cve or '', re.IGNORECASE)
    if cve_m:
        cve_id = cve_m.group(0).upper()
        kev_rec = intel['kev'].get(cve_id)
        epss_rec = intel['epss'].get(cve_id)

    kev_overdue = False
    if kev_rec:
        fm['kev'] = True
        if kev_rec.get('added'):
            fm['kev_added'] = kev_rec['added']
        if kev_rec.get('due'):
            fm['kev_due'] = kev_rec['due']
            due = parse_date(kev_rec['due'])
            if due and due < datetime.date.today():
                kev_overdue = True
                fm['kev_overdue'] = True
        if kev_rec.get('ransomware'):
            fm['kev_ransomware'] = True

    epss_score = None
    if epss_rec:
        epss_score = epss_rec.get('score')
        if epss_score is not None:
            fm['epss'] = epss_score
            fm['epss_percentile'] = epss_rec.get('percentile')

    fm['priority'] = compute_priority(
        kev=bool(kev_rec),
        kev_ransomware=bool(kev_rec and kev_rec.get('ransomware')),
        epss=epss_score,
        patched=patched,
        cvss=cvss_score,
        date_added=date_added,
    )

    content = strip_h1(text)
    content = strip_placeholder_sections(content)
    return fm, content


def write_chart_data(entries):
    """Precompute homepage chart datasets into data/homepage_charts.json.

    Hugo auto-loads data/*.json, so templates read this as
    site.Data.homepage_charts — no client-side charting library needed.
    """
    from collections import Counter, OrderedDict

    today = datetime.date.today()

    # ── 1. Archive entries entering CISA KEV, bucketed by month over ~6 months ──
    months = OrderedDict()
    for i in range(5, -1, -1):
        y, m = today.year, today.month - i
        while m <= 0:
            m += 12
            y -= 1
        months[f"{y:04d}-{m:02d}"] = 0
    kev_recent = 0
    for e in entries:
        added = e.get('kev_added') or ''
        if len(added) < 7:
            continue
        key = added[:7]
        if key in months:
            months[key] += 1
        try:
            if (today - datetime.date.fromisoformat(added)).days <= 90:
                kev_recent += 1
        except ValueError:
            pass
    kev_timeline = [{"label": k[5:7] + "/" + k[2:4], "month": k, "count": v}
                    for k, v in months.items()]

    # ── 2. Top vendors, with the KEV-confirmed share of each ──
    vend_all = Counter(e['vendor'] for e in entries if e.get('vendor'))
    vend_kev = Counter(e['vendor'] for e in entries if e.get('vendor') and e.get('kev'))
    top_vendors = [{"name": v, "count": c, "kev": vend_kev.get(v, 0)}
                   for v, c in vend_all.most_common(12)]

    # ── 3. Highest EPSS entries ──
    scored = [e for e in entries if e.get('epss')]
    scored.sort(key=lambda e: e['epss'], reverse=True)
    epss_top = [{
        "cve": e.get('cve', '') or '—',
        "title": e.get('title', ''),
        "epss": round(e['epss'], 4),
        "kev": e.get('kev', False),
        "url": e['url'],
    } for e in scored[:15]]

    payload = {
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kev_total": sum(1 for e in entries if e.get('kev')),
        "kev_last_90d": kev_recent,
        "kev_timeline": kev_timeline,
        "top_vendors": top_vendors,
        "epss_top": epss_top,
    }

    out = REPO_ROOT / "data" / "homepage_charts.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def main():
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    intel = load_intel()
    count = 0
    errors = 0
    kev_hits = 0
    entries = []

    for readme in sorted(POCS_DIR.rglob("README.md")):
        parts = readme.relative_to(POCS_DIR).parts
        if len(parts) != 3:
            continue
        category, dirname, _ = parts

        out_dir = CONTENT_DIR / category / dirname
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "index.md"

        try:
            fm, content = process(readme, intel)
            if fm.get('kev'):
                kev_hits += 1
        except Exception as e:
            print(f"  ERROR {readme.parent.name}: {e}", file=sys.stderr)
            errors += 1
            continue

        with out_file.open('w', encoding='utf-8') as f:
            write_frontmatter(f, fm)
            f.write('\n')
            f.write(content)

        # Copy bundled exploit files (non-README, non-index, non-hidden) into the content dir
        for src in sorted(readme.parent.iterdir()):
            if src.name in ("README.md", "index.md") or src.name.startswith('.') or not src.is_file():
                continue
            shutil.copy2(src, out_dir / src.name)

        entries.append({
            'title': fm.get('title', ''),
            'cve': fm.get('cve', ''),
            'vendor': fm.get('vendor', ''),
            'kev': bool(fm.get('kev')),
            'kev_added': fm.get('kev_added', ''),
            'epss': fm.get('epss'),
            'priority': fm.get('priority', 0),
            'url': f"/pocs/{category}/{dirname}/",
        })

        count += 1

    write_chart_data(entries)

    # Generate _index.md for the root pocs section and each category sub-section.
    categories = set()
    for content_dir in CONTENT_DIR.iterdir():
        if content_dir.is_dir() and not content_dir.name.startswith('.'):
            categories.add(content_dir.name)

    # Root pocs section
    root_index = CONTENT_DIR / "_index.md"
    with root_index.open('w', encoding='utf-8') as f:
        write_frontmatter(f, {'title': 'PoCs'})
        f.write('\nAll proof-of-concept entries in the archive.\n')

    # Per-category section
    for cat in sorted(categories):
        cat_index = CONTENT_DIR / cat / "_index.md"
        with cat_index.open('w', encoding='utf-8') as f:
            write_frontmatter(f, {'title': cat})

    intel_note = ""
    if intel.get('generated'):
        intel_note = f" — {kev_hits} in CISA KEV (intel as of {intel['generated']})"
    print(f"Generated {count} Hugo content pages ({errors} errors){intel_note}.")


if __name__ == '__main__':
    main()
