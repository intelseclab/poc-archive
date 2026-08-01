#!/usr/bin/env python3
"""Convert pocs/*/README.md into Hugo content pages under content/pocs/."""

import re, sys, datetime, shutil
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
POCS_DIR = REPO_ROOT / "pocs"
CONTENT_DIR = REPO_ROOT / "content" / "pocs"


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


def process(readme_path):
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
    if affected_versions:
        fm['affected_versions'] = affected_versions
    if tags:
        fm['tags'] = tags
    if references:
        fm['references'] = references
    if related and related.upper() != 'N/A':
        fm['related'] = related
    fm['patched'] = patched

    content = strip_h1(text)
    content = strip_placeholder_sections(content)
    return fm, content


def main():
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    errors = 0

    for readme in sorted(POCS_DIR.rglob("README.md")):
        parts = readme.relative_to(POCS_DIR).parts
        if len(parts) != 3:
            continue
        category, dirname, _ = parts

        out_dir = CONTENT_DIR / category / dirname
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "index.md"

        try:
            fm, content = process(readme)
        except Exception as e:
            print(f"  ERROR {readme.parent.name}: {e}", file=sys.stderr)
            errors += 1
            continue

        with out_file.open('w', encoding='utf-8') as f:
            write_frontmatter(f, fm)
            f.write('\n')
            f.write(content)

        # Copy bundled exploit files (non-README, non-hidden) into the content dir
        for src in sorted(readme.parent.iterdir()):
            if src.name == "README.md" or src.name.startswith('.') or not src.is_file():
                continue
            shutil.copy2(src, out_dir / src.name)

        count += 1

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

    print(f"Generated {count} Hugo content pages ({errors} errors).")


if __name__ == '__main__':
    main()
