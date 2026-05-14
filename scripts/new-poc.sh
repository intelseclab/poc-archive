#!/usr/bin/env bash
# new-poc.sh — Interactively scaffold a new POC entry
# Usage: ./scripts/new-poc.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$REPO_ROOT/templates/POC_TEMPLATE.md"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════╗"
echo "║       POC ARCHIVE — New Entry        ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# --- Gather inputs ---

read -rp "$(echo -e "${YELLOW}Vulnerability name${NC} (short, kebab-case, e.g. log4shell-bypass): ")" vuln_name
vuln_name="${vuln_name// /-}"
vuln_name="${vuln_name,,}"

echo ""
echo -e "${YELLOW}Category:${NC}"
categories=("web" "network" "binary" "crypto" "cloud" "hardware" "social-engineering" "misc")
select category in "${categories[@]}"; do
  [[ -n "$category" ]] && break
  echo "Please choose a valid option."
done

read -rp "$(echo -e "${YELLOW}CVE / Advisory ID${NC} (e.g. CVE-2024-12345 or N/A): ")" cve_id

echo ""
echo -e "${YELLOW}Severity:${NC}"
severities=("Critical" "High" "Medium" "Low" "Informational")
select severity in "${severities[@]}"; do
  [[ -n "$severity" ]] && break
  echo "Please choose a valid option."
done

read -rp "$(echo -e "${YELLOW}One-line description${NC}: ")" description

# --- Build paths ---

today=$(date +%Y-%m-%d)
dir_name="${today}_${vuln_name}"
poc_dir="$REPO_ROOT/pocs/$category/$dir_name"

if [[ -d "$poc_dir" ]]; then
  echo -e "${RED}Error: $poc_dir already exists.${NC}"
  exit 1
fi

mkdir -p "$poc_dir/screenshots" "$poc_dir/references"

# --- Copy and pre-fill template ---

poc_readme="$poc_dir/README.md"
cp "$TEMPLATE" "$poc_readme"

# Replace placeholders (macOS + Linux compatible sed)
sed_inplace() {
  if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "$@"
  else
    sed -i '' "$@"
  fi
}

sed_inplace "s/\[Vulnerability Name\]/${vuln_name}/g" "$poc_readme"
sed_inplace "s/YYYY-MM-DD/${today}/g" "$poc_readme"
sed_inplace "s|<!-- CVE-YYYY-XXXXX or N/A -->|${cve_id}|g" "$poc_readme"
sed_inplace "s|<!-- Critical \/ High \/ Medium \/ Low \/ Informational -->|${severity}|g" "$poc_readme"
sed_inplace "s|<!-- web \/ network \/ binary \/ crypto \/ cloud \/ hardware \/ social-engineering \/ misc -->|${category}|g" "$poc_readme"

# --- Create stub exploit file ---

cat > "$poc_dir/exploit.py" << EXPLOIT
#!/usr/bin/env python3
"""
POC: ${vuln_name}
CVE: ${cve_id}
Date: ${today}
Description: ${description}

DISCLAIMER: For authorized security research only.
"""

TARGET = "http://target:PORT"

def exploit(target: str) -> None:
    # TODO: implement exploit
    pass

if __name__ == "__main__":
    exploit(TARGET)
EXPLOIT

# --- Create .gitkeep placeholders ---
touch "$poc_dir/screenshots/.gitkeep"
touch "$poc_dir/references/.gitkeep"

# --- Done ---

echo ""
echo -e "${GREEN}✅ POC entry created:${NC}"
echo "   $poc_dir/"
echo ""
echo -e "   ${BLUE}├── README.md${NC}       ← fill in your write-up"
echo -e "   ${BLUE}├── exploit.py${NC}      ← implement your PoC"
echo -e "   ${BLUE}├── screenshots/${NC}     ← add evidence"
echo -e "   ${BLUE}└── references/${NC}      ← save advisories / papers"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Edit $poc_dir/README.md"
echo "  2. Implement exploit.py (or add your own exploit files)"
echo "  3. Run ./scripts/index.sh to update INDEX.md"
echo ""
