#!/usr/bin/env bash
# Обязательные проверки репозитория одной командой — поле checks отчёта (AGENTS.md):
# синтаксис, скиллы и ссылки в инструкциях, тесты tests/test-*.sh, данные установки в ветке.
# Печатает только провалы и строку «checks: PASS|FAIL»; код выхода 0 — только PASS. Нет нужной
# утилиты — провал, а не пропуск.
#   bash tests/check.sh [ФАЙЛ…]   ФАЙЛ — ещё текст на данные установки (сообщение коммита)
extra=(); for f in "$@"; do extra+=("$(realpath "$f")"); done
cd "${BASH_SOURCE[0]%/*}/.." || exit 1
fails=0
bad() { echo "  ✗ $*"; fails=$((fails + 1)); }

for t in git jq python3 timeout diff; do command -v "$t" >/dev/null || bad "нет $t"; done

# ─── Синтаксис
for f in setup.sh xm.sh tests/*.sh tests/vps/*.sh .claude/hooks/*.sh; do
  [[ -f $f ]] || continue
  bash -n "$f" 2>/dev/null || bad "bash -n $f"
done
for f in .claude/settings.json .claude/skills/*/evals/evals.json; do
  jq empty "$f" 2>/dev/null || bad "JSON не разбирается: $f"
done

# ─── Python панели; скиллы: фронтматтер; пути в инструкциях существуют
while IFS= read -r line; do bad "$line"; done < <(python3 - <<'EOF'
import ast, glob, os, re, subprocess
for f in glob.glob("ui/*.py"):
    try: ast.parse(open(f, encoding="utf-8").read(), f)
    except SyntaxError as e: print(f"синтаксис {f}:{e.lineno}")
for f in glob.glob(".claude/skills/*/SKILL.md"):
    m = re.match(r"---\n(.*?)\n---\n", open(f, encoding="utf-8").read(), re.S)
    fm = dict(l.split(":", 1) for l in m.group(1).splitlines() if ":" in l) if m else {}
    d = os.path.basename(os.path.dirname(f))
    if fm.get("name", "").strip() != d: print(f"{f}: name ≠ {d}")
    n = len(fm.get("description", "").strip())
    if not 0 < n <= 1024: print(f"{f}: description {n} символов (1…1024)")
files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], capture_output=True, text=True).stdout.split()
docs = ["AGENTS.md", "CLAUDE.md", ".claude/HANDOFF.md"] + glob.glob(".claude/rules/*.md") \
    + glob.glob(".claude/skills/*/SKILL.md") + glob.glob(".claude/skills/*/references/*.md")
for f in docs:
    for t in re.findall(r"`([^`\s]+)`", open(f, encoding="utf-8").read()):
        if "/" not in t or t.startswith(("/", "~", "http")) or re.search(r"[<*…$]", t): continue
        if not (re.search(r"\.(md|sh|json|py)$", t) or t.startswith((".claude/", "tests/"))): continue
        t = t.rstrip("/")
        if not any(p == t or p.endswith("/" + t) or p.startswith(t + "/") for p in files):
            print(f"{f}: нет пути {t}")
EOF
)

# ─── Тесты; внутри теста (CHECK_NESTED) — без них, иначе check.sh запустит сам себя
if [[ -z $CHECK_NESTED ]]; then
  export CHECK_NESTED=1
  for t in tests/test-*.sh; do
    [[ -f $t ]] || continue
    out=$(timeout 120 bash "$t" 2>&1) || bad "$t: $(grep -m 1 -E 'FAIL|✗' <<<"$out" || tail -n 1 <<<"$out")"
  done
fi

# ─── Данные установки: IP и UUID в коммитах ветки, индексе, рабочем дереве и ФАЙЛах
# Допустимы документационные сети (RFC 5737), петля, частные сети и публичные резолверы.
_ip_ok() {
  local a b c d; IFS=. read -r a b c d <<<"$1"
  (( 10#$a > 255 || 10#$b > 255 || 10#$c > 255 || 10#$d > 255 )) && return 0  # не адрес
  case $1 in
    0.0.0.0|127.*|10.*|192.168.*|169.254.*|192.0.2.*|198.51.100.*|203.0.113.*|255.*) return 0 ;;
    1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9|149.112.112.112|77.88.8.8|77.88.8.1) return 0 ;;
    94.140.14.14|94.140.15.15|208.67.222.222|208.67.220.220) return 0 ;;
  esac
  [[ $a == 172 ]] && (( 10#$b >= 16 && 10#$b <= 31 )) && return 0
  [[ $a == 100 ]] && (( 10#$b >= 64 && 10#$b <= 127 )) && return 0
  return 1
}
for f in "${extra[@]}"; do [[ -r $f ]] || bad "не прочитать $f"; done
base=$(git merge-base HEAD origin/main 2>/dev/null) || base=$(git hash-object -t tree /dev/null)
added=$(
  git log --format=%B "$base..HEAD" 2>/dev/null
  { git log -p --format= "$base..HEAD" 2>/dev/null; git diff --cached; git diff
    git ls-files -o --exclude-standard -z | xargs -0 -r sed 's/^/+/'; } | grep '^+[^+]'
  for f in "${extra[@]}"; do cat "$f"; done
)
for ip in $(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<<"$added" | sort -u); do
  _ip_ok "$ip" || bad "адрес $ip в ветке — не документационный, не частный, не резолвер (AGENTS.md)"
done
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-' <<<"$added" | grep -qv '^00000000-0000-' \
  && bad "UUID в ветке (AGENTS.md: данные установки — никогда)"

if (( fails )); then echo "checks: FAIL"; exit 1; fi
echo "checks: PASS"
