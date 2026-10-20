#!/usr/bin/env bash
# Тесты tests/lib.sh: отчёт и код выхода на каждом исходе; PASS — только когда всё прошло.
# Копия lib.sh — во временном «чекауте» с заглушкой check.sh (STUB=PASS|FAIL), vpr — в обход
# (_v_pr=true): ему нужны root, git и установленный xm.
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/tests"; cp "${BASH_SOURCE[0]%/*}/lib.sh" "$T/tests/"
cat >"$T/tests/check.sh" <<'STUB'
[[ $STUB == FAIL ]] && { echo "  ✗ заглушка"; echo "checks: FAIL"; exit 1; }
echo "checks: PASS"
STUB
fails=0
# case ИМЯ КОД_ВЫХОДА 'ожидаемые строки через |' 'тело скрипта'
case_() {
  local name=$1 want_rc=$2 want=$3 body=$4 out rc l
  printf 'source %q\n%s\n' "$T/tests/lib.sh" "$body" >"$T/s.sh"
  out=$(cd "$T" && bash "$T/s.sh" 2>&1); rc=$?
  [[ $rc == "$want_rc" ]] || { echo "FAIL $name: код $rc, ждали $want_rc"; echo "$out" | sed 's/^/    /'; fails=$((fails + 1)); return; }
  IFS='|' read -ra ls <<<"$want"
  for l in "${ls[@]}"; do
    grep -qxF -- "$l" <<<"$out" || { echo "FAIL $name: нет строки «$l»"; echo "$out" | sed 's/^/    /'; fails=$((fails + 1)); return; }
  done
}
case_ "всё прошло" 0 'code_pr: PASS|checks: PASS|integration: PASS|merge_ready: YES' \
  '_v_pr=true; vcheck a true; vexpect b "x y" echo "x y"; vreport'
case_ "проверка упала" 1 'code_pr: FAIL|merge_ready: NO|FAIL a — код 1' \
  '_v_pr=true; vcheck a false; vcheck b true; vreport'
case_ "таймаут" 1 'integration: FAIL — t — таймаут 1 с|merge_ready: NO' \
  '_v_pr=true; VTIMEOUT=1 vcheck t sleep 5; vreport'
case_ "ни одной проверки" 1 'integration: FAIL — ни одной проверки|merge_ready: NO' \
  '_v_pr=true; vreport'
case_ "без vpr" 2 'code_pr: NOT_RUN|merge_ready: UNKNOWN' \
  'vcheck a true; vreport'
case_ "обрыв до vreport" 1 'merge_ready: NO|FAIL скрипт — оборвался до vreport (код 3)' \
  '_v_pr=true; vcheck a true; exit 3'
case_ "предусловие" 2 'integration: BLOCKED — сеть — код 1|merge_ready: UNKNOWN' \
  '_v_pr=true; vneed сеть false; vcheck не_дошли false; vreport'
case_ "vpr вне git" 2 'merge_ready: UNKNOWN' \
  'vpr; vcheck a true; vreport'
case_ "vexpect: вывод совпал, код нет" 1 'merge_ready: NO' \
  '_v_pr=true; vexpect a x bash -c "echo x; exit 1"; vreport'
case_ "vexpect: вывод не совпал" 1 'FAIL a — ожидалось «x», получено «y»' \
  '_v_pr=true; vexpect a x echo y; vreport'
case_ "vsame: расхождения" 1 'rows: expected=2, actual=3|differences: 3|merge_ready: NO' \
  '_v_pr=true; vsnap "$VTMP/s" printf "a\nb\n"; vsame rows "$VTMP/s" printf "a\nc\nd\n"; vreport'
case_ "vsame: совпало" 0 'rows: expected=2, actual=2|differences: 0|merge_ready: YES' \
  '_v_pr=true; vsnap "$VTMP/s" printf "a\nb\n"; vsame rows "$VTMP/s" printf "a\nb\n"; vreport'
case_ "vsame: нет снимка" 1 'merge_ready: NO' \
  '_v_pr=true; vsnap "$VTMP/s" false; vsame rows "$VTMP/s" true; vreport'
STUB=FAIL case_ "checks упали" 1 'checks: FAIL — ✗ заглушка|integration: PASS|merge_ready: NO' \
  '_v_pr=true; vcheck a true; vreport'
(( fails == 0 )) || exit 1
echo "lib: ok"
