# Харнесс интеграционных проверок на живом VPS: tests/vps/<тема>.sh подключает его через source,
# владелец запускает «sudo bash tests/vps/<тема>.sh» из чекаута на ветке PR. Печатает провалы
# (по строке) и отчёт code_pr / checks / integration / merge_ready. Код выхода: 0 — merge_ready: YES,
# 1 — NO, 2 — UNKNOWN. PASS не бывает без проверок, при таймауте, при обрыве скрипта до vreport
# и без vpr: иначе неизвестно, какой код проверен.
#
#   vpr                        предусловие: чекаут = origin/<ветка>, установленные xm и ui = из чекаута
#   vneed   ИМЯ CMD…           предусловие: провал → integration: BLOCKED, скрипт кончается
#   vcheck  ИМЯ CMD…           CMD завершилась с кодом 0
#   vexpect ИМЯ ОЖИДАНИЕ CMD…  код 0 и stdout CMD (без хвостовых переводов строк) = ОЖИДАНИЕ
#   vsnap   ФАЙЛ CMD…          снимок до действия: stdout CMD в ФАЙЛ
#   vsame   ИМЯ ФАЙЛ CMD…      stdout CMD построчно = снимку; в отчёт — «ИМЯ: expected=, actual=»
#                              и differences (сумма по всем vsame)
#   vreport                    tests/check.sh на чекауте и отчёт; последняя строка скрипта
#
# CMD — программа, не функция (запускается через timeout); конвейер — bash -c '…'. Таймаут —
# VTIMEOUT секунд (60), для одной проверки: VTIMEOUT=180 vcheck … . Скрипт — без set -e.

VREPO=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
VTIMEOUT=${VTIMEOUT:-60}
VTMP=$(mktemp -d)
_v_run=0 _v_pr=false _v_done=false _v_block="" _v_diff=""
_v_fails=() _v_lines=()

_v_cut() { local s=${1//$'\n'/⏎}; (( ${#s} > 80 )) && s="${s:0:80}…"; printf '%s' "$s"; }

# _v_exec CMD… — stdout в $VTMP/out; провал — 1 и причина в _v_why
_v_exec() {
  local rc
  timeout "$VTIMEOUT" "$@" >"$VTMP/out" 2>"$VTMP/err"; rc=$?
  (( rc == 0 )) && return 0
  if (( rc == 124 )); then _v_why="таймаут ${VTIMEOUT} с"
  else _v_why="код $rc$(head -n 1 "$VTMP/err" | sed 's/^/: /')"; _v_why=$(_v_cut "$_v_why")
  fi
  return 1
}

_v_failed() { _v_fails+=("$1 — $2"); echo "FAIL $1 — $2"; }

vneed() {
  local name=$1; shift
  _v_exec "$@" && return 0
  _v_block="$name — $_v_why"
  vreport
}

vpr() {
  local br f
  [[ $EUID -eq 0 ]] || { _v_block="нужен root: sudo bash $0"; vreport; }
  br=$(git -C "$VREPO" symbolic-ref --quiet --short HEAD) \
    || { _v_block="чекаут $VREPO не на ветке"; vreport; }
  vneed "git fetch" git -C "$VREPO" fetch -q origin
  vneed "чекаут отстаёт от origin/$br: sudo git -C $VREPO checkout $br && sudo xm self-update" \
    test "$(git -C "$VREPO" rev-parse HEAD)" = "$(git -C "$VREPO" rev-parse "origin/$br" 2>/dev/null)"
  vneed "установленный xm не из чекаута: sudo xm self-update" cmp -s /usr/local/bin/xm "$VREPO/xm.sh"
  if [[ -d /usr/local/lib/xm/ui ]]; then
    for f in "$VREPO"/ui/*.*; do
      vneed "панель не из чекаута: sudo xm self-update" cmp -s "$f" "/usr/local/lib/xm/ui/${f##*/}"
    done
  fi
  _v_pr=true
}

vcheck() {
  local name=$1; shift
  _v_run=$((_v_run + 1))
  _v_exec "$@" || _v_failed "$name" "$_v_why"
}

vexpect() {
  local name=$1 exp=$2 act; shift 2
  _v_run=$((_v_run + 1))
  _v_exec "$@" || { _v_failed "$name" "$_v_why"; return; }
  act=$(<"$VTMP/out")
  [[ $act == "$exp" ]] || _v_failed "$name" "ожидалось «$(_v_cut "$exp")», получено «$(_v_cut "$act")»"
}

vsnap() {
  local file=$1; shift
  rm -f "$file"
  if _v_exec "$@"; then cp "$VTMP/out" "$file"; else _v_failed "снимок $file" "$_v_why"; fi
}

vsame() {
  local name=$1 snap=$2 d; shift 2
  _v_run=$((_v_run + 1))
  [[ -f $snap ]] || { _v_failed "$name" "нет снимка $snap"; return; }
  _v_exec "$@" || { _v_failed "$name" "$_v_why"; return; }
  _v_lines+=("$name: expected=$(grep -c '' "$snap"), actual=$(grep -c '' "$VTMP/out")")
  d=$(diff "$snap" "$VTMP/out" | grep -c '^[<>]')
  _v_diff=$(( ${_v_diff:-0} + d ))
  (( d == 0 )) || _v_failed "$name" "$d расхождений: $(diff "$snap" "$VTMP/out" | grep -m 3 '^[<>]' | cut -c 1-60 | paste -sd '|')"
}

vreport() {
  local integ checks code merge rc
  _v_done=true
  if [[ -n $_v_block ]]; then integ="BLOCKED — $_v_block"
  elif ! $_v_pr; then integ="BLOCKED — без vpr неизвестно, какой код проверен"
  elif (( ${#_v_fails[@]} )); then integ="FAIL — ${_v_fails[0]}"
    (( ${#_v_fails[@]} > 1 )) && integ+=" (+$(( ${#_v_fails[@]} - 1 )))"
  elif (( _v_run == 0 )); then integ="FAIL — ни одной проверки"
  else integ=PASS
  fi
  if bash "$VREPO/tests/check.sh" >"$VTMP/chk" 2>&1; then checks=PASS
  else checks="FAIL — $(_v_cut "$(grep -m 1 -v '^checks:' "$VTMP/chk" | sed 's/^ *//')")"
  fi
  case $integ in
    PASS) code=PASS ;;
    FAIL*) code=FAIL ;;
    *) code=NOT_RUN ;;
  esac
  if [[ $integ == PASS && $checks == PASS ]]; then merge=YES rc=0
  elif [[ $integ == FAIL* || $checks == FAIL* ]]; then merge=NO rc=1
  else merge=UNKNOWN rc=2
  fi
  printf '%s\n' "code_pr: $code" "checks: $checks" "integration: $integ" "${_v_lines[@]}"
  [[ -n $_v_diff ]] && echo "differences: $_v_diff"
  echo "merge_ready: $merge"
  rm -rf "$VTMP"
  exit "$rc"
}

_v_exit() {
  local rc=$?
  if ! $_v_done; then
    _v_failed "скрипт" "оборвался до vreport (код $rc)"
    vreport
  fi
}
trap _v_exit EXIT
