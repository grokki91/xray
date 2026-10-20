#!/usr/bin/env bash
# Вердикт по ретрансмитам в _tune_counters (xm.sh): без окна красного нет; при BBR и включённом MTU
# probing закрывать на сервере нечем — предупреждение; [✗] остаётся за тем, что чинит xm tune.
# Функции берутся из xm.sh как есть; nstat и sysctl — заглушки в формате настоящих команд,
# _backlog_report (ss, nginx) — не предмет проверки.
root=${BASH_SOURCE[0]%/*}/..
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
RED= YELLOW= GREEN= CYAN= BOLD= NC=
COUNTERS_SNAP="$T/snap"
eval "$(sed -n '/^ok()/,/^dwarn()/p; /^_counters_snap_write()/,/^}/p; /^_tune_counters()/,/^}/p' "$root/xm.sh")"
declare -F _tune_counters >/dev/null || { echo "FAIL: в xm.sh нет _tune_counters"; exit 1; }

# nstat -az [Имя…]: строка «#kernel», затем «Имя значение скорость»; без имён — все счётчики.
# Пустое значение — счётчика нет в выводе (как у ядра, где его не завели).
nstat() {
  local want=" ${*:2} " p n v
  echo "#kernel"
  for p in TcpOutSegs:$N_TX TcpRetransSegs:$N_RETR TcpExtTCPTimeouts:$N_TO \
           TcpExtListenOverflows:$N_LO TcpExtListenDrops:$N_LD UdpRcvbufErrors:$N_U; do
    n=${p%%:*}; v=${p#*:}
    [[ -n $v && ( $# -le 1 || $want == *" $n "* ) ]] && printf '%-32s%-19s%s\n' "$n" "$v" 0.0
  done
}
sysctl() {
  case $2 in
    net.ipv4.tcp_congestion_control) echo "$CC" ;;
    net.ipv4.tcp_mtu_probing)        echo "$MTU" ;;
    net.core.default_qdisc)          echo fq ;;
  esac
}
_backlog_report() { :; }

# scenario ВОЗРАСТ_СНИМКА_с «retr tx в снимке» «retr tx сейчас» CC MTU — вывод _tune_counters и
# итог «CRIT=… WARN=…». Возраст пустой — снимка нет. Таймауты, очереди и UDP — без находок.
scenario() {
  local age=$1 s_retr s_tx
  read -r s_retr s_tx <<<"$2"; read -r N_RETR N_TX <<<"$3"; CC=$4 MTU=$5
  N_TO=1000; N_LO=0; N_LD=0; N_U=0
  rm -f "$COUNTERS_SNAP"
  [[ -n $age ]] && echo "$(( $(date +%s) - age )) $s_retr $s_tx 1000 0 0 0" >"$COUNTERS_SNAP"
  DPI_CRIT=0; DPI_WARN=0
  _tune_counters 2>&1
  echo "CRIT=$DPI_CRIT WARN=$DPI_WARN"
}

fails=0
# want ИМЯ ВЫВОД ФРАГМЕНТ… — фрагмент обязан быть в выводе, «!ФРАГМЕНТ» — не обязан
want() {
  local name=$1 out=$2 w why; shift 2
  for w in "$@"; do
    if [[ $w == '!'* ]]; then [[ $out != *"${w:1}"* ]] && continue; why="лишнее «${w:1}»"
    else [[ $out == *"$w"* ]] && continue; why="нет «$w»"; fi
    echo "FAIL $name: $why"; sed 's/^/    /' <<<"$out"; fails=$((fails + 1)); return
  done
}

# Окно в 3 ч при 100 исходящих сегм/с (порог «знаменатель пуст» — 50); повторов в нём 7.4%
W_OLD="100000 1000000"
# ── Окна нет: итог с загрузки (13% повторов) — не вердикт
out=$(scenario 7200 "900000 7000000" "260000 2000000" bbr 1)
want "перезагрузка обнулила счётчики" "$out" "Счётчики обнулились" "судить рано" \
  "sudo xm tune --check" "каждый 8-й пакет" "!✗" "CRIT=0" "WARN=1"
out=$(scenario 60 "250000 1900000" "260000 2000000" bbr 1)
want "точка отсчёта свежая" "$out" "Точка отсчёта свежая" "судить рано" "!✗" "CRIT=0"
out=$(scenario "" "" "260000 2000000" bbr 1)
want "снимка нет" "$out" "Точка отсчёта поставлена" "судить рано" "!✗" "CRIT=0"
[[ -s $COUNTERS_SNAP ]] || { echo "FAIL снимка нет: точка отсчёта не записана"; fails=$((fails + 1)); }
# ── Окно есть: BBR и MTU probing стоят — закрывать нечем
out=$(scenario 10800 "$W_OLD" "179920 2080000" bbr 1)
want "окно, BBR и MTU probing стоят" "$out" "Ретрансмиты за 3 ч 0 мин: 7.40%" "каждый 14-й пакет" \
  "BBR и MTU уже настроены" "!✗" "CRIT=0" "WARN=1"
# ── Окно есть: то, что чинит xm tune, — красное
out=$(scenario 10800 "$W_OLD" "179920 2080000" bbr 0)
want "окно, MTU probing выключен" "$out" "[✗]" "MTU probing" "sudo xm tune" "CRIT=1"
out=$(scenario 10800 "$W_OLD" "179920 2080000" cubic 1)
want "окно, CUBIC" "$out" "[✗]" "Включи BBR" "CRIT=1"
# ── Окно есть: пороги ниже трёх процентов
out=$(scenario 10800 "$W_OLD" "105400 2080000" bbr 1)
want "окно, 0.5%" "$out" "[✓] Ретрансмиты за 3 ч 0 мин: 0.50% — норма" "CRIT=0 WARN=0"
out=$(scenario 10800 "$W_OLD" "121600 2080000" bbr 1)
want "окно, 2%" "$out" "заметные потери" "!✗" "CRIT=0" "WARN=1"
# ── Пустой вход: nstat без счётчиков — ни вердикта, ни падения
out=$(scenario 7200 "900000 7000000" "" bbr 1)
want "nstat без счётчиков" "$out" "!Ретрансмиты" "!✗" "MTU probing: 1" "CRIT=0"

(( fails == 0 )) || exit 1
echo "tune-counters: ok"
