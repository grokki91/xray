#!/usr/bin/env bash
# Приёмка xm health (этап 1) на живом VPS: факты для сверки, классы соединений эмуляцией iptables
# connbytes на тестовом порту петли (сверка netlink с ss), самопроверка с настоящим и с неверным
# ключом, повторный on без дублей, off со стиранием, нагрузка юнитов, адресов на диске нет.
# Рабочий трафик не трогается: правила — только -i lo и тестовый порт; правила, nf_conntrack_acct
# и прежнее состояние монитора (с данными) возвращаются. Запуск: sudo bash tests/vps/health.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
CFG=/usr/local/etc/xray/config.json
HD=/var/lib/xm/health
PY=/usr/local/lib/xm/ui/health.py
vpr
vneed "iptables есть" command -v iptables
vneed "python3 есть" command -v python3
vneed "health.py установлен (sudo xm self-update)" test -f "$PY"
vneed "Xray работает" systemctl is-active --quiet xray

# ─── Факты: числа и версии, без адресов — по ним сверяется, что код угадал о сервере
fact() { printf '  · %-28s %s\n' "$1" "$2"; }
PUB=$(jq -r '.inbounds[0].port' "$CFG")
[[ -f /etc/nginx/stream-enabled/front.conf ]] && { PUB=$(awk -F= '$1=="PORT"{print $2}' /usr/local/etc/xray/front.conf 2>/dev/null); PUB=${PUB:-443}; }
echo "Факты:"
fact "ОС / ядро" "$(lsb_release -ds 2>/dev/null) / $(uname -r)"
fact "виртуализация" "$(systemd-detect-virt 2>/dev/null)"
fact "systemd / python / ss" "$(systemctl --version | awk 'NR==1{print $2}') / $(python3 -V 2>&1 | cut -d' ' -f2) / $(ss -V 2>&1 | head -1)"
fact "iptables" "$(iptables -V 2>&1)"
fact "xray" "$(xray version 2>/dev/null | awk 'NR==1{print $2}')"
fact "нагрузка / свободно RAM" "$(cut -d' ' -f1-3 /proc/loadavg) / $(awk '$1=="MemAvailable:"{print int($2/1024)" МБ"}' /proc/meminfo)"
fact "публичный порт слушают" "$(ss -tlnH "( sport = :$PUB )" | awk '{a = $4; sub(/:[0-9]+$/, "", a)
  print (a ~ /^(0\.0\.0\.0|\[::\]|\*|127\.0\.0\.1)$/ ? a : "свой-адрес")}' | sort -u | paste -sd' ')"
fact "фронт" "$([[ -f /etc/nginx/stream-enabled/front.conf ]] && echo вкл || echo выкл)"
fact "xm stats (API)" "$(jq -r '.api.listen // "выкл"' "$CFG" | sed 's/:.*//')"
fact "таймер xm-stats" "$(systemctl is-active xm-stats.timer 2>&1)"
fact "health до теста" "$([[ -f /etc/systemd/system/xm-health.timer ]] && echo "вкл, окон $(wc -l < "$HD/windows.jsonl" 2>/dev/null || echo 0)" || echo выкл)"
fact "journald" "$(grep -hsE '^Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf | tail -1)$( [[ -d /var/log/journal ]] && echo ' /var/log/journal есть' || echo ' только /run (volatile)')"
fact "строка Consumed (образец)" "$(journalctl -q -u xray-watchdog.service -o cat --no-pager -n 200 2>/dev/null | grep -m1 -oE 'Consumed .*' || echo нет)"
fact "ротация логов nginx" "$(grep -hE '^\s*(daily|weekly|compress|delaycompress|rotate)' /etc/logrotate.d/nginx 2>/dev/null | tr -s ' \n' ' ')"
for L in /var/log/nginx/reality_fallback_error.log /var/log/nginx/front_error.log; do
  fact "${L##*/}" "$([[ -f $L ]] && echo "$(wc -l < "$L") строк, .1: $([[ -f $L.1 ]] && echo есть || echo нет)" || echo нет)"
done
fact "соединения сейчас (классы)" "$(python3 "$PY" sample --port "$PUB" --print 2>&1)"
fact "ss: ESTAB+FIN-WAIT-1 на порту" "$(ss -tnH state established state fin-wait-1 "( sport = :$PUB )" | grep -vcE ' (127\.|\[::1\]|\[::ffff:127\.)')"
fact "watchdog: починки за 7 дн" "$(journalctl -q -u xray-watchdog.service --since -7d -o cat --no-pager 2>/dev/null | grep -c перезапускаю)"

# ─── Подготовка: прежнее состояние монитора — вернуть в конце вместе с данными
WAS_ON=false; [[ -f /etc/systemd/system/xm-health.timer ]] && WAS_ON=true
STATS_ON=false; [[ -n "$(jq -r '.api.listen // empty' "$CFG")" ]] && STATS_ON=true
$WAS_ON && [[ -d $HD ]] && cp -a "$HD" "$VTMP/hd-backup"
modprobe nf_conntrack 2>/dev/null
ACCT0=$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null)
P=""; for p in $(seq 39100 39199); do ss -tlnH "( sport = :$p )" | grep -q . || { P=$p; break; }; done
vneed "свободный тестовый порт 39100–39199" test -n "$P"
RULES=()
emu_cleanup() {
  local r
  for r in "${RULES[@]}"; do eval "iptables -D INPUT $r" 2>/dev/null; done
  RULES=()
  [[ -n $SRV ]] && kill "$SRV" "$CLI" 2>/dev/null; SRV="" CLI=""
}
finish() {
  emu_cleanup
  [[ -n $ACCT0 ]] && sysctl -qw net.netfilter.nf_conntrack_acct="$ACCT0"
  if $WAS_ON && ! [[ -f /etc/systemd/system/xm-health.timer ]]; then
    [[ -d $VTMP/hd-backup ]] && { rm -rf "$HD"; cp -a "$VTMP/hd-backup" "$HD"; }
    xm health on >/dev/null 2>&1
  fi
}
trap 'finish; _v_exit' EXIT
vsnap "$VTMP/input" iptables -S INPUT

cat >"$VTMP/srv.py" <<'EOF'
# Сервер как TLS: молчит до первых байт клиента, потом отдаёт 128 КБ по 1 КБ (гранулярность для connbytes)
import socket, sys, threading, time
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", int(sys.argv[1]))); ls.listen(64)
def h(c):
    try:
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if c.recv(4096):
            for _ in range(128):
                c.send(b"x" * 1024); time.sleep(0.01)
        time.sleep(600)
    except OSError:
        pass
while True:
    c, _ = ls.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
cat >"$VTMP/cli.py" <<'EOF'
# Три клиента: «ClientHello» 300 б, читают всё, держат соединение
import socket, sys, threading, time
def one():
    s = socket.socket(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
    s.connect(("127.0.0.1", int(sys.argv[1]))); s.send(b"h" * 300)
    try:
        while s.recv(65536): pass
    except OSError:
        pass
for _ in range(3): threading.Thread(target=one, daemon=True).start()
time.sleep(600)
EOF

# scen ИМЯ ОЖИДАНИЕ ПАУЗА [ПРАВИЛО…] — дроп на входе петли, как потеря в сети: в OUTPUT ядро видит
# ошибку отправки, и unacked остаётся 0 — признака «клиент перестал отвечать» не было бы.
scen() {
  local name=$1 exp=$2 wait=$3; shift 3
  if (( $# )); then
    iptables -I INPUT -i lo -p tcp "$@" -j DROP && RULES+=("-i lo -p tcp $* -j DROP")
  fi
  python3 "$VTMP/srv.py" "$P" & SRV=$!
  sleep 0.5
  python3 "$VTMP/cli.py" "$P" & CLI=$!
  sleep "$wait"
  vexpect "класс: $name" "$exp" xm health sample --port "$P" --print --loopback
  [[ $name == "10–32 КБ" ]] && vexpect "netlink = ss: bytes_acked зависших" \
    "$(ss -tinH "( sport = :$P )" | grep -oE 'bytes_acked:[0-9]+' | cut -d: -f2 | sort -n | paste -sd' ')" \
    python3 -B -c "import sys; sys.path.insert(0, '${PY%/*}'); import health; print(' '.join(str(c['acked']) for c in sorted(health.connections($P, True), key=lambda c: c['acked'])))"
  emu_cleanup
  sleep 1
}
sysctl -qw net.netfilter.nf_conntrack_acct=1
scen "без правила — норма" "norm=3 pre=0 post=0 mid=0 f16=0 late=0" 6
scen "до ClientHello" "norm=0 pre=3 post=0 mid=0 f16=0 late=0" 12 \
  --dport "$P" -m connbytes --connbytes 3: --connbytes-dir original --connbytes-mode packets
scen "после ClientHello" "norm=0 pre=0 post=3 mid=0 f16=0 late=0" 6 \
  --sport "$P" -m connbytes --connbytes 2: --connbytes-dir reply --connbytes-mode packets
scen "10–32 КБ" "norm=0 pre=0 post=0 mid=0 f16=3 late=0" 6 \
  --sport "$P" -m connbytes --connbytes 16384: --connbytes-dir reply --connbytes-mode bytes
scen "позже 32 КБ" "norm=0 pre=0 post=0 mid=0 f16=0 late=3" 6 \
  --sport "$P" -m connbytes --connbytes 65536: --connbytes-dir reply --connbytes-mode bytes
sysctl -qw net.netfilter.nf_conntrack_acct="$ACCT0"
vsame   "правила INPUT как были" "$VTMP/input" iptables -S INPUT
vexpect "nf_conntrack_acct как был" "$ACCT0" sysctl -n net.netfilter.nf_conntrack_acct

# ─── Самопроверка: настоящий ключ — прошла, неверный — «сбой сервера: рукопожатие»
VTIMEOUT=90 vexpect "самопроверка проходит" "ok" bash -c 'xm health run --dry | jq -r .self.r'
VTIMEOUT=90 vexpect "неверный ключ → сбой сервера" "server fail handshake" \
  bash -c 'xm health run --bad-key | jq -r "\(.vd) \(.self.r) \(.self.at)"'
if $STATS_ON; then
  xm stats collect >/dev/null 2>&1; xm health run --dry >/dev/null 2>&1; xm stats collect >/dev/null 2>&1
  fact "трафик самопроверки" "$(tail -n1 /var/lib/xm/stats/samples.jsonl | jq -r '"\(.up + .down) байт (порог трафика клиентов 65536)"')"
fi

# ─── on / повторный on / окно / off
xm health off >/dev/null 2>&1
T0=$(date '+%F %T')
vcheck  "on"                       xm health on
vsnap   "$VTMP/units" bash -c 'sha256sum /etc/systemd/system/xm-health*.{service,timer}'
vexpect "повторный on: юниты не менялись" "1" bash -c 'xm health on | grep -c "уже включён"'
vsame   "юниты после повторного on" "$VTMP/units" bash -c 'sha256sum /etc/systemd/system/xm-health*.{service,timer}'
vexpect "таймеров два" "2" bash -c 'systemctl list-timers --all --no-legend "xm-health*" | grep -c xm-health'
$STATS_ON && vexpect "таймер xm-stats снят, замер — в окне" "inactive" bash -c 'systemctl is-active xm-stats.timer; true'
$STATS_ON && vcheck  "xm stats status: замер работает" bash -c 'xm stats status | grep -q "Таймер замеров работает"'
vcheck  "опрос юнитом" systemctl start xm-health-sample.service
VTIMEOUT=90 vcheck "окно юнитом" systemctl start xm-health.service
vexpect "окно записано, самопроверка прошла" "ok" bash -c "tail -n1 $HD/windows.jsonl | jq -r .self.r"
VTIMEOUT=90 vcheck "ручной run" xm health run
vexpect "дублей окон нет" "0" bash -c "jq -r .t $HD/windows.jsonl | sort | uniq -d | wc -l"
vexpect "адресов на диске нет" "" bash -c "grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' $HD /run/xm-health | sort -u; true"
vcheck  "отчёт" bash -c 'xm health | grep -q "Сервер готов"'
vcheck  "отчёт --json" bash -c 'xm health --json | jq -e ".band | length == 96" >/dev/null'
# Нагрузка: запуски с начала теста по «Consumed» systemd, на сутки — 1440 опросов и 288 окон
LOADJS=$(python3 -B - "$T0" <<'EOF'
import json, re, subprocess, sys
sys.path.insert(0, "/usr/local/lib/xm/ui"); import health as h
r = {}
for u in ("xm-health-sample.service", "xm-health.service"):
    out = subprocess.run(["journalctl", "-q", "-u", u, "--since", sys.argv[1], "-o", "cat", "--no-pager"],
                         capture_output=True, text=True).stdout
    m = [x for x in map(h._CONSUMED.search, out.splitlines()) if x]
    r[u] = (max(h._ms(x.group(1), x.group(2), x.group(3)) for x in m) if m else None,
            max((float(x.group(4)) * {"K": 1 / 1024, "M": 1, "G": 1024}[x.group(5)] for x in m if x.group(4)), default=None))
s, w = r["xm-health-sample.service"], r["xm-health.service"]
cpu = None if s[0] is None or w[0] is None else (s[0] * 1440 + w[0] * 288) / 864000
print(json.dumps({"sample_ms": s[0], "window_ms": w[0], "cpu_pct_day": cpu, "peak_mb": max([x for x in (s[1], w[1]) if x] or [0]) or None}))
EOF
)
fact "нагрузка (оценка на сутки)" "$LOADJS"
vexpect "CPU ≤ 0.3% ядра на сутки" "true" jq -r '.cpu_pct_day != null and .cpu_pct_day <= 0.3' <<<"$LOADJS"
vexpect "пик памяти ≤ 77 МБ (запас до MemoryMax 96M)" "true" jq -r '.peak_mb != null and .peak_mb <= 77' <<<"$LOADJS"
vcheck  "off" xm health off
vexpect "off: юнитов и данных нет" "0" bash -c "ls /etc/systemd/system/xm-health* $HD /run/xm-health 2>/dev/null | wc -l"
$STATS_ON && vexpect "off: таймер xm-stats вернулся" "active" systemctl is-active xm-stats.timer

# ─── Целостность: Xray цел, сквозной путь жив
vcheck "конфиг принят" xray -test -config "$CFG"
VTIMEOUT=90 vcheck "сквозной путь" xm selftest
finish
vreport
