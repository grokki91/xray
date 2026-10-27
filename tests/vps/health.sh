#!/usr/bin/env bash
# Приёмка xm health (этап 1) на живом VPS: факты для сверки, классы соединений эмуляцией iptables
# connbytes на петле отдельного сетевого пространства (сверка netlink с ss), самопроверка с настоящим
# и с неверным ключом, повторный on без дублей, off со стиранием, нагрузка юнитов по cgroup, тишина
# журнала, адресов на диске нет, curl самопроверки проверяет сертификат строго; справочно — петля
# хоста и из чего складывается CPU окна.
# Хост не трогается: правила эмуляции и nf_conntrack_acct — внутри своего пространства; прежнее
# состояние монитора (с данными) возвращается. Запуск: sudo bash tests/vps/health.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
CFG=/usr/local/etc/xray/config.json
HD=/var/lib/xm/health
PY=/usr/local/lib/xm/ui/health.py
# Как зовёт xm: модулем из каталога панели
HPY=(python3 -I -S -c "import sys; sys.path[:0] = ['${PY%/*}']; import health; sys.exit(health.main(sys.argv))")
vpr
# Второй прогон рядом сломал бы этот: общие пространство эмуляции, юниты и данные монитора
exec 9>/run/lock/xm-health-test.lock
vneed "другой прогон tests/vps/health.sh не идёт" flock -n 9
vneed "iptables есть" bash -c 'command -v iptables'
vneed "ip netns есть" bash -c 'ip netns list >/dev/null'
vneed "python3 есть" bash -c 'command -v python3'
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
fact "cgroup / memory.peak" "$(stat -fc %T /sys/fs/cgroup 2>/dev/null) / $([[ -f /sys/fs/cgroup/system.slice/memory.peak ]] && echo есть || echo нет)"
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
# Эмуляция — в своём сетевом пространстве: своя петля, свои правила и conntrack. На петле хоста её
# искажают чужие правила (ufw, соседи, остаток прерванного прогона) — на ней соединения вставали
# «после ClientHello» и без единого правила эмуляции. Порт внутри пространства всегда свободен.
NS=xm-health-test P=39100
ns_del() { ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$NS" 2>/dev/null; }
emu_cleanup() {
  ip netns exec "$NS" iptables -F INPUT 2>/dev/null
  [[ -n $SRV ]] && kill "$SRV" "$CLI" 2>/dev/null; SRV="" CLI=""
}
finish() {
  emu_cleanup; ns_del
  [[ -n $HSRV ]] && kill "$HSRV" "$HCLI" 2>/dev/null; HSRV="" HCLI=""
  if $WAS_ON && ! [[ -f /etc/systemd/system/xm-health.timer ]]; then
    [[ -d $VTMP/hd-backup ]] && { rm -rf "$HD"; cp -a "$VTMP/hd-backup" "$HD"; }
    xm health on >/dev/null 2>&1
  fi
}
trap 'finish; _v_exit' EXIT
vsnap "$VTMP/input" iptables -S INPUT
ns_del                                         # остаток прерванного прогона
vneed "своё сетевое пространство для эмуляции" bash -c "ip netns add $NS && ip -n $NS link set lo up"
vneed "conntrack с учётом байт в нём" ip netns exec "$NS" sysctl -qw net.netfilter.nf_conntrack_acct=1

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

# bytes_acked сокетов сервера по ss (через пробел, по возрастанию). Нулевые поля ss не печатает:
# нет поля у сокета — 0, а не пропуск.
ss_acked() {
  ip netns exec "$NS" ss -tinH state established state fin-wait-1 "( sport = :$P )" | awk '
    /^[^ \t]/ { if (n++) print v; v = 0; next }
    { for (i = 1; i <= NF; i++) if ($i ~ /^bytes_acked:/) v = substr($i, 13) }
    END { if (n) print v }' | sort -n | paste -sd' '
}
# scen ИМЯ ОЖИДАНИЕ ПАУЗА [ПРАВИЛО…] — дроп на входе петли, как потеря в сети: в OUTPUT ядро видит
# ошибку отправки, и unacked остаётся 0 — признака «клиент перестал отвечать» не было бы.
scen() {
  local name=$1 exp=$2 wait=$3; shift 3
  (( $# )) && ip netns exec "$NS" iptables -I INPUT -i lo -p tcp "$@" -j DROP
  ip netns exec "$NS" python3 "$VTMP/srv.py" "$P" & SRV=$!
  sleep 0.5
  ip netns exec "$NS" python3 "$VTMP/cli.py" "$P" & CLI=$!
  sleep "$wait"
  vexpect "класс: $name" "$exp" ip netns exec "$NS" xm health sample --port "$P" --print --loopback
  [[ $name == "10–32 КБ" ]] && vexpect "netlink = ss: bytes_acked зависших" "$(ss_acked)" \
    ip netns exec "$NS" python3 -B -c "import sys; sys.path.insert(0, '${PY%/*}'); import health; print(' '.join(str(c['acked']) for c in sorted(health.connections($P, True), key=lambda c: c['acked'])))"
  emu_cleanup
  sleep 1
}
scen "без правила — норма" "norm=3 pre=0 post=0 mid=0 f16=0 late=0" 6
scen "до ClientHello" "norm=0 pre=3 post=0 mid=0 f16=0 late=0" 12 \
  --dport "$P" -m connbytes --connbytes 3: --connbytes-dir original --connbytes-mode packets
scen "после ClientHello" "norm=0 pre=0 post=3 mid=0 f16=0 late=0" 6 \
  --sport "$P" -m connbytes --connbytes 2: --connbytes-dir reply --connbytes-mode packets
scen "10–32 КБ" "norm=0 pre=0 post=0 mid=0 f16=3 late=0" 6 \
  --sport "$P" -m connbytes --connbytes 16384: --connbytes-dir reply --connbytes-mode bytes
scen "позже 32 КБ" "norm=0 pre=0 post=0 mid=0 f16=0 late=3" 6 \
  --sport "$P" -m connbytes --connbytes 65536: --connbytes-dir reply --connbytes-mode bytes
ns_del
vsame   "правила INPUT хоста как были" "$VTMP/input" iptables -S INPUT
vexpect "nf_conntrack_acct хоста как был" "$ACCT0" sysctl -n net.netfilter.nf_conntrack_acct

# ─── Справочно: петля хоста. Её чужие правила (адреса скрыты) и те же соединения без единого правила
# эмуляции: не «норма» — на хосте что-то режет петлю; tcp_info сервера и клиента показывает где.
mask() { sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?/<адрес>/g; s/[0-9a-f]*:[0-9a-f:]*:[0-9a-f]+(\/[0-9]+)?/<адрес>/g'; }
fact "INPUT хоста, кроме ufw" "$(iptables -S INPUT | grep -vE '^-P |-j ufw-' | mask | paste -sd'|')"
fact "правил с connbytes на хосте" "$(iptables-save 2>/dev/null | grep -c -- '-m connbytes')"
fact "таблицы nft" "$(nft list tables 2>/dev/null | awk '{print $2 "/" $3}' | paste -sd' ')"
HP=""; for p in $(seq 39100 39199); do ss -tlnH "( sport = :$p )" | grep -q . || { HP=$p; break; }; done
if [[ -n $HP ]]; then
  python3 "$VTMP/srv.py" "$HP" & HSRV=$!
  sleep 0.5
  python3 "$VTMP/cli.py" "$HP" & HCLI=$!
  sleep 6
  ti() { ss -tinH state established "( $1 = :$HP )" | awk 'NR == 2' \
    | grep -oE '\b(unacked|backoff|retrans|bytes_acked|bytes_received):[0-9/]+' | paste -sd' '; }
  fact "петля хоста, порт без правил" "$(xm health sample --port "$HP" --print --loopback 2>&1)"
  fact "  tcp_info сервера / клиента" "$(ti sport) / $(ti dport)"
  kill "$HSRV" "$HCLI" 2>/dev/null; HSRV="" HCLI=""
fi

# ─── Самопроверка: настоящий ключ — прошла, неверный — «сбой сервера: рукопожатие»
VTIMEOUT=90 vexpect "самопроверка проходит" "ok" bash -c 'xm health run --dry | jq -r .self.r'
VTIMEOUT=90 vexpect "неверный ключ → сбой сервера" "server fail handshake" \
  bash -c 'xm health run --bad-key | jq -r "[.vd, .self.r, .self.at] | join(\" \")"'
if $STATS_ON; then
  xm stats collect >/dev/null 2>&1; xm health run --dry >/dev/null 2>&1; xm stats collect >/dev/null 2>&1
  fact "трафик самопроверки" "$(tail -n1 /var/lib/xm/stats/samples.jsonl | jq -r '"\(.up + .down) байт (порог трафика клиентов 65536)"')"
fi

# ─── curl самопроверки проверяет сертификат строго: корень — по хешу в системном каталоге (без
# загрузки всего набора CA), чужой самоподписанный — отказ, настоящий generate_204 — 204
eval "$(sed -n '/^HEALTH_CERTS=/p; /^_health_tls()/,/^}/p' /usr/local/bin/xm)"; _health_tls
vexpect "curl самопроверки: корни — по системному каталогу" "--capath $HEALTH_CERTS" printf "%s %s" "${TLS[@]:0:2}"
TP=""; for p in $(seq 39200 39299); do ss -tlnH "( sport = :$p )" | grep -q . || { TP=$p; break; }; done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$VTMP/tk.pem" -out "$VTMP/tc.pem" \
  -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null
python3 - "$VTMP" "$TP" >/dev/null 2>&1 <<'EOF2' & TSRV=$!
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", int(sys.argv[2])), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[1] + "/tc.pem", sys.argv[1] + "/tk.pem")
s.socket = c.wrap_socket(s.socket, server_side=True); s.timeout = 30; s.handle_request(); s.handle_request()
EOF2
sleep 1
vexpect "curl самопроверки: самоподписанный — отказ" "000" \
  bash -c 'curl -s --noproxy "*" -o /dev/null -w "%{http_code}" --max-time 5 "${@:2}" "https://localhost:$1/"; true' _ "$TP" "${TLS[@]}"
vexpect "curl самопроверки: generate_204 — с проверкой" "204" \
  bash -c 'curl -s --noproxy "*" -o /dev/null -w "%{http_code}" --max-time 5 "$@" https://www.google.com/generate_204; true' _ "${TLS[@]}"
kill "$TSRV" 2>/dev/null

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
for i in 1 2 3; do vcheck "опрос юнитом ($i)" systemctl start xm-health-sample.service; done
VTIMEOUT=90 vcheck "окно юнитом" systemctl start xm-health.service
vexpect "окно записано, самопроверка прошла" "ok" bash -c "tail -n1 $HD/windows.jsonl | jq -r .self.r"
fact "соединения окна" "$(tail -n1 "$HD/windows.jsonl" | jq -r '"одновременно с адреса до \(.c.pmax), новых с адреса за опрос до \(.c.pnew), вердикт \(.vd)"')"
VTIMEOUT=90 vcheck "второе окно юнитом" systemctl start xm-health.service
$STATS_ON && xm stats collect >/dev/null 2>&1
VTIMEOUT=90 vcheck "ручной run" xm health run
$STATS_ON && fact "трафик окна, самопроверка исключена" "$(tail -n1 /var/lib/xm/stats/samples.jsonl | jq -r '"\(.up + .down) байт (выше — без исключения)"')"
vexpect "дублей окон нет" "0" bash -c "jq -r .t $HD/windows.jsonl | sort | uniq -d | wc -l"
vexpect "адресов на диске нет" "" bash -c "grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' $HD /run/xm-health | sort -u; true"
vcheck  "отчёт" bash -c 'xm health | grep -q "Сервер готов"'
vcheck  "отчёт --json" bash -c 'xm health --json | jq -e ".band | length == 96" >/dev/null'
# Нагрузка — по cgroup юнитов (сами запуски пишут расход, окно его хранит); на сутки — 1440
# опросов и 288 окон по средним за прогон. load берёт и окна, и ещё не забранное в окно: итог не
# зависит от того, записал ли таймер окно этого слота раньше теста.
LOADJS=$("${HPY[@]}" load | jq -c '. + {
    sample_ms: (if .s.runs > 0 then .s.cpu_ms / .s.runs | floor else null end),
    window_ms: (if .w.runs > 0 then .w.cpu_ms / .w.runs | floor else null end),
    peak_mb: ([.s.peak_kb, .w.peak_kb] | map(select(. != null)) | if length > 0 then max / 1024 else null end)}
  | . + {cpu_pct_day: (if .sample_ms != null and .window_ms != null
                        then (.sample_ms * 1440 + .window_ms * 288) / 864000 else null end)}')
fact "нагрузка (оценка на сутки)" "$(jq -c '{s, w, sample_ms, window_ms, cpu_pct_day, peak_mb}' <<<"$LOADJS")"
vexpect "нагрузка измерена юнитами: опросы и окна" "true" jq -r '.s.runs >= 3 and .w.runs >= 2' <<<"$LOADJS"
vexpect "CPU ≤ 0.3% ядра на сутки" "true" jq -r '.cpu_pct_day != null and .cpu_pct_day <= 0.3' <<<"$LOADJS"
vexpect "пик памяти ≤ 77 МБ (запас до MemoryMax 96M)" "true" jq -r '.peak_mb != null and .peak_mb <= 77' <<<"$LOADJS"
# Справочно — из чего складывается CPU окна, мс на запуск (time: процесс с детьми): сойдётся бюджет
# или нет, по этой строке видно, что в окне дорого.
cpu() { local TIMEFORMAT='%3U %3S' t; t=$( { time "$@" >/dev/null 2>&1; } 2>&1 ); awk '{printf "%d", ($1 + $2) * 1000}' <<<"$t"; }
API=$(jq -r '.api.listen // empty' "$CFG")
fact "CPU частей окна, мс" "$(printf '%s ' "xm=$(cpu xm health __none)" "jq=$(cpu jq -r '.inbounds[0].port' "$CFG")" \
  "python=$(cpu python3 -I -S -c pass)" "xray-version=$(cpu xray version)" \
  ${API:+"xray-api=$(cpu xray api statsquery --server="$API" -pattern 'user>>>' -t 3)"} \
  "curl-204=$(cpu curl -s -o /dev/null --max-time 5 https://www.google.com/generate_204)" \
  "curl-204-каталог=$(cpu curl -s -o /dev/null --max-time 5 "${TLS[@]}" https://www.google.com/generate_204)" \
  "journalctl=$(cpu journalctl -q -u xray-watchdog.service --since -5min -o cat --no-pager)" \
  "systemctl-show=$(cpu systemctl show -p InvocationID --value xray nginx)" \
  "окно-py=$(cpu "${HPY[@]}" window --self '{"r":"ok"}' --dry --config "$CFG" --xm /usr/local/bin/xm --xray "$(command -v xray)")" \
  "run-dry=$(cpu xm health run --dry)")"
# LogLevelMax=notice: «Starting/Finished» на каждый запуск в журнал не идут, сбоев за прогон нет, а
# свой вывод юниты пишут с warning — его быть не должно. «Consumed» systemd поднимает до notice сам
# на тяжёлом запуске (холодный кеш) — это не спам. Провал показывает сами строки.
vexpect "запуски юнитов не пишут в журнал" "" \
  bash -c "journalctl -q -u xm-health-sample.service -u xm-health.service --since '$T0' -o cat --no-pager | grep -v Consumed; true"
vcheck  "status: нагрузка видна, юниты свежие" bash -c 'out=$(xm health status); grep -q "Нагрузка" <<<"$out" && ! grep -q "прежней версии" <<<"$out"'
vcheck  "off" xm health off
vexpect "off: юнитов и данных нет" "0" bash -c "ls -d /etc/systemd/system/xm-health* $HD /run/xm-health 2>/dev/null | wc -l"
$STATS_ON && vexpect "off: таймер xm-stats вернулся" "active" systemctl is-active xm-stats.timer

# ─── Целостность: Xray цел, сквозной путь жив
vcheck "конфиг принят" xray -test -config "$CFG"
VTIMEOUT=90 vcheck "сквозной путь" xm selftest
finish
vreport
