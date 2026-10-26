#!/usr/bin/env bash
# Журнал здоровья (ui/health.py): классы соединений по tcp_info, счёт «один раз за жизнь» по
# cookie, вердикт окна, логи со смещения с ротацией, трафик из замеров xm stats, дубли окон,
# отсутствие адресов на диске, полоса отчёта. Сокеты ядра — заглушка connections() с полями
# netlink в том виде, в каком их отдаёт ядро (сверку с ss держит tests/vps/health.sh); остальное —
# настоящий код на временных каталогах.
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export XM_HEALTH_DIR="$T/data" XM_HEALTH_RUN="$T/run" XM_STATS_SAMPLES="$T/samples.jsonl" PYTHONDONTWRITEBYTECODE=1
out=$(python3 - "$root/ui" "$T" <<'PY' 2>&1
import json, os, sys, time
sys.path.insert(0, sys.argv[1]); T = sys.argv[2]
import health as h

fails = []
def want(name, got, exp):
    if got != exp:
        fails.append("%s: ожидалось %r, получено %r" % (name, exp, got))

# Поля — как их отдаёт netlink (tcp_info со стороны сервера); значения сняты с эмуляции
# iptables connbytes на петле: unacked > 0 и backoff >= 2 — клиент перестал отвечать.
def sock(ck, peer, received, acked, unacked=0, backoff=0, lastrcv=500):
    return {"state": 1, "sport": 443, "dport": 50000, "cookie": ck, "peer": peer,
            "received": received, "acked": acked, "unacked": unacked, "backoff": backoff, "lastrcv": lastrcv}

# ── Классы
want("норма: всё подтверждено", h.classify(sock("1", "x", 300, 131072)), "norm")
want("до ClientHello: тишина 12 с", h.classify(sock("1", "x", 0, 0, lastrcv=12000)), "pre")
want("до ClientHello: молчит 3 с — ещё норма", h.classify(sock("1", "x", 0, 0, lastrcv=3000)), "norm")
want("после ClientHello", h.classify(sock("1", "x", 300, 1, unacked=10, backoff=3)), "post")
want("10–32 КБ", h.classify(sock("1", "x", 300, 15360, unacked=10, backoff=4)), "f16")
want("1–10 КБ — отдельно", h.classify(sock("1", "x", 300, 5000, unacked=4, backoff=2)), "mid")
want("позже 32 КБ", h.classify(sock("1", "x", 300, 63488, unacked=10, backoff=4)), "late")
want("один RTO — ещё не зависание", h.classify(sock("1", "x", 300, 15360, unacked=10, backoff=1)), "norm")
want("backoff без неподтверждённых — норма", h.classify(sock("1", "x", 300, 15360, unacked=0, backoff=4)), "norm")
want("tcp_info короче 136 б — без класса", h.classify({"cookie": "1", "peer": "x"}), None)

# ── Опрос и окно: зависшее считается один раз за жизнь, даже если живёт три окна
os.makedirs(h.DATA_DIR); json.dump({"port": 443}, open(os.path.join(h.DATA_DIR, "params.json"), "w"))
cur = []
h.connections = lambda port, loopback=False: list(cur)
stalled = [sock("a%d" % i, "192.0.2.%d" % i, 300, 15360, 10, 4) for i in range(3)]
cur = stalled + [sock("n1", "198.51.100.7", 300, 90000)]
h.cmd_sample({}); h.cmd_sample({})
w1 = h._close_conns(False)
want("окно 1: заморозки", (w1["f16"], w1["norm"], w1["new"], w1["smp"], w1["cmax"]), (3, 1, 4, 2, 4))
h.cmd_sample({})
w2 = h._close_conns(False)
want("окно 2: те же зависшие не считаются снова", (w2["f16"], w2["norm"], w2["new"]), (0, 1, 0))
cur = []
h.cmd_sample({})
w3 = h._close_conns(False)
want("окно 3: закрытые забыты", (w3["f16"], w3["norm"], w3["cmax"]), (0, 0, 0))
want("после окна 3 состояние пусто", json.load(open(os.path.join(h.RUN_DIR, "conns.json")))["c"], {})
# Закрылось между опросами одного окна — всё равно в этом окне
cur = [sock("z1", "192.0.2.50", 300, 1, 5, 3)]
h.cmd_sample({}); cur = []; h.cmd_sample({})
want("закрылось до конца окна — учтено", h._close_conns(False)["post"], 1)
want("без опросов — нет данных о соединениях", h._close_conns(False), None)
# Шквал: 31 соединение с одного адреса
cur = [sock("s%d" % i, "203.0.113.9", 300, 2000) for i in range(31)]
h.cmd_sample({})
want("шквал: максимум с адреса", h._close_conns(False)["pmax"], 31)
cur = []

# ── Вердикт окна — первая подходящая строка
V = h.verdict
tr = h.TRAFFIC_MIN
want("сбой сервера сильнее всего", V({"self": {"r": "fail", "at": "dns"}, "c": {"f16": 5}, "tr": tr}), "server")
want("заморозка при трафике", V({"self": {"r": "ok"}, "c": {"f16": 2, "post": 1}, "tr": tr}), "freeze")
want("заморозка без трафика — подозрение", V({"self": {"r": "ok"}, "c": {"f16": 3}, "tr": None}), "suspect")
want("2 зависших — не заморозка", V({"self": {"r": "ok"}, "c": {"f16": 2}, "tr": tr}), "ok")
want("pre и late — не заморозка", V({"self": {"r": "ok"}, "c": {"pre": 9, "late": 9}, "tr": tr}), "ok")
want("ретрансмиты 3% при 50 сегм/с", V({"self": {"r": "ok"}, "tcp": {"pct": 3.0}, "tr": tr}), "degraded")
want("шквал — деградация", V({"self": {"r": "ok"}, "c": {"pmax": 31}, "tr": None}), "degraded")
want("тишина — нет данных, не сбой", V({"self": {"r": "ok"}, "c": {}, "tr": None}), "nodata")
want("трафик самопроверки — не трафик клиентов", V({"self": {"r": "ok"}, "tr": 9000}), "nodata")
want("пропущенная самопроверка — не сбой", V({"self": {"r": "skip", "why": "load"}, "tr": tr}), "ok")
d = h._tcp_delta({"t": 1000, "TcpOutSegs": 0, "TcpRetransSegs": 0, "TcpPassiveOpens": 0, "TcpExtTCPTimeouts": 0,
                  "TcpExtListenOverflows": 0, "TcpExtListenDrops": 0}, 1300,
                 {"TcpOutSegs": 3000, "TcpRetransSegs": 900, "TcpPassiveOpens": 5, "TcpExtTCPTimeouts": 0,
                  "TcpExtListenOverflows": 0, "TcpExtListenDrops": 0})
want("10 сегм/с: доля не считается", (d["rate"], d["pct"]), (10, None))
d = h._tcp_delta({"t": 1000, "TcpOutSegs": 0, "TcpRetransSegs": 0, "TcpPassiveOpens": 0, "TcpExtTCPTimeouts": 0,
                  "TcpExtListenOverflows": 0, "TcpExtListenDrops": 0}, 1300,
                 {"TcpOutSegs": 30000, "TcpRetransSegs": 900, "TcpPassiveOpens": 5, "TcpExtTCPTimeouts": 0,
                  "TcpExtListenOverflows": 0, "TcpExtListenDrops": 0})
want("100 сегм/с: 3%", (d["rate"], d["pct"]), (100, 3.0))
want("счётчики обнулились — дельты нет", h._tcp_delta({"t": 1, "TcpOutSegs": 9}, 900, {"TcpOutSegs": 1}), None)

# ── Логи со смещения: первая встреча без истории, ротация в .1 дочитывается
lg = os.path.join(T, "fb.log")
open(lg, "w").write("old upstream timed out\n")
lines, pos = h._read_new(lg, None)
want("первая встреча — история не считается", lines, [])
open(lg, "a").write("a could not be resolved\nb reset by peer\nc no host in upstream\nd half")
lines, pos = h._read_new(lg, pos)
want("новые целые строки", h._log_counts(lines, [])["fb_res"] + h._log_counts(lines, [])["fb_rst"], 2)
want("strict-следы не считаются", h._log_counts(lines, [])["fb_oth"], 0)
open(lg, "a").write(" upstream timed out\n")
os.rename(lg, lg + ".1"); open(lg, "w").write("e reset by peer\n")
lines, pos = h._read_new(lg, pos)
c = h._log_counts(lines, [])
want("ротация: хвост .1 + новый файл", (c["fb_to"], c["fb_rst"]), (1, 1))

# ── Трафик своих клиентов: сумма замеров xm stats за окно
with open(os.environ["XM_STATS_SAMPLES"], "w") as f:
    for t, u, dn in ((100, 1, 1), (200, 50000, 60000), (300, 10, 10)):
        f.write(json.dumps({"t": t, "conns": 1, "up": u, "down": dn}) + "\n")
    f.write(json.dumps({"t": 250, "conns": 1}) + "\n")
want("трафик за (100, 300]", h._traffic(100, 300), 110020)
want("замеров нет — None, не 0", h._traffic(400, 500), None)

# ── Окно целиком: запись, дубль в том же слоте, адресов на диске нет
h._facts = lambda a: {"boot": "b1", "xray": "i1", "nginx": "n1", "cfg_xray": "c", "cfg_nginx": "g", "xbin": "1", "ver_xm": "m"}
h._xray_version = lambda x: "26.3.27"
h.FALLBACK_LOG = h.FRONT_LOG = os.path.join(T, "none.log")
cur = [sock("p1", "192.0.2.77", 300, 1, 5, 3)]
h.cmd_sample({})
import io, contextlib
buf, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
    h.cmd_window({"self": '{"r":"ok","ms":300}'})
    h.cmd_window({"self": '{"r":"ok","ms":300}'})
ws = h.load_windows()
want("второй run в том же слоте не пишет дубль", (len(ws), "уже записано" in err.getvalue()), (1, True))
want("окно: post и вердикт", (ws[0]["c"]["post"], ws[0]["vd"]), (1, "nodata"))
blob = ""
for d_ in (h.DATA_DIR, h.RUN_DIR):
    for n in os.listdir(d_):
        p = os.path.join(d_, n)
        if os.path.isfile(p):
            blob += open(p, errors="replace").read()
want("адресов клиентов на диске нет", [a for a in ("192.0.2.", "198.51.100.", "203.0.113.") if a in blob], [])
# Событие: перезапуск Xray без перезагрузки — событие; после перезагрузки — только boot
want("перезапуск Xray", h._events({"boot": "b1", "xray": "i1", "xbin": "1"}, {"boot": "b1", "xray": "i2", "xbin": "1"}, {}, None), ["xray"])
want("перезагрузка", h._events({"boot": "b1", "xray": "i1", "xbin": "1"}, {"boot": "b2", "xray": "i2", "xbin": "1"}, {}, None), ["boot"])

# ── Отчёт: полоса и проценты считаются по попыткам
now = 1_800_000_000
now = now // 900 * 900 + 600
lines = []
for i in range(12):                                   # последний час: 3 OK, сбой, тишина
    t = now // 300 * 300 - i * 300
    vd = "ok" if i < 3 else ("server" if i < 6 else "nodata")
    w = {"t": t, "vd": vd, "self": {"r": "fail" if vd == "server" else "ok", "at": "handshake"},
         "tr": tr if vd != "nodata" else None}
    lines.append(json.dumps(w))
open(os.path.join(h.DATA_DIR, "windows.jsonl"), "w").write("\n".join(reversed(lines)) + "\n")
r = h.build_report(now)
states = [c["s"] for c in r["band"] if c["s"] != "none"]
want("полоса: ✓ и ✗ без серых", sorted(set(states)), ["bad", "ok"])
want("сервер готов: 9 из 12 самопроверок", (r["d7"]["self_ok"], r["d7"]["self_runs"]), (9, 12))
want("сессии: 3 из 6 окон с трафиком", (r["d7"]["traffic_ok"], r["d7"]["traffic_windows"]), (3, 6))
want("одна причина: рукопожатие, 3 окна", [(x["why"], x["n"]) for x in r["incidents"]], [("сбой сервера: рукопожатие", 3)])

print("\n".join("FAIL " + f for f in fails) if fails else "ok")
PY
)
[[ $out == ok ]] || { echo "$out"; exit 1; }

# ── Самопроверка (xm.sh): где сломалось и когда это пропуск, а не сбой. Система — заглушки:
# предмет — ветвление, сам путь VLESS+REALITY проверяет tests/vps/health.sh на живом Xray.
CONFIG="$T/config.json"
echo '{"inbounds":[{"port":8443,"streamSettings":{"realitySettings":{"serverNames":["example.com"]}}}]}' >"$CONFIG"
FRONT_NGX="$T/no-front"
eval "$(sed -n '/^_get_nginx_sni()/,/^}/p; /^_front_enabled()/p; /^_front_public_port()/,/^}/p; /^HEALTH_URL=/p; /^_health_selfcheck()/,/^}/p' "$root/xm.sh")"
declare -F _health_selfcheck >/dev/null || { echo "FAIL: в xm.sh нет _health_selfcheck"; exit 1; }
HEALTH_LOADAVG="$T/loadavg" HEALTH_MEMINFO="$T/meminfo"
systemctl() { [[ $XRAY == up ]]; }
ss() { [[ $LISTEN == yes ]] && echo "LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*"; }
timeout() { shift; "$@"; }
getent() { [[ $DNS == ok ]]; }
_tunnel_up() { TUN_ARGS="$*"; [[ $TUN == up ]]; }
_tunnel_down() { :; }
_tunnel_code() { echo "$CODE"; }
curl() { echo "$DIRECT"; }
sleep() { :; }
fails=0
case_() {  # имя ожидаемый-JSON-без-ms нагрузка памятьМБ
  local name=$1 exp=$2 got
  echo "$3 0.5 0.4 1/100 1" >"$T/loadavg"; echo "MemAvailable: $(( $4 * 1024 )) kB" >"$T/meminfo"
  got=$(_health_selfcheck "${BAD:-}" | sed -E 's/,"ms":[0-9]+//')
  [[ $got == "$exp" ]] || { echo "FAIL самопроверка, $name: ожидалось $exp, получено $got"; fails=$((fails + 1)); }
}
XRAY=up LISTEN=yes DNS=ok TUN=up CODE=204 DIRECT=204
case_ "всё прошло"          '{"r":"ok"}' 0.2 900
case_ "нагрузка 1.6"        '{"r":"skip","why":"load"}' 1.6 900
case_ "памяти 140 МБ"       '{"r":"skip","why":"mem"}' 0.2 140
XRAY=down case_ "Xray остановлен"    '{"r":"fail","at":"listen"}' 0.2 900
LISTEN=no case_ "порт не слушает"    '{"r":"fail","at":"listen"}' 0.2 900
DNS=bad case_ "маска не резолвится"  '{"r":"fail","at":"dns"}' 0.2 900
TUN=down case_ "клиент не поднялся"  '{"r":"skip","why":"client"}' 0.2 900
CODE=000 case_ "тоннель не прошёл, сервер в сеть ходит" '{"r":"fail","at":"handshake"}' 0.2 900
CODE=000 DIRECT=000 case_ "сервер не ходит в сеть" '{"r":"fail","at":"egress"}' 0.2 900
_health_selfcheck >/dev/null
[[ $TUN_ARGS == "xhttp 8443 " ]] || { echo "FAIL самопроверка идёт не на публичный порт: $TUN_ARGS"; fails=$((fails + 1)); }
BAD=bad CODE=000 case_ "неверный ключ" '{"r":"fail","at":"handshake"}' 0.2 900
_health_selfcheck bad >/dev/null
[[ $TUN_ARGS =~ ^xhttp\ 8443\ [A-Za-z0-9_-]{43}$ ]] || { echo "FAIL неверный ключ не подставлен: $TUN_ARGS"; fails=$((fails + 1)); }
(( fails == 0 )) || exit 1
echo "health: ok"
