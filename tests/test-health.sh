#!/usr/bin/env bash
# Журнал здоровья (ui/health.py): классы соединений по tcp_info, счёт «один раз за жизнь» по
# cookie, шквал по новым соединениям с точкой отсчёта, вердикт окна и его пересчёт при чтении,
# логи со смещения с ротацией, трафик из замеров xm stats без трафика самопроверки, расход юнитов
# по cgroup, дубли окон, отсутствие адресов на диске и окна в журнале, полоса отчёта. Сокеты ядра —
# заглушка connections() с полями netlink в том виде, в каком их отдаёт ядро (сверку с ss держит
# tests/vps/health.sh), файлы cgroup — во временном каталоге; остальное — настоящий код.
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export XM_HEALTH_DIR="$T/data" XM_HEALTH_RUN="$T/run" XM_STATS_SAMPLES="$T/samples.jsonl" XM_STATS_DIR="$T/stats" PYTHONDONTWRITEBYTECODE=1
out=$(python3 - "$root/ui" "$T" <<'PY' 2>&1
import json, os, sys, time
sys.path.insert(0, sys.argv[1]); T = sys.argv[2]
import health as h
import stats

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

# ── Фильтр в ядре: дамп netlink отдаёт только сокеты своего порта — чужие (исходящие Xray, nginx;
# на сервере их тысячи) ядро не собирает, python не разбирает. Настоящие сокеты на петле.
import socket as so, struct
lst = [so.socket() for _ in range(2)]
for x in lst:
    x.bind(("127.0.0.1", 0)); x.listen(8)
mine, other = (x.getsockname()[1] for x in lst)
held = [so.create_connection(("127.0.0.1", p)) for p in (mine, other, other, other)]
held += [lst[0].accept()[0]] + [lst[1].accept()[0] for _ in range(3)]
want("дамп netlink — только свой порт", sorted(struct.unpack_from("!H", m, 4)[0] for m in h._diag_dump(so.AF_INET, mine)),
     [mine])
for x in held + lst:
    x.close()

# ── Опрос и окно: зависшее считается один раз за жизнь, даже если живёт три окна
os.makedirs(h.DATA_DIR); open(os.path.join(h.DATA_DIR, "params.json"), "w").write('{"port":443}\n')   # как пишет xm
cur = []
h.connections = lambda port, loopback=False: list(cur)
stalled = [sock("a%d" % i, "192.0.2.%d" % i, 300, 15360, 10, 4) for i in range(3)]
cur = stalled + [sock("n1", "198.51.100.7", 300, 90000)]
h.cmd_sample({}); h.cmd_sample({})
w1 = h._close_conns(False)
want("окно 1: заморозки; первый опрос — точка отсчёта, не новые", (w1["f16"], w1["norm"], w1["new"], w1["smp"], w1["cmax"]),
     (3, 1, 0, 2, 4))
cur.append(sock("n2", "198.51.100.8", 300, 90000))
h.cmd_sample({})
w2 = h._close_conns(False)
want("окно 2: те же зависшие не считаются снова, новое — новое", (w2["f16"], w2["norm"], w2["new"]), (0, 2, 1))
cur = []
h.cmd_sample({})
w3 = h._close_conns(False)
want("окно 3: закрытые забыты", (w3["f16"], w3["norm"], w3["cmax"]), (0, 0, 0))
want("после окна 3 состояние пусто", h._state("conns.bin")["c"], {})
# Закрылось между опросами одного окна — всё равно в этом окне
cur = [sock("z1", "192.0.2.50", 300, 1, 5, 3)]
h.cmd_sample({}); cur = []; h.cmd_sample({})
want("закрылось до конца окна — учтено", h._close_conns(False)["post"], 1)
want("без опросов — нет данных о соединениях", h._close_conns(False), None)
# Шквал — новые соединения с адреса между опросами; долгие одновременные — не шквал
cur = [sock("l%d" % i, "198.51.100.20", 300, 90000) for i in range(55)]
h.cmd_sample({}); h._close_conns(False)                # открылись окном раньше
cur += [sock("s%d" % i, "203.0.113.9", 300, 2000) for i in range(31)]
h.cmd_sample({})
w = h._close_conns(False)
want("шквал: новых с адреса за опрос, одновременных с адреса", (w["pnew"], w["pmax"], w["new"]), (31, 55, 31))
h.cmd_sample({})
want("долгие соединения без новых: шквала нет", (h._close_conns(False)["pnew"]), 0)
cur = []
h.cmd_sample({}); h._close_conns(False)
os.unlink(os.path.join(h.RUN_DIR, "conns.bin"))        # перезагрузка: /run пуст
cur = [sock("r%d" % i, "198.51.100.30", 300, 90000) for i in range(40)]
h.cmd_sample({})
want("после перезагрузки первый опрос — точка отсчёта", (h._close_conns(False)["pnew"]), 0)
cur = []
h.cmd_sample({}); h._close_conns(False)

# ── Вердикт окна — первая подходящая строка
V = h.verdict
tr = h.TRAFFIC_MIN
want("сбой сервера сильнее всего", V({"self": {"r": "fail", "at": "dns"}, "c": {"f16": 5}, "tr": tr}), "server")
want("заморозка при трафике", V({"self": {"r": "ok"}, "c": {"f16": 2, "post": 1}, "tr": tr}), "freeze")
want("заморозка без трафика — подозрение", V({"self": {"r": "ok"}, "c": {"f16": 3}, "tr": None}), "suspect")
want("2 зависших — не заморозка", V({"self": {"r": "ok"}, "c": {"f16": 2}, "tr": tr}), "ok")
want("pre и late — не заморозка", V({"self": {"r": "ok"}, "c": {"pre": 9, "late": 9}, "tr": tr}), "ok")
want("ретрансмиты 3% при 50 сегм/с", V({"self": {"r": "ok"}, "tcp": {"pct": 3.0}, "tr": tr}), "degraded")
want("шквал — деградация", V({"self": {"r": "ok"}, "c": {"pnew": 31}, "tr": None}), "degraded")
want("55 одновременных с адреса без новых — не деградация", V({"self": {"r": "ok"}, "c": {"pmax": 55, "pnew": 0}, "tr": tr}), "ok")
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
# Окно берёт точку из ref.json так, как её пишет само: время сверху, счётчики в snmp.
import io, contextlib
h._atomic_write(os.path.join(h.RUN_DIR, "ref.json"), h._dump({"t": int(time.time()) - 300, "snmp": h._snmp()}))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    h.cmd_window({"self": '{"r":"ok"}', "dry": True})
want("окно считает дельту счётчиков по точке из ref.json", sorted((json.loads(buf.getvalue()).get("tcp") or {}).keys()),
     ["ld", "lo", "out", "pct", "po", "rate", "retr", "to"])
os.unlink(os.path.join(h.RUN_DIR, "ref.json"))

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

# ── Окно целиком: запись, дубль в том же слоте, расход юнитов, адресов на диске нет
h._facts = lambda a: {"boot": "b1", "xray": "i1", "nginx": "n1", "cfg_xray": "c", "cfg_nginx": "g", "xbin": "1", "ver_xm": "m"}
h._xray_version = lambda x: "26.3.27"
h.FALLBACK_LOG = h.FRONT_LOG = os.path.join(T, "none.log")
# cgroup v2: чей запуск — по /proc/self/cgroup, расход — cpu.stat и memory.peak своего юнита
h.PROC_CGROUP, h.CG_ROOTS = os.path.join(T, "self-cgroup"), (os.path.join(T, "nocg"), os.path.join(T, "cg"))
def unit(name, usec, peak):
    open(h.PROC_CGROUP, "w").write("0::/system.slice/%s\n" % name)
    d = os.path.join(T, "cg", "system.slice", name)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "cpu.stat"), "w").write("usage_usec %d\nuser_usec 1\nsystem_usec 1\n" % usec)
    open(os.path.join(d, "memory.peak"), "w").write("%d\n" % peak)
cur = [sock("p1", "192.0.2.77", 300, 1, 5, 3)]
unit("xm-health-sample.service", 25000, 12 << 20)
h.cmd_sample({}); h.cmd_sample({})
open(h.PROC_CGROUP, "w").write("0::/user.slice/user-1000.slice/session-1.scope\n")
h.cmd_sample({})                                         # вручную из SSH — не расход юнита
unit("xm-health.service", 400000, 40 << 20)
import io, contextlib
buf, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
    h.cmd_window({"self": '{"r":"ok","ms":300}'})
    h.cmd_window({"self": '{"r":"ok","ms":300}'})
ws = h.load_windows()
# Из юнита stderr — строка журнала с уровнем warning: второй run в том же слоте молчит, в терминале — говорит
want("второй run в том же слоте: дубля нет, из юнита — ни строки", (len(ws), err.getvalue()), (1, ""))
want("окно: post и вердикт", (ws[0]["c"]["post"], ws[0]["vd"]), (1, "nodata"))
want("окно из юнита не печатается (stdout юнита — журнал)", buf.getvalue(), "")
want("расход опросов — в окне", ws[0].get("ld"), {"s": [2, 50, 12288]})
want("свои запуски окна — в следующее", h._state("load.bin"), {"w": [2, 800, 40960]})
class Tty(io.StringIO):
    def isatty(self):
        return True
err = Tty()
open(h.PROC_CGROUP, "w").write("0::/user.slice/user-1000.slice/session-1.scope\n")
with contextlib.redirect_stderr(err):
    h.cmd_window({"self": '{"r":"ok","ms":300}'})
want("в терминале второй run в слоте объясняет, куда ушли данные", "уже записано" in err.getvalue(), True)
unit("xm-health.service", 400000, 40 << 20)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    h.cmd_load({})
ld = json.loads(buf.getvalue())
want("нагрузка: запуски, CPU, пик, часы окон", (ld["s"]["runs"], ld["s"]["cpu_ms"], ld["w"]["runs"], ld["w"]["peak_kb"], ld["hours"]),
     (2, 50, 2, 40960, 0.08))
os.unlink(os.path.join(T, "cg", "system.slice", "xm-health.service", "memory.peak"))
want("ядро без memory.peak — пик неизвестен, CPU есть", h._unit_usage("w"), [400, None])
open(h.PROC_CGROUP, "w").write("0::/user.slice/user-1000.slice/session-1.scope\n")
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
# Вердикт пересчитывается при чтении: окна, записанные по прежнему правилу шквала, — не деградация
with open(os.path.join(h.DATA_DIR, "windows.jsonl"), "a") as f:
    f.write(json.dumps({"t": now // 300 * 300 + 300, "vd": "degraded", "self": {"r": "ok"},
                        "c": {"pmax": 55, "new": 0}, "tr": tr}) + "\n")
    f.write(json.dumps({"t": now // 300 * 300 + 600, "vd": "ok", "self": {"r": "ok"},
                        "c": {"pmax": 3, "pnew": 40}, "tr": tr}) + "\n")
ws = h.load_windows()
want("прежнее «degraded» по одновременным — пересчитано", ws[-2]["vd"], "ok")
want("шквал — деградация с причиной", h._incidents(ws[-1:])[0]["why"], "деградация: шквал новых соединений")

# ── Смена суток: итоги в days.jsonl, окна старше 31 дня прочь — потоком, без файла в памяти
import tracemalloc
day0 = now // 86400 * 86400 + 43200
big = os.path.join(h.DATA_DIR, "windows.jsonl")
with open(big, "w") as f:
    for i in range(33 * 288, 0, -1):
        f.write(h._dump({"t": day0 - i * 300, "self": {"r": "ok"}, "c": {"norm": 120, "late": 1, "pmax": 55, "cmax": 140},
                         "tcp": {"out": 123456, "retr": 1234, "rate": 411, "pct": 1.0}, "tr": tr, "vd": "ok"}) + "\n")
    f.write("{broken\n")
os.chmod(big, 0o600)
open(os.path.join(h.DATA_DIR, "days.jsonl"), "w").write(json.dumps({"d": h._day(day0 - 86400), "n": -1}) + "\n")
tracemalloc.start()
h._rollup(day0, day0 - 86400)
peak = tracemalloc.get_traced_memory()[1]
tracemalloc.stop()
ws = h.load_windows()
days = [json.loads(x) for x in open(os.path.join(h.DATA_DIR, "days.jsonl"))]
want("окна старше 31 дня удалены, битая строка — тоже", (ws[0]["t"] >= day0 - 31 * 86400, sum(1 for _ in open(big))), (True, len(ws)))
want("итоги: есть сутки не трогаются, новых — по окнам", ([d["n"] for d in days if d["d"] == h._day(day0 - 86400)],
     all(d["n"] > 0 and d["ok"] == d["n"] for d in days if d["d"] != h._day(day0 - 86400))), ([-1], True))
want("права файла окон — 600", oct(os.stat(big).st_mode & 0o777), "0o600")
want("пик памяти смены суток на 33 днях окон < 4 МБ", peak < 4 << 20, True)
os.unlink(big); os.unlink(os.path.join(h.DATA_DIR, "days.jsonl"))

# ── Трафик самопроверки не идёт в замер xm stats: счётчик первого клиента — как до неё
cfg = os.path.join(T, "xcfg.json")
json.dump({"inbounds": [{"settings": {"clients": [{"id": "x", "email": "pc"}, {"id": "y", "email": "phone"}]}}]}, open(cfg, "w"))
fake = os.path.join(T, "fake-xray")
open(fake, "w").write("#!/bin/sh\necho '" + json.dumps({"stat": [
    {"name": "user>>>pc>>>traffic>>>uplink", "value": "5000"}, {"name": "user>>>pc>>>traffic>>>downlink", "value": "9000"},
    {"name": "user>>>phone>>>traffic>>>downlink", "value": "700"}]}) + "'\n")
os.chmod(fake, 0o755)
def stats_run(*extra):
    for f in ("clients.json", "samples.jsonl"):
        try: os.unlink(os.path.join(stats.DATA_DIR, f))
        except OSError: pass
    stats.main(["stats.py", "collect", "--xray", fake, "--api", "127.0.0.1:1", "--port", "443", "--config", cfg] + list(extra))
    c = json.load(open(os.path.join(stats.DATA_DIR, "clients.json")))
    smp = json.loads(open(os.path.join(stats.DATA_DIR, "samples.jsonl")).read().splitlines()[-1])
    day = list(c["pc"]["days"].values())[0] if "pc" in c else None
    return day, c.get("pc", {}).get("last", 0) > 0, smp["up"] + smp["down"]
want("без самопроверки — весь счётчик", stats_run(), ([5000, 9000], True, 14700))
want("клиент молчал до самопроверки — не «в сети», её байты не в замере", stats_run("--hold", "pc", "--before", "0 0"),
     ([0, 0], False, 700))
want("клиент работал до самопроверки — его трафик остаётся", stats_run("--hold", "pc", "--before", "100 200"),
     ([100, 200], True, 1000))
want("счётчики до самопроверки не сняты — обычный замер", stats_run("--hold", "pc", "--before", ""), ([5000, 9000], True, 14700))

# ── Замер xm stats делает окно в своём процессе (без отдельного python): с --hold и до «сейчас»
# окна — его трафик в этом окне; сбой замера окно не роняет
h.STATS_SAMPLES = os.path.join(stats.DATA_DIR, "samples.jsonl")
for f in (h.STATS_SAMPLES, os.path.join(h.DATA_DIR, "windows.jsonl")):
    if os.path.exists(f):
        os.unlink(f)
h._atomic_write(os.path.join(h.RUN_DIR, "ref.json"), h._dump({"t": int(time.time()) - 300}))
st_args = {"self": '{"r":"ok"}', "api": "127.0.0.1:1", "port": "443", "xray": fake, "config": cfg,
           "hold": "pc", "before": "100 200"}
with contextlib.redirect_stdout(io.StringIO()):
    h.cmd_window(dict(st_args))
want("замер stats — в окне, трафик самопроверки снят", [w.get("tr") for w in h.load_windows()], [1000])
real_collect, stats.collect = stats.collect, lambda *a, **k: 1 / 0
os.unlink(os.path.join(h.DATA_DIR, "windows.jsonl"))
with contextlib.redirect_stdout(io.StringIO()):
    h.cmd_window(dict(st_args))
stats.collect = real_collect
want("сбой замера stats окно не роняет", len(h.load_windows()), 1)

print("\n".join("FAIL " + f for f in fails) if fails else "ok")
PY
)
[[ $out == ok ]] || { echo "$out"; exit 1; }

# ── Самопроверка (xm.sh): где сломалось и когда это пропуск, а не сбой. Система — заглушки:
# предмет — ветвление, сам путь VLESS+REALITY проверяет tests/vps/health.sh на живом Xray.
CONFIG="$T/config.json"
echo '{"inbounds":[{"port":8443,"streamSettings":{"realitySettings":{"serverNames":["example.com"]}}}]}' >"$CONFIG"
FRONT_NGX="$T/no-front"
eval "$(sed -n '/^_get_nginx_sni()/,/^}/p; /^_front_enabled()/p; /^_front_port()/,/^}/p; /^_front_public_port()/,/^}/p
  /^HEALTH_URL=/p; /^_health_pubkey()/,/^}/p; /^_health_selfcheck()/,/^[)}]$/p; /^_health_params()/,/^}/p
  /^_health_run()/,/^}/p; /^_health_tls()/,/^}/p' "$root/xm.sh")"
for f in _health_selfcheck _health_pubkey _health_params _health_run _front_port _health_tls; do
  declare -F $f >/dev/null || { echo "FAIL: в xm.sh нет $f"; exit 1; }
done
HEALTH_LOADAVG="$T/loadavg" HEALTH_MEMINFO="$T/meminfo" HEALTH_RUN="$T/hrun" HEALTH_CERTS="$T/certs"
mkdir -p "$T/certs"; : >"$T/certs/Some_Root.pem"
systemctl() { [[ $XRAY == up ]]; }
ss() { [[ $LISTEN == yes ]] && echo "LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*"; }
timeout() { shift; "$@"; }
getent() {  # cold — первая попытка не успела, вторая из кеша
  [[ $DNS == ok ]] && return 0
  [[ $DNS == cold ]] || return 1
  [[ -f $T/dns-warm ]] && return 0
  touch "$T/dns-warm"; return 1
}
# Тело самопроверки — подоболочка: что она вызвала, видно только через файлы
_tunnel_up() { echo "$*" >"$T/tun-args"; echo "$BASHPID" >"$T/tun-pid"; [[ $TUN == up ]]; }
_tunnel_down() { echo down >>"$T/tun-down"; }
_tunnel_code() { echo "${*:3}" >"$T/code-args"; [[ $CODE == term ]] && { kill -TERM "$(<"$T/tun-pid")"; echo 000; return; }; echo "$CODE"; }
curl() { echo "$*" >"$T/curl-args"; echo "$DIRECT"; }
sleep() { :; }
fails=0
SC=(8443 8443 example.com "")   # публичный порт, порт inbound, serverNames[0], privateKey — из _health_run
case_() {  # имя ожидаемый-JSON-без-ms нагрузка памятьМБ
  local name=$1 exp=$2 got
  echo "$3 0.5 0.4 1/100 1" >"$T/loadavg"; echo "MemAvailable: $(( $4 * 1024 )) kB" >"$T/meminfo"
  got=$(_health_selfcheck "${BAD:-}" "${SC[@]}" | sed -E 's/,"ms":[0-9]+//')
  [[ $got == "$exp" ]] || { echo "FAIL самопроверка, $name: ожидалось $exp, получено $got"; fails=$((fails + 1)); }
}
XRAY=up LISTEN=yes DNS=ok TUN=up CODE=204 DIRECT=204
case_ "всё прошло"          '{"r":"ok"}' 0.2 900
case_ "нагрузка 1.6"        '{"r":"skip","why":"load"}' 1.6 900
case_ "памяти 140 МБ"       '{"r":"skip","why":"mem"}' 0.2 140
XRAY=down case_ "Xray остановлен"    '{"r":"fail","at":"listen"}' 0.2 900
LISTEN=no case_ "порт не слушает"    '{"r":"fail","at":"listen"}' 0.2 900
DNS=bad case_ "маска не резолвится"  '{"r":"fail","at":"dns"}' 0.2 900
DNS=cold case_ "холодный резолвинг — не сбой" '{"r":"ok"}' 0.2 900
TUN=down case_ "клиент не поднялся"  '{"r":"skip","why":"client"}' 0.2 900
CODE=000 case_ "тоннель не прошёл, сервер в сеть ходит" '{"r":"fail","at":"handshake"}' 0.2 900
CODE=000 DIRECT=000 case_ "сервер не ходит в сеть" '{"r":"fail","at":"egress"}' 0.2 900
_health_selfcheck "" "${SC[@]}" >/dev/null
[[ $(<"$T/tun-args") == "xhttp 8443 " ]] || { echo "FAIL самопроверка идёт не на публичный порт: $(<"$T/tun-args")"; fails=$((fails + 1)); }
# Сертификат google проверяется, но корень — по хешу в каталоге сертификатов, без загрузки всего
# набора CA (с OpenSSL 3 это ~⅔ CPU curl): и через тоннель, и прямым запросом
[[ $(<"$T/code-args") == "--capath $T/certs --cacert $T/certs/Some_Root.pem" ]] \
  || { echo "FAIL curl через тоннель без каталога корней: $(<"$T/code-args")"; fails=$((fails + 1)); }
CODE=000 DIRECT=000 case_ "прямой запрос — с тем же каталогом" '{"r":"fail","at":"egress"}' 0.2 900
[[ $(<"$T/curl-args") == *"--capath $T/certs --cacert $T/certs/Some_Root.pem"* && $(<"$T/curl-args") != *" -k"* ]] \
  || { echo "FAIL прямой curl: $(<"$T/curl-args")"; fails=$((fails + 1)); }
HEALTH_CERTS="$T/no-certs" case_ "каталога корней нет — curl как обычно" '{"r":"ok"}' 0.2 900
[[ -z $(<"$T/code-args") ]] || { echo "FAIL без каталога корней ключи всё равно переданы: $(<"$T/code-args")"; fails=$((fails + 1)); }
BAD=bad CODE=000 case_ "неверный ключ" '{"r":"fail","at":"handshake"}' 0.2 900
_health_selfcheck bad "${SC[@]}" >/dev/null
[[ $(<"$T/tun-args") =~ ^xhttp\ 8443\ [A-Za-z0-9_-]{43}$ ]] || { echo "FAIL неверный ключ не подставлен: $(<"$T/tun-args")"; fails=$((fails + 1)); }
# Юнит убит (TimeoutStartSec) посреди запроса — клиент и его конфиг всё равно убраны
rm -f "$T/tun-down"
got=$(CODE=term _health_selfcheck "" "${SC[@]}")
[[ -z $got && $(<"$T/tun-down") == down ]] || { echo "FAIL после TERM клиент не убран: «$got», down=$(<"$T/tun-down")"; fails=$((fails + 1)); }

# Ключ: вывод из privateKey — один раз на ключ, дальше кеш в RAM; сменился ключ — вывод заново
echo '{"inbounds":[{"streamSettings":{"realitySettings":{"privateKey":"kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}]}' >"$T/kcfg.json"
_get_pubkey() { echo x >>"$T/derive"; echo "PUB-$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$CONFIG")-0123456789abcdef"; }
k1=$(CONFIG="$T/kcfg.json" _health_pubkey); k2=$(CONFIG="$T/kcfg.json" _health_pubkey)
sed -i 's/kAAA/kBBB/' "$T/kcfg.json"; k3=$(CONFIG="$T/kcfg.json" _health_pubkey)
[[ $k1 == "$k2" && $k3 == PUB-kBBB* && $(wc -l <"$T/derive") -eq 2 ]] \
  || { echo "FAIL кеш ключа: $k1 / $k2 / $k3, выводов $(wc -l <"$T/derive")"; fails=$((fails + 1)); }

# Окно читает config.json одним jq: окон 288 в сутки, а каждый запуск jq — заметная доля CPU окна
# (прежде — отдельный jq на порт, API, email, ключ и SNI, по нескольку раз). Самопроверка — настоящая,
# тоннель и замер — заглушки.
echo '{"inbounds":[{"port":8443,"settings":{"clients":[{"id":"x","email":"pc"}]},"streamSettings":{"realitySettings":{"privateKey":"kCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","serverNames":["example.com"]}}}],"api":{"listen":"127.0.0.1:10085"}}' >"$CONFIG"
HEALTH_DIR="$T/hdir"
_get_pubkey() { echo "PUB-0123456789abcdef0123456789abcdef"; }
_stats_peek() { echo "100 200"; }
_health_py() { :; }
jq() { echo x >>"$T/jq-n"; command jq "$@"; }
echo "0.2 0.5 0.4 1/100 1" >"$T/loadavg"; echo "MemAvailable: 921600 kB" >"$T/meminfo"
rm -f "$T/jq-n"; _health_run >/dev/null
[[ $(wc -l <"$T/jq-n") -eq 1 && $(<"$T/tun-args") == "xhttp 8443 PUB-0123456789abcdef0123456789abcdef" ]] \
  || { echo "FAIL окно: jq $(wc -l <"$T/jq-n") раз (нужен 1), тоннель: $(<"$T/tun-args")"; fails=$((fails + 1)); }
unset -f jq

# Окно: счётчики первого клиента снимаются ДО самопроверки, замер с ними делает окно в своём процессе
# (отдельного запуска stats.py нет); самопроверка идёт на публичный порт — порт фронта, когда он включён
_health_params() { :; }
_stats_peek() { echo "peek $*" >>"$T/calls"; echo "100 200"; }
_health_selfcheck() { echo "self $*" >>"$T/calls"; echo '{"r":"ok"}'; }
_stats_collect() { echo "collect $*" >>"$T/calls"; }
_health_py() { echo "py $*" >>"$T/calls"; }
SELF='self  8443 8443 example.com kCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
rm -f "$T/calls"; _health_run
exp="peek 127.0.0.1:10085 pc"$'\n'"$SELF"$'\npy window --self {"r":"ok"} --api 127.0.0.1:10085 --port 8443 --hold pc --before 100 200'
[[ $(<"$T/calls") == "$exp" ]] || { echo "FAIL порядок окна: $(paste -sd'|' "$T/calls")"; fails=$((fails + 1)); }
rm -f "$T/calls"; _health_run dry
[[ $(<"$T/calls") == "$SELF"$'\npy window --self {"r":"ok"} --dry' ]] || { echo "FAIL окно --dry трогает замер: $(paste -sd'|' "$T/calls")"; fails=$((fails + 1)); }
FRONT_NGX="$T/front.conf" FRONT_STATE="$T/front.state"; : >"$FRONT_NGX"; echo "PORT=443" >"$FRONT_STATE"
rm -f "$T/calls"; _health_run dry
[[ $(head -n 1 "$T/calls") == "self  443 8443 example.com kCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" ]] \
  || { echo "FAIL за фронтом самопроверка не на его порт: $(head -n 1 "$T/calls")"; fails=$((fails + 1)); }
FRONT_NGX="$T/no-front"
(( fails == 0 )) || exit 1

# health.py — модулем: байткод кешируется, импорт не берёт health.py из текущего каталога
mkdir -p "$T/ui" "$T/cwd"; cp "$root/ui/health.py" "$T/ui/"
echo 'print("DECOY")' >"$T/cwd/health.py"
unset PYTHONDONTWRITEBYTECODE
UI_DIR="$T/ui"; XM_BIN=/nonexistent
eval "$(sed -n '/^HEALTH_PY=/p; /^_health_py()/,/^}/p' "$root/xm.sh")"
got=$(cd "$T/cwd" && XM_HEALTH_DIR="$T/empty" _health_py report --json)
[[ $got == *'"band"'* && $got != *DECOY* ]] || { echo "FAIL запуск модулем: $got"; exit 1; }
ls "$T"/ui/__pycache__/health.*.pyc >/dev/null 2>&1 || { echo "FAIL байткод health не закеширован"; exit 1; }

# Опрос — как его зовёт юнит — не тянет json, re и обёртку socket.py: их импорт был больше половины
# CPU каждого из 1440 опросов в сутки
mkdir -p "$T/pd"; echo '{"port":1}' >"$T/pd/params.json"
got=$(cd "$T/cwd" && XM_HEALTH_DIR="$T/pd" XM_HEALTH_RUN="$T/pr" python3 -I -S -c "import sys
sys.path[:0] = ['$UI_DIR']; import health; health.main(['health.py', 'sample'])
print(' '.join(m for m in ('json', 're', 'enum', 'socket', 'selectors') if m in sys.modules))" 2>&1)
[[ -z $got && -s "$T/pr/conns.bin" ]] || { echo "FAIL опрос тянет модули или не записал состояние: «$got»"; exit 1; }
echo "health: ok"
