#!/usr/bin/env python3
"""Журнал здоровья VPN (xm health): соединения раз в минуту, окно раз в 5 минут, отчёт.

Доступность считается по попыткам, а не по времени: окно без попыток — «нет данных», в процент
не входит, тишина никогда не считается сбоем. На диск — только числа, классы и место поломки:
адреса клиентов живут в памяти одного прохода и не пишутся никуда.

  health.py sample [--port N --print --loopback]  опрос соединений (таймер раз в минуту)
  health.py window --self JSON [--dry] …          окно 5 минут (таймер через xm health run)
  health.py init                                  точки отсчёта без записи окна (xm health on)
  health.py report [--json]                       отчёт за 24 ч и 7 дней
  health.py load                                  CPU и пик памяти юнитов за сутки (journald)

Хранилище: DATA_DIR/windows.jsonl (окна, KEEP_DAYS), DATA_DIR/days.jsonl (итоги суток,
KEEP_DAYS_SUM), DATA_DIR/params.json (порт); промежуточное — RUN_DIR (RAM).
"""
import datetime
import fcntl
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

DATA_DIR = os.environ.get("XM_HEALTH_DIR", "/var/lib/xm/health")
RUN_DIR = os.environ.get("XM_HEALTH_RUN", "/run/xm-health")
STATS_SAMPLES = os.environ.get("XM_STATS_SAMPLES", "/var/lib/xm/stats/samples.jsonl")
WINDOW = 300
KEEP_DAYS = 31
KEEP_DAYS_SUM = 365

# Классы соединения на публичном порту — по tcp_info со стороны сервера. Общий признак «клиент
# перестал отвечать»: есть неподтверждённые данные (unacked > 0) и RTO сработал хотя бы дважды
# подряд (backoff >= 2). Граница 10–32 КБ — стартовая: заморозка TCP к хостинговым ASN после
# ~16–20 КБ (net4people/bbs#490, landscape.md), подстраивается по своим данным. 1–10 КБ —
# отдельный класс, чтобы такие зависания не прятались в «норме» и было видно, куда сдвигать.
SILENT_MS = 10000          # «встало до ClientHello»: ни байта от клиента за 10 с
HELLO_MAX = 1024           # «после ClientHello»: подтверждено меньше 1 КБ ответа сервера
F16_MIN, F16_MAX = 10240, 32768
CLASSES = ("norm", "pre", "post", "mid", "f16", "late")
STALL = ("post", "mid", "f16", "late")

# Вердикт окна. Заморозка — от 3 соединений «после ClientHello» или «10–32 КБ» в окне с трафиком
# своих клиентов; без трафика — только подозрение. Шквал — больше 30 соединений с одного адреса
# одновременно (тот же порог, что diag-dpi G5). Ретрансмиты — как в _tune_counters: доля
# считается только при исходящем потоке от 50 сегм/с, порог 3 %.
FREEZE_MIN = 3
STORM_PEER = 30
RETR_RATE_MIN = 50
RETR_PCT = 3.0
# «Есть трафик своих клиентов» — от 64 КБ за окно: самопроверка сама проходит через Xray под
# первым клиентом (TLS до generate_204 — единицы КБ) и не должна делать каждое окно «с трафиком».
TRAFFIC_MIN = 65536

FALLBACK_LOG = "/var/log/nginx/reality_fallback_error.log"
FRONT_LOG = "/var/log/nginx/front_error.log"

VERDICT_TEXT = {
    "ok": "OK", "server": "сбой сервера", "freeze": "заморозка (видна на сервере)",
    "degraded": "деградация", "suspect": "подозрение на заморозку (без трафика своих клиентов)",
    "nodata": "нет данных", "monitor": "нет данных (монитор)",
}
STAGE_TEXT = {
    "listen": "Xray не слушает", "dns": "домен-маска не резолвится",
    "handshake": "рукопожатие", "egress": "выход в интернет",
}
SKIP_TEXT = {"load": "высокая нагрузка", "mem": "мало памяти", "client": "клиент самопроверки не запустился",
             "off": "не запускалась"}
CLASS_TEXT = {"pre": "встало до ClientHello", "post": "встало после ClientHello",
              "mid": "встало на 1–10 КБ", "f16": "встало на 10–32 КБ",
              "late": "пропало позже (сон/смена сети)"}
EVENT_TEXT = {"boot": "перезагрузка", "xray": "перезапуск Xray", "nginx": "перезапуск nginx",
              "cfg_xray": "изменён config.json", "cfg_nginx": "изменён конфиг nginx",
              "ver_xray": "версия Xray", "ver_xm": "обновлён xm", "wd": "починки watchdog",
              "gap": "перерыв монитора"}


def _p(*names):
    return os.path.join(*names)


def _atomic_write(path, text):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, type(default)) else default
    except (OSError, ValueError):
        return default


def _dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _lock():
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    f = open(_p(RUN_DIR, ".lock"), "w")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


# ─── Соединения: netlink inet_diag ───────────────────────────────────────────
#
# Netlink, а не разбор `ss`: вывод CLI не API (ss опускает нулевые поля и меняет формат между
# версиями), а здесь одно чтение без порождения процесса раз в минуту. Cookie сокета — тот же
# идентификатор, что `sk:` в `ss -e`: ядро не выдаёт его повторно, по нему соединение считается
# один раз за жизнь.

NETLINK_INET_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR, NLMSG_DONE = 2, 3
INET_DIAG_INFO = 2
TCP_ESTABLISHED, TCP_FIN_WAIT1 = 1, 4
# struct tcp_info (linux/tcp.h): u8 backoff @4, u32 unacked @24, u32 last_data_recv @52,
# u64 bytes_acked @120, u64 bytes_received @128 (ядро 4.1+). Короче — поля нет, класс не ставится.
TI_MIN = 136


def _diag_dump(family):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_INET_DIAG)
    try:
        states = (1 << TCP_ESTABLISHED) | (1 << TCP_FIN_WAIT1)
        req = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 1 << (INET_DIAG_INFO - 1), 0, states)
        req += b"\0" * 48
        hdr = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, 0x301, 1, 0)
        s.sendto(hdr + req, (0, 0))
        while True:
            data = s.recv(1 << 16)
            off = 0
            while off + 16 <= len(data):
                ln, typ, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, off)
                if ln < 16:
                    return
                if typ == NLMSG_DONE:
                    return
                if typ == NLMSG_ERROR:
                    err = struct.unpack_from("=i", data, off + 16)[0]
                    raise OSError(-err, "inet_diag: " + os.strerror(-err))
                if typ == SOCK_DIAG_BY_FAMILY:
                    yield data[off + 16:off + ln]
                off += (ln + 3) & ~3
    finally:
        s.close()


def _parse_diag(msg):
    if len(msg) < 72:
        return None
    fam, state = msg[0], msg[1]
    sport, dport = struct.unpack_from("!HH", msg, 4)
    src, dst = msg[8:24], msg[24:40]
    c0, c1 = struct.unpack_from("=II", msg, 44)
    rec = {"state": state, "sport": sport, "dport": dport, "cookie": "%x" % (c0 | (c1 << 32))}
    if fam == socket.AF_INET:
        rec["peer"] = socket.inet_ntop(socket.AF_INET, dst[:4])
    else:
        rec["peer"] = socket.inet_ntop(socket.AF_INET6, dst)
    off = 72
    while off + 4 <= len(msg):
        alen, atype = struct.unpack_from("=HH", msg, off)
        if alen < 4:
            break
        if atype == INET_DIAG_INFO and alen - 4 >= TI_MIN:
            ti = msg[off + 4:off + alen]
            rec["backoff"] = ti[4]
            rec["unacked"] = struct.unpack_from("=I", ti, 24)[0]
            rec["lastrcv"] = struct.unpack_from("=I", ti, 52)[0]
            rec["acked"], rec["received"] = struct.unpack_from("=QQ", ti, 120)
        off += (alen + 3) & ~3
    return rec


def _is_loopback(addr):
    a = addr[7:] if addr.startswith("::ffff:") else addr
    return a.startswith("127.") or a == "::1"


def connections(port, loopback=False):
    """Соединения ESTABLISHED и FIN-WAIT-1 с локальным портом port. Петля (самопроверка) — мимо."""
    out = []
    for fam in (socket.AF_INET, socket.AF_INET6):
        for msg in _diag_dump(fam):
            r = _parse_diag(msg)
            if r and r["sport"] == port and (loopback or not _is_loopback(r["peer"])):
                out.append(r)
    return out


def classify(c):
    """Класс соединения по tcp_info; None — ядро не отдало нужных полей."""
    if "acked" not in c:
        return None
    if c["received"] == 0:
        return "pre" if c["lastrcv"] >= SILENT_MS else "norm"
    if not (c["unacked"] > 0 and c["backoff"] >= 2):
        return "norm"
    a = c["acked"]
    if a < HELLO_MAX:
        return "post"
    if a < F16_MIN:
        return "mid"
    if a <= F16_MAX:
        return "f16"
    return "late"


def _params():
    return _load_json(_p(DATA_DIR, "params.json"), {})


def cmd_sample(args):
    port = int(args.get("port") or _params().get("port") or 0)
    if not port:
        return 0                     # порт ещё не записан (первое окно после on) — тихо
    conns = connections(port, loopback="loopback" in args)
    if "print" in args:
        cnt = dict.fromkeys(CLASSES, 0)
        unknown = 0
        for c in conns:
            k = classify(c)
            if k is None:
                unknown += 1
            else:
                cnt[k] += 1
        print(" ".join("%s=%d" % (k, cnt[k]) for k in CLASSES) + (" unknown=%d" % unknown if unknown else ""))
        return 0
    now = int(time.time())
    peers = {}
    with _lock():
        st = _load_json(_p(RUN_DIR, "conns.json"), {})
        known = st.get("c") or {}
        win = st.setdefault("w", {"smp": 0, "new": 0, "pmax": 0, "cmax": 0})
        present = set()
        for c in conns:
            k = classify(c)
            if k is None:
                continue
            present.add(c["cookie"])
            peers[c["peer"]] = peers.get(c["peer"], 0) + 1
            rec = known.get(c["cookie"])
            if rec is None:
                win["new"] += 1
                known[c["cookie"]] = [k, 0, 1]
            else:
                rec[0], rec[2] = k, 1
        for ck, rec in known.items():
            if ck not in present and len(rec) == 3:
                rec.append(1)        # закрылось: досчитать в этом окне и забыть
        win["smp"] += 1
        win["cmax"] = max(win["cmax"], len(present))
        win["pmax"] = max(win["pmax"], max(peers.values()) if peers else 0)
        st["c"], st["t"] = known, now
        _atomic_write(_p(RUN_DIR, "conns.json"), _dump(st))
    peers.clear()                    # адреса — только на время прохода
    return 0


def _close_conns(dry):
    """Итог соединений окна; сбрасывает окно, если не dry. None — опроса в окне не было."""
    st = _load_json(_p(RUN_DIR, "conns.json"), {})
    win = st.get("w") or {}
    if not win.get("smp"):
        return None
    out = dict.fromkeys(CLASSES, 0)
    out.update(smp=win["smp"], new=win["new"], pmax=win["pmax"], cmax=win["cmax"])
    known = st.get("c") or {}
    for ck in list(known):
        rec = known[ck]
        if rec[2]:
            if rec[0] in STALL:
                if not rec[1]:
                    out[rec[0]] += 1
                    rec[1] = 1        # зависшее считается один раз за жизнь, не в каждом окне
            else:
                out[rec[0]] += 1
        if len(rec) == 4:
            del known[ck]
        else:
            rec[2] = 0
    if not dry:
        st["c"], st["w"] = known, {"smp": 0, "new": 0, "pmax": 0, "cmax": 0}
        _atomic_write(_p(RUN_DIR, "conns.json"), _dump(st))
    return out


# ─── Счётчики ядра: своя точка отсчёта ───────────────────────────────────────

def _snmp():
    vals = {}
    for name in ("/proc/net/snmp", "/proc/net/netstat"):
        try:
            with open(name, encoding="ascii") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for hdr, val in zip(lines[::2], lines[1::2]):
            h, v = hdr.split(), val.split()
            if h and v and h[0] == v[0]:
                for k, x in zip(h[1:], v[1:]):
                    try:
                        vals[h[0][:-1] + k] = int(x)
                    except ValueError:
                        pass
    return {k: vals.get(k) for k in ("TcpOutSegs", "TcpRetransSegs", "TcpPassiveOpens",
                                    "TcpExtTCPTimeouts", "TcpExtListenOverflows", "TcpExtListenDrops")}


def _tcp_delta(ref, now, cur):
    """Дельты счётчиков с прошлого окна; None — точки нет или счётчики обнулились."""
    if not ref or not ref.get("t") or now - ref["t"] < 60:
        return None
    d = {}
    for k, v in cur.items():
        r = ref.get(k)
        if v is None or r is None or v < r:
            return None
        d[k] = v - r
    dt = now - ref["t"]
    rate = d["TcpOutSegs"] // dt
    out = {"out": d["TcpOutSegs"], "retr": d["TcpRetransSegs"], "rate": rate,
           "to": d["TcpExtTCPTimeouts"], "lo": d["TcpExtListenOverflows"], "ld": d["TcpExtListenDrops"],
           "po": d["TcpPassiveOpens"]}
    out["pct"] = round(d["TcpRetransSegs"] * 100 / d["TcpOutSegs"], 2) \
        if rate >= RETR_RATE_MIN and d["TcpOutSegs"] else None
    return out


# ─── Логи nginx: новые строки со смещения, с учётом ротации ──────────────────

def _read_new(path, ref):
    """Новые строки лога с позиции ref = [inode, offset]. Возвращает (строки, новая позиция)."""
    try:
        st = os.stat(path)
    except OSError:
        return [], None
    if not ref:
        return [], [st.st_ino, st.st_size]   # первая встреча: история не считается
    ino, off = ref
    lines = []
    if st.st_ino != ino or st.st_size < off:
        # Ротация: logrotate унёс файл в .1 (delaycompress) — дочитать его хвост, затем новый с нуля.
        try:
            if os.stat(path + ".1").st_ino == ino:
                lines += _tail_from(path + ".1", off)[0]
        except OSError:
            pass
        off = 0
    new, n = _tail_from(path, off)
    return lines + new, [st.st_ino, off + n]


def _tail_from(path, off):
    """Целые строки с позиции off (недописанная последняя — в следующий раз) и сколько байт взято."""
    try:
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(4 << 20)        # больше 4 МБ за 5 минут — уже не важно, сколько именно
    except OSError:
        return [], 0
    data = data[:data.rfind(b"\n") + 1]
    return data.decode("utf-8", "replace").splitlines(), len(data)


def _log_counts(fb, fr):
    out = {"fb_res": 0, "fb_rst": 0, "fb_to": 0, "fb_oth": 0, "fr_lim": 0, "fr_oth": 0}
    for ln in fb:
        if "no host in upstream" in ln:
            continue                   # след снятого strict-режима
        if "could not be resolved" in ln:
            out["fb_res"] += 1
        elif "reset by peer" in ln:
            out["fb_rst"] += 1
        elif "upstream timed out" in ln:
            out["fb_to"] += 1
        elif ln.strip():
            out["fb_oth"] += 1
    for ln in fr:
        if 'limiting connections by zone "front_conn"' in ln:
            out["fr_lim"] += 1
        elif ln.strip():
            out["fr_oth"] += 1
    return out


# ─── События по изменениям ───────────────────────────────────────────────────

def _read(path, n=None):
    try:
        with open(path, "rb") as f:
            return f.read() if n is None else f.read(n)
    except OSError:
        return b""


def _sha(*paths):
    h = hashlib.sha256()
    for p in paths:
        h.update(_read(p))
    return h.hexdigest()[:12]


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _facts(a):
    nginx = ["/etc/nginx/nginx.conf"]
    for d in ("/etc/nginx/stream-enabled", "/etc/nginx/sites-enabled"):
        try:
            nginx += sorted(_p(d, f) for f in os.listdir(d))
        except OSError:
            pass
    inv = _run(["systemctl", "show", "-p", "InvocationID", "--value", "xray", "nginx"]).split("\n")
    xray = a.get("xray") or "/usr/local/bin/xray"
    try:
        s = os.stat(xray)
        xbin = "%d:%d" % (s.st_mtime, s.st_size)
    except OSError:
        xbin = ""
    return {"boot": _read("/proc/sys/kernel/random/boot_id").decode().strip(),
            "xray": inv[0].strip() if inv else "", "nginx": inv[1].strip() if len(inv) > 1 else "",
            "cfg_xray": _sha(a.get("config") or "/usr/local/etc/xray/config.json"),
            "cfg_nginx": _sha(*nginx), "xbin": xbin,
            "ver_xm": _sha(a.get("xm") or "/usr/local/bin/xm")}


def _xray_version(xray):
    m = re.search(r"Xray (\S+)", _run([xray, "version"]))
    return m.group(1) if m else "?"


def _events(prev, cur, a, since):
    ev = []
    if prev:
        for k in ("boot", "xray", "nginx", "cfg_xray", "cfg_nginx", "ver_xm"):
            if prev.get(k) and cur.get(k) and prev[k] != cur[k]:
                if k in ("xray", "nginx") and prev.get("boot") != cur.get("boot"):
                    continue           # после перезагрузки службы стартуют заново — это не событие
                ev.append(k)
        if prev.get("xbin") != cur.get("xbin"):
            cur["xver"] = _xray_version(a.get("xray") or "/usr/local/bin/xray")
            if cur["xver"] != prev.get("xver"):
                ev.append("ver_xray:" + cur["xver"])
        else:
            cur["xver"] = prev.get("xver", "?")
    else:
        cur["xver"] = _xray_version(a.get("xray") or "/usr/local/bin/xray")
    if since:
        out = _run(["journalctl", "-q", "-u", "xray-watchdog.service", "--since", "@%d" % since,
                    "-o", "cat", "--no-pager"], timeout=20)
        n = sum(1 for ln in out.splitlines() if "перезапускаю" in ln)
        if n:
            ev.append("wd:%d" % n)
    return ev


# ─── Трафик своих клиентов: замеры xm stats ──────────────────────────────────

def _traffic(since, now):
    """Сумма up+down из samples.jsonl xm stats за (since, now]; None — замеров с трафиком не было."""
    total, seen = 0, False
    try:
        size = os.path.getsize(STATS_SAMPLES)
        with open(STATS_SAMPLES, "rb") as f:
            f.seek(max(0, size - 64 * 1024))   # хвоста хватает на часы замеров
            for line in f.read().decode("utf-8", "replace").splitlines():
                try:
                    s = json.loads(line)
                except ValueError:
                    continue
                if isinstance(s, dict) and "up" in s and since < s.get("t", 0) <= now:
                    seen = True
                    total += int(s["up"]) + int(s["down"])
    except (OSError, ValueError, TypeError):
        return None
    return total if seen else None


# ─── Вердикт окна ────────────────────────────────────────────────────────────

def verdict(w):
    """Первая подходящая строка (порядок — из постановки; канарейка ПК — этап 2)."""
    s = w.get("self") or {}
    if s.get("r") == "fail":
        return "server"
    c = w.get("c") or {}
    tr = w.get("tr")
    has_tr = tr is not None and tr >= TRAFFIC_MIN
    if c.get("post", 0) + c.get("f16", 0) >= FREEZE_MIN:
        if has_tr:
            return "freeze"
        susp = True
    else:
        susp = False
    tcp = w.get("tcp") or {}
    if (tcp.get("pct") is not None and tcp["pct"] >= RETR_PCT) or c.get("pmax", 0) > STORM_PEER:
        return "degraded"
    if has_tr:
        return "ok"
    return "suspect" if susp else "nodata"


def cmd_window(args):
    now = int(time.time())
    t_end = now // WINDOW * WINDOW
    dry = "dry" in args
    try:
        self_res = json.loads(args.get("self") or "{}")
    except ValueError:
        self_res = {"r": "skip", "why": "off"}
    with _lock():
        ref = _load_json(_p(RUN_DIR, "ref.json"), {})
        last = _last_window()
        if not dry and last and last["t"] >= t_end:
            # Окно уже записано (ручной run в том же пятиминутном слоте): данные — в следующее.
            print("health: окно %s уже записано — данные уйдут в следующее" %
                  time.strftime("%H:%M", time.localtime(t_end)), file=sys.stderr)
            return 0
        conns = _close_conns(dry)
        cur_snmp = _snmp()
        tcp = _tcp_delta(ref.get("snmp"), now, cur_snmp)
        fb, fb_pos = _read_new(FALLBACK_LOG, (ref.get("logs") or {}).get("fb"))
        fr, fr_pos = _read_new(FRONT_LOG, (ref.get("logs") or {}).get("fr"))
        facts_prev = _load_json(_p(DATA_DIR, "facts.json"), {})
        facts = _facts(args)
        since = ref.get("t") or (last or {}).get("t")
        ev = _events(facts_prev, facts, args, since)
        if last and t_end - last["t"] > WINDOW:
            ev.append("gap:%d" % ((t_end - last["t"] - WINDOW) // 60))
        w = {"t": t_end, "self": self_res, "c": conns, "tcp": tcp,
             "log": _log_counts(fb, fr), "tr": _traffic(since or now - WINDOW, now)}
        if ev:
            w["ev"] = ev
        w["vd"] = verdict(w)
        if dry:
            print(_dump(w))
            return 0
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        fd = os.open(_p(DATA_DIR, "windows.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(_dump(w) + "\n")
        _atomic_write(_p(RUN_DIR, "ref.json"), _dump({
            "t": now, "snmp": cur_snmp, "logs": {"fb": fb_pos, "fr": fr_pos}}))
        _atomic_write(_p(DATA_DIR, "facts.json"), _dump(facts))
        _rollup(now, last["t"] if last else None)
    print(_dump(w))
    return 0


def cmd_init(args):
    """Точки отсчёта при включении: счётчики, смещения логов, факты. Окно не пишется."""
    now = int(time.time())
    with _lock():
        ref = _load_json(_p(RUN_DIR, "ref.json"), {})
        if ref.get("t"):
            return 0                  # уже идёт — повторный on ничего не сбрасывает
        _, fb_pos = _read_new(FALLBACK_LOG, None)
        _, fr_pos = _read_new(FRONT_LOG, None)
        _atomic_write(_p(RUN_DIR, "ref.json"), _dump({
            "t": now, "snmp": _snmp(), "logs": {"fb": fb_pos, "fr": fr_pos}}))
        if not os.path.exists(_p(DATA_DIR, "facts.json")):
            f = _facts(args)
            f["xver"] = _xray_version(args.get("xray") or "/usr/local/bin/xray")
            _atomic_write(_p(DATA_DIR, "facts.json"), _dump(f))
    return 0


# ─── Хранилище: окна, итоги суток ────────────────────────────────────────────

def load_windows(since=0):
    out = []
    try:
        with open(_p(DATA_DIR, "windows.jsonl"), encoding="utf-8") as f:
            for line in f:
                try:
                    w = json.loads(line)
                except ValueError:
                    continue
                if isinstance(w, dict) and isinstance(w.get("t"), int) and w["t"] >= since:
                    out.append(w)
    except OSError:
        pass
    return out


def _last_window():
    p = _p(DATA_DIR, "windows.jsonl")
    try:
        size = os.path.getsize(p)
        with open(p, "rb") as f:
            f.seek(max(0, size - 4096))
            lines = f.read().decode("utf-8", "replace").splitlines()
        for line in reversed(lines):
            try:
                w = json.loads(line)
                if isinstance(w, dict) and isinstance(w.get("t"), int):
                    return w
            except ValueError:
                continue
    except OSError:
        pass
    return None


def _day(ts):
    return datetime.date.fromtimestamp(ts).isoformat()


def _day_summary(day, ws):
    s = {"d": day, "n": len(ws)}
    for k in VERDICT_TEXT:
        s[k] = sum(1 for w in ws if w.get("vd") == k)
    s["self_ok"] = sum(1 for w in ws if (w.get("self") or {}).get("r") == "ok")
    s["self_fail"] = sum(1 for w in ws if (w.get("self") or {}).get("r") == "fail")
    s["trw"] = sum(1 for w in ws if (w.get("tr") or 0) >= TRAFFIC_MIN)
    s["tr"] = sum(w.get("tr") or 0 for w in ws)
    for k in STALL + ("pre",):
        s[k] = sum((w.get("c") or {}).get(k, 0) for w in ws)
    return s


def _rollup(now, prev_t):
    """Сутки сменились — итоги завершённых суток в days.jsonl, окна старше KEEP_DAYS и итоги
    старше года прочь. Раз в сутки: файл окон целиком читается только здесь и в отчёте."""
    today = _day(now)
    if prev_t is None or _day(prev_t) >= today:
        return
    dp, wp = _p(DATA_DIR, "days.jsonl"), _p(DATA_DIR, "windows.jsonl")
    days = []
    try:
        with open(dp, encoding="utf-8") as f:
            for x in f:
                try:
                    days.append(json.loads(x))
                except ValueError:
                    continue
    except OSError:
        pass
    have = {d.get("d") for d in days}
    by_day = {}
    ws = load_windows()
    for w in ws:
        d = _day(w["t"])
        if d < today and d not in have:
            by_day.setdefault(d, []).append(w)
    days += [_day_summary(d, x) for d, x in sorted(by_day.items())]
    cut_sum = _day(now - KEEP_DAYS_SUM * 86400)
    days = [d for d in days if d.get("d", "") >= cut_sum]
    _atomic_write(dp, "".join(_dump(d) + "\n" for d in days))
    cutoff = now - KEEP_DAYS * 86400
    if ws and ws[0]["t"] < cutoff:
        keep = [_dump(w) for w in ws if w["t"] >= cutoff]
        _atomic_write(wp, "\n".join(keep) + ("\n" if keep else ""))


# ─── Отчёт ───────────────────────────────────────────────────────────────────

CELL = 900


def _cell_state(ws):
    vs = [w.get("vd") for w in ws]
    if any(v in ("server", "freeze") for v in vs):
        return "bad"
    if "degraded" in vs:
        return "warn"
    if "ok" in vs:
        return "ok"
    return "none"


def _incidents(ws):
    """Подряд идущие окна с бедой — интервалы с причиной."""
    out = []
    for w in ws:
        v = w.get("vd")
        if v not in ("server", "freeze", "degraded", "suspect"):
            continue
        why = VERDICT_TEXT[v]
        if v == "server":
            why += ": " + STAGE_TEXT.get((w.get("self") or {}).get("at"), "?")
        if out and out[-1]["why"] == why and w["t"] - out[-1]["to"] <= WINDOW:
            out[-1]["to"] = w["t"]
            out[-1]["n"] += 1
        else:
            out.append({"from": w["t"] - WINDOW, "to": w["t"], "why": why, "vd": v, "n": 1})
    return out


def _events_near(ws, a, b):
    ev = []
    for w in ws:
        if a - 2 * WINDOW <= w["t"] <= b + 2 * WINDOW:
            for e in w.get("ev") or []:
                ev.append((w["t"], e))
    return ev


def _event_text(e):
    k, _, v = e.partition(":")
    t = EVENT_TEXT.get(k, k)
    if k == "gap":
        return "%s %s мин" % (t, v)
    if k == "wd":
        return "%s: %s" % (t, v)
    return t + (" " + v if v else "")


def build_report(now=None):
    now = int(now or time.time())
    ws7 = load_windows(now - 7 * 86400)
    end = (now // CELL + 1) * CELL
    start = end - 96 * CELL
    band = []
    for i in range(96):
        a = start + i * CELL
        band.append({"t": a, "s": _cell_state([w for w in ws7 if a < w["t"] <= a + CELL])})
    sc = [w for w in ws7 if (w.get("self") or {}).get("r") in ("ok", "fail")]
    sok = sum(1 for w in sc if w["self"]["r"] == "ok")
    trw = [w for w in ws7 if (w.get("tr") or 0) >= TRAFFIC_MIN]
    trok = sum(1 for w in trw if w.get("vd") == "ok")
    inc = _incidents(ws7)
    for x in inc:
        x["events"] = [{"t": t, "e": e} for t, e in _events_near(ws7, x["from"], x["to"])]
    return {
        "now": now, "band": band,
        "d7": {"windows": len(ws7), "coverage_h": round(len(ws7) * WINDOW / 3600, 1),
               "self_runs": len(sc), "self_ok": sok,
               "ready_pct": round(sok * 100 / len(sc), 1) if sc else None,
               "self_cov_h": round(len(sc) * WINDOW / 3600, 1),
               "traffic_windows": len(trw), "traffic_ok": trok,
               "sessions_pct": round(trok * 100 / len(trw), 1) if trw else None,
               "traffic_cov_h": round(len(trw) * WINDOW / 3600, 1)},
        "incidents": inc[-20:],
        "events": [{"t": w["t"], "e": e} for w in ws7 for e in (w.get("ev") or [])][-30:],
        "last": ws7[-1] if ws7 else None,
    }


def _hm(t):
    return time.strftime("%H:%M", time.localtime(t))


def _dhm(t):
    return time.strftime("%d.%m %H:%M", time.localtime(t))


def print_report(r, color=True):
    C = (lambda c, s: "\033[%sm%s\033[0m" % (c, s)) if color else (lambda c, s: s)
    sym = {"ok": C("0;32", "✓"), "warn": C("1;33", "~"), "bad": C("0;31", "✗"), "none": "·"}
    print(C("1;36", "[ Здоровье VPN: последние 24 ч, клетка — 15 мин ]"))
    for row in range(4):
        cells = r["band"][row * 24:(row + 1) * 24]
        print("  %s  %s" % (_hm(cells[0]["t"]), "".join(sym[c["s"]] for c in cells)))
    print("  ✓ OK  ~ деградация  ✗ сбой сервера или заморозка  · нет данных (не подключались, ПК выключен,"
          " монитор не работал)")
    d = r["d7"]
    print()
    print(C("1;36", "[ 7 дней ]"))
    if d["ready_pct"] is None:
        print("  Сервер готов: нет самопроверок")
    else:
        print("  Сервер готов: %.1f%% — прошло %d из %d самопроверок; покрытие %.1f ч из 168" %
              (d["ready_pct"], d["self_ok"], d["self_runs"], d["self_cov_h"]))
    if d["sessions_pct"] is None:
        print("  Сессии без заморозок: нет окон с трафиком своих клиентов (нужен sudo xm stats on)")
    else:
        print("  Сессии без заморозок: %.1f%% — %d из %d окон с трафиком; покрытие %.1f ч" %
              (d["sessions_pct"], d["traffic_ok"], d["traffic_windows"], d["traffic_cov_h"]))
    print("  Данных всего: %.1f ч из 168" % d["coverage_h"])
    print()
    print(C("1;36", "[ Причины ]"))
    if not r["incidents"]:
        print("  Сбоев, заморозок и деградации за 7 дней нет")
    for x in r["incidents"]:
        print("  %s–%s  %s" % (_dhm(x["from"]), _hm(x["to"]), x["why"]))
        for e in x["events"]:
            print("      рядом: %s %s" % (_hm(e["t"]), _event_text(e["e"])))
    other = [e for e in r["events"] if not any(e in x["events"] for x in r["incidents"])]
    if other:
        print()
        print(C("1;36", "[ События ]"))
        for e in other[-10:]:
            print("  %s  %s" % (_dhm(e["t"]), _event_text(e["e"])))
    w = r["last"]
    if w:
        print()
        s = w.get("self") or {}
        st = "прошла" if s.get("r") == "ok" else ("не прошла: " + STAGE_TEXT.get(s.get("at"), "?")) \
            if s.get("r") == "fail" else "пропущена: " + SKIP_TEXT.get(s.get("why"), "?")
        print("  Последнее окно %s: %s; самопроверка %s" % (_hm(w["t"]), VERDICT_TEXT.get(w.get("vd"), "?"), st))
        c = w.get("c")
        if c:
            print("  Соединения: %d (новых %d, с одного адреса до %d); %s" % (
                c["cmax"], c["new"], c["pmax"],
                ", ".join("%s — %d" % (CLASS_TEXT[k], c[k]) for k in CLASS_TEXT if c.get(k)) or "все в норме"))


def cmd_report(args):
    r = build_report()
    if "json" in args:
        print(_dump(r))
    else:
        print_report(r, color=sys.stdout.isatty())
    return 0


# ─── Нагрузка юнитов за сутки ────────────────────────────────────────────────

_CONSUMED = re.compile(r"Consumed (?:(\d+)min )?(?:([\d.]+)(ms|us|s) )?CPU time"
                       r"(?:, ([\d.]+)([KMG]) memory peak)?")


def _ms(mins, val, unit):
    ms = int(mins or 0) * 60000.0
    if val:
        ms += float(val) * {"ms": 1, "us": 0.001, "s": 1000}[unit]
    return ms


def cmd_load(args):
    """CPU и пик памяти юнитов за 24 ч по строкам «Consumed …» systemd в journald."""
    res = {}
    for unit in ("xm-health-sample.service", "xm-health.service"):
        out = _run(["journalctl", "-q", "-u", unit, "--since", "-24h", "-o", "cat", "--no-pager"], timeout=30)
        runs, cpu, peak = 0, 0.0, 0.0
        for ln in out.splitlines():
            m = _CONSUMED.search(ln)
            if not m:
                continue
            runs += 1
            cpu += _ms(m.group(1), m.group(2), m.group(3))
            if m.group(4):
                peak = max(peak, float(m.group(4)) * {"K": 1 / 1024, "M": 1, "G": 1024}[m.group(5)])
        res[unit] = {"runs": runs, "cpu_ms": round(cpu), "peak_mb": round(peak, 1)}
    print(_dump(res))
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    args = {}
    it = iter(argv[2:])
    for key in it:
        k = key.lstrip("-")
        if k in ("print", "loopback", "dry", "json"):
            args[k] = True
        else:
            args[k] = next(it, "")
    cmd = {"sample": cmd_sample, "window": cmd_window, "init": cmd_init,
           "report": cmd_report, "load": cmd_load}.get(argv[1])
    if not cmd:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        return cmd(args)
    except (OSError, ValueError) as e:
        print("health: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
