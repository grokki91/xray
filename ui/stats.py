#!/usr/bin/env python3
"""Статистика для панели xm: счётчики Xray раз в 5 минут и выборки для графиков.

Хранится ровно то, что нужно графикам, и ничего, что связывает трафик с адресами:
  samples.jsonl — по строке на замер: время, трафик всех клиентов за интервал, число
                  соединений на публичном порту;
  clients.json  — по клиенту: суммы за сутки и время последнего трафика.
Адреса клиентов и назначений Xray отдаёт только при statsUserOnline, он не включается.
Срок хранения — KEEP_DAYS, дальше записи удаляются при очередном замере.

  stats.py collect --xray PATH --api HOST:PORT --port N --config PATH
"""
import bisect
import datetime
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time

DATA_DIR = os.environ.get("XM_STATS_DIR", "/var/lib/xm/stats")
SAMPLES = "samples.jsonl"
CLIENTS = "clients.json"
KEEP_DAYS = 31

# Окна графиков: (число интервалов, длина интервала в секундах; None — календарные сутки).
RANGES = {"24h": (96, 900), "7d": (168, 3600), "30d": (30, None)}

_STAT_RE = re.compile(r"^user>>>(.+)>>>traffic>>>(uplink|downlink)$")


def _path(name):
    return os.path.join(DATA_DIR, name)


def _day(ts):
    return datetime.date.fromtimestamp(ts).isoformat()


def _midnight(d):
    return int(datetime.datetime.combine(d, datetime.time()).timestamp())


def _atomic_write(path, text):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
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


# ─── Источники ───────────────────────────────────────────────────────────────

def query_users(xray, api, timeout=5):
    """Приращение счётчиков клиентов с прошлого замера: {email: [uplink, downlink]}.

    -reset отдаёт значение и обнуляет счётчик, поэтому перезапуск Xray и сброс
    счётчиков не нужно отслеживать: каждое чтение — это дельта. Нулевой счётчик
    приходит без поля value.
    """
    cmd = [xray, "api", "statsquery", "--server=" + api, "-pattern", "user>>>",
           "-reset", "-t", str(timeout)]
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=timeout + 5)
    if r.returncode != 0:
        raise RuntimeError("xray api: " + (r.stderr or r.stdout).strip()[:200])
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        raise RuntimeError("xray api: ответ не JSON")
    out = {}
    for item in data.get("stat") or []:
        m = _STAT_RE.match(item.get("name", ""))
        if not m:
            continue
        try:
            value = int(item.get("value") or 0)
        except (TypeError, ValueError):
            value = 0
        rec = out.setdefault(m.group(1), [0, 0])
        rec[0 if m.group(2) == "uplink" else 1] += max(value, 0)
    return out


def count_established(port):
    """Соединения ESTABLISHED на локальном порту — по /proc/net/tcp*, без разбора вывода ss."""
    n = 0
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(name, encoding="ascii") as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) > 3 and cols[3] == "01" \
                            and int(cols[1].rsplit(":", 1)[1], 16) == port:
                        n += 1
        except (OSError, ValueError, IndexError):
            continue
    return n


def client_emails(config_path):
    """email всех клиентов во всех inbound: по нему Xray ведёт счётчики."""
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)
    emails = set()
    for ib in cfg.get("inbounds") or []:
        for c in (ib.get("settings") or {}).get("clients") or []:
            if c.get("email"):
                emails.add(c["email"])
    return emails


# ─── Хранилище ───────────────────────────────────────────────────────────────

def _load_clients():
    try:
        with open(_path(CLIENTS), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_samples(since=0):
    out = []
    try:
        with open(_path(SAMPLES), encoding="utf-8") as f:
            for line in f:
                try:
                    s = json.loads(line)
                except ValueError:
                    continue
                if isinstance(s, dict) and isinstance(s.get("t"), int) and s["t"] >= since:
                    out.append(s)
    except OSError:
        pass
    return out


def _prune_samples(now):
    cutoff = now - KEEP_DAYS * 86400
    p = _path(SAMPLES)
    try:
        with open(p, encoding="utf-8") as f:
            first = f.readline()
        if not first or json.loads(first).get("t", now) >= cutoff - 86400:
            return
    except (OSError, ValueError):
        return
    keep = [json.dumps(s, separators=(",", ":")) for s in load_samples(cutoff)]
    _atomic_write(p, "\n".join(keep) + ("\n" if keep else ""))


def collect(xray, api, port, config_path, now=None):
    """Один замер. Возвращает (код возврата, сообщение или "")."""
    now = int(now or time.time())
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    lock = open(_path(".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0, "замер уже идёт"
    emails = client_emails(config_path)
    problem = ""
    users = None
    try:
        users = query_users(xray, api)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        problem = str(e)

    sample = {"t": now, "conns": count_established(port)}
    if users is not None:
        clients = _load_clients()
        today = _day(now)
        up = down = 0
        for email, (u, d) in users.items():
            if email not in emails:
                continue
            up += u
            down += d
            rec = clients.setdefault(email, {"days": {}, "last": 0})
            day = rec["days"].setdefault(today, [0, 0])
            day[0] += u
            day[1] += d
            if u + d > 0:
                rec["last"] = now
        oldest = _day(now - KEEP_DAYS * 86400)
        # Удалённый клиент уходит вместе с историей: статистика не переживает его.
        clients = {e: r for e, r in clients.items() if e in emails}
        for rec in clients.values():
            rec["days"] = {k: v for k, v in rec["days"].items() if k >= oldest}
        sample["up"], sample["down"] = up, down
        _atomic_write(_path(CLIENTS), json.dumps(clients, separators=(",", ":")))

    fd = os.open(_path(SAMPLES), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(sample, separators=(",", ":")) + "\n")
    _prune_samples(now)
    return (1 if problem else 0), problem


# ─── Выборки для панели ──────────────────────────────────────────────────────

def _edges(range_name, now):
    n, step = RANGES[range_name]
    if step:
        end = (now // step + 1) * step
        return [end - (n - i) * step for i in range(n + 1)]
    today = datetime.date.fromtimestamp(now)
    days = [today - datetime.timedelta(days=n - 1 - i) for i in range(n)]
    return [_midnight(d) for d in days] + [_midnight(today + datetime.timedelta(days=1))]


def series(range_name, now=None):
    """Ряды для графиков: Мбит/с вверх и вниз, максимум соединений, байты для таблицы."""
    now = int(now or time.time())
    edges = _edges(range_name, now)
    n = len(edges) - 1
    up = [None] * n
    down = [None] * n
    conns = [None] * n
    last = 0
    for s in load_samples(edges[0]):
        i = bisect.bisect_right(edges, s["t"]) - 1
        if not 0 <= i < n:
            continue
        last = max(last, s["t"])
        if "up" in s:
            up[i] = (up[i] or 0) + s["up"]
            down[i] = (down[i] or 0) + s["down"]
        if isinstance(s.get("conns"), int):
            conns[i] = max(conns[i] or 0, s["conns"])
    # Последний интервал не закончился: делим на прошедшее время, иначе скорость занижена.
    span = [max(1, min(now, edges[i + 1]) - edges[i]) for i in range(n)]

    def mbit(b, sp):
        return None if b is None else round(b * 8 / sp / 1e6, 3)

    return {
        "range": range_name,
        "edges": edges[:-1],
        "ends": edges[1:],
        "now": now,
        "up_bytes": up,
        "down_bytes": down,
        "up_mbit": [mbit(b, sp) for b, sp in zip(up, span)],
        "down_mbit": [mbit(b, sp) for b, sp in zip(down, span)],
        "conns_max": conns,
        "last_sample": last,
        "has_data": any(v is not None for v in up) or any(v is not None for v in conns),
    }


def traffic_since(seconds, now=None):
    """Сумма трафика всех клиентов за последние seconds секунд: [uplink, downlink] или None."""
    now = int(now or time.time())
    up = down = 0
    seen = False
    for s in load_samples(now - seconds):
        if "up" in s:
            seen = True
            up += s["up"]
            down += s["down"]
    return [up, down] if seen else None


def clients_summary(now=None):
    """По email: трафик за сегодня, 7 и 30 суток (календарных) и время последнего трафика."""
    now = int(now or time.time())
    today = datetime.date.fromtimestamp(now)
    windows = {"today": 1, "d7": 7, "d30": 30}
    wanted = {k: {(today - datetime.timedelta(days=i)).isoformat() for i in range(n)}
              for k, n in windows.items()}
    out = {}
    for email, rec in _load_clients().items():
        row = {"last": rec.get("last", 0)}
        for key, days in wanted.items():
            u = d = 0
            for day, (du, dd) in (rec.get("days") or {}).items():
                if day in days:
                    u += du
                    d += dd
            row[key] = [u, d]
        out[email] = row
    return out


def main(argv):
    if len(argv) < 2 or argv[1] != "collect":
        print(__doc__, file=sys.stderr)
        return 2
    args = {}
    it = iter(argv[2:])
    for key in it:
        args[key.lstrip("-")] = next(it, "")
    try:
        rc, msg = collect(args["xray"], args["api"], int(args["port"]), args["config"])
    except (KeyError, ValueError, OSError) as e:
        print("stats: " + str(e), file=sys.stderr)
        return 2
    if msg:
        print("stats: " + msg, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
