#!/usr/bin/env python3
"""Панель xm: веб-интерфейс к командам xm. Запускается командой `sudo xm ui`.

Слушает только 127.0.0.1 и работает, пока открыт SSH-сеанс: к панели ходят через
`ssh -L <порт на ПК>:127.0.0.1:<порт панели>`. Защита поверх этого:
  * случайный токен в пути (`/<токен>/…`), новый при каждом запуске, в argv его нет;
    без него любой ответ — пустой 404. Токен нужен не из-за сети, а из-за ПК: проброшенный
    порт доступен любой программе на нём, и браузерной странице чужого сайта тоже;
  * заголовок Host — только loopback (защита от DNS-rebinding), Origin и Sec-Fetch-Site
    у POST — тоже, плюс обязательный заголовок X-Xm (форсирует CORS-preflight);
  * CSP без inline-скриптов и стилей, no-store, ни одного внешнего запроса;
  * панель умеет только фиксированный набор операций, каждая — вызов `xm` без shell:
    консоли, файлов и правки конфига руками в ней нет;
  * сама закрывается после бездействия.
"""
import argparse
import datetime
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import stats

UI_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC = {
    "": ("index.html", "text/html; charset=utf-8"),
    "app.js": ("app.js", "text/javascript; charset=utf-8"),
    "app.css": ("app.css", "text/css; charset=utf-8"),
    "icon.svg": ("icon.svg", "image/svg+xml"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "HOME": "/root", "TERM": "dumb"}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
NAME_RE = re.compile(r"^\w[\w.-]{0,31}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Проверки, которые панель умеет запускать: команда xm, предел времени, нужна ли итоговая строка.
JOBS = {
    "selftest": (["selftest"], 180, False),
    "diag-dpi": (["diag-dpi", "--quick"], 600, True),
}
LOG_BYTES = 256 * 1024
JOB_LINES = 4000


class ApiError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


class Job:
    def __init__(self, name):
        self.id = secrets.token_hex(4)
        self.name = name
        self.lines = []
        self.truncated = False
        self.done = False
        self.rc = None
        self.result = None
        self.proc = None
        self.started = time.time()

    def add(self, line):
        if len(self.lines) >= JOB_LINES:
            self.truncated = True
        else:
            self.lines.append(line)


class Panel:
    def __init__(self, args):
        self.port = args.port
        self.xm = args.xm
        self.config = args.config
        self.logs = {"xray": args.xray_log, "nginx": args.nginx_log, "journal": args.journal}
        self.idle_max = args.idle * 60
        self.token = secrets.token_urlsafe(24)
        self.touched = time.monotonic()
        self.lock = threading.Lock()  # одна изменяющая операция или проверка за раз
        self.job = None
        self.uris = {}
        self.httpd = None
        self.static = {}
        for key, (fname, ctype) in STATIC.items():
            with open(os.path.join(UI_DIR, fname), "rb") as f:
                self.static[key] = (ctype, f.read())

    def touch(self):
        self.touched = time.monotonic()

    def idle_left(self):
        return max(0, int(self.idle_max - (time.monotonic() - self.touched)))

    def busy(self):
        return self.job is not None and not self.job.done


P = None


# ─── Вызовы xm и системы ─────────────────────────────────────────────────────

def run_xm(args, timeout):
    """xm с фиксированными аргументами, без shell: (код, stdout, stderr)."""
    try:
        r = subprocess.run([P.xm] + args, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, errors="replace", timeout=timeout, env=SAFE_ENV)
    except subprocess.TimeoutExpired:
        return 124, "", "время ожидания вышло"
    except OSError as e:
        return 127, "", str(e)
    return r.returncode, r.stdout or "", r.stderr or ""


def tail_text(text, n=6):
    lines = [ln for ln in ANSI_RE.sub("", text).splitlines() if ln.strip()]
    return " / ".join(ln.strip() for ln in lines[-n:])


def get_clients():
    rc, out, err = run_xm(["clients", "--json"], 90)
    try:
        data = json.loads(out)
        if not isinstance(data, list):
            raise ValueError
    except ValueError:
        raise ApiError(500, "xm clients --json не вернул список: " + (tail_text(err or out) or "пусто"))
    P.uris = {c["uuid"]: (c.get("uri") or "", c.get("uri_tcp") or "") for c in data}
    return data


def system_numbers():
    out = {"ncpu": os.cpu_count() or 1}
    try:
        out["load1"] = round(os.getloadavg()[0], 2)
    except OSError:
        out["load1"] = None
    try:
        mem = {}
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                key, _, rest = line.partition(":")
                mem[key] = int(rest.split()[0])
        out["mem_total_mb"] = mem["MemTotal"] // 1024
        out["mem_used_mb"] = (mem["MemTotal"] - mem["MemAvailable"]) // 1024
    except (OSError, KeyError, ValueError, IndexError):
        out["mem_total_mb"] = out["mem_used_mb"] = None
    try:
        du = shutil.disk_usage("/")
        out["disk_pct"] = round(du.used * 100 / du.total)
    except OSError:
        out["disk_pct"] = None
    try:
        with open("/proc/uptime", encoding="ascii") as f:
            out["uptime_s"] = int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        out["uptime_s"] = None
    return out


def client_names():
    """{email: имя} по конфигу — подписи для статистики; xm тут не нужен."""
    try:
        with open(P.config, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return {}
    names = {}
    for ib in cfg.get("inbounds") or []:
        for c in (ib.get("settings") or {}).get("clients") or []:
            if c.get("email"):
                names[c["email"]] = c.get("comment") or c["email"]
    return names


def stats_state():
    api = ""
    try:
        with open(P.config, encoding="utf-8") as f:
            api = (json.load(f).get("api") or {}).get("listen") or ""
    except (OSError, ValueError):
        pass
    try:
        r = subprocess.run(["systemctl", "is-active", "xm-stats.timer"], capture_output=True,
                           text=True, timeout=5, env=SAFE_ENV)
        timer = r.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        timer = False
    return {"enabled": bool(api), "collector": timer}


def read_tail(path, n):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - LOG_BYTES))
        data = f.read()
    lines = data.decode("utf-8", "replace").split("\n")
    if size > LOG_BYTES:
        lines = lines[1:]  # первая строка обрезана
    while lines and not lines[-1]:
        lines.pop()
    return lines[-n:]


def read_journal(unit, n):
    try:
        r = subprocess.run(["journalctl", "-u", unit, "-n", str(n), "--no-pager", "-o", "short-iso"],
                           capture_output=True, text=True, errors="replace", timeout=15, env=SAFE_ENV)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return [ln for ln in r.stdout.splitlines() if ln and not ln.startswith("-- ")]


# ─── Проверки (selftest, diag-dpi): фоновый процесс, вывод читается опросом ─────

def _kill_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except (OSError, ProcessLookupError):
        pass


def _run_job(job, argv, limit, want_result):
    env = dict(SAFE_ENV)
    if want_result:
        env["XM_RESULT_LINE"] = "1"
    timer = None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, start_new_session=True)
        job.proc = proc
        timer = threading.Timer(limit, _kill_group, (proc, signal.SIGTERM))
        timer.daemon = True
        timer.start()
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip("\n")
            m = re.match(r"^XM-RESULT crit=(\d+) warn=(\d+)$", line)
            if m:
                job.result = {"crit": int(m.group(1)), "warn": int(m.group(2))}
            else:
                job.add(line)
        proc.wait()
        job.rc = proc.returncode
    except Exception as e:  # noqa: BLE001 — любой сбой запуска должен дойти до интерфейса
        job.add("Не удалось запустить: %s" % e)
        job.rc = -1
    finally:
        if timer:
            timer.cancel()
        job.done = True
        P.lock.release()


# ─── API ─────────────────────────────────────────────────────────────────────

def api_session(q, body):
    offset = datetime.datetime.now().astimezone().utcoffset()
    return {"idle_left": P.idle_left(), "idle_max": P.idle_max, "port": P.port,
            "tz_offset": int(offset.total_seconds() // 60) if offset else 0}


def api_ping(q, body):
    return {}


def api_stop(q, body):
    threading.Timer(0.3, P.httpd.shutdown).start()
    return {"stopping": True}


def api_overview(q, body):
    rc, out, err = run_xm(["info", "--json"], 40)
    try:
        info = json.loads(out)
    except ValueError:
        raise ApiError(500, "xm info --json не вернул JSON: " + (tail_text(err or out) or "пусто"))
    info["sys"] = system_numbers()
    pub = (info.get("config") or {}).get("public_port")
    info["conns_now"] = stats.count_established(pub) if isinstance(pub, int) else None
    info["traffic_24h"] = stats.traffic_since(86400)
    info["stats"] = stats_state()
    info["now"] = int(time.time())
    return info


def api_clients(q, body):
    clients = get_clients()
    summary = stats.clients_summary()
    for c in clients:
        c["stats"] = summary.get(c.get("email") or "")
    return {"clients": clients, "stats": stats_state(), "now": int(time.time())}


def api_add(q, body):
    name = body.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ApiError(400, "Имя: до 32 символов — буквы, цифры, точка, дефис, подчёркивание; без пробелов")
    if not P.lock.acquire(blocking=False):
        raise ApiError(409, "Идёт другая операция — дождись её завершения")
    try:
        before = get_clients()
        if any(c["name"].lower() == name.lower() for c in before):
            raise ApiError(409, "Клиент с таким именем уже есть")
        known = {c["uuid"] for c in before}
        rc, out, err = run_xm(["add", name], 120)
        after = get_clients()
        new = [c for c in after if c["uuid"] not in known and c["name"] == name]
        if not new:
            raise ApiError(500, "xm add не создал клиента: " + (tail_text(out + err) or "код %d" % rc))
        return {"client": new[0], "xm_rc": rc}
    finally:
        P.lock.release()


def api_del(q, body):
    uuid = body.get("uuid")
    if not isinstance(uuid, str) or not UUID_RE.fullmatch(uuid):
        raise ApiError(400, "Некорректный UUID")
    if not P.lock.acquire(blocking=False):
        raise ApiError(409, "Идёт другая операция — дождись её завершения")
    try:
        if not any(c["uuid"] == uuid for c in get_clients()):
            raise ApiError(404, "Такого клиента нет")
        rc, out, err = run_xm(["del", uuid], 120)
        if any(c["uuid"] == uuid for c in get_clients()):
            raise ApiError(500, "xm del не удалил клиента: " + (tail_text(out + err) or "код %d" % rc))
        return {"deleted": uuid}
    finally:
        P.lock.release()


def api_run(q, body):
    name = body.get("cmd")
    if name not in JOBS:
        raise ApiError(400, "Неизвестная проверка")
    if not P.lock.acquire(blocking=False):
        raise ApiError(409, "Идёт другая операция — дождись её завершения")
    args, limit, want = JOBS[name]
    job = Job(name)
    P.job = job
    # Замок снимает сам поток проверки, когда она закончится.
    threading.Thread(target=_run_job, args=(job, [P.xm] + args, limit, want), daemon=True).start()
    return {"id": job.id}


def api_job(q, body):
    job = P.job
    if job is None:
        return {"id": None, "done": True, "lines": [], "total": 0}
    try:
        since = max(0, int(q.get("since", ["0"])[0]))
    except ValueError:
        since = 0
    lines = list(job.lines)
    return {"id": job.id, "name": job.name, "lines": lines[since:], "total": len(lines),
            "done": job.done, "rc": job.rc, "result": job.result, "truncated": job.truncated,
            "started": int(job.started)}


def api_job_cancel(q, body):
    job = P.job
    if job and not job.done and job.proc:
        _kill_group(job.proc, signal.SIGTERM)
    return {}


def api_logs(q, body):
    src = (q.get("src") or ["xray"])[0]
    try:
        n = min(2000, max(10, int((q.get("n") or ["300"])[0])))
    except ValueError:
        n = 300
    if src in P.logs:
        path = P.logs[src]
        try:
            return {"src": src, "path": path, "lines": read_tail(path, n), "missing": False}
        except OSError:
            return {"src": src, "path": path, "lines": [], "missing": True}
    if src == "watchdog":
        lines, label = read_journal("xray-watchdog.service", n), "journalctl -u xray-watchdog"
    elif src == "f2b":
        label = "/var/log/fail2ban.log"
        try:
            lines = read_tail(label, n)
        except OSError:
            lines, label = read_journal("fail2ban.service", n), "journalctl -u fail2ban"
    else:
        raise ApiError(400, "Неизвестный источник лога")
    return {"src": src, "path": label, "lines": lines or [], "missing": lines is None}


def api_stats(q, body):
    rng = (q.get("range") or ["24h"])[0]
    if rng not in stats.RANGES:
        raise ApiError(400, "Окно: 24h, 7d или 30d")
    out = stats.series(rng)
    out["state"] = stats_state()
    summary = stats.clients_summary()
    key = {"24h": "today", "7d": "d7", "30d": "d30"}[rng]
    names = client_names()
    out["clients"] = sorted(
        ({"name": names[e], "up": r[key][0], "down": r[key][1], "last": r["last"]}
         for e, r in summary.items() if e in names),
        key=lambda x: -(x["up"] + x["down"]))
    return out


GET_ROUTES = {"session": api_session, "overview": api_overview, "clients": api_clients,
              "job": api_job, "logs": api_logs, "stats": api_stats}
POST_ROUTES = {"ping": api_ping, "stop": api_stop, "clients/add": api_add, "clients/del": api_del,
               "run": api_run, "job/cancel": api_job_cancel}


def make_qr(uuid, kind):
    if kind not in ("xhttp", "tcp"):
        raise ApiError(400, "kind: xhttp или tcp")
    if not UUID_RE.fullmatch(uuid or ""):
        raise ApiError(400, "Некорректный UUID")
    if uuid not in P.uris:
        get_clients()
    if uuid not in P.uris:
        raise ApiError(404, "Такого клиента нет")
    uri = P.uris[uuid][0 if kind == "xhttp" else 1]
    if not uri:
        raise ApiError(404, "Для этого транспорта ссылки нет")
    if not shutil.which("qrencode", path=SAFE_ENV["PATH"]):
        raise ApiError(501, "qrencode не установлен: sudo apt install -y qrencode")
    # Ссылка уходит через stdin: в argv её видел бы весь список процессов.
    r = subprocess.run(["qrencode", "-t", "SVG", "-m", "1", "-l", "L", "-o", "-"],
                       input=uri.encode(), capture_output=True, timeout=15, env=SAFE_ENV)
    if r.returncode != 0 or not r.stdout:
        raise ApiError(500, "qrencode не смог построить QR (ссылка слишком длинная?)")
    return r.stdout


# ─── HTTP ────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "xm"
    sys_version = ""
    timeout = 30

    def log_message(self, *args):  # в терминал не пишем: в адресе токен
        pass

    def send_error(self, code, message=None, explain=None):
        self._send(code if code in (400, 404, 405, 413) else 404)

    def _send(self, status, body=b"", ctype="application/json; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _loopback_host(self, value):
        try:
            return (urllib.parse.urlsplit("//" + value).hostname or "") in LOOPBACK
        except ValueError:
            return False

    def _checked(self, post):
        """Host и (у POST) происхождение запроса; иначе — пустой 404, как у чужого пути."""
        if not self._loopback_host(self.headers.get("Host", "")):
            return False
        if not post:
            return True
        origin = self.headers.get("Origin")
        if origin is not None:
            parts = urllib.parse.urlsplit(origin)
            if parts.scheme != "http" or (parts.hostname or "") not in LOOPBACK:
                return False
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
            return False
        return self.headers.get("X-Xm") == "1"

    def _dispatch(self, post):
        if not self._checked(post):
            return self._send(404)
        url = urllib.parse.urlsplit(self.path)
        parts = url.path.split("/")
        if len(parts) < 2 or not hmac.compare_digest(parts[1].encode(), P.token.encode()):
            return self._send(404)
        rest = "/".join(parts[2:])
        if len(parts) == 2:  # /<токен> без слэша: относительные адреса страницы иначе не сработают
            return self._send(308, extra={"Location": "/%s/" % P.token})
        if not self.headers.get("X-Xm-Bg"):
            P.touch()

        if not post and rest in P.static:
            ctype, data = P.static[rest]
            extra = {"Content-Security-Policy": CSP} if rest == "" else None
            return self._send(200, data, ctype, extra)

        q = urllib.parse.parse_qs(url.query)
        try:
            if not post and rest == "api/qr":
                svg = make_qr((q.get("uuid") or [""])[0], (q.get("kind") or ["xhttp"])[0])
                return self._send(200, svg, "image/svg+xml",
                                  {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})
            table = POST_ROUTES if post else GET_ROUTES
            fn = table.get(rest[4:]) if rest.startswith("api/") else None
            if fn is None:
                return self._send(404)
            body = {}
            if post:
                length = int(self.headers.get("Content-Length") or 0)
                if length > 4096:
                    return self._send(413)
                if length:
                    if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                        return self._send(404)
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                    if not isinstance(body, dict):
                        raise ApiError(400, "Тело запроса — JSON-объект")
            return self._json(200, fn(q, body))
        except ApiError as e:
            return self._json(e.status, {"error": e.message})
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "Некорректный запрос"})
        except Exception as e:  # noqa: BLE001 — сбой обработчика не должен ронять панель
            return self._json(500, {"error": "Внутренняя ошибка: %s" % e})

    def do_GET(self):
        self._dispatch(False)

    def do_POST(self):
        self._dispatch(True)

    def do_HEAD(self):
        self._send(404)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    address_family = socket.AF_INET
    request_queue_size = 64  # браузер открывает десяток соединений разом; 5 по умолчанию мало

    def handle_error(self, request, client_address):
        pass  # обрыв соединения браузером — не событие


def monitor():
    """Закрывает панель после бездействия; идущую проверку не прерывает."""
    while True:
        time.sleep(1)
        if P.idle_left() == 0 and not P.busy():
            print("\nПанель закрыта: %d мин без действий." % (P.idle_max // 60), flush=True)
            P.httpd.shutdown()
            return


def main():
    global P
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--idle", type=int, default=30)
    ap.add_argument("--xm", default="/usr/local/bin/xm")
    ap.add_argument("--config", default="/usr/local/etc/xray/config.json")
    ap.add_argument("--xray-log", default="/var/log/xray/error.log")
    ap.add_argument("--nginx-log", default="/var/log/nginx/reality_fallback.log")
    ap.add_argument("--journal", default="/usr/local/etc/xray/journal.md")
    ap.add_argument("--ssh-port", default="22")
    args = ap.parse_args()
    if not 1024 <= args.port <= 65535 or args.idle < 1:
        sys.exit("Порт 1024–65535, бездействие — от 1 минуты")
    if os.geteuid() != 0:
        sys.exit("Нужен root: sudo xm ui")
    P = Panel(args)
    try:
        # Адрес зашит в коде, а не берётся из аргументов: снаружи панель не поднять.
        P.httpd = Server(("127.0.0.1", args.port), Handler)
    except OSError as e:
        sys.exit("Порт %d занят или недоступен (%s). Другой порт: sudo xm ui --port <N>" % (args.port, e))

    def stop(*_):
        threading.Thread(target=P.httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)
    threading.Thread(target=monitor, daemon=True).start()

    print("Панель xm слушает только 127.0.0.1:%d этого сервера." % args.port)
    print("Токен в пути: /%s/" % P.token)
    print("")
    print("Из окна на своём ПК (если тоннеля ещё нет):")
    print("  ssh -L 8080:127.0.0.1:%d -p %s <пользователь>@<сервер>" % (args.port, args.ssh_port))
    print("Потом в браузере (первое число после -L — порт на ПК):")
    print("  http://127.0.0.1:8080/%s/" % P.token)
    print("")
    print("Остановить: Ctrl+C. Сама закроется через %d мин без действий." % args.idle, flush=True)
    try:
        P.httpd.serve_forever(poll_interval=0.5)
    finally:
        job = P.job
        if job and not job.done and job.proc:
            _kill_group(job.proc, signal.SIGTERM)
        P.httpd.server_close()
        print("Панель остановлена.", flush=True)


if __name__ == "__main__":
    main()
