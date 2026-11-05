#!/usr/bin/env python3
"""xm bridge facts — факты сервера для xdiag одной строкой JSON (контракт bridge-facts 1.0).

  bridge.py facts --config PATH --xver V --active B --port N --fp FP --front B --tcp B --pq B
                  --ufw open|closed|off --doh B --hijack B --nonip V --ru B --self JSON --health B
                  --commit SHA --branch BR --pbk KEY            (B — true|false)

Соль сессии (32 hex) — в окружении XM_BRIDGE_SALT (командную строку процесса видит любой
пользователь): без неё поля profile нет. Значения профиля наружу не уходят — только
HMAC-SHA256(соль, значение), первые 12 hex; нормализация — как в xdiag (internal/profile.Hashes):
UUID и shortId — нижний регистр, SNI — нижний регистр, путь как есть, порт числом; пустое
значение — пустая строка. Профиль — первый inbound (XHTTP), порт — публичный (за фронтом — его).
"""
import hashlib
import hmac
import json
import os
import re
import sys
import time

# Правило долей REALITY (ClientHello без X25519MLKEM768 перед X25519 — сайту-маске): Xray v26.9.9 и
# новее (XTLS/REALITY 8cdf7bf; landscape.md, тот же порог — reality_decide в doctor.py).
MLKEM_FROM = (26, 9, 9)


def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def _b(v):
    return v == "true"


def _health(now):
    """Журнал здоровья: последнее окно и последний трафик своих клиентов (как timeline в doctor.py)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import health
    except ImportError:
        return {}, None
    ws = health.load_windows(now - 7 * 86400)
    last = {"t": ws[-1]["t"], "vd": ws[-1].get("vd")} if ws else {}
    tr = [w["t"] for w in ws if (w.get("tr") or 0) >= health.TRAFFIC_MIN]
    return last, (tr[-1] if tr else None)


def profile(cfg, salt, pbk, port):
    def h(v):
        return hmac.new(salt, v.encode(), hashlib.sha256).hexdigest()[:12] if v else ""
    ib = (cfg.get("inbounds") or [{}])[0]
    ss = ib.get("streamSettings") or {}
    rs = ss.get("realitySettings") or {}
    clients = {}
    for i, c in enumerate((ib.get("settings") or {}).get("clients") or []):
        clients[c.get("email") or "#%d" % (i + 1)] = h(str(c.get("id", "")).strip().lower())
    return {"salted": True, "clients": clients, "pbk": h(pbk.strip()),
            "short_ids": [h(str(s).lower()) for s in rs.get("shortIds") or []],
            "path": h((ss.get("xhttpSettings") or {}).get("path") or ""),
            "sni": [h(str(s).lower()) for s in rs.get("serverNames") or []],
            "port": h(str(port)) if port else ""}


def cmd_facts(a):
    with open(a.get("config") or "/usr/local/etc/xray/config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    ib = (cfg.get("inbounds") or [{}])[0]
    ss = ib.get("streamSettings") or {}
    port = int(a["port"]) if (a.get("port") or "").isdigit() else 0
    xver = a.get("xver") or ""
    try:
        self_res = json.loads(a.get("self") or "{}")
    except ValueError:
        self_res = {}
    now = int(time.time())
    last, traffic = _health(now)
    out = {
        "schema": {"name": "bridge-facts", "major": 1, "minor": 0},
        "xm": {"commit": a.get("commit") or "", "branch": a.get("branch") or ""},
        "time": now,
        # «?» — xray не ответил: xdiag без версии отверг бы и остальные факты (self: listen и т. п.).
        "xray": {"version": xver or "?", "active": _b(a.get("active")),
                 "mlkem_rule": _ver(xver) >= MLKEM_FROM if _ver(xver) else None, "min_client_ver": None},
        "public": {"port": port, "transport": ss.get("network") or "", "mode": (ss.get("xhttpSettings") or {}).get("mode") or "auto",
                   "fp": a.get("fp") or "", "sni": ((ss.get("realitySettings") or {}).get("serverNames") or [""])[0],
                   "front": _b(a.get("front")), "tcp_inbound": _b(a.get("tcp")), "pq": _b(a.get("pq"))},
        "firewall": {"ufw": a.get("ufw") or "off"},
        "dns": {"doh": _b(a.get("doh")), "hijack53": _b(a.get("hijack")), "nonip": a.get("nonip") or ""},
        "ru_block": _b(a.get("ru")),
        "self": self_res,
        "health": {"enabled": _b(a.get("health")), "last_window": last, "last_traffic": traffic},
    }
    salt = os.environ.get("XM_BRIDGE_SALT", "")
    if re.fullmatch(r"[0-9a-f]{32}", salt):
        out["profile"] = profile(cfg, bytes.fromhex(salt), a.get("pbk") or "", port)
    print(json.dumps(out, ensure_ascii=False, separators=(",", ":")))
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] != "facts":
        print(__doc__, file=sys.stderr)
        return 2
    a, it = {}, iter(argv[2:])
    for key in it:
        a[key.lstrip("-")] = next(it, "")
    try:
        return cmd_facts(a)
    except (OSError, ValueError) as e:
        print("bridge: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
