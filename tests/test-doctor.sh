#!/usr/bin/env bash
# Анализатор xm doctor (ui/doctor.py): повтор решения REALITY по настоящим ClientHello клиента Xray-core
# 26.10.21 (фикстура: fp chrome, firefox, edge) и по ClientHello формы sing-box (из chrome: без
# X25519MLKEM768, версия 1.8.1 — как в common/tls/reality_client.go sing-box и Hiddify 4.x); стадии
# попытки, вердикт, смена профиля по бэкапам; под root — захват AF_PACKET на петле: фильтр порта,
# ClientHello из двух сегментов, обрыв на стадиях, адресов в выводе нет. Что решения совпадают с
# настоящим сервером, проверяет tests/vps/doctor.sh (клиенты Xray на петле VPS).
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export XM_HEALTH_DIR="$T/health" XM_HEALTH_RUN="$T/run" XM_STATS_DIR="$T/stats" PYTHONDONTWRITEBYTECODE=1
out=$(python3 - "$root" "$T" <<'PY' 2>&1
import json, os, socket, struct, sys, threading, time
root, T = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(root, "ui"))
import doctor as d

fails = []
def want(name, got, exp):
    if got != exp:
        fails.append("%s: ожидалось %r, получено %r" % (name, exp, got))

fx = json.load(open(os.path.join(root, "tests", "fixtures", "doctor-hellos.json")))
def cfg(**rs):
    r = {"dest": "127.0.0.1:8443", "serverNames": [fx["serverName"]], "privateKey": fx["privateKey"],
         "shortIds": [fx["shortId"]], "maxTimeDiff": 10000}
    r.update(rs)
    return {"inbounds": [{"port": 443, "protocol": "vless", "settings": {"clients": [{"id": "u1", "email": "pc"}]},
                          "streamSettings": {"network": "xhttp", "security": "reality", "realitySettings": r,
                                             "xhttpSettings": {"path": "/a"}}}]}
INS = d.reality_inbounds(cfg())
def hello(fp):
    raw = bytes.fromhex(fx["hellos"][fp]["hex"])
    return raw, fx["hellos"][fp]["t"]
def decide(raw, t, ins=INS, xver="26.10.21"):
    return d.reality_decide(d.parse_hello(raw), ins, t, xver=xver)

# ── Настоящие ClientHello Xray-core 26.10.21: своё ядро, ключ и shortId открываются ключом сервера
for fp in ("chrome", "firefox"):
    r = decide(*hello(fp))
    want("%s: REALITY принял бы, свой, версия, shortId" % fp, (r["r"], r["own"], r["ver"], r["sid_ok"], r["mlkem"]),
         ("ok", True, (26, 10, 21), True, True))
r = decide(*hello("edge"))
want("edge (без X25519MLKEM768): отказ по правилу долей, но ключ свой", (r["r"], r["own"], r["shares"]),
     ("mlkem", True, ["X25519"]))
want("edge на сервере старше v26.9.9 — правила долей нет", decide(*hello("edge"), xver="26.7.28")["r"], "ok")

# ── Форма sing-box: тот же ClientHello chrome без X25519MLKEM768 в supported_groups и key_share, версия
# 1.8.1, session_id запечатан заново — ключом из ECDH стороны сервера (он равен ключу клиента).
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
def reseal(raw, t, ver=(1, 8, 1), drop_mlkem=True, sid=fx["shortId"]):
    h = d.parse_hello(raw)
    hs = h["original"]
    p = 38 + 1 + hs[38]
    p += 2 + int.from_bytes(hs[p:p + 2], "big")
    p += 1 + hs[p]
    head, end, q, exts = hs[4:p], p + 2 + int.from_bytes(hs[p:p + 2], "big"), p + 2, b""
    while q < end:
        typ, n = struct.unpack_from("!HH", hs, q)
        data = hs[q + 4:q + 4 + n]
        q += 4 + n
        if drop_mlkem and typ == 10:
            g = [data[i:i + 2] for i in range(2, len(data), 2) if data[i:i + 2] != b"\x11\xec"]
            data = struct.pack("!H", 2 * len(g)) + b"".join(g)
        if drop_mlkem and typ == 51:
            sh = b"".join(struct.pack("!HH", gg, len(v)) + v for gg, v in h["shares"] if gg != d.MLKEM)
            data = struct.pack("!H", len(sh)) + sh
        exts += struct.pack("!HH", typ, len(data)) + data
    body = head + struct.pack("!H", len(exts)) + exts
    hs2 = bytearray(b"\x01" + len(body).to_bytes(3, "big") + body)
    hs2[39:71] = bytes(32)
    x = next(v for gg, v in h["shares"] if gg == d.X25519)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=h["random"][:20], info=b"REALITY").derive(
        X25519PrivateKey.from_private_bytes(d._b64(fx["privateKey"])).exchange(X25519PublicKey.from_public_bytes(x)))
    pt = bytes(ver) + b"\0" + struct.pack("!I", t) + bytes.fromhex(sid).ljust(8, b"\0")
    hs2[39:71] = AESGCM(key).encrypt(h["random"][20:], pt, bytes(hs2))
    return b"\x16\x03\x01" + len(hs2).to_bytes(2, "big") + bytes(hs2)
raw, t = hello("chrome")
sb = reseal(raw, t)
r = decide(sb, t)
want("sing-box: отказ по правилу долей, ключ и shortId свои, ядро названо", (r["r"], r["own"], r["sid_ok"], r["core"][:8]),
     ("mlkem", True, True, "sing-box"))
want("контроль пересборки: с X25519MLKEM768 и версией Xray — принят", decide(reseal(raw, t, (26, 10, 21), False), t)["r"], "ok")

# ── Остальные причины отказа — в порядке проверок REALITY
want("shortId не из списка", decide(reseal(raw, t, (26, 10, 21), False, sid="99"), t)["r"], "sid")
want("часы клиента на 60 с вперёд", decide(raw, t - 60)["r"], "time")
want("maxTimeDiff 0 — время не проверяется", decide(raw, t - 600, d.reality_inbounds(cfg(maxTimeDiff=0)))["r"], "ok")
r = decide(raw, t, d.reality_inbounds(cfg(serverNames=["other.example.com"])))
want("SNI не из serverNames — но ключ свой", (r["r"], r["own"]), ("sni", True))
other = X25519PrivateKey.generate().private_bytes_raw()
import base64
r = decide(raw, t, d.reality_inbounds(cfg(privateKey=base64.urlsafe_b64encode(other).rstrip(b"=").decode())))
want("ключ сервера другой — не свой", (r["r"], r["own"]), ("key", False))
want("minClientVer выше ядра клиента", decide(raw, t, d.reality_inbounds(cfg(minClientVer="26.11.0")))["r"], "ver")
want("shortId короче 8 байт дополняется нулями, как у Xray",
     decide(reseal(raw, t, (26, 10, 21), False, sid="ab"), t, d.reality_inbounds(cfg(shortIds=["ab"])))["r"], "ok")

# ── Разбор: неполный, не TLS
want("ClientHello не целиком — сколько есть и сколько нужно", d.parse_hello(raw[:600]), {"err": "partial", "have": 600,
                                                                                    "need": len(raw)})
want("HTTP вместо TLS", d.parse_hello(b"GET / HTTP/1.1\r\n\r\n")["err"], "nottls")
junk = b"\x01\x00\x00\x30" + b"\xff" * 48
want("мусор в рукопожатии не роняет разбор", d.parse_hello(b"\x16\x03\x01" + struct.pack("!H", len(junk)) + junk)["err"], "bad")

# ── Стадии попытки (поток собран руками: так ведёт его захват)
def flow(**kw):
    f = d.Flow(b"\xc0\x00\x02\x07", 1000.0, 100)
    for k, v in kw.items():
        setattr(f, k, v)
    return f
H = d.parse_hello(raw)
st = lambda f: d.stage(f, INS, 1010.0)
want("SYN без ответа", st(flow(syn=3))["st"], "syn")
want("SYN-ACK ушёл, ACK нет", st(flow(syn=3, synack=3))["st"], "synack")
want("RST сразу после SYN-ACK — сканер", st(flow(synack=1, c_rst=1000.1))["st"], "scan")
want("TCP без данных", st(flow(synack=1, est=True))["st"], "tcp")
want("ClientHello не целиком", st(flow(synack=1, est=True, c_max=600, have=600, need=1789))["st"], "partial")
a = st(flow(synack=1, est=True, c_max=1789, hello=H, t_hello=float(t), s_max=4000, s_acked=0, s_retx=4, t_c=1001.0))
want("ответ сервера не подтверждается, клиент молчит — встало после ClientHello", (a["rd"]["r"], a["after"]), ("ok", "post"))
a = st(flow(synack=1, est=True, c_max=1789, hello=H, t_hello=float(t), s_max=20000, s_acked=16000, s_retx=3, t_c=1001.0))
want("встало на 10–32 КБ", a["after"], "f16")
a = st(flow(synack=1, est=True, c_max=1789, hello=H, t_hello=float(t), s_max=1400, s_acked=1300, s_retx=1, c_rst=1001.0, t_c=1001.0))
want("клиент сам закрыл (RST) — не заморозка", a["after"], "flow")
a = st(flow(synack=1, est=True, c_max=2500, hello=H, t_hello=1000.2, s_max=900, s_acked=901, s_fin=1000.5))
want("сервер закрыл сразу после рукопожатия", a["after"], "closed")

# ── Вердикт
srv = {"self": {"r": "ok", "ms": 200}, "xver": "26.10.21", "port": 443, "ufw": "open", "server_ip": "203.0.113.5"}
def g(attempts, own=False, ssh=False):
    return [{"label": "A", "ssh": ssh, "own": own, "attempts": attempts}]
def att(raw_, t_, **kw):
    f = flow(synack=1, est=True, c_max=len(raw_), hello=d.parse_hello(raw_), t_hello=float(t_), s_max=5000, s_acked=5000, **kw)
    return d.stage(f, INS, t_ + 5)
V = lambda s, gs, live=True, tl=None, prof=None: d.verdict(s, gs, tl or {}, prof or {}, live)["code"]
want("сбой самопроверки — сервер", V(dict(srv, self={"r": "fail", "at": "dns"}), []), "server.dns")
want("UFW закрыт — сервер", V(dict(srv, ufw="closed"), []), "server.firewall")
want("свой клиент без X25519MLKEM768 — ядро клиента", V(srv, g([att(sb, t)], own=True)), "client.core")
want("свой клиент, старый shortId — профиль", V(srv, g([att(reseal(raw, t, (26, 10, 21), False, sid="99"), t)], own=True)),
     "profile.sid")
want("свой клиент, всё принято — путь работает", V(srv, g([att(raw, t)], own=True)), "ok")
fz = d.stage(flow(synack=1, est=True, c_max=1789, hello=H, t_hello=float(t), s_max=4000, s_retx=4, t_c=float(t)), INS, t + 9)
want("свой клиент, ответ не доходит — заморозка", V(srv, g([fz], own=True)), "net.freeze")
want("сеть SSH: SYN-ACK не доходит — блок по пути", V(srv, g([st(flow(syn=4, synack=4))], ssh=True)), "net.synack")
ins_other = d.reality_inbounds(cfg(privateKey=base64.urlsafe_b64encode(other).rstrip(b"=").decode()))
foreign = d.stage(flow(synack=1, est=True, c_max=1789, hello=H, t_hello=float(t)), ins_other, t + 1)
want("сеть SSH: ключ не наш при верном SNI — профиль от другого сервера", V(srv, g([foreign], ssh=True)), "profile.key")
want("ни одной попытки — до сервера не доходит", V(srv, []), "net.nosyn")
want("только сканеры — до сервера не доходит", V(srv, g([st(flow(synack=1, c_rst=1000.1))])), "net.nosyn")
tl = {"last_traffic": 1000, "after": [{"t": 1300, "e": "ver_xray:26.10.21", "text": "версия Xray 26.10.21"}]}
want("без окна: обновление Xray после последнего трафика — вероятно ядро клиента", V(srv, [], False, tl), "client.core")
want("без окна: профиль менялся после трафика", V(srv, [], False, tl, {"changed": ["shortIds inbound 0"], "before": 1100}),
     "profile.changed")
want("без окна: профиль менялся до трафика — не причина", V(srv, [], False, tl, {"changed": ["shortIds inbound 0"],
                                                                                 "before": 900}), "client.core")
want("без окна и без хронологии — данных нет", V(srv, [], False), "nodata")

# ── Профиль по бэкапам: что менялось — словами, без значений
bk = os.path.join(T, "backups"); os.makedirs(bk)
c0 = cfg()
json.dump(c0, open(os.path.join(bk, "config_20261020_100000.json"), "w"))
json.dump(c0, open(os.path.join(bk, "config_20261021_100000_before_update.json"), "w"))
p = d.profile_history(c0, bk)
want("не менялся с самого старого бэкапа", (p.get("changed"), p["same_since"] == time.mktime((2026, 10, 20, 10, 0, 0, 0, 0, -1))),
     (None, True))
c1 = cfg(shortIds=["77"])
c1["inbounds"][0]["settings"]["clients"].append({"id": "u2", "email": "phone"})
p = d.profile_history(c1, bk)
want("сменились shortIds, добавлен клиент", sorted(p["changed"]), ["shortIds inbound 0", "клиент phone добавлен"])
want("в описании смены нет значений", any("77" in x or "u2" in x for x in p["changed"]), False)

# ── Захват на петле (нужен root: AF_PACKET)
if os.geteuid() == 0:
    lst = socket.socket(); lst.bind(("127.0.0.1", 0)); lst.listen(16); port = lst.getsockname()[1]
    oth = socket.socket(); oth.bind(("127.0.0.1", 0)); oth.listen(4); oport = oth.getsockname()[1]
    held = []
    def srv_loop():
        lst.settimeout(6)
        try:
            while True:
                c, _ = lst.accept(); held.append(c); c.settimeout(0.3)
                try:
                    if c.recv(65536):
                        c.sendall(b"\x16\x03\x03" + b"\0" * 1200)
                except OSError:
                    pass
        except OSError:
            pass
    def cli():
        time.sleep(0.8)
        a = socket.create_connection(("127.0.0.1", port)); a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        a.sendall(raw[:700]); time.sleep(0.3); a.sendall(raw[700:]); time.sleep(0.3); a.recv(65536); held.append(a)
        b = socket.create_connection(("127.0.0.1", port)); b.sendall(raw[:600]); held.append(b)
        held.append(socket.create_connection(("127.0.0.1", port)))
        o = socket.create_connection(("127.0.0.1", oport)); o.sendall(raw); held.append(o)
    threading.Thread(target=srv_loop, daemon=True).start()
    threading.Thread(target=cli, daemon=True).start()
    flows, old, drops = d.capture([port], 4, "lo")
    gs = d.groups(flows, d.reality_inbounds(cfg(maxTimeDiff=0)), time.time(), "127.0.0.1", "26.10.21")
    sts = sorted(a["st"] + ":" + a.get("rd", {}).get("r", "") for a in gs[0]["attempts"]) if gs else []
    want("захват: только свой порт, ClientHello из двух сегментов, неполный, пустой",
         sts, ["hello:ok", "partial:", "tcp:"])
    want("захват: сеть SSH узнана, свой ключ узнан", (len(gs), gs[0]["ssh"], gs[0]["own"]) if gs else None, (1, True, True))
    blob = json.dumps(gs, default=lambda x: x.hex() if isinstance(x, bytes) else list(x))
    want("в выводе нет адресов", [x for x in ("127.0.0.1", "7f000001") if x in blob], [])
    for x in held + [lst, oth]:
        x.close()
else:
    print("захват AF_PACKET пропущен: не root (проверяет tests/vps/doctor.sh)")

print("\n".join("FAIL " + f for f in fails) if fails else "doctor: ok")
PY
)
echo "$out"
[[ "$out" == *"doctor: ok"* ]]
