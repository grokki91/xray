#!/usr/bin/env python3
"""Анализатор «почему клиент не подключается» (xm doctor).

Каждую стадию подключения сервер видит сам, если смотреть в момент попытки: дошёл ли SYN, ушёл ли
SYN-ACK и вернулся ли ACK, пришёл ли ClientHello целиком, принял бы его REALITY и почему нет,
подтверждает ли клиент ответ сервера. Решение REALITY повторяется по ClientHello и ключу сервера
из config.json в том же порядке проверок, что в XTLS/REALITY tls.go (Server): без перезапуска Xray,
без show и логов с адресами. Расшифровка session_id ключом сервера отличает свой клиент от зонда:
расшифровалось — это профиль с этого сервера, и видно его shortId, время и версию ядра.

Адреса — только в памяти прохода: в отчёте сети помечены буквами, на диск не пишется ничего.
Захват — сокет AF_PACKET с фильтром BPF по порту в ядре: python получает только пакеты своего
порта и только на время окна.

  doctor.py run --config PATH [--self JSON] [--xver X.Y.Z] [--port N] [--ufw open|closed|off]
                [--server-ip ADDR] [--live СЕК] [--iface IF] [--backups DIR]
                [--api HOST:PORT] [--xray PATH] [--json]
  Адрес SSH-сеанса — в XM_SSH_PEER: окружение процесса читает только root, командную строку — все.
  doctor.py hello HEX [--config PATH] [--now T]   разбор одного ClientHello (тесты, ручной разбор)
"""
import base64
import hashlib
import json
import os
import re
import socket
import struct
import sys
import time

STATS_DIR = os.environ.get("XM_STATS_DIR", "/var/lib/xm/stats")

# ─── ClientHello ─────────────────────────────────────────────────────────────

X25519, MLKEM = 0x001D, 0x11EC
MLKEM_PUB = 1184                     # ключ ML-KEM-768 в доле X25519MLKEM768, за ним 32 б X25519
TLS13 = 0x0304
HELLO_MAX = 20480                    # больше REALITY не читает: запись TLS — до 16 КБ


def _grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def parse_hello(buf):
    """ClientHello из начала потока клиента. {"err": "nottls"|"partial"|"bad", "have", "need"} или
    поля: sni, alpn, versions, groups, shares [(группа, данные)], random, sid, original."""
    if len(buf) < 5:
        return {"err": "partial", "have": len(buf), "need": 5}
    if buf[0] != 0x16 or buf[1] != 3:
        return {"err": "nottls"}
    # Сообщение может идти несколькими записями: склеить их до длины из заголовка рукопожатия.
    hs, off = b"", 0
    while True:
        if off + 5 > len(buf):
            return {"err": "partial", "have": len(buf), "need": off + 5}
        if buf[off] != 0x16:
            return {"err": "bad"}
        rl = int.from_bytes(buf[off + 3:off + 5], "big")
        if off + 5 + rl > len(buf):
            return {"err": "partial", "have": len(buf), "need": off + 5 + rl}
        hs += buf[off + 5:off + 5 + rl]
        off += 5 + rl
        if len(hs) >= 4:
            if hs[0] != 1:
                return {"err": "bad"}
            need = 4 + int.from_bytes(hs[1:4], "big")
            if len(hs) >= need:
                hs = hs[:need]
                break
    try:
        return _hello_fields(hs)
    except (IndexError, ValueError, struct.error):
        return {"err": "bad"}


def _hello_fields(hs):
    p = 4
    h = {"original": hs, "random": hs[p + 2:p + 34]}
    p += 34
    n = hs[p]
    h["sid"] = hs[p + 1:p + 1 + n]
    p += 1 + n
    n = int.from_bytes(hs[p:p + 2], "big")
    h["ciphers"] = n // 2
    p += 2 + n
    p += 1 + hs[p]
    end = p + 2 + int.from_bytes(hs[p:p + 2], "big")
    p += 2
    h.update(sni="", alpn=[], versions=[], groups=[], shares=[], exts=[])
    while p + 4 <= end:
        t, n = struct.unpack_from("!HH", hs, p)
        d = hs[p + 4:p + 4 + n]
        p += 4 + n
        h["exts"].append(t)
        if t == 0 and len(d) >= 5 and d[2] == 0:
            h["sni"] = d[5:5 + int.from_bytes(d[3:5], "big")].decode("ascii", "replace")
        elif t == 10:
            h["groups"] = [int.from_bytes(d[i:i + 2], "big") for i in range(2, 2 + int.from_bytes(d[:2], "big"), 2)]
        elif t == 16:
            q, e = 2, 2 + int.from_bytes(d[:2], "big")
            while q < e:
                h["alpn"].append(d[q + 1:q + 1 + d[q]].decode("ascii", "replace"))
                q += 1 + d[q]
        elif t == 43:
            h["versions"] = [int.from_bytes(d[i:i + 2], "big") for i in range(1, 1 + d[0], 2)]
        elif t == 51:
            q, e = 2, 2 + int.from_bytes(d[:2], "big")
            while q + 4 <= e:
                g, ln = struct.unpack_from("!HH", d, q)
                h["shares"].append((g, d[q + 4:q + 4 + ln]))
                q += 4 + ln
    h["grease"] = any(_grease(x) for x in h["exts"] + h["groups"])
    return h


def share_names(h):
    names = {X25519: "X25519", MLKEM: "X25519MLKEM768", 0x0017: "P-256", 0x0018: "P-384"}
    return [names.get(g, "0x%04x" % g) for g, _ in h["shares"] if not _grease(g)]


# ─── REALITY: решение сервера по ClientHello ─────────────────────────────────
#
# Порядок — как в XTLS/REALITY tls.go (Server) с 8cdf7bf (Xray v26.9.9 и новее): TLS 1.3 и SNI
# из serverNames → первая из долей X25519MLKEM768/X25519 — X25519MLKEM768, без повторов → AEAD
# session_id ключом сервера → версия ядра, время, shortId. На ядре старше v26.9.9 правила долей
# нет: тогда «mlkem» сервер пропустил бы — это видно по полю mlkem_rule.

def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _ver(s):
    try:
        v = tuple(int(x) for x in str(s).split("."))
        return v if len(v) == 3 and all(0 <= x < 256 for x in v) else None
    except ValueError:
        return None


def reality_inbounds(cfg):
    out = []
    for i, ib in enumerate(cfg.get("inbounds") or []):
        ss = ib.get("streamSettings") or {}
        rs = ss.get("realitySettings") or {}
        if ss.get("security") != "reality" or not rs.get("privateKey"):
            continue
        try:
            priv = _b64(rs["privateKey"])
            sids = set()
            for s in rs.get("shortIds") or []:
                sids.add(bytes.fromhex(s).ljust(8, b"\0")[:8])
        except ValueError:
            continue
        out.append({"idx": i, "port": ib.get("port"), "net": ss.get("network") or "tcp",
                    "names": set(rs.get("serverNames") or []), "priv": priv, "sids": sids,
                    "mtd": int(rs.get("maxTimeDiff") or 0), "minv": _ver(rs.get("minClientVer", "")),
                    "maxv": _ver(rs.get("maxClientVer", ""))})
    return out


def _peer_keys(h):
    """(X25519 по правилу REALITY или None, X25519 для расшифровки при нарушенном правиле)."""
    peer = peer2 = None
    for g, d in h["shares"]:
        if g == MLKEM and len(d) == MLKEM_PUB + 32:
            if peer2 is not None:
                peer2 = None
                break
            peer2 = d[MLKEM_PUB:]
            continue
        if g == X25519 and len(d) == 32:
            if peer is not None:
                peer2 = None
                break
            peer = d
            break
    rule = (peer or peer2) if peer2 is not None else None
    any25519 = next((d for g, d in h["shares"] if g == X25519 and len(d) == 32), None)
    if any25519 is None:
        any25519 = next((d[MLKEM_PUB:] for g, d in h["shares"] if g == MLKEM and len(d) == MLKEM_PUB + 32), None)
    return rule, any25519


def _open_sid(priv, peer, h):
    """16 байт session_id, расшифрованные ключом сервера; None — ключ не тот или не REALITY."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.exceptions import InvalidTag
    except ImportError:
        raise RuntimeError("нет python3-cryptography")
    if len(h["sid"]) != 32 or peer is None:
        return None
    try:
        shared = X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(peer))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=h["random"][:20], info=b"REALITY").derive(shared)
        aad = bytearray(h["original"])
        aad[39:71] = bytes(32)
        return AESGCM(key).decrypt(h["random"][20:], h["sid"], bytes(aad))
    except (InvalidTag, ValueError):
        return None


def core_name(v):
    if v == (1, 8, 1):
        return "sing-box: Hiddify 4.x, NekoBox, Karing, SFA/SFI"
    if v == (1, 8, 2):
        return "mihomo: Clash Meta, FlClash, Clash Verge"
    return "Xray-core %d.%d.%d" % v


def reality_decide(h, ins, now, port=None, xver=None):
    """Что сделал бы REALITY с этим ClientHello. r: ok | tls13 | sni | mlkem | key | ver | time | sid;
    own — session_id расшифрован ключом одного из inbound (это профиль с этого сервера)."""
    rule_key, any_key = _peer_keys(h)
    mlkem = rule_key is not None
    res = {"sni": h["sni"], "mlkem": mlkem, "shares": share_names(h), "own": False,
           "mlkem_rule": xver is None or _ver_ge(xver, (26, 9, 9))}
    cand = [i for i in ins if port is None or i["port"] == port] or ins
    # Своим считается ClientHello, который открылся ключом любого inbound — даже с чужим SNI.
    pt, ib = None, None
    for i in sorted(cand, key=lambda x: h["sni"] not in x["names"]) + [x for x in ins if x not in cand]:
        pt = _open_sid(i["priv"], rule_key if mlkem else any_key, h)
        if pt is not None:
            ib = i
            break
    if pt is not None:
        v = (pt[0], pt[1], pt[2])
        res.update(own=True, idx=ib["idx"], ver=v, core=core_name(v),
                   dt=int(now) - int.from_bytes(pt[4:8], "big"), sid_ok=pt[8:16] in ib["sids"])
    names = set().union(*(i["names"] for i in cand)) if cand else set()
    if TLS13 not in h["versions"]:
        res["r"] = "tls13"
    elif h["sni"] not in names:
        res["r"] = "sni"
    elif not mlkem and res["mlkem_rule"]:
        res["r"] = "mlkem"
    elif pt is None:
        res["r"] = "key"
    elif (ib["minv"] and v < ib["minv"]) or (ib["maxv"] and v > ib["maxv"]):
        res["r"] = "ver"
    elif ib["mtd"] and abs(res["dt"]) * 1000 > ib["mtd"]:
        res["r"] = "time"
    elif not res["sid_ok"]:
        res["r"] = "sid"
    else:
        res["r"] = "ok"
    return res


def _ver_ge(a, b):
    va = _ver(a) if isinstance(a, str) else a
    return va is not None and va >= b


# ─── Захват: AF_PACKET + BPF по порту ────────────────────────────────────────
#
# SOCK_DGRAM: пакет начинается с IP-заголовка, канальный уровень не важен (ethernet, venet, tun).
# Входящие видны до netfilter — SYN, который отбросит ufw, всё равно посчитается; исходящие — после.

PACKET_OUTGOING = 4
SNAP = 18432
MAX_FLOWS = 20000                    # SYN-флуд за окно не съест память: дальше новые попытки не заводятся


def _bpf(ports):
    """Классический BPF: TCP (IPv4 без фрагментов или IPv6 без цепочки заголовков) с портом из ports."""
    prog = [(0x30, 0, None, None), (0x74, 4, None, None), (0x15, 4, "v4", "c6"), ("c6",),
            (0x15, 6, "v6", "drop"), ("v4",), (0x30, 9, None, None), (0x15, 6, "t4", "drop"), ("t4",),
            (0x28, 6, None, None), (0x45, 0x1FFF, "drop", "o4"), ("o4",), (0xB1, 0, None, None)]
    for off in (0, 2):
        prog.append((0x48, off, None, None))
        for j, p in enumerate(ports):
            prog.append((0x15, p, "acc", None if j < len(ports) - 1 else ("d4" if off else "n4")))
        if not off:
            prog.append(("n4",))
    prog += [("d4",), (0x06, 0, None, None), ("v6",), (0x30, 6, None, None), (0x15, 6, "t6", "drop"), ("t6",)]
    for off in (40, 42):
        prog.append((0x28, off, None, None))
        for j, p in enumerate(ports):
            prog.append((0x15, p, "acc", None if j < len(ports) - 1 else ("drop" if off == 42 else "n6")))
        if off == 40:
            prog.append(("n6",))
    prog += [("acc",), (0x06, SNAP, None, None), ("drop",), (0x06, 0, None, None)]
    pos, n = {}, 0
    for x in prog:
        if len(x) == 1:
            pos[x[0]] = n
        else:
            n += 1
    out, i = [], 0
    for x in prog:
        if len(x) == 1:
            continue
        code, k, jt, jf = x
        out.append(struct.pack("HBBI", code, pos[jt] - i - 1 if jt else 0, pos[jf] - i - 1 if jf else 0, k))
        i += 1
    return b"".join(out), i


def _attach(sock, ports):
    import ctypes
    code, n = _bpf(ports)
    buf = ctypes.create_string_buffer(code)
    sock.setsockopt(socket.SOL_SOCKET, 26, struct.pack("HP", n, ctypes.addressof(buf)))   # SO_ATTACH_FILTER
    return buf                        # держать живым, пока сокет открыт


def _tcp(data):
    """(src, dst, sport, dport, seq, ack, flags, длина данных, данные) или None."""
    if len(data) < 20:
        return None
    v = data[0] >> 4
    if v == 4:
        t = (data[0] & 15) * 4
        if data[9] != 6 or len(data) < t + 20:
            return None
        src, dst, total = data[12:16], data[16:20], int.from_bytes(data[2:4], "big") - t
    elif v == 6:
        t = 40
        if data[6] != 6 or len(data) < 60:
            return None
        src, dst, total = data[8:24], data[24:40], int.from_bytes(data[4:6], "big")
    else:
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", data, t)
    off = (data[t + 12] >> 4) * 4
    return src, dst, sport, dport, seq, ack, data[t + 13], max(0, total - off), data[t + off:]


SYN, ACK, RST, FIN = 2, 16, 4, 1
M32 = 1 << 32


class Flow:
    __slots__ = ("peer", "t0", "syn", "synack", "est", "isn_c", "isn_s", "segs", "c_max", "s_max", "s_acked",
                 "s_retx", "c_rst", "c_fin", "s_rst", "s_fin", "t_last", "t_c", "hello", "t_hello", "have", "need")

    def __init__(self, peer, t, isn):
        self.peer, self.t0, self.syn, self.synack, self.est = peer, t, 1, 0, False
        self.isn_c, self.isn_s, self.segs = isn, None, {}
        self.c_max = self.s_max = self.s_acked = self.s_retx = 0
        self.c_rst = self.c_fin = self.s_rst = self.s_fin = None
        self.t_last = self.t_c = t
        self.hello, self.t_hello, self.have, self.need = None, None, 0, 0

    def client(self, t, seq, ack, flags, plen, pay):
        self.t_last = self.t_c = t
        if self.isn_s is not None and flags & ACK:
            self.est = True
            a = (ack - self.isn_s - 1) % M32
            if a < M32 // 2:
                self.s_acked = max(self.s_acked, a)
        if plen:
            rel = (seq - self.isn_c - 1) % M32
            if rel < M32 // 2:
                self.c_max = max(self.c_max, rel + plen)
                if self.hello is None and rel < HELLO_MAX:
                    self.segs[rel] = bytes(pay[:plen])
                    self._try_hello(t)
        if flags & RST:
            self.c_rst = self.c_rst or t
        if flags & FIN:
            self.c_fin = self.c_fin or t

    def server(self, t, seq, flags, plen):
        self.t_last = t
        if flags & SYN:
            self.synack += 1
            self.isn_s = seq
        elif plen and self.isn_s is not None:
            end = (seq - self.isn_s - 1 + plen) % M32
            if end < M32 // 2:
                if end <= self.s_max:
                    self.s_retx += 1
                else:
                    self.s_max = end
        if flags & RST:
            self.s_rst = self.s_rst or t
        if flags & FIN:
            self.s_fin = self.s_fin or t

    def _try_hello(self, t):
        buf = b""
        for start in sorted(self.segs):
            seg = self.segs[start]
            if start > len(buf):
                break
            if start + len(seg) > len(buf):
                buf += seg[len(buf) - start:]
        h = parse_hello(buf)
        if h.get("err") == "partial":
            self.have, self.need = len(buf), h["need"]
            return
        self.hello, self.t_hello, self.segs = h, t, None


def capture(ports, seconds, iface=None, tick=None):
    """Соединения на ports за seconds с. Возвращает (потоки с SYN в окне, старых соединений, потеряно
    пакетов). iface — только этот интерфейс (тесты: lo); иначе все, кроме петли."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
    keep = _attach(s, ports)
    try:
        # SO_RCVBUF упирается в net.core.rmem_max (~200 КБ): под root буфер ставится в обход него.
        try:
            s.setsockopt(socket.SOL_SOCKET, 33, 8 << 20)             # SO_RCVBUFFORCE
        except OSError:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        if iface:
            s.bind((iface, 0))
        s.settimeout(0.5)
        flows, old = {}, set()
        end = time.monotonic() + seconds
        nxt = time.monotonic() + 10
        try:
            while True:
                now = time.monotonic()
                if now >= end:
                    break
                if tick and now >= nxt:
                    tick(int(end - now))
                    nxt += 10
                try:
                    data, addr = s.recvfrom(SNAP + 64)
                except socket.timeout:
                    continue
                if addr[0] == "lo" and (not iface or addr[2] == PACKET_OUTGOING):
                    continue                  # петля: самопроверка и fallback; на lo пакет виден дважды
                try:
                    p = _tcp(data)
                except (IndexError, struct.error):
                    p = None
                if p is None:
                    continue
                src, dst, sport, dport, seq, ack, flags, plen, pay = p
                t = time.time()
                if dport in ports and sport not in ports:
                    key = (src, sport, dport)
                    f = flows.get(key)
                    if flags & SYN and not flags & ACK:
                        if (f is None or f.isn_c != seq) and len(flows) < MAX_FLOWS:
                            flows[key] = Flow(src, t, seq)
                            old.discard(key)
                        elif f is not None:
                            f.syn += 1
                    elif f is not None:
                        f.client(t, seq, ack, flags, plen, pay)
                    else:
                        old.add(key)
                elif sport in ports:
                    f = flows.get((dst, dport, sport))
                    if f is not None:
                        f.server(t, seq, flags, plen)
        except KeyboardInterrupt:
            pass
        try:
            drops = struct.unpack("II", s.getsockopt(263, 6, 8))[1]   # SOL_PACKET, PACKET_STATISTICS
        except OSError:
            drops = 0
    finally:
        s.close()
        del keep
    return flows, len(old), drops


# ─── Стадия каждой попытки ───────────────────────────────────────────────────

def stage(f, ins, now, xver=None):
    """Где остановилась попытка: syn | synack | scan | tcp | partial | nottls | hello (+ решение REALITY и
    что было после)."""
    out = {"t": f.t0, "syn": f.syn, "c": f.c_max, "s": f.s_max, "acked": f.s_acked, "retx": f.s_retx}
    if not f.synack:
        out["st"] = "syn"
    elif not f.est:
        out["st"] = "scan" if f.c_rst else "synack"
    elif f.hello is None:
        if f.c_max == 0:
            out["st"] = "tcp"
        else:
            out.update(st="partial", have=f.have, need=f.need)
    elif f.hello.get("err"):
        out["st"] = "nottls"
    else:
        out["st"] = "hello"
        # Время клиента сверяется с моментом ClientHello, как у REALITY, а не с концом окна.
        out["rd"] = reality_decide(f.hello, ins, f.t_hello or f.t0, port=None, xver=xver)
        # Встало — сервер переотправляет неподтверждённое, а от клиента 3 с ни пакета, ни FIN/RST:
        # закрывший соединение клиент жив, его пакеты доходят — это не заморозка.
        closed = f.s_fin or f.s_rst
        if f.s_max > f.s_acked and f.s_retx and not (f.c_rst or f.c_fin) and now - f.t_c >= 3:
            a = f.s_acked
            out["after"] = "post" if a < 1024 else "mid" if a < 10240 else "f16" if a <= 32768 else "late"
        elif closed and f.c_max < 8192 and closed - (f.t_hello or f.t0) < 3 and not (f.c_fin and f.c_fin < closed):
            out["after"] = "closed"
        else:
            out["after"] = "flow"
    return out


def _net(peer):
    return peer[:3] if len(peer) == 4 else peer[:6]


def _addr_bytes(a):
    a = (a or "").strip()
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            b = socket.inet_pton(fam, a)
            return b[12:] if fam == socket.AF_INET6 and b[:12] == bytes(10) + b"\xff\xff" else b
        except OSError:
            continue
    return None


def groups(flows, ins, now, ssh_peer=None, xver=None):
    """Попытки по сетям (/24 и /48), сети — буквами по времени первой попытки."""
    ssh = _addr_bytes(ssh_peer)
    by = {}
    for f in sorted(flows.values(), key=lambda x: x.t0):
        by.setdefault(_net(f.peer), []).append(stage(f, ins, now, xver))
    out = []
    for i, (net, st) in enumerate(by.items()):
        out.append({"label": chr(65 + i) if i < 26 else "Z%d" % i, "ssh": ssh is not None and _net(ssh) == net,
                    "own": any(x.get("rd", {}).get("own") for x in st), "attempts": st})
    return out


# ─── Факты сервера: хронология и профиль ─────────────────────────────────────

def timeline(now):
    """Последний трафик своих клиентов по журналу здоровья и что случилось после него."""
    # python3 -I каталог скрипта в sys.path не кладёт, а health.py лежит рядом (UI_DIR, root).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import health
    except ImportError:
        return {"windows": 0}
    ws = health.load_windows(now - 7 * 86400)
    out = {"windows": len(ws)}
    if not ws:
        return out
    tr = [w for w in ws if (w.get("tr") or 0) >= health.TRAFFIC_MIN]
    last = tr[-1]["t"] if tr else None
    out["last_traffic"] = last
    since = (last - health.WINDOW) if last else ws[0]["t"] - health.WINDOW
    out["after"] = [{"t": w["t"], "e": e, "text": health._event_text(e)} for w in ws if w["t"] > since
                    for e in (w.get("ev") or [])]
    out["self_fail"] = sum(1 for w in ws if w["t"] > since and (w.get("self") or {}).get("r") == "fail")
    out["self_last"] = (ws[-1].get("self") or {}).get("r")
    try:
        with open(os.path.join(STATS_DIR, "clients.json"), encoding="utf-8") as f:
            out["clients"] = {e: r.get("last", 0) for e, r in json.load(f).items() if isinstance(r, dict)}
    except (OSError, ValueError, AttributeError):
        pass
    return out


def _sha(s):
    return hashlib.sha256(str(s).encode()).hexdigest()[:12]


def profile_sig(cfg):
    """То, что клиент держит в профиле, по inbound: порт, клиенты, ключ, shortIds, SNI, путь."""
    out = {}
    for i, ib in enumerate(cfg.get("inbounds") or []):
        if ib.get("protocol") != "vless":
            continue
        ss = ib.get("streamSettings") or {}
        rs = ss.get("realitySettings") or {}
        xs = ss.get("xhttpSettings") or {}
        users = {}
        for c in (ib.get("settings") or {}).get("clients") or []:
            users[c.get("email") or c.get("comment") or _sha(c.get("id"))] = _sha((c.get("id"), c.get("flow", "")))
        out[i] = {"порт": ib.get("port"), "клиенты": users, "ключ REALITY": _sha(rs.get("privateKey")),
                  "shortIds": sorted(rs.get("shortIds") or []), "SNI": sorted(rs.get("serverNames") or []),
                  "путь XHTTP": xs.get("path"), "транспорт": (ss.get("network"), xs.get("mode"))}
    return out


def _diff(a, b):
    """Что в профиле изменилось от a к b — словами, без значений."""
    out = []
    for i in sorted(set(a) | set(b)):
        if i not in a or i not in b:
            out.append("inbound %d %s" % (i, "добавлен" if i in b else "удалён"))
            continue
        for k in b[i]:
            if k == "клиенты":
                ua, ub = a[i][k], b[i][k]
                out += ["клиент %s добавлен" % n for n in ub if n not in ua]
                out += ["клиент %s удалён" % n for n in ua if n not in ub]
                out += ["UUID клиента %s сменился" % n for n in ub if n in ua and ua[n] != ub[n]]
            elif a[i][k] != b[i][k]:
                out.append("%s inbound %d" % (k, i))
    return out


def profile_history(cfg, backups):
    """Последняя смена профиля по бэкапам config.json: (время бэкапа до смены, время после, что) или
    «не менялся с …»."""
    cur = profile_sig(cfg)
    files = []
    try:
        for n in os.listdir(backups):
            m = re.match(r"config_(\d{8})_(\d{6})", n)
            if m and n.endswith(".json"):
                files.append((time.mktime(time.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")), n))
    except OSError:
        return {"backups": 0}
    files.sort(reverse=True)
    out = {"backups": len(files)}
    newer, newer_t = cur, None
    for t, n in files:
        try:
            with open(os.path.join(backups, n), encoding="utf-8") as f:
                sig = profile_sig(json.load(f))
        except (OSError, ValueError):
            continue
        d = _diff(sig, newer)
        if d:
            out.update(changed=d, before=t, after=newer_t)
            return out
        newer, newer_t = sig, t
        out["same_since"] = t
    return out


# ─── Вердикт ─────────────────────────────────────────────────────────────────

RD_TEXT = {"ok": "REALITY принял бы", "tls13": "без TLS 1.3", "sni": "SNI не из serverNames",
           "mlkem": "нет X25519MLKEM768 перед X25519", "key": "ключ не этого сервера",
           "ver": "версия ядра вне min/maxClientVer", "time": "время клиента вне maxTimeDiff",
           "sid": "shortId не из списка"}
ST_TEXT = {"syn": "SYN дошёл, сервер не ответил", "synack": "SYN-ACK ушёл, клиент не подтвердил",
           "scan": "сканер портов (RST сразу после SYN-ACK)", "tcp": "TCP есть, данных от клиента нет",
           "partial": "ClientHello пришёл не целиком", "nottls": "не TLS"}
AFTER_TEXT = {"post": "ответ сервера не подтверждён (встало до 1 КБ)", "mid": "встало на 1–10 КБ",
              "f16": "встало на 10–32 КБ", "late": "встало позже 32 КБ",
              "closed": "сервер закрыл сразу после рукопожатия", "flow": "данные идут в обе стороны"}

CLIENTS = ("Android — v2rayNG; Windows — v2rayN; macOS — v2rayN или Happ; iOS — Happ: ядро Xray от v25.7.26, "
           "fp=chrome (firefox и safari — ядро от v26.3.27)")


def _kb(n):
    return "%.1f КБ" % (n / 1024)


def _v(v):
    return "%d.%d.%d" % v


def attempt_text(a):
    if a["st"] != "hello":
        s = ST_TEXT[a["st"]]
        if a["st"] == "partial":
            s += " (%d из %d б)" % (a.get("have", 0), a.get("need", 0))
        if a["st"] in ("syn", "synack") and a["syn"] > 1:
            s += ", SYN повторён %d раз" % (a["syn"] - 1)
        return s
    rd = a["rd"]
    s = "SNI %s, key_share %s: %s" % (rd["sni"] or "—", "+".join(rd["shares"]) or "—", RD_TEXT[rd["r"]])
    if rd.get("own"):
        s += "; ключ этого сервера%s, ядро %s, часы клиента %+d с" % (
            ", shortId верный" if rd["sid_ok"] else "", rd["core"], -rd["dt"])
    if rd["r"] == "ok":
        s += "; " + AFTER_TEXT[a["after"]] + " (от клиента %s, ответ %s, подтверждено %s)" % (
            _kb(a["c"]), _kb(a["s"]), _kb(a["acked"]))
    return s


def verdict(srv, gs, tl, prof, live):
    """{code, title, evidence[], actions[], ruled_out[]} — одна причина, первая по порядку стека:
    сервер → что видно в окне от своего клиента → сеть клиента → догадка по хронологии."""
    ip = srv.get("server_ip") or "<адрес сервера>"
    port = srv.get("port") or 443
    ruled = []
    s = srv.get("self") or {}
    xver = srv.get("xver") or "?"

    def out(code, title, ev, act):
        return {"code": code, "title": title, "evidence": ev, "actions": act, "ruled_out": ruled}

    # 1. Сервер
    if s.get("r") == "fail":
        at = s.get("at")
        if at == "listen":
            return out("server.listen", "Сервер: Xray не слушает публичный порт",
                       ["самопроверка: Xray не активен или порт %s не слушается" % port],
                       ["sudo systemctl status xray --no-pager", "sudo journalctl -u xray -n 30 --no-pager",
                        "sudo xm restart"])
        if at == "dns":
            return out("server.dns", "Сервер: домен-маска не резолвится — REALITY некуда отдать соединение",
                       ["самопроверка: имя из serverNames не резолвится с сервера"],
                       ["sudo xm watchdog now", "sudo xm diag-dpi"])
        if at == "egress":
            return out("server.egress", "Сервер: нет выхода в интернет",
                       ["самопроверка: и через тоннель, и напрямую запрос наружу не прошёл"],
                       ["curl -sI --max-time 5 https://www.google.com/generate_204", "вопрос хостеру"])
        return out("server.handshake", "Сервер: собственный клиент на петле не проходит рукопожатие",
                   ["самопроверка: VLESS+REALITY с самого сервера не прошёл, а прямой запрос наружу — да"],
                   ["sudo xray -test -config /usr/local/etc/xray/config.json", "sudo xm pubkey", "sudo xm selftest"])
    if srv.get("ufw") == "closed":
        return out("server.firewall", "Сервер: публичный порт %s закрыт в UFW" % port,
                   ["ufw status: правила ALLOW для %s/tcp нет — снаружи SYN отбрасывается" % port],
                   ["sudo ufw allow %s/tcp" % port])
    if s.get("r") == "ok":
        ruled.append("сервер: Xray слушает, самопроверка через публичный порт прошла (%s мс)" % s.get("ms", "?"))
    if srv.get("ufw") == "open":
        ruled.append("файрвол: порт %s открыт" % port)

    # 2. Окно: свой клиент — по ключу сервера; иначе сеть SSH-сеанса
    if live:
        own = [g for g in gs if g["own"]]
        if own:
            g = own[0]
            mine = [a for a in g["attempts"] if a.get("rd", {}).get("own")]
            ruled.append("сеть: TCP и ClientHello клиента доходят до сервера (сеть %s, попыток %d)" % (g["label"], len(mine)))
            bad = {}
            for a in mine:
                bad.setdefault(a["rd"]["r"], []).append(a)
            a0 = mine[0]["rd"]
            ev = ["сеть %s%s: попыток с ключом этого сервера — %d" % (g["label"], " (та же, что у SSH)" if g["ssh"] else "",
                                                                     len(mine))]
            for r in ("mlkem", "sni", "sid", "time", "ver"):
                if r not in bad:
                    continue
                a = bad[r][0]["rd"]
                ev.append(attempt_text(bad[r][0]))
                if r == "mlkem":
                    ruled.append("профиль: ключ, shortId и SNI совпадают с сервером")
                    return out("client.core",
                               "Клиент: ядро не шлёт X25519MLKEM768 — REALITY Xray %s отдаёт его ClientHello сайту-маске" % xver,
                               ev + ["REALITY с v26.9.9 (XTLS/REALITY 8cdf7bf) принимает только ClientHello, где "
                                     "X25519MLKEM768 идёт перед X25519; ядро %s долю X25519MLKEM768 не шлёт — "
                                     "клиент получает настоящий сертификат маски и пишет «таймаут»" % a["core"]],
                               ["сменить клиент на ядро Xray: " + CLIENTS,
                                "профиль в новый клиент: sudo xm qr <имя>   (или sudo xm uri <имя>)",
                                "проверка: sudo xm doctor — в окне попытка с «REALITY принял бы»"])
                if r == "sni":
                    return out("profile.sni", "Профиль: SNI «%s» не из serverNames сервера" % a["sni"], ev,
                               ["заново импортировать профиль: sudo xm qr <имя>"])
                if r == "sid":
                    return out("profile.sid", "Профиль: shortId не из списка сервера (профиль старый)", ev,
                               ["заново импортировать профиль: sudo xm qr <имя>"])
                if r == "time":
                    return out("client.clock", "Клиент: часы расходятся с сервером на %+d с" % -a["dt"], ev,
                               ["включить автоматическое время и часовой пояс на устройстве"])
                return out("client.version", "Клиент: версия ядра %s вне minClientVer/maxClientVer сервера" % _v(a["ver"]),
                           ev, ["обновить клиент или убрать minClientVer/maxClientVer из realitySettings"])
            ruled.append("профиль и ядро: REALITY принимает ClientHello клиента")
            after = {a["after"] for a in mine}
            ev.append(attempt_text(mine[-1]))
            for k in ("post", "mid"):
                if k in after:
                    return out("net.freeze", "Сеть: после ClientHello ответ сервера до клиента не доходит — заморозка по пути",
                               ev + ["клиент перестал подтверждать данные сервера сразу после рукопожатия: так выглядит "
                                     "заморозка ТСПУ по отпечатку или SNI"],
                               ["в клиенте fp=firefox (ядро Xray от v26.3.27), во время заморозки fp не менять",
                                "проверить из другой сети (Wi-Fi ↔ мобильная)", "сменить маску: sudo xm sni-scan"])
            if "f16" in after or "late" in after:
                return out("net.f16", "Сеть: соединение встаёт на 10–32 КБ — заморозка TCP к адресам хостинга",
                           ev, ["конфигом не лечится: другой хостер/ASN или мост; проверить из другой сети"])
            if "closed" in after and "flow" not in after:
                return out("profile.user", "Профиль: REALITY принят, но сервер сразу закрыл соединение — UUID или path "
                           "(вероятно)", ev, ["sudo xm clients — есть ли клиент; заново импортировать: sudo xm qr <имя>",
                                             "подтвердить: sudo xm reality-debug on → попытка → sudo xm log | grep -i invalid "
                                             "→ sudo xm reality-debug off"])
            used = srv.get("traffic") or {}
            if used:
                ev.append("трафик клиентов за окно: " + ", ".join("%s %s" % (k, _kb(v)) for k, v in used.items()))
            return out("ok", "Путь до сервера работает: REALITY принят, данные идут в обе стороны", ev,
                       ["проблема за тоннелем: в клиенте маршруты/DNS или «таймаут» — его тест задержки по URL; "
                        "проверить сайт через тоннель, а не индикатор"])
        ssh = [g for g in gs if g["ssh"]]
        cand = ssh or [g for g in gs if any(a["st"] in ("synack", "tcp", "partial") or
                                             a.get("rd", {}).get("r") in ("key", "mlkem") for a in g["attempts"])]
        if cand:
            g = cand[0]
            sts = [a for a in g["attempts"] if a["st"] != "scan"]
            if sts:
                a = sts[-1]
                ev = ["сеть %s%s: попыток %d; последняя — %s" % (g["label"], " (та же, что у SSH)" if g["ssh"] else
                                                                " (своя ли — по времени попытки)", len(sts), attempt_text(a))]
                if a["st"] == "syn":
                    return out("server.syn", "Сервер: SYN доходит, но сервер не отвечает", ev,
                               ["sudo ufw status verbose", "sudo ss -tlnp | grep ':%s '" % port])
                if a["st"] == "synack":
                    return out("net.synack", "Сеть: SYN доходит, ответ сервера до клиента — нет: TCP не устанавливается",
                               ev + ["так выглядит блокировка адреса сервера по пути (ТСПУ/провайдер)"],
                               ["с клиента: Test-NetConnection %s -Port %s (Windows) — False подтверждает" % (ip, port),
                                "проверить из другой сети; конфигом не лечится: запасной адрес/хостер"])
                if a["st"] in ("tcp", "partial"):
                    return out("net.hello", "Сеть: TCP есть, а ClientHello до сервера не доходит%s" %
                               (" целиком" if a["st"] == "partial" else ""),
                               ev + ["режут первый пакет с SNI (ТСПУ) или большой ClientHello не проходит по MTU"],
                               ["проверить из другой сети", "сменить маску: sudo xm sni-scan",
                                "sudo sysctl net.ipv4.tcp_mtu_probing   (нужно 1)"])
                if a["st"] == "hello" and a["rd"]["r"] == "key":
                    return out("profile.key", "Профиль: публичный ключ (pbk) не от этого сервера", ev +
                               ["SNI верный, X25519MLKEM768 есть, но session_id ключом сервера не открывается"],
                               ["заново импортировать профиль: sudo xm qr <имя>"])
                if a["st"] == "hello" and a["rd"]["r"] == "mlkem":
                    return out("client.core", "Клиент: ClientHello без X25519MLKEM768 — REALITY Xray %s его отвергает" % xver,
                               ev, ["сменить клиент на ядро Xray: " + CLIENTS, "sudo xm qr <имя>"])
        nets = len(gs)
        ev = ["за окно на :%s пришло попыток: %d из %d сетей, ни одной с ключом этого сервера" % (
            port, sum(len(g["attempts"]) for g in gs), nets)]
        if srv.get("ssh_peer"):
            ev.append("с сети SSH-сеанса попыток на :%s не было, хотя SSH из неё работает" % port)
        return out("net.nosyn", "До сервера не доходит ни одной попытки клиента", ev,
                   ["в браузере устройства открыть https://%s/ — предупреждение о сертификате: порт доступен, "
                    "клиент не шлёт (адрес/порт в профиле, приложение); бесконечная загрузка: путь режется "
                    "(бан адреса, белый список мобильной сети)" % ip,
                    "Windows: Test-NetConnection %s -Port %s" % (ip, port),
                    "Android, Hiddify «createService - null» — остановить приложение и запустить заново",
                    "повторить sudo xm doctor, нажимая «Подключить» в окне"])

    # 3. Без окна — по хронологии
    ev = []
    last = tl.get("last_traffic")
    if last:
        ev.append("последний трафик своих клиентов: %s" % time.strftime("%d.%m %H:%M", time.localtime(last)))
    after = tl.get("after") or []
    vx = [e for e in after if e["e"].startswith("ver_xray:")]
    # Бэкап пишется перед правкой: его время — время смены профиля.
    if prof.get("changed") and (not last or prof["before"] >= last):
        return out("profile.changed", "Вероятно: профиль на сервере менялся — у клиента старый (подтвердить окном)",
                   ev + ["изменилось: " + ", ".join(prof["changed"])],
                   ["заново импортировать профиль: sudo xm qr <имя>", "подтвердить: sudo xm doctor"])
    if vx and _ver_ge(vx[-1]["e"].split(":", 1)[1], (26, 9, 9)):
        return out("client.core", "Вероятно: после обновления Xray до %s клиент без X25519MLKEM768 отвергается "
                   "(подтвердить окном)" % vx[-1]["e"].split(":", 1)[1],
                   ev + ["%s — %s" % (time.strftime("%d.%m %H:%M", time.localtime(vx[-1]["t"])), vx[-1]["text"])],
                   ["подтвердить: sudo xm doctor и «Подключить» в клиенте в окне", "сменить клиент: " + CLIENTS])
    return out("nodata", "Без окна причину не назвать: попытки клиента нужно увидеть", ev,
               ["sudo xm doctor и «Подключить» в клиенте в течение окна"])


# ─── Отчёт ───────────────────────────────────────────────────────────────────

def _dhm(t):
    return time.strftime("%d.%m %H:%M", time.localtime(t))


def report(r, color=True):
    C = (lambda c, s: "\033[%sm%s\033[0m" % (c, s)) if color else (lambda c, s: s)
    srv, tl, prof, v = r["server"], r["timeline"], r["profile"], r["verdict"]
    ok, bad, inf = C("0;32", "[✓]"), C("0;31", "[✗]"), "[-]"
    print(C("1;36", "[ Сервер ]"))
    s = srv.get("self") or {}
    print("  %s Самопроверка через публичный порт: %s" % (
        ok if s.get("r") == "ok" else bad if s.get("r") == "fail" else inf,
        {"ok": "прошла (%s мс)" % s.get("ms"), "fail": "не прошла: " + str(s.get("at"))}.get(s.get("r"), "пропущена")))
    print("  %s UFW: %s" % (bad if srv.get("ufw") == "closed" else ok if srv.get("ufw") == "open" else inf,
                           {"open": "порт %s открыт" % srv.get("port"), "closed": "порт %s закрыт" % srv.get("port")}.get(
                               srv.get("ufw"), "не активен")))
    xv = srv.get("xver") or "?"
    print("  %s Xray %s%s" % (inf, xv, ": REALITY пускает только ClientHello с X25519MLKEM768 перед X25519 — "
                                      "ядра sing-box (Hiddify 4.x, NekoBox, Karing) и Xray старше v25.7.26 не проходят"
                                      if _ver_ge(xv, (26, 9, 9)) else ""))
    print()
    print(C("1;36", "[ Хронология (журнал здоровья) ]"))
    if not tl.get("windows"):
        print("  %s Журнала нет: sudo xm health on" % inf)
    else:
        lt = tl.get("last_traffic")
        print("  %s Последний трафик своих клиентов: %s" % (inf, _dhm(lt) if lt else "за 7 дней не было"))
        for e in (tl.get("after") or [])[-12:]:
            print("      после: %s %s" % (_dhm(e["t"]), e["text"]))
        for e, t in sorted((tl.get("clients") or {}).items(), key=lambda x: -x[1]):
            print("  %s Клиент %s: трафик последний раз %s" % (inf, e, _dhm(t) if t else "не было"))
    print()
    print(C("1;36", "[ Профиль клиентов (бэкапы config.json) ]"))
    if prof.get("changed"):
        print("  %s Менялся между %s и %s: %s" % (C("1;33", "[!]"), _dhm(prof["before"]),
                                                 _dhm(prof["after"]) if prof.get("after") else "сейчас",
                                                 ", ".join(prof["changed"])))
    elif prof.get("same_since"):
        print("  %s Порт, клиенты, ключ, shortIds, SNI и путь не менялись с %s (бэкапов: %d)" % (
            ok, _dhm(prof["same_since"]), prof["backups"]))
    else:
        print("  %s Бэкапов нет — сравнить не с чем" % inf)
    if r.get("live") is not None:
        print()
        lv = r["live"]
        print(C("1;36", "[ Окно %d с: попытки на :%s ]" % (lv["seconds"], srv.get("port"))))
        if lv.get("error"):
            print("  %s Захват не запустился: %s" % (bad, lv["error"]))
        if not r["groups"]:
            print("  %s Новых соединений не было (уже открытых: %d)" % (inf, lv.get("old", 0)))
        for g in r["groups"]:
            tag = " — сеть SSH-сеанса" if g["ssh"] else ""
            tag += " — ключ этого сервера" if g["own"] else ""
            print("  Сеть %s%s: попыток %d" % (g["label"], tag, len(g["attempts"])))
            for a in g["attempts"][-5:]:
                print("      %s  %s" % (time.strftime("%H:%M:%S", time.localtime(a["t"])), attempt_text(a)))
        if lv.get("drops"):
            print("  %s Захват потерял пакетов: %d — картина неполная" % (C("1;33", "[!]"), lv["drops"]))
    print()
    print(C("1;36", "[ Вердикт ]"))
    for x in v["ruled_out"]:
        print("  %s исключено — %s" % (ok, x))
    print("  %s %s" % (C("1;31", "✗") if v["code"] != "ok" else C("0;32", "✓"), C("1", v["title"])))
    for x in v["evidence"]:
        print("      • %s" % x)
    if v["actions"]:
        print("  Что делать:")
        for x in v["actions"]:
            print("      %s" % x)
    print()
    print("ВЕРДИКТ: %s — %s" % (v["code"], v["title"]))


# ─── Точка входа ─────────────────────────────────────────────────────────────

def _traffic_delta(xray, api, before):
    """Прирост счётчиков клиентов за окно без сброса: {email: байт}. Пусто — API нет или сбросил замер."""
    if not api or not xray:
        return {}
    import subprocess
    try:
        r = subprocess.run([xray, "api", "statsquery", "--server=" + api, "-pattern", "user>>>", "-t", "3"],
                           capture_output=True, text=True, timeout=8, stdin=subprocess.DEVNULL)
        cur = {}
        for s in json.loads(r.stdout or "{}").get("stat") or []:
            m = re.match(r"^user>>>(.+)>>>traffic>>>", s.get("name", ""))
            if m:
                cur[m.group(1)] = cur.get(m.group(1), 0) + int(s.get("value") or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    if before is None:
        return cur
    return {e: v - before.get(e, 0) for e, v in cur.items() if v - before.get(e, 0) > 0}


def cmd_run(a):
    with open(a.get("config") or "/usr/local/etc/xray/config.json", encoding="utf-8") as f:
        cfg = json.load(f)
    ins = reality_inbounds(cfg)
    try:
        self_res = json.loads(a.get("self") or "{}")
    except ValueError:
        self_res = {}
    port = int(a.get("port") or (ins[0]["port"] if ins else 443))
    peer = os.environ.get("XM_SSH_PEER", "")
    srv = {"self": self_res, "xver": a.get("xver") or None, "port": port, "ufw": a.get("ufw") or "off",
           "ssh_peer": bool(peer), "server_ip": a.get("server-ip")}
    now = time.time()
    r = {"server": srv, "timeline": timeline(now), "profile": profile_history(cfg, a.get("backups") or
                                                                             "/usr/local/etc/xray/backups"),
         "groups": [], "live": None}
    secs = int(a.get("live") or 0)
    if secs > 0:
        ports = sorted({port} | {i["port"] for i in ins if isinstance(i["port"], int)})
        lv = {"seconds": secs}
        before = _traffic_delta(a.get("xray"), a.get("api"), None)
        if sys.stderr.isatty():
            print("Окно %d с: нажми «Подключить» в клиенте (2–3 раза с паузой 10 с); Ctrl+C — закончить раньше"
                  % secs, file=sys.stderr)
        tick = (lambda left: print("  … осталось %d с" % left, file=sys.stderr)) if sys.stderr.isatty() else None
        try:
            flows, lv["old"], lv["drops"] = capture(ports, secs, a.get("iface"), tick)
        except (OSError, RuntimeError) as e:
            flows, lv["error"] = {}, str(e)
        end = time.time()
        try:
            r["groups"] = groups(flows, ins, end, peer, srv["xver"])
        except RuntimeError as e:          # нет cryptography — без расшифровки вердикта по ключу нет
            lv["error"] = str(e)
        srv["traffic"] = _traffic_delta(a.get("xray"), a.get("api"), before)
        r["live"] = lv
    r["verdict"] = verdict(srv, r["groups"], r["timeline"], r["profile"], secs > 0 and "error" not in r["live"])
    if "json" in a:
        print(json.dumps(r, ensure_ascii=False, default=lambda x: x.hex() if isinstance(x, bytes) else list(x)))
    else:
        report(r, color=sys.stdout.isatty())
    return 0


def cmd_hello(a):
    h = parse_hello(bytes.fromhex(a.get("hex", "")))
    out = {k: v for k, v in h.items() if k not in ("original", "random", "sid", "shares")}
    if not h.get("err"):
        out["shares"] = share_names(h)
        if a.get("config"):
            with open(a["config"], encoding="utf-8") as f:
                ins = reality_inbounds(json.load(f))
            rd = reality_decide(h, ins, float(a.get("now") or time.time()), xver=a.get("xver"))
            out["reality"] = {k: (_v(v) if k == "ver" else v) for k, v in rd.items()}
    print(json.dumps(out, ensure_ascii=False))
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] not in ("run", "hello"):
        print(__doc__, file=sys.stderr)
        return 2
    a, it = {}, iter(argv[2:])
    if argv[1] == "hello":
        a["hex"] = next(it, "")
    for key in it:
        k = key.lstrip("-")
        a[k] = True if k == "json" else next(it, "")
    try:
        return cmd_run(a) if argv[1] == "run" else cmd_hello(a)
    except (OSError, ValueError) as e:
        print("doctor: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
