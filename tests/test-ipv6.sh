#!/usr/bin/env bash
# IPv6 в ссылках (xm.sh): какой адрес идёт в ссылку — постоянный глобальный, src маршрута наружу, если
# он среди годных; временный, ULA и link-local — нет; строка «SERVER IP6» в client-info.txt
# перекрывает выбор. --v6 (_uri_v6) даёт ссылку с [адрес] и хвостом -v6, без IPv6 — отказ; ссылка
# по IPv4 не изменилась. Функции — из xm.sh как есть; ip — заглушка в формате iproute2, ключ и
# фронт — не предмет проверки.
root=${BASH_SOURCE[0]%/*}/..
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
RED= NC=
fails=0
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
eq()  { [[ $2 == "$3" ]] || bad "$1: ожидалось «$3», получено «$2»"; }
eval "$(sed -n '/^_get_field()/,/^}/p; /^_get_server_ip()/,/^}/p; /^_ip6_candidates()/,/^}/p
  /^_get_server_ip6()/,/^}/p; /^URI_HOST=/p; /^_uri_v6()/,/^}/p; /^_uri_addr()/p; /^_url_encode()/,/^}/p
  /^_make_uri_xhttp()/,/^}/p; /^_make_uri_tcp()/,/^}/p' "$root/xm.sh")"
for f in _ip6_candidates _get_server_ip6 _uri_v6 _uri_addr _make_uri_xhttp _make_uri_tcp; do
  declare -F $f >/dev/null || { echo "FAIL: в xm.sh нет $f"; exit 1; }
done

CONFIG="$T/config.json" CLIENT_FILE="$T/client-info.txt"
cat >"$CONFIG" <<'EOF'
{"inbounds": [
  {"port": 8443, "settings": {"clients": [{"id": "00000000-0000-4000-8000-000000000001"}]},
   "streamSettings": {"realitySettings": {"serverNames": ["www.example.com"], "shortIds": ["ab12"]},
     "xhttpSettings": {"host": "www.example.com", "path": "/p", "mode": "auto"}}},
  {"port": 9443, "settings": {"clients": [{"id": "00000000-0000-4000-8000-000000000001"}]},
   "streamSettings": {"realitySettings": {"serverNames": ["www.example.com"], "shortIds": ["cd34"]}}}]}
EOF
_front_public_port() { echo 443; }
_get_pubkey_xhttp() { echo "PUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUBKEY"; }
_get_pubkey_tcp()   { _get_pubkey_xhttp; }
_get_fp() { echo chrome; }

# ip -o -6 addr show scope global / ip -6 route get …: строки в формате iproute2 из $ADDRS и $ROUTE
ip() {
  case "$*" in
    "-o -6 addr show scope global") [[ -n $ADDRS ]] && printf '%s\n' "$ADDRS" ;;
    "-6 route get 2001:4860:4860::8888") [[ -n $ROUTE ]] || return 2; echo "$ROUTE" ;;
    *) return 1 ;;
  esac
}
A_STATIC='2: eth0    inet6 2001:DB8:1:2::5/64 scope global \       valid_lft forever preferred_lft forever'
A_SLAAC='2: eth0    inet6 2001:db8:1:2:a00:27ff:fe4e:66a1/64 scope global dynamic mngtmpaddr noprefixroute \       valid_lft 86235sec preferred_lft 14235sec'
A_TEMP='2: eth0    inet6 2001:db8:1:2:9c3e:1d2f:aa01:7b2c/64 scope global temporary dynamic \       valid_lft 86235sec preferred_lft 14235sec'
A_DEPR='2: eth0    inet6 2001:db8:1:2::9/64 scope global deprecated dynamic \       valid_lft 600sec preferred_lft 0sec'
A_ULA='2: eth0    inet6 fd00:1::5/64 scope global \       valid_lft forever preferred_lft forever'
route_src() { echo "2001:4860:4860::8888 from :: via fe80::1 dev eth0 proto static src $1 metric 1024 pref medium"; }
echo "SERVER IP: 192.0.2.10" >"$CLIENT_FILE"

# ─── Выбор адреса
ADDRS=$(printf '%s\n' "$A_ULA" "$A_TEMP" "$A_DEPR" "$A_STATIC" "$A_SLAAC")
eq "годные: без temporary, deprecated и ULA, в нижнем регистре" "$(_ip6_candidates | paste -sd ' ')" \
  "2001:db8:1:2::5 2001:db8:1:2:a00:27ff:fe4e:66a1"
ROUTE=$(route_src 2001:db8:1:2:a00:27ff:fe4e:66a1)
eq "src маршрута среди годных — он" "$(_get_server_ip6)" "2001:db8:1:2:a00:27ff:fe4e:66a1"
ROUTE=$(route_src 2001:db8:1:2:9c3e:1d2f:aa01:7b2c)
eq "src маршрута — временный: первый годный" "$(_get_server_ip6)" "2001:db8:1:2::5"
ROUTE=""
eq "маршрута нет: первый годный" "$(_get_server_ip6)" "2001:db8:1:2::5"
ADDRS=$(printf '%s\n' "$A_ULA" "$A_TEMP"); ROUTE=$(route_src 2001:db8:1:2:9c3e:1d2f:aa01:7b2c)
eq "только временный и ULA — пусто" "$(_get_server_ip6)" ""
ADDRS=""; ROUTE=""
eq "IPv6 нет — пусто" "$(_get_server_ip6)" ""
printf 'SERVER IP: 192.0.2.10\nSERVER IP6 : 2001:DB8:FFFF::1\n' >"$CLIENT_FILE"
eq "SERVER IP6 в client-info.txt перекрывает" "$(_get_server_ip6)" "2001:db8:ffff::1"
eq "SERVER IP6 не подменяет SERVER IP" "$(_get_server_ip)" "192.0.2.10"
echo "SERVER IP: 192.0.2.10" >"$CLIENT_FILE"

# ─── Ссылки
X4='vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUBKEY&sid=ab12&type=xhttp&path=%2Fp&host=www.example.com&mode=auto#pc'
eq "XHTTP по IPv4 — как раньше" "$(_make_uri_xhttp 00000000-0000-4000-8000-000000000001 pc)" "$X4"
ADDRS="$A_STATIC"
_uri_v6 2>"$T/err"; eq "_uri_v6 с адресом — успех" "$?" 0
eq "XHTTP по IPv6: [адрес] и хвост -v6" "$(_make_uri_xhttp 00000000-0000-4000-8000-000000000001 pc)" \
  "${X4/@192.0.2.10:443/@[2001:db8:1:2::5]:443}-v6"
eq "TCP по IPv6: [адрес]:порт inbound, хвост -v6-TCP" \
  "$(_make_uri_tcp 00000000-0000-4000-8000-000000000001 pc | sed -E 's/\?.*#/ #/')" \
  "vless://00000000-0000-4000-8000-000000000001@[2001:db8:1:2::5]:9443 #pc-v6-TCP"
URI_HOST=""; URI_SFX=""; ADDRS=""
_uri_v6 2>"$T/err"; rc=$?
eq "_uri_v6 без IPv6 — отказ" "$rc" 1
grep -q "sudo xm ipv6" "$T/err" || bad "отказ _uri_v6 не называет следующий шаг: $(<"$T/err")"
eq "после отказа ссылка — по IPv4" "$(_make_uri_xhttp 00000000-0000-4000-8000-000000000001 pc)" "$X4"

(( fails )) && exit 1
echo "test-ipv6: PASS"
