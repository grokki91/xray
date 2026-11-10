#!/usr/bin/env bash
# Приёмка IPv6 на живом VPS: xm ipv6 со стороны сервера проблем не находит; ссылки --v6 — те же, что
# по IPv4, но с [адрес], с которым сервер виден снаружи (api64.ipify.org — независимо от src
# маршрута, по которому выбирает код), и хвостом -v6; ссылки по IPv4 прежние; на [IPv6]:публичный
# порт сервер отвечает зонду сертификатом маски, как по IPv4. config.json, Xray, ufw и nginx не
# тронуты. Доступность снаружи отсюда не видна (зонд идёт через lo) — это проверка с клиента.
# Адресов скрипт не печатает. Запуск: sudo bash tests/vps/ipv6.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
CFG=/usr/local/etc/xray/config.json
INFO=/usr/local/etc/xray/client-info.txt
vpr
vneed "Xray работает" systemctl is-active --quiet xray
vneed "у VPS есть маршрут IPv6 наружу (настроить — по подсказке sudo xm ipv6)" ip -6 route get 2001:4860:4860::8888
vneed "есть curl, openssl" bash -c 'command -v curl && command -v openssl'

fact() { printf '  · %-34s %s\n' "$1" "$2"; }
mask6() { sed -E 's/\x1b\[[0-9;]*m//g; s/\[?[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}\]?/<v6>/g'; }
PUB=$(jq -r '.inbounds[0].port' "$CFG") FRONT=off
if [[ -f /etc/nginx/stream-enabled/front.conf ]]; then
  PUB=$(awk -F= '$1=="PORT"{print $2}' /usr/local/etc/xray/front.conf 2>/dev/null); PUB=${PUB:-443}; FRONT=on
fi
export SNI; SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CFG")
EXT6=$(curl -6 -fsS --max-time 8 https://api64.ipify.org 2>/dev/null | tr -d '[:space:]' | tr 'A-F' 'a-f')
SRC6=$(ip -6 route get 2001:4860:4860::8888 | sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' | tr 'A-F' 'a-f')
V4=$(awk -F: 'toupper($1) ~ /^SERVER IP[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$INFO" 2>/dev/null)

echo "Факты:"
fact "чекаут" "$(git -C "$VREPO" rev-parse --short HEAD)"
fact "xray" "$(xray version 2>/dev/null | awk 'NR==1{print $2}')"
fact "фронт / публичный порт" "$FRONT / $([[ $PUB == 443 ]] && echo 443 || echo 'не 443')"
fact "глобальных IPv6 без временных" "$(ip -o -6 addr show scope global | grep -vcE ' (temporary|deprecated|tentative|dadfailed) ')"
fact "src маршрута = адрес снаружи" "$([[ -n $EXT6 && $SRC6 == "$EXT6" ]] && echo да || echo нет)"
fact "SERVER IP6 в client-info.txt" "$(grep -qiE '^SERVER IP6[[:space:]]*:' "$INFO" && echo задан || echo нет)"
fact "ufw / IPV6" "$(ufw status 2>/dev/null | head -1) / $(grep -E '^IPV6=' /etc/default/ufw 2>/dev/null)"
fact "ip6tables INPUT" "$(ip6tables -S INPUT 2>/dev/null | head -1)"
fact "сокеты публичного порта" "$(ss -Htln "sport = :$PUB" | awk '{sub(/:[0-9]+$/, "", $4); print $4}' | mask6 | sort -u | paste -sd ' ')"

# Целостность: проверка и ссылки ничего не меняют
vsnap "$VTMP/cfg" sha256sum "$CFG"
vsnap "$VTMP/inv" systemctl show -p InvocationID --value xray
vsnap "$VTMP/ufw" ufw status
vsnap "$VTMP/ngx" bash -c 'cat /etc/nginx/stream-enabled/*.conf 2>/dev/null | sha256sum'

vneed "сервер выходит наружу по IPv6 (curl -6 https://api64.ipify.org)" test -n "$EXT6"
vneed "в client-info.txt есть SERVER IP" test -n "$V4"

# ─── xm ipv6: всё, что видно с VPS
VTIMEOUT=120 vcheck "xm ipv6: со стороны VPS готов" bash -c "xm ipv6 > $VTMP/ipv6.out 2>&1"
mask6 <"$VTMP/ipv6.out" | grep -E '\[(✗|!)\]' | sed 's/^ */  · xm ipv6: /'

# ─── Ссылки: --v6 = IPv4-ссылка с [внешний IPv6] и хвостом -v6
NCL=$(jq '.inbounds[0].settings.clients | length' "$CFG")
NT=$(jq '[.inbounds[1]] | map(select(. != null)) | length' "$CFG")
xm uri --all      2>&1 | grep -o 'vless://[^[:space:]]*' >"$VTMP/u4"
xm uri --all --v6 2>&1 | grep -o 'vless://[^[:space:]]*' >"$VTMP/u6"
vexpect "ссылок по IPv4 — по клиенту на транспорт" "$(( NCL * (1 + NT) ))" grep -c . "$VTMP/u4"
vexpect "ссылки по IPv4: адрес из client-info.txt, без -v6" "$(( NCL * (1 + NT) ))" \
  bash -c "grep -F '@$V4:' $VTMP/u4 | grep -vc -- '-v6'"
vsnap "$VTMP/u6want" bash -c "sed -E 's/@$V4:/@[$EXT6]:/; /-TCP\$/ s/-TCP\$/-v6-TCP/; /-v6-TCP\$/! s/\$/-v6/' $VTMP/u4"
vsame "ссылки --v6 = IPv4-ссылки с [адрес снаружи] и -v6" "$VTMP/u6want" cat "$VTMP/u6"
vexpect "ссылки XHTTP --v6 — на публичный порт" "$NCL" bash -c "grep -F '@[$EXT6]:$PUB?' $VTMP/u6 | grep -c 'type=xhttp'"

# ─── Зонд на [IPv6]:публичный порт отвечает как маска — так же, как по IPv4
subj() { echo | timeout 8 openssl s_client -connect "$1" -servername "$SNI" 2>/dev/null | openssl x509 -noout -subject; }
export -f subj
vsnap "$VTMP/c4" bash -c 'subj "$0"' "$V4:$PUB"
vsame "зонд на [IPv6]:порт — сертификат маски, как по IPv4" "$VTMP/c4" bash -c 'subj "$0"' "[$EXT6]:$PUB"

vsame "config.json не тронут" "$VTMP/cfg" sha256sum "$CFG"
vsame "Xray не перезапускался" "$VTMP/inv" systemctl show -p InvocationID --value xray
vsame "ufw не тронут" "$VTMP/ufw" ufw status
vsame "nginx не тронут" "$VTMP/ngx" bash -c 'cat /etc/nginx/stream-enabled/*.conf 2>/dev/null | sha256sum'
vreport
