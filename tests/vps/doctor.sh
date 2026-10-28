#!/usr/bin/env bash
# Приёмка xm doctor на живом VPS. Решение анализатора сверяется с тем, что делает настоящий REALITY
# этого сервера: клиенты Xray на петле идут на публичный порт с ключом и профилем из config.json —
# fp=chrome, fp=edge (ClientHello без X25519MLKEM768, как у ядра sing-box), чужой shortId, чужой ключ.
# Для каждого: прошёл ли запрос через тоннель (ответ сервера) и что сказал doctor в окне захвата
# на петле. Плюс: doctor ничего не меняет (config.json, перезапуск Xray), адресов в выводе нет,
# захват на настоящем интерфейсе — окно 60 с, в которое владелец жмёт «Подключить» в своём клиенте:
# его отчёт печатается фактом для разбора. Запуск: sudo bash tests/vps/doctor.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
CFG=/usr/local/etc/xray/config.json
vpr
vneed "Xray работает" systemctl is-active --quiet xray
vneed "python3 с cryptography" python3 -c "import cryptography"
vneed "doctor.py установлен (sudo xm self-update)" test -f /usr/local/lib/xm/ui/doctor.py

fact() { printf '  · %-30s %s\n' "$1" "$2"; }
XVER=$(xray version 2>/dev/null | awk 'NR==1{print $2}')
PUB_PORT=$(jq -r '.inbounds[0].port' "$CFG")
[[ -f /etc/nginx/stream-enabled/front.conf ]] && { PUB_PORT=$(awk -F= '$1=="PORT"{print $2}' /usr/local/etc/xray/front.conf 2>/dev/null); PUB_PORT=${PUB_PORT:-443}; }
echo "Факты:"
fact "чекаут" "$(git -C "$VREPO" rev-parse --short HEAD)"
fact "ОС / ядро / python" "$(lsb_release -ds 2>/dev/null) / $(uname -r) / $(python3 -V 2>&1 | cut -d' ' -f2)"
fact "xray / cryptography" "$XVER / $(python3 -c 'import cryptography; print(cryptography.__version__)')"
fact "публичный порт / фронт" "$PUB_PORT / $([[ -f /etc/nginx/stream-enabled/front.conf ]] && echo вкл || echo выкл)"
fact "интерфейсы" "$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | paste -sd' ')"

# ─── Клиент Xray на петле с профилем этого сервера: $1 — fp, $2 — shortId, $3 — публичный ключ
{ IFS= read -r UUID; IFS= read -r SNI; IFS= read -r SID; IFS= read -r XPATH; IFS= read -r XMODE; IFS= read -r PRIV; } < <(
  jq -r '.inbounds[0] | .settings.clients[0].id, (.streamSettings | .realitySettings.serverNames[0],
    .realitySettings.shortIds[0], (.xhttpSettings.path // "/"), (.xhttpSettings.mode // "auto"),
    .realitySettings.privateKey)' "$CFG")
PUBKEY=$(xray x25519 -i "$PRIV" 2>/dev/null | awk -F': ' '/Password|Public/{print $2; exit}')
OTHERKEY=$(xray x25519 2>/dev/null | awk -F': ' '/Password|Public/{print $2; exit}')
unset PRIV
vneed "публичный ключ из privateKey (xray x25519 -i)" test ${#PUBKEY} -ge 40
CPID=""
client_try() {   # $1 fp, $2 sid, $3 pbk → печатает HTTP-код запроса через тоннель
  local c="$VTMP/cli-$1-$2.json" sp=$(( 30000 + RANDOM % 5000 ))
  jq -n --arg u "$UUID" --arg pub "$3" --arg sni "$SNI" --arg sid "$2" --arg fp "$1" --arg p "$XPATH" \
        --arg m "$XMODE" --argjson port "$PUB_PORT" --argjson sp "$sp" '{log:{loglevel:"warning"},
    inbounds:[{listen:"127.0.0.1",port:$sp,protocol:"socks"}],
    outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$port,users:[{id:$u,encryption:"none"}]}]},
      streamSettings:{network:"xhttp",security:"reality",
        realitySettings:{serverName:$sni,fingerprint:$fp,publicKey:$pub,shortId:$sid},
        xhttpSettings:{path:$p,host:$sni,mode:$m}}}]}' > "$c"
  xray run -c "$c" >/dev/null 2>&1 & CPID=$!
  sleep 2
  curl -s --noproxy '' -x "socks5h://127.0.0.1:$sp" --max-time 8 -o /dev/null -w '%{http_code}' \
    https://www.google.com/generate_204 2>/dev/null || true
  kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; CPID=""
  rm -f "$c"
}
trap '[[ -n $CPID ]] && kill "$CPID" 2>/dev/null; pkill -f "doctor.py run" 2>/dev/null; _v_exit' EXIT

# Целостность: doctor не трогает конфиг и не перезапускает Xray
vsnap "$VTMP/cfg" sha256sum "$CFG"
INV0=$(systemctl show -p InvocationID --value xray)

# ─── Окно на петле на каждого клиента: ответ сервера и решение doctor
window() {   # $1 имя, $2 fp, $3 sid, $4 pbk → $VTMP/w-$1.json и код ответа в $VTMP/code-$1
  xm doctor --live 16 --iface lo --json > "$VTMP/w-$1.json" 2>/dev/null & local dp=$!
  for _ in $(seq 1 40); do pgrep -f "doctor.py run" >/dev/null && break; sleep 0.5; done
  sleep 1                                     # самопроверка doctor прошла, захват открыт
  client_try "$2" "$3" "$4" > "$VTMP/code-$1"
  wait "$dp"
  echo "  · окно $1: ответ сервера $(cat "$VTMP/code-$1"); doctor: $(jq -r '[.groups[].attempts[] |
    (.rd.r // .st) + (if .rd.own then "/свой" else "" end)] | group_by(.) | map("\(.[0])×\(length)") | join(" ")' \
    "$VTMP/w-$1.json" 2>/dev/null); вердикт $(jq -r '.verdict.code' "$VTMP/w-$1.json" 2>/dev/null)"
}
echo "Окна на петле:"
window chrome chrome "$SID" "$PUBKEY"
window edge edge "$SID" "$PUBKEY"
window sid chrome "f00d" "$PUBKEY"
window key chrome "$SID" "$OTHERKEY"

# Есть ли в окне попытка с решением r и признаком «свой ключ» own (jq — программа: vcheck зовёт через timeout)
HAS='[.groups[].attempts[] | select(.rd.r == $r and (.rd.own // false) == $own)] | length > 0'
vexpect "fp=chrome: сервер принял (204)" 204 cat "$VTMP/code-chrome"
vcheck  "fp=chrome: doctor — «REALITY принял бы», свой ключ" jq -e --arg r ok --argjson own true "$HAS" "$VTMP/w-chrome.json"
if python3 -c "import sys; v = tuple(map(int, sys.argv[1].split('.'))); sys.exit(v < (26, 9, 9))" "$XVER"; then
  vcheck "fp=edge: сервер отверг (Xray $XVER — правило X25519MLKEM768)" bash -c "! grep -qx 204 '$VTMP/code-edge'"
  vcheck "fp=edge: doctor — «нет X25519MLKEM768», ключ свой" jq -e --arg r mlkem --argjson own true "$HAS" "$VTMP/w-edge.json"
  vexpect "fp=edge: вердикт doctor — ядро клиента" client.core jq -r .verdict.code "$VTMP/w-edge.json"
else
  vexpect "fp=edge: сервер принял (Xray $XVER — правила долей нет)" 204 cat "$VTMP/code-edge"
  vcheck  "fp=edge: doctor — «REALITY принял бы»" jq -e --arg r ok --argjson own true "$HAS" "$VTMP/w-edge.json"
fi
vcheck  "чужой shortId: сервер отверг" bash -c "! grep -qx 204 '$VTMP/code-sid'"
vcheck  "чужой shortId: doctor — «shortId не из списка», ключ свой" jq -e --arg r sid --argjson own true "$HAS" "$VTMP/w-sid.json"
vcheck  "чужой ключ: сервер отверг" bash -c "! grep -qx 204 '$VTMP/code-key'"
vcheck  "чужой ключ: doctor — «ключ не этого сервера»" jq -e --arg r key --argjson own false "$HAS" "$VTMP/w-key.json"
vcheck  "в выводе doctor нет адресов клиентов (127.0.0.1)" bash -c "! grep -q '127\.0\.0\.1' $VTMP/w-*.json"

# ─── Настоящий интерфейс: окно для клиента владельца
echo
echo "Окно 60 с на настоящем интерфейсе: сейчас нажми «Подключить» в своём клиенте (Hiddify) 2–3 раза"
TIMEFORMAT='%U %S'
exec 3>&2                                     # подсказки окна — в терминал, время — в файл
{ time xm doctor --live 60 > "$VTMP/real.txt" 2>&3; } 2> "$VTMP/cpu"
echo "Отчёт doctor (факт для разбора):"
sed 's/^/  | /' "$VTMP/real.txt"
CPU=$(awk '{printf "%.2f", $1 + $2}' "$VTMP/cpu" | tail -n 1)
fact "CPU doctor за окно 60 с" "${CPU} с"
vcheck  "doctor на настоящем интерфейсе дошёл до вердикта" grep -q '^ВЕРДИКТ: ' "$VTMP/real.txt"
vcheck  "захват не потерял пакетов" bash -c "! grep -q 'Захват потерял' '$VTMP/real.txt'"
vcheck  "CPU doctor за окно < 6 с (10 % ядра)" awk -v c="$CPU" 'BEGIN {exit !(c < 6)}'
vsame   "config.json не тронут" "$VTMP/cfg" sha256sum "$CFG"
vexpect "Xray не перезапускался" "$INV0" systemctl show -p InvocationID --value xray
vreport
