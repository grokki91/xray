#!/usr/bin/env bash
# Мост для xdiag (xm bridge, ui/bridge.py): контракт bridge-facts 1.0 и хэши профиля — сверка с
# векторами, посчитанными кодом xdiag (grokki91/xray_client internal/profile.Hashes на той же соли и
# значениях, с его нормализацией регистра); без соли и с битой солью — без profile; журнал здоровья;
# правило долей по версии. Диспетчер: лишние и чужие аргументы — отказ в stderr, stdout пуст.
# Правило sudo — синтаксис visudo; что sudo -n пускает только список, проверяет tests/vps/bridge.sh.
# Адрес SSH-сеанса без терминала: who/ps/ss — заглушки (предмет — разбор их вывода).
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export XM_HEALTH_DIR="$T/health" PYTHONDONTWRITEBYTECODE=1
fails=0
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
# want ИМЯ ОЖИДАНИЕ JQ ФАЙЛ — значение jq -c по файлу
want() { local got; got=$(jq -c "$3" "$4" 2>&1); [[ $got == "$2" ]] || bad "$1: ожидалось $2, получено $got"; }

cat >"$T/config.json" <<'EOF'
{"inbounds": [
  {"port": 8443, "protocol": "vless",
   "settings": {"clients": [{"id": " 00000000-0000-4000-8000-0000000000AB ", "email": "pc"},
                            {"id": "00000000-0000-4000-8000-0000000000cd"}]},
   "streamSettings": {"network": "xhttp", "security": "reality",
     "realitySettings": {"serverNames": ["Example.com", "www.example.com"], "shortIds": ["AbCd12", ""]},
     "xhttpSettings": {"path": "/Path-Test", "mode": "packet-up"}}},
  {"port": 9443, "protocol": "vless", "settings": {"clients": [{"id": "00000000-0000-4000-8000-0000000000ef"}]},
   "streamSettings": {"network": "raw", "realitySettings": {"serverNames": ["other.example.com"], "shortIds": ["ff"]}}}]}
EOF
now=$(date +%s); mkdir -p "$XM_HEALTH_DIR"
printf '%s\n' "{\"t\":$((now - 900)),\"vd\":\"ok\",\"tr\":70000}" "{\"t\":$((now - 600)),\"vd\":\"ok\",\"tr\":100}" \
  "{\"t\":$((now - 300)),\"vd\":\"nodata\",\"tr\":0}" >"$XM_HEALTH_DIR/windows.jsonl"

facts() {   # $1 — соль (окружение), $2 — версия Xray; остальное — как передаёт xm bridge facts
  XM_BRIDGE_SALT="$1" python3 -I -B "$root/ui/bridge.py" facts --config "$T/config.json" --xver "$2" --active true \
    --port 443 --fp chrome --front true --tcp true --pq false --ufw open --doh true --hijack true --nonip reject \
    --ru false --self '{"r":"fail","at":"dns"}' --health true --commit abc1234 --branch main \
    --pbk "pbk-test-0123456789abcdefghijklmnopqrstuv"
}
SALT=000102030405060708090a0b0c0d0e0f
facts "$SALT" 26.10.21 >"$T/f.json" 2>"$T/f.err" || bad "facts: код $? $(head -1 "$T/f.err")"
[[ $(wc -l <"$T/f.json") == 1 ]] || bad "facts: не одна строка JSON"
want "schema" '{"name":"bridge-facts","major":1,"minor":0}' .schema "$T/f.json"
want "xray" '{"version":"26.10.21","active":true,"mlkem_rule":true,"min_client_ver":null}' .xray "$T/f.json"
want "public" '{"port":443,"transport":"xhttp","mode":"packet-up","fp":"chrome","sni":"Example.com","front":true,"tcp_inbound":true,"pq":false}' \
  .public "$T/f.json"
want "dns, ufw, ru" '[{"doh":true,"hijack53":true,"nonip":"reject"},{"ufw":"open"},false]' '[.dns, .firewall, .ru_block]' "$T/f.json"
want "self — как отдал xm" '{"r":"fail","at":"dns"}' .self "$T/f.json"
want "health: последнее окно, последний трафик ≥ 64 КБ" \
  "{\"enabled\":true,\"last_window\":{\"t\":$((now - 300)),\"vd\":\"nodata\"},\"last_traffic\":$((now - 900))}" .health "$T/f.json"
want "time" true "(.time - $now) | (. >= 0 and . < 30)" "$T/f.json"
# Векторы — вывод xdiag profile.Hashes (соль 00…0f): UUID «…ab» с пробелами и в верхнем регистре,
# pbk, shortId «AbCd12», путь «/Path-Test», SNI «Example.com», порт 443; второй клиент — «…cd»,
# SNI «www.example.com». Пустой shortId — пустая строка. TCP inbound в профиль не входит.
want "profile: хэши = xdiag" \
  '{"salted":true,"clients":{"pc":"cfaaacd9bedc","#2":"4b464c654b60"},"pbk":"9a85c64af8d9","short_ids":["ae83cdbd18e3",""],"path":"ed56a9ccb39d","sni":["e1c1566e8a1a","825b8fc1d8a4"],"port":"ed17f9f100b5"}' \
  .profile "$T/f.json"
want "в выводе нет значений профиля" false \
  'tostring | test("0000000000ab|0000000000AB|pbk-test|AbCd12|Path-Test|abcd12"; "i")' "$T/f.json"

facts "" 26.10.21 >"$T/n.json" && want "без соли — без profile" false 'has("profile")' "$T/n.json"
facts "${SALT^^}" 26.10.21 >"$T/n.json" && want "соль не в нижнем регистре — без profile" false 'has("profile")' "$T/n.json"
facts "${SALT:0:30}" 26.10.21 >"$T/n.json" && want "короткая соль — без profile" false 'has("profile")' "$T/n.json"
facts "$SALT" 26.8.0 >"$T/v.json" && want "Xray 26.8.0 — правила долей нет" false .xray.mlkem_rule "$T/v.json"
facts "$SALT" 26.9.9 >"$T/v.json" && want "Xray 26.9.9 — правило долей" true .xray.mlkem_rule "$T/v.json"
facts "$SALT" "" >"$T/v.json" && want "версия не определилась — «?», mlkem_rule null" '["?",null]' "[.xray.version, .xray.mlkem_rule]" "$T/v.json"
rm -f "$XM_HEALTH_DIR/windows.jsonl"
facts "$SALT" 26.10.21 >"$T/e.json" && want "журнала нет" '{"enabled":true,"last_window":{},"last_traffic":null}' .health "$T/e.json"
echo '{' >"$T/config.json"
facts "$SALT" 26.10.21 >"$T/b.json" 2>"$T/b.err"; rc=$?
[[ $rc == 1 && ! -s $T/b.json ]] && grep -q '^bridge: ' "$T/b.err" || bad "битый config.json: код $rc, stdout «$(head -c 80 "$T/b.json")»"

# ── Диспетчер: только список и допустимые аргументы; отказ — stderr и код 1, stdout пуст
if [[ $EUID -eq 0 ]]; then
  for a in "facts --x" "health --json" "doctor --live 9" "doctor --live 121" "doctor --live 060x" \
           "doctor --live 60 --iface lo" "doctor --no-live" "nope" ""; do
    # shellcheck disable=SC2086
    out=$(bash "$root/xm.sh" bridge $a 2>"$T/err"); rc=$?
    [[ $rc == 1 && -z $out && -s $T/err ]] || bad "bridge $a: код $rc, stdout «${out:0:60}»"
  done
  grep -q 'неизвестн' "$T/err" || bad "bridge без команды: нет «неизвестная команда» (по ней xdiag узнаёт старый xm)"
else
  echo "  пропуск диспетчера: не root"
fi

# ── Правило sudo: синтаксис visudo, без «*», доступ только к командам моста
eval "$(sed -n '/^_bridge_rule() {/,/^}/p; /^_ssh_peer() {/,/^}/p' "$root/xm.sh")"
declare -F _bridge_rule _ssh_peer >/dev/null || bad "в xm.sh нет _bridge_rule или _ssh_peer"
XM_BIN=/usr/local/bin/xm
_bridge_rule owner >"$T/rule"
grep -q '\*' "$T/rule" && bad "правило с «*» — совпадёт с любыми аргументами дальше"
[[ $(grep -v '^#' "$T/rule" | grep -o "$XM_BIN bridge [a-z]*" | sort -u | paste -sd' ') == \
   "$XM_BIN bridge doctor $XM_BIN bridge facts $XM_BIN bridge health" ]] || bad "правило: команды не из списка моста"
if command -v visudo >/dev/null; then
  visudo -cqf "$T/rule" >/dev/null 2>&1 || bad "visudo отверг правило: $(visudo -cf "$T/rule" 2>&1 | head -1)"
else
  echo "  пропуск синтаксиса правила: нет visudo (его проверит tests/vps/bridge.sh)"
fi

# ── Адрес SSH-сеанса: с терминалом — who -m; без него — сокет предка sshd, мимо проброса на петлю
SSHD=4242
ps() { case "$*" in "-o comm= -p $SSHD") echo sshd-session ;; "-o comm= -p "*) echo bash ;;
                    "-o ppid= -p $$") echo " $SSHD" ;; *) echo 1 ;; esac; }
who() { [[ -n $WHO ]] && echo "owner pts/0 2026-11-05 10:00 ($WHO)"; }
ss() { printf '%s\n' "0 0 127.0.0.1:55001 127.0.0.1:8080 users:((\"sshd-session\",pid=$SSHD,fd=9))" \
  "0 0 192.0.2.10:22 $PEER users:((\"sshd-session\",pid=1$SSHD,fd=4),(\"sshd-session\",pid=$SSHD,fd=4))"; }
WHO="" PEER="203.0.113.7:50123";  [[ $(_ssh_peer) == 203.0.113.7 ]] || bad "без терминала, v4: «$(_ssh_peer)»"
WHO="" PEER="[2001:db8::7]:50123"; [[ $(_ssh_peer) == 2001:db8::7 ]] || bad "без терминала, v6: «$(_ssh_peer)»"
WHO=198.51.100.9 PEER="203.0.113.7:1"; [[ $(_ssh_peer) == 198.51.100.9 ]] || bad "с терминалом: «$(_ssh_peer)»"
SSHD=1; WHO="";                     [[ -z $(_ssh_peer) ]] || bad "не SSH: «$(_ssh_peer)»"

(( fails == 0 )) && echo ok || exit 1
