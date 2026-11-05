#!/usr/bin/env bash
# Приёмка xm bridge на живом VPS — то, что делает xdiag: от пользователя владельца, без терминала и
# без метки sudo (setsid), «sudo -n xm bridge …». on ставит правило (visudo, 0440), повтор ничего не
# меняет; пускает facts (соль в stdin), health, doctor --live 10 — JSON с schema; хэши профиля равны
# пересчёту openssl по config.json на той же соли, значений профиля в выводе нет; лишние аргументы и
# чужие команды требуют пароль; doctor через мост узнаёт сеть SSH-сеанса без терминала; config.json и
# Xray не тронуты; off убирает правило — мост снова отказывает. В конце — состояние, как до скрипта.
# Запуск: sudo bash tests/vps/bridge.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
CFG=/usr/local/etc/xray/config.json
RULE=/etc/sudoers.d/xm-bridge
vpr
OWNER=${SUDO_USER:-}
vneed "запуск через sudo из-под своего пользователя (sudo bash tests/vps/bridge.sh)" test -n "$OWNER" -a "$OWNER" != root
vneed "Xray работает" systemctl is-active --quiet xray
vneed "bridge.py установлен (sudo xm self-update)" test -f /usr/local/lib/xm/ui/bridge.py
vneed "есть openssl, setsid, runuser" bash -c 'command -v openssl && command -v setsid && command -v runuser' >/dev/null

fact() { printf '  · %-30s %s\n' "$1" "$2"; }
WAS=off; [[ -f $RULE ]] && WAS=on
# Как xdiag: пользователь владельца, без управляющего терминала, stdin — $1 (соль) или пусто
asowner() { local in=$1; shift; printf '%s' "$in" | setsid -w runuser -u "$OWNER" -- "$@"; }
export -f asowner; export OWNER
echo "Факты:"
fact "чекаут" "$(git -C "$VREPO" rev-parse --short HEAD)"
fact "ОС / sudo / OpenSSH" "$(lsb_release -ds 2>/dev/null) / $(sudo -V | awk 'NR==1{print $3}') / $(ssh -V 2>&1 | cut -d, -f1)"
fact "xray" "$(xray version 2>/dev/null | awk 'NR==1{print $2}')"
fact "правило до скрипта" "$WAS"
fact "sudo без пароля на всё у $OWNER" "$(asowner '' sudo -n true 2>/dev/null && echo да || echo нет)"

# Целостность: мост не трогает конфиг и не перезапускает Xray; в sudoers.d — только своё
vsnap "$VTMP/cfg" sha256sum "$CFG"
vsnap "$VTMP/inv" systemctl show -p InvocationID --value xray
# ls -A: временный .xm-bridge.* от on, оставшийся по ошибке, — тоже расхождение
vsnap "$VTMP/sudoers" bash -c "ls -A /etc/sudoers.d | grep -vx xm-bridge; true"

# ─── on: правило с нуля и повтор
xm bridge off >/dev/null
vcheck  "on" xm bridge on
vexpect "правило: root, 0440" "root 440" stat -c '%U %a' "$RULE"
vcheck  "sudoers целиком принят" visudo -cq
vsnap   "$VTMP/rule" sha256sum "$RULE"
vexpect "повтор on — «уже включён»" "1" bash -c 'xm bridge on | grep -c "уже включён"'
vsame   "повтор on: правило не изменилось" "$VTMP/rule" sha256sum "$RULE"
vcheck  "status" xm bridge status

# ─── facts от пользователя владельца, соль в stdin
SALT=$(openssl rand -hex 16)
VTIMEOUT=90 vcheck "facts: sudo -n от $OWNER" bash -c "asowner '$SALT
' sudo -n xm bridge facts > $VTMP/facts.json"
jq -c '{schema, xray, public: (.public | del(.sni)), firewall, dns, ru_block, self, health, profile_fields: (.profile | keys?)}' \
  "$VTMP/facts.json" 2>/dev/null | sed 's/^/  · facts: /'
vexpect "facts: контракт bridge-facts 1" '"bridge-facts" 1' jq -r '"\"\(.schema.name)\" \(.schema.major)"' "$VTMP/facts.json"
vexpect "facts: версия Xray" "$(xray version | awk 'NR==1{print $2}')" jq -r .xray.version "$VTMP/facts.json"
PUB=$(jq -r '.inbounds[0].port' "$CFG")
[[ -f /etc/nginx/stream-enabled/front.conf ]] && { PUB=$(awk -F= '$1=="PORT"{print $2}' /usr/local/etc/xray/front.conf 2>/dev/null); PUB=${PUB:-443}; }
vexpect "facts: публичный порт" "$PUB" jq -r .public.port "$VTMP/facts.json"
vexpect "facts: самопроверка прошла" "ok" jq -r .self.r "$VTMP/facts.json"

# Хэши — пересчёт openssl (независимо от bridge.py) по config.json; публичный ключ — xray x25519 -i
hm() { [[ -z $1 ]] && return; printf '%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SALT" | awk '{print substr($NF, 1, 12)}'; }
{ IFS= read -r UUID; IFS= read -r SID; IFS= read -r SNI; IFS= read -r XPATH; IFS= read -r PRIV; } < <(
  jq -r '.inbounds[0] | (.settings.clients[0].id | ascii_downcase), (.streamSettings | (.realitySettings.shortIds[0] // "" | ascii_downcase),
    (.realitySettings.serverNames[0] | ascii_downcase), (.xhttpSettings.path // ""), .realitySettings.privateKey)' "$CFG")
PBK=$(xray x25519 -i "$PRIV" 2>/dev/null | awk -F': ' '/Password|Public/{print $2; exit}'); unset PRIV
vexpect "хэш UUID первого клиента" "true" jq --arg h "$(hm "$UUID")" '[.profile.clients[]] | index($h) != null' "$VTMP/facts.json"
vexpect "хэш pbk" "$(hm "$PBK")" jq -r .profile.pbk "$VTMP/facts.json"
vexpect "хэш shortId" "true" jq --arg h "$(hm "$SID")" '.profile.short_ids | index($h) != null' "$VTMP/facts.json"
vexpect "хэш SNI" "true" jq --arg h "$(hm "$SNI")" '.profile.sni | index($h) != null' "$VTMP/facts.json"
vexpect "хэш пути" "$(hm "$XPATH")" jq -r .profile.path "$VTMP/facts.json"
vexpect "хэш порта" "$(hm "$PUB")" jq -r .profile.port "$VTMP/facts.json"
SRVIP=$(awk -F: 'toupper($1) ~ /^SERVER IP/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /usr/local/etc/xray/client-info.txt 2>/dev/null)
vexpect "facts без значений профиля и адреса сервера" "0" bash -c 'n=0; for v in "$@"; do [[ ${#v} -ge 4 ]] && grep -qiF -- "$v" '"$VTMP/facts.json"' && n=$((n+1)); done; echo $n' \
  _ "$UUID" "$SID" "$XPATH" "$PBK" "$SRVIP"
vexpect "facts без соли — без profile" "false" bash -c "asowner '' sudo -n xm bridge facts | jq 'has(\"profile\")'"

# ─── health и doctor через мост
vexpect "health: schema health" "health" bash -c "asowner '' sudo -n xm bridge health | jq -r .schema.name"
VTIMEOUT=120 vcheck "doctor --live 10: sudo -n от $OWNER" bash -c "asowner '' sudo -n xm bridge doctor --live 10 > $VTMP/doctor.json"
fact "doctor через мост" "$(jq -c '{schema, verdict: .verdict.code, ssh_peer: .server.ssh_peer, groups: (.groups | length)}' "$VTMP/doctor.json" 2>/dev/null)"
vexpect "doctor: schema doctor и вердикт" "doctor true" jq -r '"\(.schema.name) \(.verdict.code != null and .verdict.code != "")"' "$VTMP/doctor.json"
# Сеть SSH-сеанса без терминала (так ходит xdiag): адрес — по сокету предка sshd. Проверяемо, если сам
# скрипт запущен прямо из SSH-сеанса (who -m видит адрес), а не из tmux/screen.
if [[ -n $(who -m --ips 2>/dev/null | sed -n 's/.*(\([^)]*\)).*/\1/p') ]]; then
  vexpect "doctor через мост узнал сеть SSH-сеанса" "true" jq -r .server.ssh_peer "$VTMP/doctor.json"
else
  fact "ssh_peer" "не проверен: скрипт запущен не прямо из SSH-сеанса (tmux/screen?)"
fi

# ─── Отказы: лишние аргументы и чужие команды без пароля не проходят. Признак — отказ sudo
# («password is required»), а не код: «facts --x» отверг бы и сам xm bridge, даже пропусти его sudo.
if asowner '' sudo -n true 2>/dev/null; then
  fact "отказы" "не проверить: у $OWNER sudo без пароля на всё"
else
  for c in "bridge facts --x" "bridge doctor --live 60 --iface lo" "bridge doctor --live 9" "bridge on" "info"; do
    # shellcheck disable=SC2086
    vexpect "sudo требует пароль: xm $c" "1" bash -c "asowner '' sudo -n xm $c 2>&1 >/dev/null | grep -c 'password is required'"
  done
fi

# ─── off: правила нет, мост отказывает
vcheck  "off" xm bridge off
vexpect "off: файла нет" "нет" bash -c "[[ -e $RULE ]] && echo есть || echo нет"
if ! asowner '' sudo -n true 2>/dev/null; then
  vexpect "off: sudo -n xm bridge health — пароль" "1" bash -c "asowner '' sudo -n xm bridge health 2>&1 >/dev/null | grep -c 'password is required'"
fi
[[ $WAS == on ]] && xm bridge on >/dev/null

vsame "config.json не тронут" "$VTMP/cfg" sha256sum "$CFG"
vsame "Xray не перезапускался" "$VTMP/inv" systemctl show -p InvocationID --value xray
vsame "в sudoers.d — ничего чужого" "$VTMP/sudoers" bash -c "ls -A /etc/sudoers.d | grep -vx xm-bridge; true"
vreport
