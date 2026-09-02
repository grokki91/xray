#!/usr/bin/env bash
# =============================================================================
#  xm — Xray Manager Helper  v5.8
#  Использование: xm [команда]
#
#  Команды:
#   Сервис:      start / stop / restart / status
#   Конфиг:      edit / test / apply / set-sni / set-port
#   Бэкапы:      backup / restore / backups
#   Клиенты:     clients / add-client / del-client / uri / qr
#   TCP:         add-tcp
#   Обновление:  self-update [--check|--force|--from] / update [--check] / update-geo
#   Nginx:       nginx-status / nginx-log / nginx-reload / nginx-probes
#   Fail2ban:    ban-list / ban-ssh-stat / unban
#   Логи:        log / log-live / log-clear
#   Инфо:        info / paths / uuid / pubkey
#   Анти-DPI:    harden [--check|--off|--dot|--nonip [drop|skip|off]] / pq status|on|off
#   Фронт:       front [status|on|off|add <sni> <порт>|del <sni>]
#   Стабильность: tune [--check|--off] / watchdog on|off|now|status
#   Соседи:      neighbors — что ещё живёт на сервере и что трогает xm
#   Диагностика: diag / diag-dpi [--quick] / diag-ntp / diag-ports / diag-tls / diag-fw / diag-log
# =============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/usr/local/etc/xray/backups"
LOG="/var/log/xray/error.log"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"
XM_BIN="/usr/local/bin/xm"
# Путь к git-чекауту репозитория, из которого ставился xm. Пишется setup.sh и
# xm self-update — чтобы обновление знало, откуда тянуть, и не приходилось
# каждый раз вспоминать, куда именно был сделан clone.
XM_SRC_FILE="/usr/local/etc/xray/xm-source"

# Пороги размера TLS Certificate для совместимости с REALITY (см. setup.sh)
REALITY_CERT_WARN=7000
REALITY_CERT_LIMIT=8192

ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
fail() { echo -e "  ${RED}[✗]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
info() { echo -e "  ${CYAN}[-]${NC} $*"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────${NC}"; }

# ─── Вспомогательные ─────────────────────────────────────────────────────────

# Чтение поля из client-info.txt (формат "LABEL: value" с любыми пробелами)
_get_field() {
  local label="$1"
  grep -i "^${label}[[:space:]]*:" "$CLIENT_FILE" 2>/dev/null \
    | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '[:space:]'
}

# SNI из whitelist-map: строка строго вида "X   X;".
# [FIX] Прежняя регулярка '^\s*\w+\s+\w+;' совпадала также с
# "resolver_timeout 5s;" и "set_real_ip_from 127.0.0.1;" — при чтении спасал
# head -1, но sed -i в set-sni шёл без адресации и переписывал ИХ ТОЖЕ.
_get_nginx_sni() {
  awk '$1 ~ /^[a-zA-Z0-9._-]+$/ && $2 == $1";" {print $1; exit}' \
    /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null
}

# Вычисление публичного ключа X25519 из приватного (stdin → stdout)
_derive_pubkey() {
  python3 -c "
import sys, base64
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = base64.urlsafe_b64decode(sys.stdin.read().strip() + '==')
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(base64.urlsafe_b64encode(pub).rstrip(b'=').decode())
except Exception:
    pass
" 2>/dev/null
}

# Публичный ключ inbound'а: сначала из privateKey в config.json, иначе из client-info.txt
# $1 — индекс inbound, $2 — имя fallback-поля
_get_pubkey() {
  local idx="$1" fallback="$2" privkey pub
  privkey=$(jq -r ".inbounds[$idx].streamSettings.realitySettings.privateKey // \"\"" "$CONFIG" 2>/dev/null)
  if [[ -n "$privkey" && ${#privkey} -ge 30 ]]; then
    pub=$(echo "$privkey" | _derive_pubkey)
    [[ -n "$pub" && ${#pub} -ge 30 ]] && { echo "$pub"; return; }
  fi
  _get_field "$fallback"
}
_get_pubkey_xhttp() { _get_pubkey 0 "PUBLIC KEY"; }
_get_pubkey_tcp()   { _get_pubkey 1 "PUBLIC KEY2"; }

_get_server_ip() {
  local ip
  ip=$(_get_field "SERVER IP")
  if [[ -z "$ip" || "$ip" == "ТВОЙ_IP" ]]; then
    ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      ip=$(curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null | tr -d '[:space:]' || echo "SERVER_IP")
    fi
  fi
  echo "$ip"
}

_get_fp() {
  local fp
  fp=$(_get_field "FINGERPRINT")
  echo "${fp:-chrome}"
}

_get_ssh_port() {
  local port
  port=$(_get_field "SSH PORT")
  [[ -z "$port" ]] && port=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "")
  [[ -z "$port" ]] && port=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || echo "")
  echo "${port:-22}"
}

_has_tcp_inbound() {
  [[ $(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo 0) -ge 2 ]]
}

# ─── UFW ─────────────────────────────────────────────────────────────────────
#
# ЗАЧЕМ ОТДЕЛЬНО: трафик на СОБСТВЕННЫЙ внешний адрес уходит через lo, а ufw
# петлю пропускает целиком (`-i lo -j ACCEPT` в ufw-before-input). Значит все
# зонды diag-dpi, запущенные с самого VPS, проходят мимо файрвола и показывают
# зелень на порту, который снаружи закрыт наглухо. Правило приходится проверять
# отдельной командой — сетевым тестом изнутри его не увидеть.
_ufw_active()  { ufw status 2>/dev/null | grep -q "Status: active"; }
_ufw_allowed() { ufw status 2>/dev/null | grep -qE "^${1}(/tcp)?[[:space:]]+ALLOW"; }

# _ufw_open <порт> <комментарий>
#   0 — открыли, 1 — уже было открыто, 2 — ufw не активен, 3 — ufw отказал
_ufw_open() {
  _ufw_active || return 2
  _ufw_allowed "$1" && return 1
  ufw allow "${1}/tcp" comment "$2" >/dev/null 2>&1 || return 3
  return 0
}

# Список активных джейлов fail2ban. Раньше вызывалась в ban-list, но НЕ была
# определена нигде → "_jails: command not found".
_jails() {
  fail2ban-client status 2>/dev/null \
    | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' '
}

# Каталог с git-чекаутом репозитория. Порядок поиска: записанный путь, затем
# типовые места. Пустой вывод и код 1 — чекаут не найден.
_xm_repo() {
  local d
  if [[ -f "$XM_SRC_FILE" ]]; then
    d=$(head -1 "$XM_SRC_FILE" 2>/dev/null | tr -d '[:space:]')
    [[ -n "$d" && -d "$d/.git" && -f "$d/xm.sh" ]] && { echo "$d"; return 0; }
  fi
  for d in /opt/xray /root/xray /home/*/xray; do
    [[ -d "$d/.git" && -f "$d/xm.sh" ]] && { echo "$d"; return 0; }
  done
  return 1
}

# Тег последнего релиза Xray-core. Пусто = GitHub недоступен.
_xray_latest_ver() {
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 10 \
    https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null \
    | jq -r '.tag_name // empty'
}

# Бэкап config.json. Каталог 700, файл 600: внутри приватный ключ REALITY,
# а cp по умолчанию создал бы 644 — ключ стал бы читаем любому пользователю
# системы. Печатает путь к бэкапу.
_backup_config() {
  local suffix="${1:-}" path
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  path="$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S)${suffix:+_$suffix}.json"
  cp "$CONFIG" "$path" && chmod 600 "$path" && echo "$path"
}

_url_encode() {
  python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

# ─── DNS: DoH на сервере + перехват :53 ──────────────────────────────────────
#
# ЗАЧЕМ: с августа 2025 массово сообщают об ограничениях DoH/DoT (dns.google,
# 1.1.1.1:853 и т.п.) у российских операторов. Насколько это системно —
# со стороны сервера не проверить, но и не нужно: утечки ниже существуют
# независимо от этих сообщений, просто блокировка DoH делает их массовыми.
# Сам VPN такая блокировка не ломает, но ломает ЛОГИКУ клиента: браузер/ОС,
# не достучавшись до Secure DNS, откатывается на ОБЫЧНЫЙ DNS. Дальше два сценария утечки:
#   1) VPN выключен/split-режим → запрос уходит провайдеру открытым текстом,
#      и он видит имя заблокированного домена + может подменить ответ (НСДИ);
#   2) VPN включён → запрос идёт в тоннель, но НАШ сервер по умолчанию
#      резолвит его системным резолвером хостера тоже открытым текстом.
# Оба закрываются здесь: сервер сам перехватывает :53 из тоннеля и отвечает
# по DoH. Клиенту при этом ничего настраивать не надо — он даже не знает.
#
# Резолверы заданы IP-ЛИТЕРАЛОМ: нет bootstrap-зависимости от резолвера
# хостера (иначе первый же запрос «а какой IP у dns.google» ушёл бы открытым).
# https+local:// = запрос идёт мимо routing → нет петли с перехватом :53.
DOH_LIST='["https+local://1.1.1.1/dns-query","https+local://9.9.9.9/dns-query","https+local://8.8.8.8/dns-query"]'
DOH_IPS=(1.1.1.1 9.9.9.9 8.8.8.8)
RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/xm-dot.conf

# Четыре апстрима, а не два, и три независимых провайдера. Под СТРОГИМ DoT
# недоступный :853 — это не деградация, а отказ: резолвед обязан вернуть
# ошибку вместо открытого UDP. Дальше nginx не находит апстрим fallback,
# REALITY некуда форвардить, и сервер принимает TCP и рвёт, то есть выдаёт
# подпись прокси. Замерено: watchdog чинил мёртвый резолвинг dest несколько
# раз за трое суток. Резервирование здесь — часть маскировки, а не удобство.
# FallbackDNS пустой обязателен: с непустым резолвед при недоступном :853
# молча уходит в открытый UDP — та же утечка, но уже без признаков.
RESOLVED_DOT_CONF='[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 8.8.8.8#dns.google
FallbackDNS=
DNSOverTLS=yes
Domains=~.'

_has_ipv6() { ip -6 route get 2001:4860:4860::8888 &>/dev/null; }

# DoH прописан в конфиге?
_dns_doh_on() {
  [[ $(jq '[.dns.servers[]? | select(type=="string") | select(startswith("https"))] | length' \
       "$CONFIG" 2>/dev/null || echo 0) -gt 0 ]]
}

# Перехват :53 включён? Нужны И dns-outbound, И правило маршрутизации на него.
_dns_hijack_on() {
  jq -e '([.outbounds[]? | select(.protocol=="dns")] | length) > 0
     and ([.routing.rules[]? | select(.outboundTag=="dns-out")] | length) > 0' \
     "$CONFIG" >/dev/null 2>&1
}

# systemd-resolved переведён на DoT в СТРОГОМ режиме?
# Засчитываем только "yes". При "opportunistic" резолвед молча сваливается в
# открытый UDP, как только :853 не отвечает, — то есть даёт ровно ту утечку,
# от которой мы защищаемся, и не оставляет ни одного признака.
_resolved_dot_on() {
  resolvectl status 2>/dev/null \
    | grep -qiE '^[[:space:]]*DNSOverTLS setting:[[:space:]]*yes[[:space:]]*$'
}

# Эффективный список апстримов резолвера: main-конфиг плюс ВСЕ drop-in в
# порядке применения, последнее присваивание побеждает. Нужен именно он:
# «DNSOverTLS=yes» одинаково выглядит и с одним апстримом, и с четырьмя, а под
# строгим DoT это разница между «провайдер лёг — стало медленно» и «провайдер
# лёг — резолвинга нет вообще».
_resolved_dns_line() {
  systemd-analyze cat-config systemd/resolved.conf 2>/dev/null \
    | grep -E '^[[:space:]]*DNS=' | tail -1 | sed 's/^[[:space:]]*DNS=[[:space:]]*//'
}

# Записать наш профиль DoT, перезапустить резолвед, проверить и откатиться
# самому, если DoT не поднялся (хостер режет :853).
_resolved_write_dot() {
  local bak=""
  [[ -f "$RESOLVED_DROPIN" ]] && {
    bak="${RESOLVED_DROPIN}.bak_$(date +%Y%m%d_%H%M%S)"; cp "$RESOLVED_DROPIN" "$bak"; }
  mkdir -p "$(dirname "$RESOLVED_DROPIN")"
  printf '%s\n' "$RESOLVED_DOT_CONF" > "$RESOLVED_DROPIN"
  systemctl restart systemd-resolved 2>/dev/null; sleep 1
  _resolved_dot_on && resolvectl query example.com &>/dev/null && return 0
  if [[ -n "$bak" ]]; then cp "$bak" "$RESOLVED_DROPIN"; else rm -f "$RESOLVED_DROPIN"; fi
  systemctl restart systemd-resolved 2>/dev/null
  return 1
}

# Классификация DNS-дампа по АДРЕСУ ИСТОЧНИКА пакета. Источник — единственное,
# что отличает три РАЗНЫЕ вещи, которые прошлая версия теста валила в одну:
#   wire — есть пакет с источником вне петли: имя физически покинуло машину
#   stub — только 127.x → 127.0.0.53: спросили локальный резолвер, а что он
#          сделает дальше, решает _resolved_dot_on, а не этот дамп
#   none — запроса не было вовсе
# Ответы резолвера тоже содержат имя, и это не мешает: у ответа с провода
# источник тоже внешний, то есть вывод только подтверждается.
_dns_leak_class() {
  local f="$1" n="$2" src cls="none"
  while read -r src; do
    [[ -z "$src" ]] && continue
    if [[ "$src" == 127.* || "$src" == "::1" ]]; then
      [[ "$cls" == "none" ]] && cls="stub"
    else
      cls="wire"; break
    fi
  done < <(grep -F "$n" "$f" 2>/dev/null \
           | awk '$2=="IP"||$2=="IP6"{s=$3; sub(/\.[0-9]+$/,"",s); print s}')
  echo "$cls"
}

# Человеческая формулировка для класса утечки. Вынесена отдельно, потому что
# «хостер видит, какие домены ты открываешь» верно ровно для одного из трёх
# случаев, а печаталось раньше для всех.
_e5_where() {
  case "$1" in
    wire) echo "ушло С МАШИНЫ открытым UDP/53 — имя видит любой на пути, хостер в первую очередь" ;;
    stub) _resolved_dot_on \
            && echo "ушло в системный резолвер; тот на строгом DoT, поэтому открытым текстом на провод не попадёт — но резолвит имя не Xray" \
            || echo "ушло в системный резолвер, а он без DoT — значит через миллисекунду будет на проводе открытым текстом" ;;
    *)    echo "не запрашивалось" ;;
  esac
}

# nginx-fallback отвечает на чужой SNI (mimic), а не рвёт соединение?
# Смотрим ТОЛЬКО внутрь map $reality_upstream: во втором map ($log_probe)
# свой default 1;, и по нему легко получить ложное «включено».
_ngx_mimic_on() {
  awk '
    /map[[:space:]]+\$ssl_preread_server_name[[:space:]]+\$reality_upstream/ { inblk=1; next }
    inblk && $1 == "default" { if ($2 != "\"\";") found=1; inblk=0; next }
    inblk && /\}/ { inblk=0 }
    END { exit !found }
  ' /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null
}

# DNS-запрос в wireformat RFC 8484, base64url — для проверки DoH через curl.
# JSON-API (?name=) есть не у всех резолверов, wireformat обязателен у всех.
_dns_wire_b64() {
  python3 -c '
import base64, struct, sys
q = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)   # ID=0 — так требует RFC для GET
for l in sys.argv[1].split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)             # QTYPE=A, QCLASS=IN
print(base64.urlsafe_b64encode(q).rstrip(b"=").decode())' "$1" 2>/dev/null
}

# _doh_probe <ip> [домен] → печатает RTT в мс, код 0 = резолвер отвечает.
# Проверяет ИМЕННО то, что нужно: доходит ли DoH с ЭТОГО VPS до резолвера.
_doh_probe() {
  local ip="$1" b64 code t0 t1
  b64=$(_dns_wire_b64 "${2:-example.com}") || return 1
  [[ -z "$b64" ]] && return 1
  t0=$(date +%s%N)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
         -H 'accept: application/dns-message' \
         "https://${ip}/dns-query?dns=${b64}" 2>/dev/null) || code="000"
  t1=$(date +%s%N)
  [[ "$code" == "200" ]] || return 1
  echo $(( (t1 - t0) / 1000000 ))
}

# ─── Локальный тоннель к самому себе (общая база selftest и живых DPI-тестов) ─
#
# ПОЧЕМУ ЭТО ЕДИНСТВЕННАЯ ЧЕСТНАЯ ПРОВЕРКА: REALITY при провале хендшейка
# НЕ ПИШЕТ НИЧЕГО в лог — это штатная ветка протокола, а не ошибка. Поэтому
# «в логах пусто» ничего не доказывает. Здесь поднимается настоящий VLESS-
# клиент на loopback: сеть, провайдер и клиентское приложение исключены.
# У клиента есть СВОЙ dns-блок с теми же DoH. Резолвить ему нечего (адрес
# outbound — литерал 127.0.0.1, домен из SOCKS уходит внутрь VLESS строкой),
# но пока блока не было, при разборе утечки его нельзя было исключить иначе
# как рассуждением. Теперь исключается конфигом.
TUN_PORT=""; TUN_PID=""; TUN_CFG=""; TUN_LOG=""; TUN_SNI=""; TUN_SRVPORT=""

_tunnel_up() {
  local net="${1:-xhttp}" idx=0 fb="PUBLIC KEY" uuid port sni sid pub path_v mode
  [[ "$net" == "tcp" ]] && { idx=1; fb="PUBLIC KEY2"; }
  uuid=$(jq -r ".inbounds[$idx].settings.clients[0].id" "$CONFIG" 2>/dev/null)
  port=$(jq -r ".inbounds[$idx].port" "$CONFIG" 2>/dev/null)
  sni=$(jq  -r ".inbounds[$idx].streamSettings.realitySettings.serverNames[0]" "$CONFIG" 2>/dev/null)
  sid=$(jq  -r ".inbounds[$idx].streamSettings.realitySettings.shortIds[0]" "$CONFIG" 2>/dev/null)
  pub=$(_get_pubkey "$idx" "$fb")
  [[ -z "$pub" || ${#pub} -lt 30 ]] && return 1

  TUN_PORT=$(( 20000 + RANDOM % 10000 )); TUN_SNI="$sni"; TUN_SRVPORT="$port"
  TUN_CFG=$(mktemp /tmp/xm-tunnel.XXXXXX.json)
  TUN_LOG=$(mktemp /tmp/xm-tunnel.XXXXXX.log)

  if [[ "$net" == "xhttp" ]]; then
    path_v=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.path' "$CONFIG")
    mode=$(jq   -r '.inbounds[0].streamSettings.xhttpSettings.mode' "$CONFIG")
    jq -n --arg uuid "$uuid" --arg pub "$pub" --arg sni "$sni" --arg sid "$sid" \
          --arg p "$path_v" --arg m "$mode" --argjson port "$port" --argjson sp "$TUN_PORT" \
          --argjson doh "$DOH_LIST" '{
      log:{loglevel:"warning"},
      dns:{servers:$doh, queryStrategy:"UseIPv4"},
      inbounds:[{listen:"127.0.0.1",port:$sp,protocol:"socks",settings:{udp:true}}],
      outbounds:[{protocol:"vless",
        settings:{vnext:[{address:"127.0.0.1",port:$port,users:[{id:$uuid,encryption:"none"}]}]},
        streamSettings:{network:"xhttp",security:"reality",
          realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pub,shortId:$sid},
          xhttpSettings:{path:$p,host:$sni,mode:$m}}}]}' > "$TUN_CFG"
  else
    jq -n --arg uuid "$uuid" --arg pub "$pub" --arg sni "$sni" --arg sid "$sid" \
          --argjson port "$port" --argjson sp "$TUN_PORT" --argjson doh "$DOH_LIST" '{
      log:{loglevel:"warning"},
      dns:{servers:$doh, queryStrategy:"UseIPv4"},
      inbounds:[{listen:"127.0.0.1",port:$sp,protocol:"socks",settings:{udp:true}}],
      outbounds:[{protocol:"vless",
        settings:{vnext:[{address:"127.0.0.1",port:$port,
          users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},
        streamSettings:{network:"tcp",security:"reality",
          realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pub,shortId:$sid}}}]}' > "$TUN_CFG"
  fi

  xray run -c "$TUN_CFG" >"$TUN_LOG" 2>&1 &
  TUN_PID=$!
  sleep 2
  kill -0 "$TUN_PID" 2>/dev/null || return 1
  return 0
}

# Причина отказа из лога локального клиента (вызывать ДО _tunnel_down)
_tunnel_hint() { grep -iE "failed|EOF|reject|reality" "$TUN_LOG" 2>/dev/null | tail -3; }

_tunnel_down() {
  [[ -n "$TUN_PID" ]] && { kill "$TUN_PID" 2>/dev/null; wait "$TUN_PID" 2>/dev/null; }
  rm -f "$TUN_CFG" "$TUN_LOG" 2>/dev/null
  TUN_PID=""; TUN_CFG=""; TUN_LOG=""
}

# HTTP-код запроса через поднятый тоннель (пустой URL → проверка выхода в сеть)
_tunnel_code() {
  local url="${1:-https://api.ipify.org}" code
  code=$(curl -s -x "socks5h://127.0.0.1:${TUN_PORT}" --max-time 15 -o /dev/null \
         -w '%{http_code}' "$url" 2>/dev/null) || true
  echo "${code:-000}"
}

# _socks_dns <resolver_ip> <домен> → OK | TIMEOUT | ERR
# DNS поверх TCP через SOCKS5 тоннеля. Резолвер 192.0.2.1 (RFC 5737 TEST-NET-1)
# заведомо мёртв и не маршрутизируется — ответ физически может прийти ТОЛЬКО
# если сервер перехватывает :53 и отвечает сам. Бинарный тест перехвата.
_socks_dns() {
  python3 - "$TUN_PORT" "$1" "$2" <<'PY' 2>/dev/null || echo "ERR"
import socket, struct, sys
sp, rip, name = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def query(n):
    b = struct.pack(">HHHHHH", 0x2a2a, 0x0100, 1, 0, 0, 0)
    for l in n.split("."):
        b += bytes([len(l)]) + l.encode()
    return b + b"\x00" + struct.pack(">HH", 1, 1)
try:
    s = socket.create_connection(("127.0.0.1", sp), 5)
    s.settimeout(8)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        print("ERR"); sys.exit()
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(rip) + struct.pack(">H", 53))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        print("TIMEOUT"); sys.exit()
    p = query(name)
    s.sendall(struct.pack(">H", len(p)) + p)
    hdr = s.recv(2)
    if len(hdr) < 2:
        print("TIMEOUT"); sys.exit()
    need, data = struct.unpack(">H", hdr)[0], b""
    while len(data) < need:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print("OK" if len(data) >= 12 else "TIMEOUT")
except socket.timeout:
    print("TIMEOUT")
except Exception:
    print("ERR")
PY
}

# _socks_connect <домен> <порт> → OK | FAIL
# SOCKS5 CONNECT с ATYP=DOMAIN (0x03): имя уезжает в тоннель строкой, клиент
# теста его не резолвит ПО ПОСТРОЕНИЮ. Это и есть атрибуция: что бы ни всплыло
# в DNS-дампе после такого запроса — резолвил сервер. curl с socks5h делает то
# же самое, но доказать это по дампу нельзя, а здесь доказывать нечего.
_socks_connect() {
  python3 - "$TUN_PORT" "$1" "$2" <<'PY' 2>/dev/null || echo "FAIL"
import socket, struct, sys
sp, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
try:
    s = socket.create_connection(("127.0.0.1", sp), 5)
    s.settimeout(8)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        print("FAIL"); sys.exit()
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
    rep = s.recv(10)
    good = len(rep) >= 2 and rep[1] == 0
    if good:
        # Данные обязательны. SOCKS-инбаунд отвечает на CONNECT сразу, а
        # дозванивается до цели только когда пойдёт трафик. Без этой строки
        # сервер имя не резолвит вовсе, и тест покажет ложную чистоту.
        try:
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + h + b"\r\nConnection: close\r\n\r\n")
            s.recv(1)
        except Exception:
            pass
    print("OK" if good else "FAIL")
except Exception:
    print("FAIL")
PY
}

# _tls_probe <host:port> <sni|-> → cert | alert | closed
# Что увидит сканер (Censys/Shodan/ТСПУ), постучавшись на порт:
#   cert   — полноценный TLS-ответ с сертификатом (как настоящий сайт)
#   alert  — TLS-отказ (тоже нормально: так отвечают многие CDN)
#   closed — TCP приняли и молча закрыли, ни байта TLS. Для веб-сервера
#            нетипично; это и есть подпись «порт открыт, TLS не говорит».
# Вердикт всегда СРАВНИТЕЛЬНЫЙ: тот же зонд шлём на реальный сайт-маску.
_tls_probe() {
  local target="$1" sn="$2" out
  if [[ "$sn" == "-" ]]; then
    out=$(echo | timeout 8 openssl s_client -connect "$target" -noservername 2>&1) || true
  else
    out=$(echo | timeout 8 openssl s_client -connect "$target" -servername "$sn" 2>&1) || true
  fi
  if printf '%s' "$out" | grep -q "BEGIN CERTIFICATE"; then echo "cert"
  elif printf '%s' "$out" | grep -qiE "alert|handshake fail|wrong version"; then echo "alert"
  else echo "closed"; fi
}

# ─── Хардening: DoH на сервере + перехват :53 + mimic-fallback ───────────────
#
# Одна идемпотентная команда, закрывающая два разных канала утечки:
#   [DNS]   сервер резолвит домены клиентов ЧЕРЕЗ DoH, а не системным
#           резолвером хостера, и сам перехватывает :53 из тоннеля;
#   [PROBE] nginx-fallback на чужой/пустой SNI отдаёт ответ НАСТОЯЩЕГО сайта,
#           а не молча рвёт TCP (обрыв — самая заметная подпись прокси).
# Всё обратимо: xm harden --off.

# JSON-патч конфига. Порядок outbounds не меняем: freedom обязан остаться
# первым (первый outbound = дефолтный маршрут).
_harden_patch() {
  local qs="$1" ds="$2" nonip="$3"
  jq --argjson doh "$DOH_LIST" --arg qs "$qs" --arg ds "$ds" --arg nonip "$nonip" '
      .dns = { servers: $doh, queryStrategy: $qs, disableCache: false, tag: "dns-in" }
    | .outbounds = ([ .outbounds[]? | select(.protocol != "dns") ]
                  + [ { protocol: "dns", tag: "dns-out" }
                      + (if $nonip == "" then {} else { settings: { nonIPQuery: $nonip } } end) ])
    | .routing.rules = ([ { type: "field", port: 53, network: "tcp,udp", outboundTag: "dns-out" } ]
                      + [ .routing.rules[]? | select(.outboundTag != "dns-out") ])
    | (.outbounds[] | select(.protocol == "freedom")).settings.domainStrategy = $ds
  ' "$CONFIG"
}

_harden_unpatch() {
  jq '  del(.dns)
      | .outbounds = [ .outbounds[]? | select(.protocol != "dns") ]
      | .routing.rules = [ .routing.rules[]? | select(.outboundTag != "dns-out") ]
  ' "$CONFIG"
}

# ─── nonIPQuery: режим для запросов не-A/AAAA ────────────────────────────────
#
# ЧТО ЭТО. Android с 11-й версии сам спрашивает HTTPS/SVCB (тип 65) перед
# каждым соединением. При nonIPQuery=drop такой запрос отбрасывается МОЛЧА:
# клиент не получает ни ответа, ни отказа и ждёт своего таймаута. На десктопе
# это незаметно, на телефоне выглядит как «соединение — переподключение».
#
# ЗАЧЕМ ОТДЕЛЬНАЯ РУЧКА. Раньше единственным способом это проверить был
# `xm harden --off`, который заодно сносит DoH, перехват :53, строгий DoT и
# mimic-fallback. Проверять одну гипотезу ценой всех остальных защит нельзя:
# на время теста сервер становится ровно тем, чем был до harden.
#
# ЦЕНА `skip`: запрос не-A/AAAA уходит на исходный адрес, то есть покидает VPS
# открытым UDP. Утечка узкая (только тип 65 и подобные, не имена сайтов в A),
# но это утечка — режим диагностический, не целевой.
#
# Набор допустимых значений между сборками Xray менялся, поэтому его не
# угадываем, а проверяем на копии конфига через `xray -test` (_nonip_try).

# Текущее значение; пусто = поле не задано (сборка его не приняла или --nonip off)
_nonip_current() {
  jq -r '[.outbounds[]? | select(.protocol=="dns") | .settings.nonIPQuery? // empty] | first // ""' \
     "$CONFIG" 2>/dev/null
}

# _nonip_patch <значение|""> → конфиг с этим значением на stdout.
# Пустое значение убирает поле целиком, вместе с осиротевшим settings:{}.
_nonip_patch() {
  jq --arg v "$1" '
    .outbounds = [ .outbounds[]
      | if .protocol == "dns"
        then ( .settings = ((.settings // {}) | del(.nonIPQuery))
             | (if $v == "" then . else .settings.nonIPQuery = $v end)
             | (if (.settings | length) == 0 then del(.settings) else . end) )
        else . end ]
  ' "$CONFIG"
}

# Принимает ли ЭТА сборка Xray такое значение. Копия временная и 600 (mktemp),
# но в ней лежит приватный ключ REALITY — поэтому удаляется сразу.
_nonip_try() {
  local tmp rc=1
  tmp=$(mktemp /tmp/xm-nonip.XXXXXX.json) || return 1
  if _nonip_patch "$1" > "$tmp" 2>/dev/null \
     && xray -test -config "$tmp" 2>&1 | grep -q "Configuration OK"; then rc=0; fi
  rm -f "$tmp"
  return $rc
}

# Переключение поведения nginx-fallback на чужой SNI.
# ВАЖНО: правим default ТОЛЬКО в map $reality_upstream. В файле есть второй
# map ($log_probe) со своим default 1; — тронуть его значит сломать фильтр
# логирования и начать писать IP всех своих клиентов на диск.
_ngx_map_default() {
  python3 - "$1" "$2" <<'PY' 2>/dev/null
import re, sys
path, target = sys.argv[1], sys.argv[2]
try:
    src = open(path).read()
except OSError:
    sys.exit(1)
def fix(m):
    body = re.sub(r'(?m)^([ \t]*)default([ \t]+)\S+;',
                  lambda d: d.group(1) + 'default' + d.group(2) + target + ';',
                  m.group(2), count=1)
    return m.group(1) + body + m.group(3)
out, n = re.subn(r'(map\s+\$ssl_preread_server_name\s+\$reality_upstream\s*\{)(.*?)(\})',
                 fix, src, count=1, flags=re.S)
if n != 1:
    sys.exit(1)
open(path, 'w').write(out)
PY
}

# nginx резолвит апстрим fallback сам и МИМО системного резолвера: изначально
# в конфиге стоит resolver 1.1.1.1 8.8.8.8 valid=30s, то есть открытый UDP/53
# раз в полминуты — только чтобы отдать proxy_pass адрес домена-маски. Браузинг
# это не раскрывает (домен-маска и так публичен), но это постоянный открытый
# маячок, который противоречит остальному harden. Переводим на стаб: после
# шага DoT он ходит по :853, а кэш становится общим с остальной машиной.
#
# valid=900s, а не 30s или 300s. Причина в цене промаха: этот резолвинг —
# не фон, а часть тракта REALITY, потому что dest задан именем. Каждое
# истечение кэша — окно, в котором неудачный запрос роняет fallback целиком
# и сервер начинает рвать соединения (замерено: "could not be resolved
# (110: Operation timed out)" в reality_fallback_error.log). Со строгим DoT
# промах становится вероятнее: при недоступном :853 резолвед не имеет права
# свалиться в открытый UDP и честно возвращает ошибку. Реже ходим — реже
# попадаем в это окно; адреса CDN-домена меняются несопоставимо медленнее.
# Возврат 0 — что-то изменили, 1 — менять было нечего.
_ngx_resolver_local() {
  local f rc=1
  for f in /etc/nginx/stream-enabled/reality-fallback.conf /etc/nginx/reality-fallback.conf.tmpl; do
    [[ -f "$f" ]] || continue
    grep -qE '^[[:space:]]*resolver[[:space:]]' "$f" || continue
    grep -qE '^[[:space:]]*resolver[[:space:]]+127\.0\.0\.53[[:space:]]+valid=900s' "$f" && continue
    sed -i -E 's|^([[:space:]]*)resolver[[:space:]]+[^;]*;|\1resolver 127.0.0.53 valid=900s ipv6=off;|' "$f" && rc=0
  done
  return $rc
}

# Обратная операция для harden --off. Возврат 0 — что-то вернули на место.
# Обходим файлы по одному: sed на несуществующем файле вернул бы ошибку на
# весь вызов, и nginx не перезагрузился бы после реальной правки соседнего.
_ngx_resolver_public() {
  local f rc=1
  for f in /etc/nginx/stream-enabled/reality-fallback.conf /etc/nginx/reality-fallback.conf.tmpl; do
    [[ -f "$f" ]] || continue
    grep -qE '^[[:space:]]*resolver[[:space:]]+127\.0\.0\.53([[:space:]]|;)' "$f" || continue
    sed -i -E 's|^([[:space:]]*)resolver[[:space:]]+127\.0\.0\.53[^;]*;|\1resolver 1.1.1.1 8.8.8.8 valid=30s ipv6=off;|' "$f" && rc=0
  done
  return $rc
}

# :80 — привести заголовки к тому, что отдаёт домен-маска.
#
# ПОЧЕМУ ЭТО АНТИ-DPI, А НЕ КОСМЕТИКА: на :443 мы отдаём чужой валидный
# сертификат и совпадаем с настоящим сайтом по всем зондам. А :80 рядом
# отвечал `Server: nginx` и `Location: https://<наш IP>/`. Редирект на голый
# IP — то, чего не делает ни один сайт: он сообщает сканеру, что виртуалхоста
# здесь нет, и обесценивает всю маскировку соседнего порта. Одного `curl -I`
# достаточно. Проверка: xm diag-dpi, тест B7.
#
# Правим ТОЧЕЧНО, sed по конкретным директивам: файл мог быть отредактирован
# руками, и перезапись целиком снесла бы чужие правки.

# headers-more — единственный способ поменять заголовок Server: `server_tokens
# off` убирает только версию, слово nginx остаётся. Без модуля :80 отвечает
# «nginx» там, где домен-маска отвечает своим именем, и тест B7 остаётся
# красным навсегда: предупреждением это не лечится. Пакет и так в списке
# зависимостей setup.sh — на серверах, поставленных до его появления, его
# просто нет. Поэтому harden не советует, а ставит.
# Новый динамический модуль подхватывается только полным перезапуском nginx:
# load_module по reload не применяется.
_ngx_headers_more() {
  grep -rqs "headers_more" /usr/lib/nginx/modules/ /etc/nginx/modules-enabled/ 2>/dev/null && return 2
  command -v apt-get >/dev/null 2>&1 || return 1
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confold libnginx-mod-http-headers-more-filter >/dev/null 2>&1 || return 1
  grep -rqs "headers_more" /usr/lib/nginx/modules/ /etc/nginx/modules-enabled/ 2>/dev/null || return 1
  nginx -t &>/dev/null || return 1
  systemctl restart nginx 2>/dev/null || return 1
  return 0
}

_ngx_http80_fix() {
  local f="/etc/nginx/sites-available/fallback" sni srv cur_srv bak changed=1
  [[ -f "$f" ]] || { warn "$f не найден — :80 не трогаю"; return 1; }
  sni=$(_get_nginx_sni)
  [[ -z "$sni" ]] && { warn "Не читается домен-маска — :80 не трогаю"; return 1; }

  mkdir -p "$BACKUP_DIR"
  bak="$BACKUP_DIR/fallback_$(date +%Y%m%d_%H%M%S).conf.bak"
  cp "$f" "$bak"

  # 1. Цель редиректа. Сравниваем с ИТОГОВЫМ желаемым видом, а не ищем $host:
  # один и тот же код чинит и исходный конфиг (там https://$host), и ситуацию
  # xm set-sni, где надо заменить один домен на другой. Идемпотентно по
  # значению: если строка уже правильная, sed вообще не запускается.
  local sni_esc; sni_esc=$(printf '%s' "$sni" | sed 's/[].[^$*\/]/\\&/g')
  if ! grep -qE "^[[:space:]]*return[[:space:]]+301[[:space:]]+https://${sni_esc}\\\$request_uri;" "$f"; then
    sed -i -E "s|^([[:space:]]*)return[[:space:]]+301[[:space:]]+https://[^;]*;|\1return 301 https://${sni}\$request_uri;|" "$f"
    changed=0
  fi

  # 2. Server: значение берём с ЖИВОГО домена-маски, не выдумываем. Если строка
  # уже есть, но домен сменился — обновляем, иначе останется имя чужого сайта.
  if grep -rqs "headers_more" /usr/lib/nginx/modules/ /etc/nginx/modules-enabled/ 2>/dev/null; then
    for scheme in https http; do
      srv=$(curl -sI --max-time 8 "${scheme}://${sni}/" 2>/dev/null \
            | grep -im1 '^server:' | tr -d '\r' | sed 's/^[Ss]erver:[[:space:]]*//')
      [[ -n "$srv" ]] && break
    done
    if [[ "$srv" =~ ^[A-Za-z0-9._/\ -]{1,64}$ ]]; then
      cur_srv=$(grep -oE 'more_set_headers[[:space:]]+"Server:[^"]*"' "$f" | head -1 | sed -E 's|.*Server:[[:space:]]*||; s|"$||')
      if [[ -z "$cur_srv" ]]; then
        sed -i -E "s|^([[:space:]]*)server_tokens[[:space:]]+off;|\\1server_tokens off;\\n\\1more_set_headers \"Server: ${srv}\";|" "$f"
        changed=0
      elif [[ "$cur_srv" != "$srv" ]]; then
        sed -i -E "s|more_set_headers[[:space:]]+\"Server:[^\"]*\"|more_set_headers \"Server: ${srv}\"|" "$f"
        changed=0
      fi
    else
      warn "Не удалось прочитать Server у $sni — заголовок оставляю как есть"
    fi
  else
    warn "Модуль headers-more не установлен: sudo apt install -y libnginx-mod-http-headers-more-filter"
    warn "Без него :80 продолжит отвечать «Server: nginx» вместо имени домена-маски"
  fi

  # 3. access_log: адреса всех, кто трогал :80, копились без пользы.
  if ! grep -qE '^[[:space:]]*access_log[[:space:]]+off;' "$f"; then
    sed -i -E "s|^([[:space:]]*)server_tokens[[:space:]]+off;|\\1server_tokens off;\\n\\1access_log off;|" "$f"
    changed=0
  fi

  [[ "$changed" -ne 0 ]] && { rm -f "$bak"; return 2; }
  if nginx -t &>/dev/null && systemctl reload nginx; then
    return 0
  fi
  fail "nginx -t не прошёл после правки :80 — откат"
  cp "$bak" "$f"; nginx -t &>/dev/null && systemctl reload nginx
  return 1
}

# _ngx_fallback_mode <mimic|strict> — правит и живой конфиг, и шаблон
# (из шаблона регенерируется конфиг при xm set-sni), проверяет и перезагружает.
_ngx_fallback_mode() {
  local mode="$1" conf="/etc/nginx/stream-enabled/reality-fallback.conf"
  local tmpl="/etc/nginx/reality-fallback.conf.tmpl" sni bak target
  [[ -f "$conf" ]] || { warn "$conf не найден — nginx-fallback не тронут"; return 1; }
  sni=$(_get_nginx_sni)
  [[ -z "$sni" ]] && { warn "Не читается SNI из nginx-map — nginx-fallback не тронут"; return 1; }
  [[ "$mode" == "mimic" ]] && target="$sni" || target='""'

  mkdir -p "$BACKUP_DIR"
  bak="$BACKUP_DIR/reality-fallback_$(date +%Y%m%d_%H%M%S)_harden.conf.bak"
  cp "$conf" "$bak"
  if ! _ngx_map_default "$conf" "$target"; then
    fail "Не удалось изменить map \$reality_upstream в $conf"; return 1
  fi
  # Шаблон живёт с плейсхолдером — туда пишем __DEST_SNI__, иначе set-sni
  # регенерирует конфиг обратно в strict.
  [[ -f "$tmpl" ]] && _ngx_map_default "$tmpl" \
    "$([[ "$mode" == "mimic" ]] && echo '__DEST_SNI__' || echo '""')"

  if ! nginx -t 2>/dev/null; then
    fail "nginx -t не прошёл — откат"; cp "$bak" "$conf"; nginx -t &>/dev/null; return 1
  fi
  systemctl reload nginx || { fail "nginx reload не удался — откат"; cp "$bak" "$conf"; systemctl reload nginx; return 1; }
  return 0
}

# ─── Фронт: демультиплексор по SNI на публичном порту ────────────────────────
#
# ЗАЧЕМ: номер порта виден сканеру ДО всякого анализа TLS, и сертификат
# крупного сайта на нестандартном порту обесценивает всю маскировку REALITY
# (diag-dpi, тест B8). 443 при этом может держать только один сокет. Фронт —
# тот же приём, что уже работает в reality-fallback.conf: ssl_preread читает
# SNI из ClientHello, НЕ терминируя TLS, и разводит поток по локальным службам.
# Соседняя служба на том же 443 (свой VPN, сайт) продолжает работать, её
# клиентам ничего перевыпускать не нужно — они по-прежнему стучатся в 443.
#
# ПОЧЕМУ ОТДЕЛЬНЫМ ФАЙЛОМ, А НЕ ПРАВКОЙ reality-fallback.conf: все пишущие
# пути xm адресуют fallback поимённо, так что harden/set-sni/set-port фронт
# не трогают. setup.sh --reinstall чистит stream-enabled/ целиком — поэтому
# источник правды не в /etc/nginx, а в FRONT_STATE, и восстановление после
# переустановки стоит одной команды: sudo xm front on.
FRONT_STATE="/usr/local/etc/xray/front.conf"
FRONT_NGX="/etc/nginx/stream-enabled/front.conf"
FRONT_LOG="/var/log/nginx/front.log"

# Фронт включён = конфиг лежит там, откуда nginx его читает.
_front_enabled() { [[ -f "$FRONT_NGX" ]]; }

_front_port() {
  local p=""
  [[ -f "$FRONT_STATE" ]] && p=$(awk -F= '$1=="PORT"{print $2; exit}' "$FRONT_STATE")
  [[ "$p" =~ ^[0-9]+$ ]] && echo "$p" || echo 443
}

# Маршруты соседей: строки "ROUTE <sni> <порт>" → "<sni> <порт>".
_front_routes() {
  [[ -f "$FRONT_STATE" ]] || return 0
  awk '$1=="ROUTE" && NF==3 {print $2, $3}' "$FRONT_STATE"
}

# Публичный порт нашего XHTTP inbound: за фронтом клиент идёт на 443, а сам
# Xray продолжает слушать свой локальный порт. Отсюда берут порт и URI, и B8 —
# иначе клиентам уедет адрес мимо фронта, и вся затея обнуляется.
_front_public_port() {
  if _front_enabled; then _front_port
  else jq -r '.inbounds[0].port' "$CONFIG" 2>/dev/null; fi
}

_front_state_init() {
  [[ -f "$FRONT_STATE" ]] && return 0
  cat > "$FRONT_STATE" <<'FSEOF'
# Состояние SNI-фронта. Читается `xm front on` при каждой генерации конфига
# nginx и переживает setup.sh --reinstall — в этом весь смысл файла.
# Маршрут нашего собственного inbound здесь НЕ хранится: он выводится из
# config.json, поэтому set-sni и set-port доезжают до фронта сами.
#   PORT=<публичный порт>
#   ROUTE <sni соседа> <локальный порт соседа>
PORT=443
FSEOF
  chmod 600 "$FRONT_STATE"
}

# Апстрим всегда 127.0.0.1: фронт разводит СВОИ службы, а не проксирует наружу.
# Литеральный адрес заодно избавляет nginx от resolver в этом server{} —
# открытых DNS-запросов фронт не делает.
_front_set_route() {
  local sni="$1" port="$2"
  _front_state_init
  sed -i "/^ROUTE ${sni//./\\.} /d" "$FRONT_STATE"
  echo "ROUTE $sni $port" >> "$FRONT_STATE"
}

_front_del_route() {
  [[ -f "$FRONT_STATE" ]] || return 1
  grep -q "^ROUTE ${1//./\\.} " "$FRONT_STATE" || return 1
  sed -i "/^ROUTE ${1//./\\.} /d" "$FRONT_STATE"
}

# Генерация конфига nginx из FRONT_STATE + config.json. Пишет во временный
# файл: класть незаконченный конфиг прямо в stream-enabled/ нельзя — nginx
# подхватит его по маске при любой посторонней перезагрузке.
_front_generate() {
  local out="$1" port ours oport sni up
  port=$(_front_port)
  ours=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
  oport=$(jq -r '.inbounds[0].port' "$CONFIG")
  [[ "$ours" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1
  [[ "$oport" =~ ^[0-9]+$ ]] || return 1

  {
    cat <<'HEADEOF'
# Сгенерировано `xm front on` — правки руками теряются при следующей генерации.
# Маршруты: /usr/local/etc/xray/front.conf (xm front add / xm front del).
#
# ssl_preread читает SNI из ClientHello и разводит поток, не терминируя TLS:
# ни ключей, ни сертификатов здесь нет, содержимое соединения фронту недоступно.
HEADEOF
    echo "map \$ssl_preread_server_name \$front_upstream {"
    # default уходит нам: чужой и пустой SNI должен и дальше получать ответ
    # настоящего сайта через наш REALITY-fallback (mimic), а не обрыв.
    printf '    %-40s %s;\n' "default" "127.0.0.1:$oport"
    printf '    %-40s %s;\n' "$ours" "127.0.0.1:$oport"
    while read -r sni up; do
      [[ -n "$sni" ]] && printf '    %-40s %s;\n' "$sni" "127.0.0.1:$up"
    done < <(_front_routes)
    echo "}"
    echo ""
    cat <<'MAPEOF'
# На диск пишем только то, что не попало ни в один маршрут — то есть сканы.
# Через фронт идёт ВЕСЬ боевой трафик: без этого фильтра в access_log легли бы
# адреса всех клиентов (ровно то, от чего уходили в reality-fallback.conf).
MAPEOF
    echo "map \$ssl_preread_server_name \$front_probe {"
    printf '    %-40s %s;\n' "default" "1"
    printf '    %-40s %s;\n' "$ours" "0"
    while read -r sni up; do
      [[ -n "$sni" ]] && printf '    %-40s %s;\n' "$sni" "0"
    done < <(_front_routes)
    echo "}"
    echo ""
    cat <<'TAILEOF'
# $remote_addr здесь — настоящий адрес клиента: фронт стоит первым, PROXY
# protocol ниоткуда не приходит и ngx_stream_realip не нужен. Это же и
# восстанавливает лимит по IP, который за фронтом теряет смысл в fallback:
# туда все соединения приходят от нашего же Xray, то есть с 127.0.0.1.
limit_conn_zone $remote_addr zone=front_conn:10m;

log_format front '$remote_addr [$time_local] SNI="$ssl_preread_server_name" '
                 'up=$front_upstream status=$status sent=$bytes_sent';

server {
TAILEOF
    echo "    listen 0.0.0.0:${port};"
    echo "    listen [::]:${port};"
    cat <<'SRVEOF'

    ssl_preread on;
    limit_conn front_conn 200;

    proxy_pass $front_upstream;
    proxy_connect_timeout 5s;

    access_log /var/log/nginx/front.log front if=$front_probe;
    error_log  /var/log/nginx/front_error.log error;
}
SRVEOF
  } > "$out"
}

# Сборка фронта: генерация → проверка → перезагрузка → откат при любой осечке.
_front_apply() {
  local tmp bak
  tmp=$(mktemp /etc/nginx/front.XXXXXX.tmp)
  if ! _front_generate "$tmp"; then
    rm -f "$tmp"; fail "Не собрать конфиг: в config.json нет SNI или порта inbound"; return 1
  fi
  bak=""
  [[ -f "$FRONT_NGX" ]] && { bak="$BACKUP_DIR/front_$(date +%Y%m%d_%H%M%S).conf.bak"; cp "$FRONT_NGX" "$bak"; }
  mv "$tmp" "$FRONT_NGX"; chmod 644 "$FRONT_NGX"
  if ! nginx -t 2>/dev/null; then
    # Стек без IPv6 отвергает listen [::] — второй заход без него, прежде
    # чем считать конфиг сломанным.
    sed -i "/listen \[::\]:/d" "$FRONT_NGX"
    if nginx -t 2>/dev/null; then
      info "IPv6-сокет не принят стеком — фронт слушает только IPv4"
    else
      fail "nginx -t не прошёл — откат"
      nginx -t 2>&1 | sed 's/^/    /'
      if [[ -n "$bak" ]]; then cp "$bak" "$FRONT_NGX"; else rm -f "$FRONT_NGX"; fi
      nginx -t &>/dev/null && systemctl reload nginx
      return 1
    fi
  fi
  if ! systemctl reload nginx; then
    fail "nginx reload не удался — откат"
    if [[ -n "$bak" ]]; then cp "$bak" "$FRONT_NGX"; else rm -f "$FRONT_NGX"; fi
    systemctl reload nginx; return 1
  fi
  return 0
}

# Лимит в fallback за фронтом теряет смысл и становится опасен: ключ
# $proxy_protocol_addr приходит от нашего же Xray, то есть у всех клиентов
# один и тот же 127.0.0.1 — общий счётчик на всех. Упёрлись в потолок →
# fallback отказывает → REALITY некуда форвардить → «принял TCP и закрыл»,
# то есть ровно та подпись прокси, ради ухода от которой сделан mimic.
# Ограничение по реальному IP берёт на себя фронт (limit_conn front_conn).
_front_fallback_limit() {
  local want="$1" f="/etc/nginx/stream-enabled/reality-fallback.conf" cur
  [[ -f "$f" ]] || return 1
  cur=$(grep -oE '^[[:space:]]*limit_conn[[:space:]]+reality_conn[[:space:]]+[0-9]+' "$f" | grep -oE '[0-9]+$')
  [[ -z "$cur" || "$cur" == "$want" ]] && return 1
  sed -i -E "s|^([[:space:]]*)limit_conn[[:space:]]+reality_conn[[:space:]]+[0-9]+;|\1limit_conn reality_conn ${want};|" "$f"
}

# Каждое фронтовое соединение стоит nginx двух дескрипторов, и ещё два уходят
# на дозвон REALITY до fallback — вчетверо больше, чем до фронта. Дефолтные
# 768 упираются в потолок молча, а молча потерянные соединения на этом сервере
# и есть демаскировка.
_front_worker_conn() {
  local f=/etc/nginx/nginx.conf cur
  cur=$(grep -oE '^[[:space:]]*worker_connections[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$')
  [[ -z "$cur" ]] && return 1
  [[ "$cur" -ge 4096 ]] && return 2
  sed -i -E 's|^([[:space:]]*)worker_connections[[:space:]]+[0-9]+;|\1worker_connections 4096;|' "$f"
}

# worker_connections без worker_rlimit_nofile — половина дела: соединение это
# дескриптор, а больше, чем разрешил systemd (по умолчанию 1024 на процесс),
# воркер открыть не может. nginx пишет об этом одну строку при старте
# («worker_connections exceed open file resource limit») и дальше просто не
# принимает лишние соединения — молча. А молча потерянное соединение на этом
# сервере равно «принял TCP и закрыл», то есть подписи прокси.
# Директива top-level, поэтому ставится рядом с worker_processes.
# Возврат: 0 — поправили, 1 — не смогли, 2 — уже достаточно.
_ngx_rlimit_nofile() {
  local f=/etc/nginx/nginx.conf cur bak
  [[ -f "$f" ]] || return 1
  cur=$(grep -oE '^[[:space:]]*worker_rlimit_nofile[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$')
  [[ -n "$cur" && "$cur" -ge 16384 ]] && return 2

  mkdir -p "$BACKUP_DIR"
  bak="$BACKUP_DIR/nginx.conf_$(date +%Y%m%d_%H%M%S).bak"
  cp "$f" "$bak"
  if [[ -n "$cur" ]]; then
    sed -i -E 's|^([[:space:]]*)worker_rlimit_nofile[[:space:]]+[0-9]+;|\1worker_rlimit_nofile 16384;|' "$f"
  else
    grep -qE '^[[:space:]]*worker_processes[[:space:]]' "$f" || { rm -f "$bak"; return 1; }
    sed -i -E '0,/^[[:space:]]*worker_processes[[:space:]][^;]*;/s//&\nworker_rlimit_nofile 16384;/' "$f"
  fi
  # nginx.conf общий для всей машины: сломать его — уронить и соседей.
  nginx -t &>/dev/null && { rm -f "$bak"; return 0; }
  cp "$bak" "$f"; rm -f "$bak"; return 1
}

# ─── Стабильность: sysctl-профиль и watchdog ─────────────────────────────────
#
# ЗАЧЕМ ОТДЕЛЬНО ОТ harden: harden закрывает утечки, tune чинит обрывы.
# Замерено на живом сервере (51 день аптайма): TcpRetransSegs 1.9 млн при
# 24.8 млн TX-пакетов — 7.7% ретрансмитов; TcpExtTCPTimeouts 1.38 млн;
# TcpExtListenOverflows 776 и ListenDrops 1156 — соединения терялись молча
# в очереди accept, ещё ДО того как их видел Xray. Никакой правкой конфига
# Xray это не лечится: проблема ниже, в стеке ядра.
#
# ЧЕГО ЗДЕСЬ СОЗНАТЕЛЬНО НЕТ — и это часть анти-DPI, а не экономия:
#   · tcp_fastopen=3 (серверный TFO) — редкость в вебе; включив, мы начинаем
#     отличаться от домена-маски на уровне TCP, ещё до всякого TLS;
#   · tcp_timestamps=0 — тоже отличие от типового сервера, плюс ломает PAWS;
#   · нестандартный initcwnd/initrwnd — уникальный размер первого окна
#     это стабильная подпись, по которой сервер узнаётся между сессиями.
# Устойчивость к DPI дороже пары процентов скорости.
SYSCTL_FILE="/etc/sysctl.d/99-xray-tune.conf"
WATCHDOG_SVC="/etc/systemd/system/xray-watchdog.service"
WATCHDOG_TIMER="/etc/systemd/system/xray-watchdog.timer"

_tune_on() { [[ -f "$SYSCTL_FILE" ]]; }

# Профиль пишется целиком, идемпотентно. nf_conntrack_max выставляется
# отдельно: модуль может быть не загружен, и тогда sysctl -p ругается на весь
# файл сразу, а не на одну строку.
_tune_write() {
  cat > "$SYSCTL_FILE" <<'SYSCTLEOF'
# Профиль стабильности VPN. Создан xm tune. Откат: sudo xm tune --off
# Значения подобраны под VPS 1-2 vCPU с клиентами на мобильных сетях.

# BBR + fq: при потерях 2-5% (типичный мобильный интернет) CUBIC режет окно
# вдвое на каждой потере, BBR держит скорость. Фиксируем явно, чтобы профиль
# был самодостаточным, даже если кто-то откатит настройки хостера.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Буферы. Дефолт 212992 (208 КБ) рассчитан на LAN. При RTT 80-250 мс до
# клиента столько окна не хватает, и канал простаивает вместо передачи.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216

# Очередь accept. Замерены ListenOverflows — это соединения, где SYN прошёл,
# а accept не успел: клиент считает, что подключился, сервер молча выбросил.
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384

# PMTU blackhole — главная причина «подключилось, но ничего не грузится» на
# мобильных сетях: пакеты в 1500 б не проходят, а ICMP Too Big режется, и
# соединение висит насмерть. С probing ядро само нащупывает рабочий MTU.
net.ipv4.tcp_mtu_probing = 1

# Не сбрасывать окно после простоя: иначе каждое возвращение из idle
# (телефон в кармане) начинается с медленного старта заново.
net.ipv4.tcp_slow_start_after_idle = 0

# Мобильные клиенты пропадают без FIN. Держать их часами — впустую занятые
# сокеты; 10 мин до первой пробы и 5 проб по 30 с — разумный компромисс.
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15

# Сервер сам инициирует исходящее соединение на каждый запрос клиента —
# дефолтные ~28 тыс. портов кончаются быстрее, чем истекает TIME_WAIT.
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1

# Замерены UdpRcvbufErrors — потерянные UDP-датаграммы (DNS и QUIC).
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
SYSCTLEOF
  chmod 644 "$SYSCTL_FILE"
}

# Применение с отчётом: sysctl -p печатает только то, что принял.
_tune_apply() {
  local out rc=0
  out=$(sysctl -p "$SYSCTL_FILE" 2>&1) || rc=1
  printf '%s\n' "$out" | grep -vE '^\s*$' | sed 's/^/      /'
  # conntrack отдельно и без фатальности: на VPS без загруженного модуля
  # nf_conntrack этой переменной просто нет, и это не ошибка.
  if [[ -w /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1 \
      && ok "nf_conntrack_max = 262144" || true
  fi
  return $rc
}

# Точка отсчёта для дельт по счётчикам ядра. Накопительное с загрузки не
# отвечает на вопрос «помогла ли правка»: 6% ретрансмитов могут быть целиком
# из одного аварийного часа трёхдневной давности, а сегодня быть чисто.
# Снимок пишется, когда его нет, и заново из xm tune — чтобы эффект правки
# считался от момента правки.
COUNTERS_SNAP="/var/lib/xm-counters"

# Пустой снимок хуже отсутствующего: нули в файле дали бы на следующем запуске
# дельту размером со всю историю с загрузки, то есть тот же неверный вердикт,
# от которого дельта и заводится. Поэтому сначала в переменную, и только
# непустое — на диск.
_counters_snap_write() {
  local snap
  snap=$(nstat -az 2>/dev/null | awk -v now="$(date +%s)" '
      $1=="TcpRetransSegs"        {r=$2}
      $1=="TcpOutSegs"            {t=$2}
      $1=="TcpExtTCPTimeouts"     {o=$2}
      $1=="TcpExtListenOverflows" {l=$2}
      $1=="TcpExtListenDrops"     {d=$2}
      $1=="UdpRcvbufErrors"       {u=$2}
      END { if (t == "" || t+0 == 0) exit 1
            printf "%d %d %d %d %d %d %d\n", now, r, t, o, l, d, u }')
  [[ -z "$snap" ]] && return 1
  mkdir -p "$(dirname "$COUNTERS_SNAP")" 2>/dev/null || return 1
  ( umask 077; printf '%s\n' "$snap" > "$COUNTERS_SNAP" ) 2>/dev/null
}

# Счётчики, по которым видно потери ДО Xray. Все накопительные с загрузки,
# поэтому смысл имеет доля, а не абсолют: 1.9 млн ретрансмитов сами по себе
# ничего не значат, 7.7% от отправленного — значат много.
_tune_counters() {
  local retr tx to lo ld udperr pct
  retr=$(nstat -az TcpRetransSegs      2>/dev/null | awk 'NR==2{print $2}')
  tx=$(nstat -az   TcpOutSegs          2>/dev/null | awk 'NR==2{print $2}')
  to=$(nstat -az   TcpExtTCPTimeouts   2>/dev/null | awk 'NR==2{print $2}')
  lo=$(nstat -az   TcpExtListenOverflows 2>/dev/null | awk 'NR==2{print $2}')
  ld=$(nstat -az   TcpExtListenDrops   2>/dev/null | awk 'NR==2{print $2}')
  udperr=$(nstat -az UdpRcvbufErrors   2>/dev/null | awk 'NR==2{print $2}')

  local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)

  # ── Окно с прошлого замера считается ПЕРВЫМ, потому что вердикт даётся по
  # нему. Накопительное с загрузки отвечает на вопрос «случалось ли это
  # когда-нибудь», а не «происходит ли сейчас»: авария трёхдневной давности
  # держит красный процент неделями, а свежая правка в нём не видна. Ровно на
  # такой подаче прошлая сессия обвинила домен-маску по счётчику за шесть суток.
  local s_t s_r s_x s_o s_l s_d s_u d_age=0 d_tx=0 d_retr=0 d_lo=0 d_ld=0
  local w_ok=0 w_label=""
  if [[ -r "$COUNTERS_SNAP" ]] \
     && read -r s_t s_r s_x s_o s_l s_d s_u < "$COUNTERS_SNAP" \
     && [[ -n "${s_t:-}" ]]; then
    d_age=$(( $(date +%s) - s_t ))
    d_tx=$((   ${tx:-0} - ${s_x:-0} )); d_retr=$(( ${retr:-0} - ${s_r:-0} ))
    d_lo=$((   ${lo:-0} - ${s_l:-0} )); d_ld=$((  ${ld:-0}  - ${s_d:-0} ))
    if [[ "$d_tx" -lt 0 || "$d_retr" -lt 0 ]]; then
      info "Счётчики обнулились (перезагрузка) — точка отсчёта обновлена"
      _counters_snap_write
    elif [[ "$d_age" -ge 300 && "$d_tx" -gt 0 ]]; then
      w_ok=1; w_label="за $(( d_age / 3600 )) ч $(( (d_age % 3600) / 60 )) мин"
    else
      info "Точка отсчёта свежая ($(( d_age / 60 )) мин) — вердикт пока по накопительному"
    fi
  else
    _counters_snap_write
    info "Точка отсчёта поставлена — следующий запуск даст вердикт по окну"
  fi

  local src cum_pct
  if [[ -n "${retr:-}" && -n "${tx:-}" && "${tx:-0}" -gt 0 ]]; then
    cum_pct=$(awk -v r="$retr" -v t="$tx" 'BEGIN{printf "%.2f", r*100/t}')
  fi
  if [[ "$w_ok" -eq 1 ]]; then
    pct=$(awk -v r="$d_retr" -v t="$d_tx" 'BEGIN{printf "%.2f", r*100/t}'); src="$w_label"
  else
    pct="$cum_pct"; src="накопительно с загрузки"
  fi

  if [[ -n "${pct:-}" ]]; then
    if   awk -v p="$pct" 'BEGIN{exit !(p<1)}'; then ok   "Ретрансмиты ${src}: ${pct}% — норма"
    elif awk -v p="$pct" 'BEGIN{exit !(p<3)}'; then warn "Ретрансмиты ${src}: ${pct}% — заметные потери на пути к клиентам"
    elif [[ "$cc" == "bbr" ]]; then
      # BBR уже стоит, а потери всё равно высокие — значит дело не в
      # алгоритме. Обычно это либо реальные потери на последней миле у
      # клиентов (мобильный интернет), либо PMTU blackhole: пакеты полного
      # размера не проходят, ICMP Too Big режется, и ядро молча ретранслирует.
      fail "Ретрансмиты ${src}: ${pct}% при уже включённом BBR — алгоритм ни при чём. Проверь MTU probing ниже и учти, что часть потерь может быть на стороне клиентских сетей"
    else
      fail "Ретрансмиты ${src}: ${pct}% при cc=${cc:-?} — на потерях CUBIC режет окно вдвое каждый раз. Включи BBR: ${BOLD}sudo xm tune${NC}"
    fi
    [[ "$w_ok" -eq 1 && -n "${cum_pct:-}" ]] \
      && info "  Накопительно с загрузки: ${cum_pct}% (${retr} из ${tx}) — история, не текущее состояние"
  fi

  [[ -n "${to:-}" ]] && info "TCP-таймауты накопительно: ${to}"

  local q_lo q_ld
  if [[ "$w_ok" -eq 1 ]]; then q_lo="$d_lo"; q_ld="$d_ld"; else q_lo="${lo:-0}"; q_ld="${ld:-0}"; fi
  if [[ "$q_lo" -gt 0 || "$q_ld" -gt 0 ]]; then
    warn "Очередь accept переполнялась ${src}: overflows=${q_lo}, drops=${q_ld} — это молча потерянные подключения"
  else
    ok "Очередь accept не переполнялась ${src}"
  fi
  [[ "$w_ok" -eq 1 && $(( ${lo:-0} + ${ld:-0} )) -gt $(( q_lo + q_ld )) ]] \
    && info "  Накопительно с загрузки: overflows=${lo:-0}, drops=${ld:-0} — было до последней правки"

  [[ "${udperr:-0}" -gt 0 ]] && warn "UDP-датаграмм потеряно по буферу (накопительно): ${udperr}" \
                             || ok "UDP-буфер без потерь"
  info "Congestion control: ${cc:-?}, qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null)"
  info "MTU probing: $(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null) (нужен 1 — иначе мобильные клиенты виснут на PMTU blackhole)"
}

# ─── Watchdog ────────────────────────────────────────────────────────────────
#
# ЗАЧЕМ: REALITY дозванивается до dest на КАЖДОЕ входящее соединение, а dest
# в nginx задан ИМЕНЕМ и резолвится в рантайме. Значит сдохший резолвинг = сдохший
# VPN, причём сразу для всех. Замерено на живом сервере, /var/log/nginx/
# reality_fallback_error.log:
#   "www.cloudflare.com could not be resolved (110: Operation timed out)"
# шесть раз подряд — всё это время сервер принимал TCP и рвал соединение,
# то есть выдавал ровно ту подпись прокси, ради ухода от которой сделан mimic.
# Xray при этом жив, systemd ничего не перезапустит: с его точки зрения всё в
# порядке. Проверять надо именно сквозной путь, а не статус юнитов.
_wd_check() {
  local sni rc=0
  sni=$(_get_nginx_sni)
  [[ -z "$sni" ]] && sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG" 2>/dev/null)
  [[ -z "$sni" ]] && { echo "watchdog: не определить домен-маску — пропуск"; return 0; }

  # 1. Резолвинг dest. Именно то, что упало на живом сервере.
  if ! getent hosts "$sni" >/dev/null 2>&1; then
    echo "watchdog: $sni не резолвится — перезапускаю systemd-resolved"
    systemctl restart systemd-resolved 2>/dev/null || true
    sleep 2
    getent hosts "$sni" >/dev/null 2>&1 \
      && echo "watchdog: резолвинг восстановлен" \
      || { echo "watchdog: резолвинг всё ещё мёртв"; rc=1; }
  fi

  # 2. Слушает ли nginx REALITY-fallback. Без него dest мёртв целиком.
  if ! ss -tln 2>/dev/null | grep -q '127.0.0.1:10443'; then
    echo "watchdog: fallback :10443 не слушает — перезапускаю nginx"
    nginx -t >/dev/null 2>&1 && systemctl restart nginx 2>/dev/null || true
    rc=1
  fi

  # 3. Слушает ли фронт свой публичный порт. Он первый в тракте: сокета нет —
  # снаружи не отвечает ни один канал, при живых Xray и fallback.
  if _front_enabled; then
    local fport
    fport=$(_front_port)
    if ! ss -tln 2>/dev/null | tail -n +2 | awk -v p=":$fport" '$4 ~ p"$"' | grep -q .; then
      echo "watchdog: фронт :${fport} не слушает — перезапускаю nginx"
      nginx -t >/dev/null 2>&1 && systemctl restart nginx 2>/dev/null || true
      rc=1
    fi
  fi

  # 4. Слушает ли сам Xray свой порт. Restart=on-failure не ловит случай,
  # когда процесс жив, но порт потерян.
  local xport
  xport=$(jq -r '.inbounds[0].port' "$CONFIG" 2>/dev/null)
  if [[ -n "$xport" && "$xport" != "null" ]] \
     && ! ss -tln 2>/dev/null | grep -qE "(^|[^0-9:]):${xport}([^0-9]|$)"; then
    echo "watchdog: Xray не слушает :${xport} — перезапускаю"
    systemctl restart xray 2>/dev/null || true
    rc=1
  fi
  return $rc
}

# Юниты пишутся только при включении. Сообщения уходят в journald и НЕ содержат
# ни одного клиентского адреса — проверяется в diag-dpi, блок F.
_wd_install() {
  cat > "$WATCHDOG_SVC" <<'WDSVCEOF'
[Unit]
Description=Xray path watchdog (dest resolve + fallback + listener)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xm watchdog --run
WDSVCEOF
  cat > "$WATCHDOG_TIMER" <<'WDTIMEREOF'
[Unit]
Description=Run Xray path watchdog every 2 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=15s

[Install]
WantedBy=timers.target
WDTIMEREOF
  systemctl daemon-reload
  systemctl enable --now xray-watchdog.timer >/dev/null 2>&1
}

# ─── ML-DSA-65: post-quantum подпись REALITY ─────────────────────────────────
#
# ЧТО ДАЁТ: сервер подписывает «подпись сертификата + сырые ClientHello и
# ServerHello» post-quantum ключом. Клиент с mldsa65Verify это проверяет.
# Смысл — MITM: тот, у кого есть публичный ключ REALITY (он раздаётся в URI,
# и утечь может элементарно), теоретически может встать посередине. С ML-DSA
# не может, в том числе задним числом «накопил сейчас — расшифровал потом».
#
# ЦЕНА: наш Certificate вырастает примерно на 3.3 КБ. Если у домена-маски
# сертификат маленький, длина нашего ответа начинает отличаться от настоящего
# сайта — то есть мы меняем одну зацепку для DPI на другую. Поэтому включать
# имеет смысл, когда у dest сертификат от ~3500 б.
#
# СОВМЕСТИМОСТЬ: клиенты БЕЗ mldsa65Verify продолжают работать как раньше —
# сервер просто не требует проверки. Поэтому включение безопасно.
_parse_mldsa() {
  MLDSA_SEED=$(echo "$1"   | grep -iE "^[[:space:]]*(seed|private)"           | awk '{print $NF}' | head -1 | tr -d '[:space:]')
  MLDSA_VERIFY=$(echo "$1" | grep -iE "^[[:space:]]*(verify|public|password)" | awk '{print $NF}' | head -1 | tr -d '[:space:]')
}

_pq_on() { jq -e '.inbounds[0].streamSettings.realitySettings.mldsa65Seed // empty' "$CONFIG" >/dev/null 2>&1; }

_make_uri_xhttp() {
  local uuid="$1" comment="$2"
  local sni port sid path_val mode pubkey fp server_ip encoded_path
  sni=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host // .inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
  # За фронтом Xray слушает свой локальный порт, а клиент идёт на публичный.
  # URI с локальным портом увёл бы клиента мимо фронта — и на нестандартный
  # порт, ради ухода с которого фронт и поднимался.
  port=$(_front_public_port)
  sid=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG")
  path_val=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.path' "$CONFIG")
  mode=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.mode' "$CONFIG")
  pubkey=$(_get_pubkey_xhttp)
  fp=$(_get_fp)
  server_ip=$(_get_server_ip)
  encoded_path=$(_url_encode "$path_val")

  if [[ -z "$pubkey" || ${#pubkey} -lt 30 ]]; then
    echo -e "${RED}[ERR] Не удалось получить публичный ключ XHTTP. Запусти: xm pubkey${NC}" >&2
    return 1
  fi

  echo "vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pubkey}&sid=${sid}&type=xhttp&path=${encoded_path}&host=${sni}&mode=${mode}#${comment}"
}

_make_uri_tcp() {
  local uuid="$1" comment="$2"
  local sni port sid pubkey fp server_ip
  sni=$(jq -r '.inbounds[1].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
  port=$(jq -r '.inbounds[1].port' "$CONFIG")
  sid=$(jq -r '.inbounds[1].streamSettings.realitySettings.shortIds[0]' "$CONFIG")
  pubkey=$(_get_pubkey_tcp)
  fp=$(_get_fp)
  server_ip=$(_get_server_ip)

  if [[ -z "$pubkey" || ${#pubkey} -lt 30 ]]; then
    echo -e "${RED}[ERR] Не удалось получить публичный ключ TCP. Запусти: xm pubkey${NC}" >&2
    return 1
  fi

  echo "vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pubkey}&sid=${sid}&type=tcp&flow=xtls-rprx-vision#${comment}-TCP"
}

_apply() {
  if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
    systemctl restart xray
    echo -e "${GREEN}Конфиг применён, Xray перезапущен${NC}"
    return 0
  else
    echo -e "${RED}Конфиг невалиден — Xray не перезапущен${NC}"
    xray -test -config "$CONFIG"
    return 1
  fi
}

# Оценка размера TLS Certificate у SNI. Большая цепочка/OCSP staple переполняют
# захардкоженный буфер REALITY (~8192 б) и рвут хендшейк, хотя curl отвечает 200.
# Печатает верхнюю оценку размера записи в байтах, либо "-1" если сайт недоступен.
_check_cert_size() {
  local host="$1"
  local raw tmpd cert size total=0 ocsp_add=0 framing=0 ncerts=0

  raw=$(echo | timeout 10 openssl s_client -connect "${host}:443" \
        -servername "$host" -showcerts -status 2>/dev/null) || raw=""
  if [[ -z "$raw" ]]; then echo "-1"; return 0; fi

  tmpd=$(mktemp -d)
  printf '%s\n' "$raw" | awk -v d="$tmpd" '
    /-----BEGIN CERTIFICATE-----/ {c++}
    c>0 {print > (d "/cert" c ".pem")}
  '
  for cert in "$tmpd"/cert*.pem; do
    [[ -f "$cert" ]] || continue
    size=$(openssl x509 -in "$cert" -outform DER 2>/dev/null | wc -c) || size=0
    if [[ "${size:-0}" -gt 0 ]]; then
      total=$((total + size)); ncerts=$((ncerts + 1))
    fi
  done
  rm -rf "$tmpd"
  [[ "$ncerts" -eq 0 ]] && { echo "-1"; return 0; }

  # OCSP staple ~1500 б (консервативная верхняя оценка) + служебные поля Certificate
  printf '%s' "$raw" | grep -qi "OCSP Response Data" && ocsp_add=1600
  framing=$((10 + ncerts * 6))
  echo $((total + ocsp_add + framing)); return 0
}

# Вердикт по домену через ok/warn/fail. 0 = годится/предупреждение, 1 = нет/недоступен
_sni_cert_gate() {
  local host="$1" est
  info "Проверка размера TLS-сертификата $host (совместимость с REALITY)..."
  est=$(_check_cert_size "$host")
  if [[ "$est" == "-1" ]]; then
    warn "Не удалось получить сертификат $host по :443 (сайт недоступен)"; return 1
  elif [[ "$est" -ge "$REALITY_CERT_LIMIT" ]]; then
    fail "Оценка Certificate ${est} б ≥ лимита REALITY (${REALITY_CERT_LIMIT} б) — REALITY-хендшейк будет рваться. Домен НЕ подходит."; return 1
  elif [[ "$est" -ge "$REALITY_CERT_WARN" ]]; then
    warn "Оценка Certificate ${est} б — близко к лимиту (${REALITY_CERT_LIMIT} б). Риск на части версий Xray."; return 0
  else
    ok "Размер Certificate ~${est} б — с запасом ниже лимита REALITY (${REALITY_CERT_LIMIT} б)"; return 0
  fi
}

# =============================================================================
# _selftest <xhttp|tcp> — живой хендшейк через loopback поверх _tunnel_up.
# Единственная проверка, дающая бинарный ответ «сервер или клиент»: REALITY
# при провале молчит, поэтому пустой лог — норма, а не признак здоровья.
# =============================================================================
_selftest() {
  local net="$1" code
  if ! _tunnel_up "$net"; then
    fail "Не поднять локальный клиент — нет публичного ключа? (sudo xm pubkey)"
    _tunnel_down; return 1
  fi
  info "Транспорт: $net | порт: $TUN_SRVPORT | SNI: $TUN_SNI"
  code=$(_tunnel_code "https://api.ipify.org")
  if [[ "$code" == "200" ]]; then
    ok "Трафик прошёл (HTTP 200) — сервер исправен по транспорту $net"
    ok "Значит проблема НА КЛИЕНТЕ: креды, приложение или сеть до сервера"
  else
    fail "Трафик НЕ прошёл (код: $code) — виноват сервер, не клиент"
    _tunnel_hint | sed 's/^/    /'
    warn "Дальше: sudo xm sni-scan  |  sudo xm reality-debug on"
  fi
  _tunnel_down
  [[ "$code" == "200" ]]
}

# Атомарная замена config.json: JSON через stdin → mktemp → chmod 640 root:nogroup → mv.
# mktemp (непредсказуемое имя) исключает symlink/race, mv в пределах ФС атомарен.
_atomic_write_config() {
  local tmp
  tmp=$(mktemp "$(dirname "$CONFIG")/config.XXXXXX.json")
  trap 'rm -f "$tmp"' EXIT INT TERM
  cat > "$tmp"
  # Не затираем рабочий конфиг пустым/битым JSON (если jq слева упал)
  if [[ ! -s "$tmp" ]] || ! jq empty "$tmp" 2>/dev/null; then
    echo -e "${RED}[ERR] Новый конфиг пуст или невалиден — запись отменена, config.json не тронут${NC}" >&2
    rm -f "$tmp"; trap - EXIT INT TERM; return 1
  fi
  # 640 root:nogroup выставляем до mv, чтобы приватный ключ не был доступен по umask
  chmod 640 "$tmp"
  chown root:nogroup "$tmp"
  mv "$tmp" "$CONFIG"
  trap - EXIT INT TERM
}

# ─── QR-код в терминал ───────────────────────────────────────────────────────

# _print_qr URI [заголовок]
_print_qr() {
  local uri="$1"
  local label="${2:-QR-код}"

  if ! command -v qrencode &>/dev/null; then
    warn "qrencode не установлен. Установи: apt install qrencode"
    return 1
  fi

  echo -e "\n${BOLD}${CYAN}┌─────────────────────────────────────────┐${NC}"
  echo -e "${BOLD}${CYAN}│  ${label}${NC}"
  echo -e "${BOLD}${CYAN}└─────────────────────────────────────────┘${NC}"
  qrencode -t UTF8 -m 1 -l L -s 2 "$uri" || {
    warn "Не удалось сгенерировать QR. URI слишком длинный?"
    warn "Попробуй вручную: qrencode -t UTF8 -m 1 -l L -s 2 '$uri'"
  }
}

# _print_qr_pair UUID COMMENT [show_tcp]
_print_qr_pair() {
  local uuid="$1"
  local comment="$2"
  local show_tcp="${3:-false}"

  local uri_xhttp
  uri_xhttp=$(_make_uri_xhttp "$uuid" "$comment") || return 1

  echo -e "\n${BOLD}VLESS URI (XHTTP):${NC}"
  echo "  $uri_xhttp"
  _print_qr "$uri_xhttp" "QR-код XHTTP · ${comment}"

  if [[ "$show_tcp" == "true" ]] && _has_tcp_inbound; then
    local uri_tcp
    uri_tcp=$(_make_uri_tcp "$uuid" "$comment") || return 1
    echo -e "\n${BOLD}VLESS URI (TCP):${NC}"
    echo "  $uri_tcp"
    _print_qr "$uri_tcp" "QR-код TCP · ${comment}"
  fi
}

# =============================================================================
case "$1" in

# ─── Сервис ──────────────────────────────────────────────────────────────────
start)    systemctl start xray;   echo -e "${GREEN}Xray запущен${NC}" ;;
stop)     systemctl stop xray;    echo -e "${YELLOW}Xray остановлен${NC}" ;;
restart)  systemctl restart xray; echo -e "${GREEN}Xray перезапущен${NC}" ;;
status)   systemctl status xray --no-pager ;;

# ─── Конфиг ──────────────────────────────────────────────────────────────────
edit)
    echo -e "${GREEN}Бэкап: $(_backup_config)${NC}"
    nano "$CONFIG"
    ;;

test)
    xray -test -config "$CONFIG" \
      && echo -e "${GREEN}Конфиг валиден${NC}" \
      || echo -e "${RED}Конфиг невалиден!${NC}"
    ;;

apply)
    _apply
    ;;

# ─── Смена домена-маски (единый источник правды для SNI/dest) ────────────────
# Домен-маска дублируется в 4 местах и должен меняться атомарно во всех:
#   1) inbounds[0] realitySettings.serverNames (XHTTP)
#   2) inbounds[0] xhttpSettings.host (XHTTP; именно его _make_uri_xhttp кладёт в URI)
#   3) inbounds[1] realitySettings.serverNames (TCP, если есть)
#   4) nginx map $ssl_preread_server_name в reality-fallback.conf
# Рассинхрон → у клиента "server name mismatch". Откат при любой ошибке.
set-sni)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm set-sni <domain>${NC}"; exit 1
    fi
    NEW_SNI="${2:-}"
    [[ -z "$NEW_SNI" ]] && read -rp "Новый домен-маска (SNI/dest): " NEW_SNI
    if [[ ! "$NEW_SNI" =~ ^[a-zA-Z0-9._-]+$ ]]; then
      echo -e "${RED}Недопустимые символы в SNI: $NEW_SNI${NC}"; exit 1
    fi

    NGINX_CONF="/etc/nginx/stream-enabled/reality-fallback.conf"
    OLD_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
    echo -e "${BOLD}${CYAN}[ Смена домена-маски: ${OLD_SNI:-?} → ${NEW_SNI} ]${NC}"; sep

    # Проверка совместимости нового домена с REALITY (размер сертификата)
    if ! _sni_cert_gate "$NEW_SNI"; then
      read -rp "Домен рискованный/недоступен. Всё равно применить? [y/N]: " C
      [[ "$C" =~ ^[Yy]$ ]] || { info "Отменено, ничего не изменено."; exit 1; }
    fi

    # Бэкапы для отката: config.json + nginx-conf
    STAMP=$(date +%Y%m%d_%H%M%S)
    CFG_BACKUP=$(_backup_config before_setsni)
    # Бэкап кладём в $BACKUP_DIR, а НЕ рядом в stream-enabled/: nginx включает
    # оттуда файлы по маске, и любой лишний файл в этом каталоге — риск второго
    # server{} на 127.0.0.1:10443 и падения nginx -t после смены домена.
    NGX_BACKUP=""
    [[ -f "$NGINX_CONF" ]] && { NGX_BACKUP="$BACKUP_DIR/reality-fallback_${STAMP}.conf.bak"; cp "$NGINX_CONF" "$NGX_BACKUP"; }
    ok "Бэкапы созданы (config + nginx)"

    # config.json: все SNI-поля одним jq → атомарная запись
    if _has_tcp_inbound; then
      JQ_FILTER='.inbounds[0].streamSettings.realitySettings.serverNames = [$sni]
                 | .inbounds[0].streamSettings.xhttpSettings.host = $sni
                 | .inbounds[1].streamSettings.realitySettings.serverNames = [$sni]'
    else
      JQ_FILTER='.inbounds[0].streamSettings.realitySettings.serverNames = [$sni]
                 | .inbounds[0].streamSettings.xhttpSettings.host = $sni'
    fi
    if ! jq --arg sni "$NEW_SNI" "$JQ_FILTER" "$CONFIG" | _atomic_write_config; then
      fail "Не удалось записать config.json — ничего не изменено"; exit 1
    fi
    _has_tcp_inbound \
      && ok "config.json: serverNames(XHTTP+TCP) + xhttpSettings.host → $NEW_SNI" \
      || ok "config.json: serverNames(XHTTP) + xhttpSettings.host → $NEW_SNI"

    # nginx map: старый SNI → новый в whitelist
    if [[ -f "$NGINX_CONF" ]]; then
      # Источник правды — сам файл (а не config.json): заменяем текущий SNI
      # во ВСЕХ map сразу ($reality_upstream и $log_probe).
      NGX_CUR=$(_get_nginx_sni)
      if [[ -n "$NGX_CUR" && "$NGX_CUR" != "$NEW_SNI" ]]; then
        NGX_ESC=$(printf '%s' "$NGX_CUR" | sed 's/[.[\*^$/]/\\&/g')
        sed -i "s/${NGX_ESC}/${NEW_SNI}/g" "$NGINX_CONF"
      fi
      # Проверяем результат вместо «страховочного» sed без адресации
      if [[ "$(_get_nginx_sni)" != "$NEW_SNI" ]]; then
        fail "SNI в $NGINX_CONF не обновился — откат"
        [[ -n "$NGX_BACKUP" ]] && cp "$NGX_BACKUP" "$NGINX_CONF"
        cp "$CFG_BACKUP" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
        exit 1
      fi
      if ! nginx -t 2>/dev/null; then
        fail "nginx -t не прошёл — откат nginx и config"
        [[ -n "$NGX_BACKUP" ]] && cp "$NGX_BACKUP" "$NGINX_CONF"
        cp "$CFG_BACKUP" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
        systemctl reload nginx 2>/dev/null || true
        exit 1
      fi
      systemctl reload nginx && ok "nginx map обновлён и перезагружен: $NEW_SNI"

      # :80 тоже содержит домен-маску — в цели редиректа и в заголовке Server.
      # Без этого шага после смены домена порт 80 продолжал бы называть старый
      # сайт, а :443 отдавать сертификат нового: рассинхрон, который сканеру
      # виден одним запросом и который мы же ловим в diag-dpi (тест B7).
      # Маска — ключ map и на фронте: без пересборки наш SNI уедет в default.
      # Канал не умрёт (default ведёт к нам же), но зонды перестанут отличаться
      # от клиентов, и в access_log фронта начнут падать их адреса.
      if _front_enabled; then
        _front_apply && ok "Фронт пересобран под $NEW_SNI" \
                     || warn "Фронт пересобрать не удалось — sudo xm front on"
      fi
      case "$(_ngx_http80_fix; echo $?)" in
        0) ok ":80 обновлён под $NEW_SNI (редирект + Server)" ;;
        2) ok ":80 уже соответствует $NEW_SNI" ;;
        *) warn ":80 обновить не удалось — проверь: sudo xm diag-dpi (тест B7)" ;;
      esac
    else
      warn "nginx-conf $NGINX_CONF не найден — проверь REALITY fallback вручную"
    fi

    # Валидация Xray новым конфигом + перезапуск (с откатом)
    if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      systemctl restart xray; sleep 1
      if systemctl is-active --quiet xray; then
        ok "Xray перезапущен с новым SNI"
      else
        fail "Xray не поднялся — откат config"
        cp "$CFG_BACKUP" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
        systemctl restart xray; exit 1
      fi
    else
      fail "Конфиг невалиден — откат config"
      cp "$CFG_BACKUP" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
      exit 1
    fi

    # Старые URI/QR больше не валидны — сразу выдаём новые
    sep
    echo -e "${YELLOW}${BOLD}⚠  Домен-маска изменён на ${NEW_SNI}.${NC}"
    echo -e "${YELLOW}   ВСЕ ранее выданные URI и QR-коды больше НЕ валидны${NC}"
    echo -e "${YELLOW}   (в них зашит старый SNI). Разошли клиентам новые ниже.${NC}"
    sep
    SHOW_TCP=$(_has_tcp_inbound && echo true || echo false)
    while IFS= read -r line; do
      UUID=$(echo "$line" | jq -r '.id')
      COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
      echo -e "\n${BOLD}${CYAN}══ ${COMMENT} ══${NC}"
      _print_qr_pair "$UUID" "$COMMENT" "$SHOW_TCP"
    done < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")
    ;;

# ─── Бэкапы ──────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# set-port — сменить порт inbound с проверкой занятости, UFW и откатом.
#
# ЗАЧЕМ ЭТО ВООБЩЕ НУЖНО: номер порта — признак, который DPI и сканер видят
# ДО всякого анализа TLS. Сертификат крупного сайта, отданный на 8443 или
# 8448, обесценивает всю маскировку REALITY: сайтов на таких портах не бывает,
# а сами эти номера — первые в списке любого сканера прокси. 443 стоит того,
# чтобы ради него разово перевыпустить клиентские URI.
#
# ВАЖНО ПРО «ПОРТ ЗАНЯТ»: занятость проверяется ТОЛЬКО по TCP. Порт — это пара
# (протокол, номер), поэтому служба, слушающая UDP на том же номере, нам не
# мешает и трогать её не нужно. Частый случай: на 443/udp живёт другой VPN,
# а 443/tcp при этом полностью свободен.
set-port)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm set-port <порт>${NC}"; exit 1; }
    NEW_PORT="${2:-}"
    PORT_IDX=0; PORT_LABEL="XHTTP"
    [[ "${3:-}" == "--tcp" ]] && { PORT_IDX=1; PORT_LABEL="TCP/Vision"; }

    if [[ -z "$NEW_PORT" ]]; then
      echo -e "${BOLD}Использование:${NC} xm set-port <порт> [--tcp]"
      echo    "  xm set-port 443          порт XHTTP inbound"
      echo    "  xm set-port 8443 --tcp   порт TCP/Vision inbound"
      echo ""
      echo -e "${BOLD}Сейчас:${NC}"
      jq -r '.inbounds[] | "  \(.streamSettings.network)\t порт \(.port)"' "$CONFIG" 2>/dev/null | sed 's/^/  /'
      exit 0
    fi
    [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [[ "$NEW_PORT" -ge 1 && "$NEW_PORT" -le 65535 ]] \
      || { fail "Порт должен быть числом 1-65535"; exit 1; }
    [[ "$PORT_IDX" -eq 1 ]] && ! _has_tcp_inbound && { fail "TCP inbound отсутствует — нечего переносить"; exit 1; }

    echo -e "\n${BOLD}${CYAN}[ Смена порта: $PORT_LABEL ]${NC}\n"
    OLD_PORT=$(jq -r ".inbounds[$PORT_IDX].port" "$CONFIG")
    [[ "$OLD_PORT" == "$NEW_PORT" ]] && { ok "Порт уже $NEW_PORT — ничего не меняю"; exit 0; }

    # Второй inbound не должен оказаться на том же номере.
    OTHER_PORT=$(jq -r "[.inbounds[].port] | del(.[$PORT_IDX]) | .[0] // empty" "$CONFIG")
    [[ -n "$OTHER_PORT" && "$OTHER_PORT" == "$NEW_PORT" ]] \
      && { fail "Порт $NEW_PORT занят другим inbound этого же Xray"; exit 1; }

    # Занятость по TCP. Свой же xray на старом порту в расчёт не идёт.
    # tail -n +2 вместо ss -H: флаг есть не во всех сборках iproute2, а
    # заголовок один и тот же везде (так же сделано в diag-ports).
    BUSY=$(ss -tlnp 2>/dev/null | tail -n +2 | awk -v p=":$NEW_PORT" '$4 ~ p"$" {print $NF}' | head -1)
    if [[ -n "$BUSY" ]]; then
      fail "TCP-порт $NEW_PORT уже слушает: $BUSY"
      info "Порт — это пара (протокол, номер). Служба на UDP/$NEW_PORT помехой не является"
      info "и в этой проверке не участвует — здесь занят именно TCP."
      exit 1
    fi
    ok "TCP-порт $NEW_PORT свободен"
    UDP_HINT=$(ss -ulnp 2>/dev/null | tail -n +2 | awk -v p=":$NEW_PORT" '$4 ~ p"$" {print $NF}' | head -1)
    [[ -n "$UDP_HINT" ]] && info "На UDP/$NEW_PORT есть служба ($UDP_HINT) — она не мешает и не трогается"

    PBAK=$(_backup_config before_setport); ok "Бэкап: $PBAK"

    if ! jq ".inbounds[$PORT_IDX].port = ${NEW_PORT}" "$CONFIG" | _atomic_write_config; then
      fail "Не удалось записать конфиг"; exit 1
    fi
    if ! xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      fail "Конфиг невалиден — откат"
      cp "$PBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"; exit 1
    fi

    # UFW открываем ДО рестарта: иначе между стартом и правилом есть окно,
    # когда порт слушает, а файрвол его режет.
    ufw allow "${NEW_PORT}/tcp" comment "Xray ${PORT_LABEL}" >/dev/null 2>&1 \
      && ok "UFW: открыт ${NEW_PORT}/tcp" || warn "UFW не принял правило — проверь: sudo ufw status"

    systemctl restart xray; sleep 2
    if ss -tln 2>/dev/null | tail -n +2 | awk -v p=":$NEW_PORT" '$4 ~ p"$"' | grep -q .; then
      ok "Xray слушает $NEW_PORT"
    else
      fail "Xray не поднялся на $NEW_PORT — откат"
      cp "$PBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
      ufw delete allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
      systemctl restart xray
      journalctl -u xray -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
      exit 1
    fi

    # Старое правило убираем только после успеха.
    ufw delete allow "${OLD_PORT}/tcp" >/dev/null 2>&1 \
      && ok "UFW: закрыт старый ${OLD_PORT}/tcp" || info "Старое правило ${OLD_PORT}/tcp не найдено"

    sep
    warn "URI клиентов содержат порт — старые перестали работать. Раздай новые:"
    echo -e "  ${BOLD}sudo xm qr --all${NC}   или   ${BOLD}sudo xm uri --all${NC}"
    echo ""
    ok "Порт $PORT_LABEL: $OLD_PORT → $NEW_PORT"
    # Апстрим фронта задан номером порта: без пересборки он указывает в пустоту.
    if [[ "$PORT_IDX" -eq 0 ]] && _front_enabled; then
      _front_apply && ok "Фронт пересобран под новый порт" \
                   || warn "Фронт пересобрать не удалось — sudo xm front on"
    fi
    echo -e "  Проверить: ${BOLD}sudo xm selftest${NC}, затем ${BOLD}sudo xm diag-dpi${NC} (тест B8)"
    echo ""
    ;;
backup)
    echo -e "${GREEN}Бэкап: $(_backup_config)${NC}"
    ;;

restore)
    mkdir -p "$BACKUP_DIR"
    mapfile -t FILES < <(ls -t "$BACKUP_DIR"/*.json 2>/dev/null)
    [[ ${#FILES[@]} -eq 0 ]] && { echo -e "${RED}Нет бэкапов${NC}"; exit 1; }
    for i in "${!FILES[@]}"; do echo "  $((i+1))) ${FILES[$i]}"; done
    read -rp "Выбери [Enter=1]: " CHOICE; CHOICE=${CHOICE:-1}
    cp "${FILES[$((CHOICE-1))]}" "$CONFIG"
    chmod 640 "$CONFIG"
    chown root:nogroup "$CONFIG"
    echo -e "${GREEN}Восстановлен: ${FILES[$((CHOICE-1))]}${NC}"
    _apply
    ;;

backups)
    ls -lh "$BACKUP_DIR"/*.json 2>/dev/null || echo "Бэкапов нет"
    ;;

# ─── Диагностика публичных ключей ────────────────────────────────────────────
pubkey)
    echo -e "${BOLD}${CYAN}[ Диагностика публичных ключей ]${NC}"
    sep
    echo -e "${BOLD}XHTTP inbound (inbounds[0]):${NC}"
    PRIV0=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // "NOT_FOUND"' "$CONFIG" 2>/dev/null)
    echo "  Приватный ключ в config.json: [СКРЫТ] (длина: ${#PRIV0})"
    PUB0=$(_get_pubkey_xhttp)
    echo "  Вычисленный публичный ключ:   ${PUB0}"
    PUB0_FILE=$(_get_field "PUBLIC KEY")
    echo "  Публичный ключ из client-info: ${PUB0_FILE}"
    if [[ "$PUB0" == "$PUB0_FILE" ]]; then
      ok "Ключи совпадают"
    else
      warn "Ключи расходятся — используй вычисленный из config.json"
    fi

    if _has_tcp_inbound; then
      sep
      echo -e "${BOLD}TCP inbound (inbounds[1]):${NC}"
      PRIV1=$(jq -r '.inbounds[1].streamSettings.realitySettings.privateKey // "NOT_FOUND"' "$CONFIG" 2>/dev/null)
      echo "  Приватный ключ в config.json: [СКРЫТ] (длина: ${#PRIV1})"
      PUB1=$(_get_pubkey_tcp)
      echo "  Вычисленный публичный ключ:   ${PUB1}"
      PUB1_FILE=$(_get_field "PUBLIC KEY2")
      echo "  Публичный ключ из client-info: ${PUB1_FILE}"
      if [[ "$PUB1" == "$PUB1_FILE" ]]; then
        ok "Ключи совпадают"
      else
        warn "Ключи расходятся — используй вычисленный из config.json"
      fi
    fi

    sep
    echo -e "${YELLOW}Если python3-cryptography не установлена, ключи вычислить не получится.${NC}"
    echo -e "Установка: ${BOLD}pip3 install cryptography --break-system-packages${NC}"
    echo -e "Или вручную: ${BOLD}xray x25519 -i PRIVATE_KEY${NC} (если Xray ≥ 1.8.6)"
    ;;

# ─── Клиенты ─────────────────────────────────────────────────────────────────
clients)
    echo -e "${BOLD}Клиенты (inbound 0 — XHTTP):${NC}"
    jq -r '.inbounds[0].settings.clients[] |
      "  UUID: \(.id)  |  \(.comment // "—")"' "$CONFIG"
    if _has_tcp_inbound; then
      echo -e "${BOLD}Клиенты (inbound 1 — TCP):${NC}"
      jq -r '.inbounds[1].settings.clients[] |
        "  UUID: \(.id)  |  flow: \(.flow // "-")  |  \(.comment // "—")"' "$CONFIG"
    fi
    ;;

add|add-client)
    COMMENT="${2:-}"
    [[ -z "$COMMENT" ]] && read -rp "Имя клиента: " COMMENT
    NEW_UUID=$(xray uuid)
    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG" "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"

    if _has_tcp_inbound; then
      jq --arg uuid "$NEW_UUID" --arg comment "$COMMENT" \
        '.inbounds[0].settings.clients += [{"id": $uuid, "comment": $comment}]
         | .inbounds[1].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "comment": $comment}]' \
        "$CONFIG" | _atomic_write_config
      echo -e "${GREEN}Добавлен в оба inbound${NC}"
    else
      jq --arg uuid "$NEW_UUID" --arg comment "$COMMENT" \
        '.inbounds[0].settings.clients += [{"id": $uuid, "comment": $comment}]' \
        "$CONFIG" | _atomic_write_config
      echo -e "${GREEN}Клиент добавлен${NC}"
    fi

    echo -e "${BOLD}UUID:${NC}    $NEW_UUID"
    echo -e "${BOLD}Comment:${NC} $COMMENT"

    _apply && _print_qr_pair "$NEW_UUID" "$COMMENT" "$(_has_tcp_inbound && echo true || echo false)"
    ;;

del|del-client)
    echo -e "${BOLD}Текущие клиенты:${NC}"
    jq -r '.inbounds[0].settings.clients[] |
      "  UUID: \(.id)  |  \(.comment // "—")"' "$CONFIG"
    echo ""
    read -rp "Введи UUID клиента для удаления: " TARGET_UUID

    FOUND=$(jq -r --arg uuid "$TARGET_UUID" \
      '.inbounds[0].settings.clients[] | select(.id == $uuid) | .id' "$CONFIG")
    if [[ -z "$FOUND" ]]; then
      echo -e "${RED}UUID не найден: $TARGET_UUID${NC}"
      exit 1
    fi

    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG" "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"

    if jq --arg uuid "$TARGET_UUID" \
        '.inbounds |= map(.settings.clients |= map(select(.id != $uuid)))' \
        "$CONFIG" | _atomic_write_config; then
      echo -e "${GREEN}Клиент $TARGET_UUID удалён из всех inbound${NC}"
      _apply
    else
      echo -e "${RED}Не удалось записать конфиг — клиент НЕ удалён, config.json не изменён${NC}"
      exit 1
    fi
    ;;

# ─── URI ─────────────────────────────────────────────────────────────────────
uri)
    MODE_TCP=false; SEARCH_ARG=""
    for arg in "${@:2}"; do
      case "$arg" in --tcp) MODE_TCP=true ;; --all) SEARCH_ARG="--all" ;; *) SEARCH_ARG="$arg" ;; esac
    done

    $MODE_TCP && ! _has_tcp_inbound && {
      echo -e "${RED}TCP inbound не обнаружен. Запусти: xm add-tcp${NC}"; exit 1; }

    case "$SEARCH_ARG" in
    --all)
        while IFS= read -r line; do
          UUID=$(echo "$line" | jq -r '.id')
          COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
          echo -e "${CYAN}▸ ${COMMENT}${NC}"
          echo -e "  XHTTP: $(_make_uri_xhttp "$UUID" "$COMMENT")"
          _has_tcp_inbound && echo -e "  TCP:   $(_make_uri_tcp "$UUID" "$COMMENT")"
          echo ""
        done < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")
        ;;
    "")
        mapfile -t CLIENTS < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")
        for i in "${!CLIENTS[@]}"; do
          echo "  $((i+1))) $(echo "${CLIENTS[$i]}" | jq -r '.comment // "—"')  ($(echo "${CLIENTS[$i]}" | jq -r '.id' | cut -c1-8)...)"
        done
        read -rp "Номер [Enter=1]: " CHOICE; CHOICE=${CHOICE:-1}
        SELECTED="${CLIENTS[$((CHOICE-1))]}"
        UUID=$(echo "$SELECTED" | jq -r '.id')
        COMMENT=$(echo "$SELECTED" | jq -r '.comment // "no-comment"')
        $MODE_TCP && _make_uri_tcp "$UUID" "$COMMENT" || _make_uri_xhttp "$UUID" "$COMMENT"
        ;;
    *)
        FOUND=$(jq -c --arg s "$SEARCH_ARG" \
          '.inbounds[0].settings.clients[] | select(.comment // "" | ascii_downcase | contains($s | ascii_downcase))' \
          "$CONFIG")
        [[ -z "$FOUND" ]] && { echo -e "${RED}Не найден: $SEARCH_ARG${NC}"; exit 1; }
        while IFS= read -r line; do
          UUID=$(echo "$line" | jq -r '.id')
          COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
          $MODE_TCP && _make_uri_tcp "$UUID" "$COMMENT" || _make_uri_xhttp "$UUID" "$COMMENT"
        done <<< "$FOUND"
        ;;
    esac
    ;;

# ─── QR-код ──────────────────────────────────────────────────────────────────
qr)
    MODE_TCP=false
    MODE_BOTH=false
    MODE_ALL=false
    SEARCH_ARG=""

    for arg in "${@:2}"; do
      case "$arg" in
        --tcp)  MODE_TCP=true ;;
        --both) MODE_BOTH=true ;;
        --all)  MODE_ALL=true ;;
        *)      SEARCH_ARG="$arg" ;;
      esac
    done

    if ( $MODE_TCP || $MODE_BOTH ) && ! _has_tcp_inbound; then
      echo -e "${RED}TCP inbound не обнаружен. Запусти: xm add-tcp${NC}"
      exit 1
    fi

    if $MODE_ALL; then
      echo -e "${BOLD}${CYAN}[ QR-коды всех клиентов ]${NC}"
      while IFS= read -r line; do
        UUID=$(echo "$line" | jq -r '.id')
        COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
        echo -e "\n${BOLD}${CYAN}══ ${COMMENT} ══${NC}"
        if $MODE_TCP && _has_tcp_inbound; then
          URI=$(_make_uri_tcp "$UUID" "$COMMENT")
          echo "  $URI"
          _print_qr "$URI" "QR TCP · ${COMMENT}"
        elif $MODE_BOTH && _has_tcp_inbound; then
          URI_X=$(_make_uri_xhttp "$UUID" "$COMMENT")
          URI_T=$(_make_uri_tcp  "$UUID" "$COMMENT")
          echo "  XHTTP: $URI_X"
          _print_qr "$URI_X" "QR XHTTP · ${COMMENT}"
          echo "  TCP:   $URI_T"
          _print_qr "$URI_T" "QR TCP · ${COMMENT}"
        else
          URI=$(_make_uri_xhttp "$UUID" "$COMMENT")
          echo "  $URI"
          _print_qr "$URI" "QR XHTTP · ${COMMENT}"
        fi
      done < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")
      exit 0
    fi

    if [[ -n "$SEARCH_ARG" ]]; then
      FOUND=$(jq -c --arg s "$SEARCH_ARG" \
        '.inbounds[0].settings.clients[] | select(.comment // "" | ascii_downcase | contains($s | ascii_downcase))' \
        "$CONFIG")
      if [[ -z "$FOUND" ]]; then
        echo -e "${RED}Клиент не найден: $SEARCH_ARG${NC}"
        exit 1
      fi
      while IFS= read -r line; do
        UUID=$(echo "$line" | jq -r '.id')
        COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
        if $MODE_BOTH && _has_tcp_inbound; then
          _print_qr_pair "$UUID" "$COMMENT" "true"
        elif $MODE_TCP; then
          URI=$(_make_uri_tcp "$UUID" "$COMMENT")
          echo "  $URI"
          _print_qr "$URI" "QR TCP · ${COMMENT}"
        else
          URI=$(_make_uri_xhttp "$UUID" "$COMMENT")
          echo "  $URI"
          _print_qr "$URI" "QR XHTTP · ${COMMENT}"
        fi
      done <<< "$FOUND"
      exit 0
    fi

    echo -e "${BOLD}Выбери клиента:${NC}"
    mapfile -t CLIENTS < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")
    if [[ ${#CLIENTS[@]} -eq 0 ]]; then
      echo -e "${RED}Нет клиентов в конфиге${NC}"; exit 1
    fi
    for i in "${!CLIENTS[@]}"; do
      echo "  $((i+1))) $(echo "${CLIENTS[$i]}" | jq -r '.comment // "—"')  ($(echo "${CLIENTS[$i]}" | jq -r '.id' | cut -c1-8)...)"
    done
    read -rp "Номер [Enter=1]: " CHOICE; CHOICE=${CHOICE:-1}
    SELECTED="${CLIENTS[$((CHOICE-1))]}"
    UUID=$(echo "$SELECTED" | jq -r '.id')
    COMMENT=$(echo "$SELECTED" | jq -r '.comment // "no-comment"')

    if $MODE_BOTH && _has_tcp_inbound; then
      _print_qr_pair "$UUID" "$COMMENT" "true"
    elif $MODE_TCP; then
      URI=$(_make_uri_tcp "$UUID" "$COMMENT")
      echo "  $URI"
      _print_qr "$URI" "QR TCP · ${COMMENT}"
    else
      URI=$(_make_uri_xhttp "$UUID" "$COMMENT")
      echo "  $URI"
      _print_qr "$URI" "QR XHTTP · ${COMMENT}"
    fi
    ;;

# ─── Добавить TCP inbound ─────────────────────────────────────────────────────
add-tcp)
    echo -e "${BOLD}Добавление VLESS+REALITY+TCP (XTLS-Vision) inbound${NC}"
    echo ""

    if _has_tcp_inbound; then
      echo -e "${YELLOW}TCP inbound уже существует в конфиге.${NC}"
      jq -r '.inbounds[1] | "  Порт: \(.port)"' "$CONFIG"
      echo ""
      echo -e "QR-коды: ${BOLD}xm qr --both${NC}  |  URI: ${BOLD}xm uri --tcp${NC}"
      exit 0
    fi

    XHTTP_PORT_CURRENT=$(jq -r '.inbounds[0].port' "$CONFIG")

    while true; do
      read -rp "Порт для TCP inbound [Enter=8443]: " PORT2_INPUT
      PORT2=${PORT2_INPUT:-8443}
      [[ "$PORT2" =~ ^[0-9]+$ ]] && [[ "$PORT2" -ge 1 ]] && [[ "$PORT2" -le 65535 ]] \
        || { echo -e "${RED}Некорректный порт: $PORT2${NC}"; continue; }
      if [[ "$PORT2" -eq "$XHTTP_PORT_CURRENT" ]]; then
        echo -e "${RED}Порт $PORT2 уже используется XHTTP inbound — выбери другой${NC}"
        continue
      fi
      if [[ "$PORT2" -eq 10443 ]]; then
        echo -e "${RED}Порт 10443 зарезервирован под локальный REALITY fallback — выбери другой${NC}"
        continue
      fi
      break
    done

    echo -e "${CYAN}Генерация ключей X25519...${NC}"
    KEY_OUTPUT=$(xray x25519)
    # В новых версиях Xray вывод: PrivateKey/Password/Hash32 (Password = бывший Public key).
    # Якорим по метке в начале строки — значение ключа в начале строки не стоит.
    PRIV=$(echo "$KEY_OUTPUT" | grep -iE "^[[:space:]]*private"          | awk '{print $NF}' | head -1 | tr -d '[:space:]')
    PUB=$(echo  "$KEY_OUTPUT" | grep -iE "^[[:space:]]*(public|password)" | awk '{print $NF}' | head -1 | tr -d '[:space:]')
    [[ -z "$PRIV" || ${#PRIV} -lt 30 || -z "$PUB" || ${#PUB} -lt 30 ]] && {
      echo -e "${RED}Не удалось сгенерировать ключи${NC}"
      echo "Вывод xray x25519:"
      echo "$KEY_OUTPUT"
      exit 1
    }

    SID1=$(openssl rand -hex 8)
    SID2=$(openssl rand -hex 4)

    info "Public key: $PUB"
    info "Short IDs:  $SID1 / $SID2"

    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    info "SNI (dest): $SNI"

    echo ""
    echo -e "${CYAN}Проверка доступности dest ${SNI}...${NC}"
    HTTP_CODE=$(curl -svo /dev/null "https://${SNI}" \
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null) || true
    HTTP_CODE=${HTTP_CODE:-000}
    if [[ "$HTTP_CODE" =~ ^[23] || "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
      ok "dest доступен (HTTP $HTTP_CODE)"
    else
      warn "dest вернул код $HTTP_CODE — продолжаем, но проверь вручную"
    fi
    # Сертификат сайта мог измениться — перепроверяем размер под REALITY
    _sni_cert_gate "$SNI" || warn "SNI $SNI сомнителен по размеру сертификата (см. выше) — TCP inbound может ловить handshake failed"

    CLIENTS_TCP=$(jq '[.inbounds[0].settings.clients[] |
      { id: .id, flow: "xtls-rprx-vision", comment: .comment }]' "$CONFIG")

    # dest/xver ЗЕРКАЛИМ с inbounds[0], а не хардкодим. На сервере со старой
    # архитектурой (dest = внешний сайт, xver = 0) хардкод 127.0.0.1:10443
    # создаёт МЁРТВЫЙ inbound: nginx stream-fallback там не поднят, а симптом —
    # тот же таймаут при пустых логах.
    DEST_MIRROR=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG")
    XVER_MIRROR=$(jq -r '.inbounds[0].streamSettings.realitySettings.xver // 0' "$CONFIG")
    info "dest: $DEST_MIRROR (xver=$XVER_MIRROR) — как у XHTTP inbound"
    if [[ "$DEST_MIRROR" == "127.0.0.1:10443" ]] && ! ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10443"; then
      fail "dest = 127.0.0.1:10443, но никто там не слушает — nginx stream-fallback не поднят"
      fail "TCP inbound окажется нерабочим. Сначала почини fallback: xm diag → блок [6]"
      exit 1
    fi

    TCP_INBOUND=$(jq -n \
      --arg     sni     "$SNI" \
      --arg     priv    "$PRIV" \
      --arg     sid1    "$SID1" \
      --arg     sid2    "$SID2" \
      --arg     dest    "$DEST_MIRROR" \
      --argjson xver    "$XVER_MIRROR" \
      --argjson port    "$PORT2" \
      --argjson clients "$CLIENTS_TCP" \
      '{
        listen: "0.0.0.0",
        port: $port,
        protocol: "vless",
        settings: { clients: $clients, decryption: "none" },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: $dest,
            xver: $xver,
            serverNames: [$sni],
            privateKey: $priv,
            maxTimeDiff: 10000,
            shortIds: [$sid1, $sid2]
          },
          tcpSettings: { header: { type: "none" } }
        },
        sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
      }')

    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S)_before_tcp.json"
    cp "$CONFIG" "$BACKUP_FILE"
    echo -e "${GREEN}Бэкап: $BACKUP_FILE${NC}"

    jq --argjson tcp "$TCP_INBOUND" '.inbounds += [$tcp]' \
      "$CONFIG" | _atomic_write_config

    if [[ -f "$CLIENT_FILE" ]]; then
      {
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo "TCP INBOUND добавлен: $(date)"
        echo "───────────────────────────────────────────────────────"
        echo "PUBLIC KEY2: ${PUB}"
        echo "SHORT ID TCP: ${SID1} / ${SID2}"
        echo "PORT2: ${PORT2}"
      } >> "$CLIENT_FILE"
      echo -e "${GREEN}Данные сохранены в $CLIENT_FILE${NC}"
    fi

    if ufw status | grep -q "Status: active"; then
      ufw allow "${PORT2}/tcp" comment 'Xray TCP' 2>/dev/null && \
        echo -e "${GREEN}UFW: порт $PORT2 открыт${NC}"
    else
      warn "UFW не активен — открой порт $PORT2 вручную"
    fi

    touch /var/log/nginx/reality_fallback.log 2>/dev/null || true

    echo ""
    if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      systemctl restart xray
      sleep 1
      if systemctl is-active --quiet xray; then
        ok "Xray перезапущен успешно"
      else
        fail "Xray не запустился после перезапуска"
        echo -e "${YELLOW}Откат к бэкапу...${NC}"
        cp "$BACKUP_FILE" "$CONFIG"
        chmod 640 "$CONFIG"
        chown root:nogroup "$CONFIG"
        systemctl restart xray
        exit 1
      fi
    else
      echo -e "${RED}Конфиг невалиден — откат к бэкапу${NC}"
      cp "$BACKUP_FILE" "$CONFIG"
      chmod 640 "$CONFIG"
      chown root:nogroup "$CONFIG"
      systemctl restart xray
      exit 1
    fi

    SERVER_IP=$(_get_server_ip)
    FP=$(_get_fp)
    echo ""
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  TCP inbound добавлен!${NC}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}Порт:${NC}       $PORT2"
    echo -e "${BOLD}Public key:${NC} $PUB"
    echo -e "${BOLD}Short ID:${NC}   $SID1"
    echo -e "${BOLD}SNI:${NC}        $SNI"
    echo ""
    echo -e "${BOLD}VLESS URI (TCP) для всех клиентов:${NC}"
    echo ""
    while IFS= read -r line; do
      UUID=$(echo "$line" | jq -r '.id')
      COMMENT=$(echo "$line" | jq -r '.comment // "no-comment"')
      URI="vless://${UUID}@${SERVER_IP}:${PORT2}?encryption=none&security=reality&sni=${SNI}&fp=${FP}&pbk=${PUB}&sid=${SID1}&type=tcp&flow=xtls-rprx-vision#${COMMENT}-TCP"
      echo -e "${CYAN}▸ ${COMMENT}${NC}"
      echo "  $URI"
      _print_qr "$URI" "QR TCP · ${COMMENT}"
      echo ""
    done < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")

    echo -e "${YELLOW}Совет: добавь оба URI в клиент (XHTTP + TCP)${NC}"
    echo -e "${YELLOW}QR для XHTTP: ${BOLD}xm qr${NC}  |  Оба QR: ${BOLD}xm qr --both${NC}"
    ;;

# ─── Обновление Xray ─────────────────────────────────────────────────────────
# Обновление из официального XTLS/Xray-install: скачиваем во временный файл,
# sanity-check (это shell-скрипт), только потом исполняем. --proto '=https'
# --tlsv1.2 запрещают downgrade. Бэкап конфига + контроль прав 640 после.
update)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm update${NC}"; exit 1
    fi

    echo -e "${BOLD}${CYAN}[ Обновление Xray-core (официальный источник XTLS/Xray-install) ]${NC}"
    sep

    CUR_VER=$(xray version 2>/dev/null | head -1 || echo "не установлен")
    info "Текущая версия: $CUR_VER"

    # --check: только сравнить с последним релизом на GitHub, ничего не менять
    if [[ "${2:-}" == "--check" ]]; then
      LATEST=$(_xray_latest_ver)
      if [[ -z "$LATEST" ]]; then
        fail "Не удалось получить информацию о релизах с GitHub API"
        exit 1
      fi
      info "Последний релиз на GitHub: $LATEST"
      CUR_NUM=$(echo "$CUR_VER" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
      NEW_NUM=$(echo "$LATEST"  | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
      if [[ -n "$CUR_NUM" && "$CUR_NUM" == "$NEW_NUM" ]]; then
        ok "Установлена актуальная версия ($CUR_NUM)"
      else
        warn "Доступно обновление: $CUR_NUM → $NEW_NUM. Запусти: xm update"
      fi
      exit 0
    fi

    echo ""
    read -rp "Обновить Xray-core? Сервис будет перезапущен. [y/N]: " UPD_CONFIRM
    [[ "$UPD_CONFIRM" =~ ^[Yy]$ ]] || { info "Отменено."; exit 0; }

    # Шаг 1: бэкап конфига (точка отката)
    UPD_BACKUP=$(_backup_config before_update)
    ok "Бэкап конфига: $UPD_BACKUP"

    # Шаг 2: скачиваем официальный установщик во временный файл (URL захардкожен)
    INSTALLER_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    INSTALLER=$(mktemp /tmp/xray-install.XXXXXX.sh)
    trap 'rm -f "$INSTALLER"' EXIT INT TERM

    info "Скачивание установщика: $INSTALLER_URL"
    if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 \
        -o "$INSTALLER" "$INSTALLER_URL"; then
      fail "Не удалось скачать установщик (сеть/GitHub недоступны)"
      exit 1
    fi

    # Sanity-check: непустой и начинается с shebang (не HTML-страница ошибки)
    if [[ ! -s "$INSTALLER" ]] || ! head -1 "$INSTALLER" | grep -q '^#!'; then
      fail "Скачанный файл не похож на shell-скрипт — установка отменена"
      exit 1
    fi
    ok "Установщик скачан и прошёл базовую проверку"

    # Шаг 3: обновление (бинарник + geodata; config.json не трогается)
    if ! bash "$INSTALLER" install; then
      fail "Установщик завершился с ошибкой — бинарник мог не обновиться"
      warn "Проверь: xray version  и  journalctl -u xray -n 30"
      exit 1
    fi

    NEW_VER=$(xray version 2>/dev/null | head -1 || echo "?")
    ok "Бинарник обновлён: $NEW_VER"

    # Шаг 4: контроль прав config.json (приватный ключ не должен стать всеобщим)
    UPD_PERMS=$(stat -c "%a %U:%G" "$CONFIG" 2>/dev/null || echo "?")
    if [[ "$UPD_PERMS" != "640 root:nogroup" ]]; then
      warn "Права config.json после обновления: $UPD_PERMS — восстанавливаю 640 root:nogroup"
      chmod 640 "$CONFIG"
      chown root:nogroup "$CONFIG"
    fi
    ok "config.json: 640 root:nogroup"

    # Шаг 5: валидация конфига новым бинарником + перезапуск
    if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      ok "Конфиг валиден для новой версии"
      systemctl restart xray
      sleep 2
      if systemctl is-active --quiet xray; then
        ok "Xray перезапущен и работает"
        sep
        echo -e "${GREEN}${BOLD}  Обновление завершено: $CUR_VER → $NEW_VER${NC}"
        echo -e "  Рекомендуется: ${BOLD}xm diag${NC} для полной проверки"
      else
        fail "Xray не запустился после обновления!"
        warn "Смотри: journalctl -u xray -n 50"
        warn "Конфиг НЕ менялся; бэкап на всякий случай: $UPD_BACKUP"
        exit 1
      fi
    else
      fail "Новая версия НЕ принимает текущий конфиг!"
      xray -test -config "$CONFIG" 2>&1 | tail -5 | sed 's/^/    /'
      warn "Конфиг не тронут. Изучи changelog Xray-core перед правками."
      warn "Бэкап: $UPD_BACKUP"
      exit 1
    fi
    ;;

# Обновление geoip.dat / geosite.dat (базы для routing-правил geoip:cn / geoip:ir)
update-geo)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm update-geo${NC}"; exit 1
    fi

    echo -e "${BOLD}${CYAN}[ Обновление geoip.dat / geosite.dat ]${NC}"
    sep

    INSTALLER_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    INSTALLER=$(mktemp /tmp/xray-install.XXXXXX.sh)
    trap 'rm -f "$INSTALLER"' EXIT INT TERM

    if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 \
        -o "$INSTALLER" "$INSTALLER_URL"; then
      fail "Не удалось скачать установщик"
      exit 1
    fi
    if [[ ! -s "$INSTALLER" ]] || ! head -1 "$INSTALLER" | grep -q '^#!'; then
      fail "Скачанный файл не похож на shell-скрипт — отменено"
      exit 1
    fi

    if bash "$INSTALLER" install-geodata; then
      ok "geodata обновлена"
      # Xray читает geo-файлы при старте — нужен перезапуск
      _apply
    else
      fail "Обновление geodata завершилось с ошибкой"
      exit 1
    fi
    ;;

autoupd)
    case "${2:-status}" in
    on)   systemctl enable --now apt-daily.timer apt-daily-upgrade.timer; ok "Включено" ;;
    off)  systemctl disable --now apt-daily-upgrade.timer; ok "Выключено" ;;
    now)  unattended-upgrade --dry-run -v 2>&1 | tail -20 ;;
    log)  tail -40 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo "Лог пуст" ;;
    *)    systemctl list-timers apt-daily-upgrade.timer --no-pager | sed 's/^/  /'
      echo -e "\n${BOLD}Последние применённые:${NC}"
      UUL=$(grep -a "Packages that will be upgraded" /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -5)
      [[ -n "$UUL" ]] && sed 's/^/  /' <<< "$UUL" || echo "  нет данных"
      ;;
    esac
    ;;

# ─── Nginx ───────────────────────────────────────────────────────────────────
nginx-status)  systemctl status nginx --no-pager ;;
nginx-log)     tail -30 "$(_front_enabled && echo "$FRONT_LOG" || echo /var/log/nginx/reality_fallback.log)" 2>/dev/null || echo "Лог пуст" ;;
nginx-reload)  nginx -t && systemctl reload nginx && echo -e "${GREEN}Nginx перезагружен${NC}" ;;
nginx-probes)
    echo -e "${BOLD}Активные зонды (соединения с чужим/пустым SNI):${NC}"
    echo -e "${CYAN}(легитимные клиенты сюда НЕ попадают — у них правильный SNI)${NC}"
    # За фронтом адрес сканера виден только в его логе: в fallback все
    # соединения приходят от нашего же Xray, то есть с 127.0.0.1.
    awk '{print $1}' "$(_front_enabled && echo "$FRONT_LOG" || echo /var/log/nginx/reality_fallback.log)" 2>/dev/null \
      | sort | uniq -c | sort -rn | head -20 || echo "Лог недоступен"
    ;;

# ─── Fail2ban ─────────────────────────────────────────────────────────────────
ban-list)
    for jail in $(_jails); do
      echo -e "${BOLD}Джейл ${jail}:${NC}"
      fail2ban-client status "$jail" 2>/dev/null | sed 's/^/  /'
    done
    [[ -z "$(_jails)" ]] && echo "fail2ban не запущен или джейлов нет"
    ;;

ban-ssh-stat)  fail2ban-client status 2>/dev/null || echo "fail2ban не запущен" ;;

unban)
    TARGET_IP="${2:-}"
    [[ -z "$TARGET_IP" ]] && read -rp "IP для разбана: " TARGET_IP
    for jail in $(_jails); do
      fail2ban-client status "$jail" &>/dev/null && {
        fail2ban-client set "$jail" unbanip "$TARGET_IP" 2>/dev/null \
          && echo -e "${GREEN}${jail}: разбан${NC}" \
          || echo -e "${YELLOW}${jail}: IP не в бане${NC}"
      } || true
    done
    ;;

# Временное включение access-лога для отладки. Держать выключенным!
log-access)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm log-access on|off${NC}"; exit 1
    fi
    case "${2:-status}" in
    on)
      jq '.log.access = "/var/log/xray/access.log"' "$CONFIG" | _atomic_write_config || exit 1
      _apply || exit 1
      warn "Access-лог ВКЛЮЧЁН — пишется 'IP клиента → адрес назначения'"
      warn "Выключи сразу после отладки: sudo xm log-access off"
      ;;
    off)
      jq '.log.access = "none"' "$CONFIG" | _atomic_write_config || exit 1
      _apply || exit 1
      [[ -f /var/log/xray/access.log ]] && \
        { shred -u /var/log/xray/access.log 2>/dev/null || rm -f /var/log/xray/access.log; }
      ok "Access-лог выключен, файл затёрт"
      ;;
    *)
      CUR=$(jq -r '.log.access // "<не задано>"' "$CONFIG")
      [[ "$CUR" == "none" ]] && ok "Access-лог отключён (none)" || warn "Access-лог: $CUR"
      ;;
    esac
    ;;

# Единственный способ увидеть, ПОЧЕМУ REALITY отказывает. Пишет IP клиентов —
# поэтому авто-выключение через 15 мин, чтобы забытая отладка не копила логи.
reality-debug)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm reality-debug on|off|status${NC}"; exit 1
    fi
    case "${2:-status}" in
    on)
      jq '.inbounds[0].streamSettings.realitySettings.show = true | .log.loglevel = "debug"' \
        "$CONFIG" | _atomic_write_config || exit 1
      _apply || exit 1
      warn "REALITY-отладка ВКЛЮЧЕНА — в $LOG пишутся IP клиентов и детали хендшейка"
      info "Строка 'REALITY: processed invalid connection' = клиент не прошёл аутентификацию"
      info "(старый pbk/UUID/shortId у клиента). Её отсутствие = проблема выше по стеку."
      systemd-run --on-active=15min --unit=xray-reality-debug-off \
        /usr/local/bin/xm reality-debug off &>/dev/null \
        && ok "Авто-выключение через 15 мин запланировано" \
        || warn "Авто-выключение не запланировано — выключи вручную!"
      ;;
    off)
      systemctl stop xray-reality-debug-off.timer &>/dev/null || true
      jq '.inbounds[0].streamSettings.realitySettings.show = false | .log.loglevel = "warning"' \
        "$CONFIG" | _atomic_write_config || exit 1
      _apply || exit 1
      [[ -f "$LOG" ]] && { shred -u "$LOG" 2>/dev/null || rm -f "$LOG"; }
      touch "$LOG"; chown nobody:nogroup "$LOG" 2>/dev/null || true
      ok "REALITY-отладка выключена, лог затёрт"
      ;;
    *)
      SHOW=$(jq -r '.inbounds[0].streamSettings.realitySettings.show // false' "$CONFIG")
      LVL=$(jq -r '.log.loglevel // "?"' "$CONFIG")
      [[ "$SHOW" == "true" ]] \
        && warn "show=true, loglevel=$LVL — ОТЛАДКА ВКЛЮЧЕНА, выключи: sudo xm reality-debug off" \
        || ok "show=false, loglevel=$LVL"
      ;;
    esac
    ;;

# ─── Логи ────────────────────────────────────────────────────────────────────
log)       tail -50 "$LOG" 2>/dev/null || echo "Лог пуст" ;;
log-live)  tail -f "$LOG" ;;
log-clear) > "$LOG"; echo -e "${GREEN}Лог очищен${NC}" ;;

# ─── Инфо ────────────────────────────────────────────────────────────────────
info)
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}  Xray Info${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}Версия:${NC}     $(xray version | head -1)"
    echo -e "${BOLD}Сервисы:${NC}"
    echo -e "  xray:      $(systemctl is-active xray)"
    echo -e "  nginx:     $(systemctl is-active nginx)"
    echo -e "  fail2ban:  $(systemctl is-active fail2ban)"
    echo -e "  chrony:    $(systemctl is-active chrony)"
    echo ""
    echo -e "${BOLD}Логи:${NC}     xm log / log-live / log-clear"
    echo -e "  ${GREEN}xm log-access on|off|status${NC}   Временный access-лог для отладки (по умолч. off)"
    echo ""
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    echo -e "${BOLD}Порт XHTTP:${NC} $PORT  ($(ss -tlnp | grep -c ":$PORT" || echo 0) сокет)"
    if _has_tcp_inbound; then
      PORT2=$(jq -r '.inbounds[1].port' "$CONFIG")
      echo -e "${BOLD}Порт TCP:${NC}   $PORT2  ($(ss -tlnp | grep -c ":$PORT2" || echo 0) сокет)"
    fi
    echo -e "${BOLD}Клиентов:${NC}  $(jq '.inbounds[0].settings.clients | length' "$CONFIG")"
    echo ""
    echo -e "${BOLD}SSH порт:${NC}  $(_get_ssh_port)"
    echo ""
    echo -e "${BOLD}NTP дрейф:${NC}"
    if [[ -f /var/lib/xray-sni-watch.flag ]]; then
      echo ""
      warn "Watchdog домена-маски:"
      sed 's/^/    /' /var/lib/xray-sni-watch.flag
    fi
    chronyc tracking 2>/dev/null | grep "System time" | sed 's/^/  /' || echo "  ?"
    ;;

paths)
    echo "  Конфиг:      $CONFIG"
    echo "  Бэкапы:      $BACKUP_DIR"
    echo "  Лог Xray:    $LOG"
    echo "  Клиент-файл: $CLIENT_FILE"
    echo "  Бинарник:    $(which xray)"
    echo "  Nginx conf:  /etc/nginx/stream-enabled/reality-fallback.conf  (тракт REALITY)"
    echo "  Nginx :80:   /etc/nginx/sites-available/fallback  (только 301-редирект)"
    echo "  F2b jail:    /etc/fail2ban/jail.d/sshd-xray.conf"
    ;;

uuid) xray uuid ;;

# =============================================================================
# ─── ДИАГНОСТИКА ─────────────────────────────────────────────────────────────
# =============================================================================

diag)
    echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       Xray Full Diagnostic  v5.8         ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    ISSUES=0

    echo -e "${BOLD}[ 1 ] Сервисы${NC}"; sep
for svc in xray nginx fail2ban chrony; do
      systemctl is-active --quiet "$svc" && ok "$svc запущен" || { fail "$svc НЕ запущен"; ((ISSUES++)); }
    done
    [[ -f /var/run/reboot-required ]] && warn "Требуется перезагрузка (обновлено ядро/libc) — перезагрузи в удобное время" || true

    echo -e "\n${BOLD}[ 2 ] Порты${NC}"; sep
    # Точное сопоставление порта: ":PORT([^0-9]|$)", иначе ":443" ловил бы ":4433"
    XHTTP_PORT=$(jq -r '.inbounds[0].port' "$CONFIG" 2>/dev/null || echo "?")
    if ss -tlnp | grep -qE ":${XHTTP_PORT}([^0-9]|$)"; then
      ok "Порт $XHTTP_PORT (XHTTP) слушается"
    else
      fail "Порт $XHTTP_PORT не слушается"; ((ISSUES++))
    fi
    if _has_tcp_inbound; then
      TCP_PORT=$(jq -r '.inbounds[1].port' "$CONFIG")
      ss -tlnp | grep -qE ":${TCP_PORT}([^0-9]|$)" \
        && ok "Порт $TCP_PORT (TCP) слушается" \
        || { fail "Порт $TCP_PORT не слушается"; ((ISSUES++)); }
    fi
    ss -tlnp | grep -qE ":80([^0-9]|$)" \
      && ok "Порт 80 (nginx) слушается" \
      || warn "Порт 80 не слушается"

    SSH_P=$(_get_ssh_port)
    ss -tlnp | grep -qE ":${SSH_P}([^0-9]|$)" \
      && ok "SSH порт $SSH_P слушается" \
      || { fail "SSH порт $SSH_P не слушается!"; ((ISSUES++)); }

    echo -e "\n${BOLD}[ 3 ] Конфиг Xray${NC}"; sep
    if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      ok "xray -test: OK"
    else
      fail "Конфиг невалиден!"; ((ISSUES++))
    fi
    info "Inbound'ов: $(jq '.inbounds | length' "$CONFIG")"
    info "Клиентов:   $(jq '.inbounds[0].settings.clients | length' "$CONFIG")"

    CONFIG_PERMS=$(stat -c "%a" "$CONFIG" 2>/dev/null || echo "???")
    if [[ "$CONFIG_PERMS" == "640" ]]; then
      ok "config.json права: 640 (root:nogroup — xray читает, остальные нет)"
    else
      fail "config.json права: ${CONFIG_PERMS} — должно быть 640! Исправь: chmod 640 $CONFIG && chown root:nogroup $CONFIG"
      ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 3b ] Публичные ключи${NC}"; sep
    PUB_CHECK=$(_get_pubkey_xhttp)
    if [[ -n "$PUB_CHECK" && ${#PUB_CHECK} -ge 30 ]]; then
      ok "Публичный ключ XHTTP получен (длина ${#PUB_CHECK})"
    else
      fail "Не удалось получить публичный ключ XHTTP — URI будут невалидны!"; ((ISSUES++))
      warn "Запусти: xm pubkey  для диагностики"
    fi

    echo -e "\n${BOLD}[ 4 ] NTP / Время${NC}"; sep
    if systemctl is-active --quiet chrony; then
      DRIFT_LINE=$(chronyc tracking 2>/dev/null | grep "System time" || echo "")
      if [[ -n "$DRIFT_LINE" ]]; then
        DRIFT_VAL=$(echo "$DRIFT_LINE" | awk '{print $4}' | tr -d '-')
        info "Дрейф: $DRIFT_VAL сек"
        if awk "BEGIN {exit !($DRIFT_VAL < 1)}"; then
          ok "Дрейф < 1 сек — отлично"
        elif awk "BEGIN {exit !($DRIFT_VAL < 10)}"; then
          ok "Дрейф < 10 сек — в пределах maxTimeDiff"
        else
          fail "Дрейф > 10 сек — REALITY будет отклонять клиентов (maxTimeDiff=10000)!"; ((ISSUES++))
        fi
        info "Stratum: $(chronyc tracking 2>/dev/null | grep 'Stratum' | awk '{print $3}')"
      else
        warn "chrony работает, tracking недоступен"
      fi
    else
      fail "chrony не запущен"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 5 ] Доступность upstream-сайта (реальный dest REALITY)${NC}"; sep
    # dest = 127.0.0.1:10443 (локальный fallback), поэтому проверяем реальный
    # upstream = serverNames[0], на который nginx проксирует REALITY-хендшейк.
    DEST_RAW=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" 2>/dev/null)
    SNI_UP=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG" 2>/dev/null)
    if [[ "$DEST_RAW" =~ ^127\.0\.0\.1: || "$DEST_RAW" =~ ^localhost: ]]; then
      CHECK_HOST="$SNI_UP"
    else
      CHECK_HOST=$(echo "$DEST_RAW" | sed 's/:443$//')
    fi
    info "Проверяю реальный upstream: $CHECK_HOST"
    HTTP_CODE=$(curl -svo /dev/null "https://${CHECK_HOST}" \
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null) || true
    HTTP_CODE=${HTTP_CODE:-000}
    if [[ "$HTTP_CODE" =~ ^[1-5][0-9][0-9]$ ]]; then
      ok "upstream ${CHECK_HOST} отвечает (HTTP $HTTP_CODE) — путь fallback до реального сайта жив"
    else
      fail "upstream ${CHECK_HOST} недоступен (код: $HTTP_CODE) — REALITY fallback сломается, зонды получат reset"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 6 ] REALITY fallback (nginx stream)${NC}"; sep
    if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10443"; then
      ok "nginx stream-fallback слушает 127.0.0.1:10443"
    else
      fail "127.0.0.1:10443 не слушается — REALITY dest недоступен, хендшейки упадут!"; ((ISSUES++))
    fi
    DEST_CFG=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" 2>/dev/null)
    if [[ "$DEST_CFG" == "127.0.0.1:10443" ]]; then
      ok "REALITY dest → 127.0.0.1:10443 (проходит через nginx)"
    else
      warn "REALITY dest = $DEST_CFG (ожидался 127.0.0.1:10443)"
    fi
    XVER_CFG=$(jq -r '.inbounds[0].streamSettings.realitySettings.xver // 0' "$CONFIG" 2>/dev/null)
    [[ "$XVER_CFG" == "2" ]] \
      && ok "xver=2 (PROXY protocol → реальный IP клиента в логах)" \
      || warn "xver=$XVER_CFG (ожидался 2 — иначе nginx видит только 127.0.0.1)"
    if grep -rq "limit_conn" /etc/nginx/stream-enabled/ 2>/dev/null; then
      ok "limit_conn настроен в stream-fallback"
    else
      warn "limit_conn не найден в stream-fallback"
    fi
    # Без реального IP клиента limit_conn считает всех как 127.0.0.1 → лимит
    # действует на весь сервер и отстреливает своих же (status=503).
    # Годится ЛЮБОЙ из двух способов: $proxy_protocol_addr (работает везде)
    # или set_real_ip_from (нужен ngx_stream_realip_module, в Ubuntu его нет).
    if grep -rqE 'limit_conn_zone[[:space:]]+\$proxy_protocol_addr' /etc/nginx/stream-enabled/ 2>/dev/null; then
      ok "limit_conn по \$proxy_protocol_addr — считает реальный IP клиента"
    elif grep -rq "set_real_ip_from" /etc/nginx/stream-enabled/ 2>/dev/null; then
      ok "limit_conn по \$remote_addr + set_real_ip_from (realip-модуль доступен)"
    else
      fail "limit_conn считает все соединения как 127.0.0.1 — лимит бьёт по своим же клиентам"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 6b ] Синхронизация домена-маски (SNI/dest)${NC}"; sep
    # Сверяем все источники SNI с эталоном serverNames[0] (XHTTP)
    SNI_REF=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
    SNI_HOST=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host // ""' "$CONFIG")
    NGINX_CONF="/etc/nginx/stream-enabled/reality-fallback.conf"
    NGINX_SNI=$(grep -oE '^[[:space:]]*[a-zA-Z0-9._-]+[[:space:]]+[a-zA-Z0-9._-]+;' "$NGINX_CONF" 2>/dev/null | grep -v 'default' | head -1 | awk '{print $1}')
    info "эталон serverNames[0] (XHTTP): ${SNI_REF:-<пусто>}"

    if [[ -z "$SNI_HOST" ]]; then
      warn "xhttpSettings.host пуст — URI возьмёт serverNames[0], но лучше задать явно: xm set-sni $SNI_REF"
    elif [[ "$SNI_HOST" == "$SNI_REF" ]]; then
      ok "xhttpSettings.host == serverNames[0] (клиент шлёт правильный SNI)"
    else
      fail "РАССИНХРОН: xhttpSettings.host=$SNI_HOST ≠ serverNames[0]=$SNI_REF → клиент получит 'server name mismatch'. Исправь: xm set-sni $SNI_REF"; ((ISSUES++))
    fi

    if [[ -z "$NGINX_SNI" ]]; then
      warn "не удалось прочитать SNI из nginx-map ($NGINX_CONF)"
    elif [[ "$NGINX_SNI" == "$SNI_REF" ]]; then
      ok "nginx map SNI == serverNames[0] (fallback идёт на нужный сайт)"
    else
      fail "РАССИНХРОН: nginx map=$NGINX_SNI ≠ serverNames[0]=$SNI_REF → REALITY-зонды уводятся не туда. Исправь: xm set-sni $SNI_REF"; ((ISSUES++))
    fi

    if _has_tcp_inbound; then
      SNI_TCP=$(jq -r '.inbounds[1].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
      if [[ "$SNI_TCP" == "$SNI_REF" ]]; then
        ok "TCP inbound serverNames[0] == XHTTP (общий SNI, как в архитектуре)"
      else
        fail "РАССИНХРОН: TCP serverNames[0]=$SNI_TCP ≠ XHTTP=$SNI_REF. Исправь: xm set-sni $SNI_REF"; ((ISSUES++))
      fi
    fi

    echo -e "\n${BOLD}[ 7 ] Fail2ban${NC}"; sep
    if fail2ban-client status sshd &>/dev/null; then
      ok "SSH jail активен"
      BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | awk -F: '{print $2}' | xargs)
      [[ -n "$BANNED" ]] && warn "Забанены: $BANNED" || info "Банов нет"
    else
      fail "fail2ban SSH jail не активен"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 8 ] Firewall (UFW)${NC}"; sep
    if ufw status | grep -q "Status: active"; then
      ok "UFW активен"
      # if/else вместо && || : прежняя запись потеряла '\' после grep, из-за чего
      # строка "&& ok ..." становилась отдельной командой → syntax error → весь
      # case не парсился → xm не запускался НИ ОДНОЙ командой.
      if ufw status | grep -qE "(^|[^0-9])${SSH_P}/tcp"; then
        ok "SSH порт $SSH_P открыт в UFW"
      else
        fail "SSH порт $SSH_P не найден в UFW — риск потери доступа!"; ((ISSUES++))
      fi
    else
      fail "UFW не активен — сервер открыт!"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 9 ] Логирование (анонимность)${NC}"; sep
    # [FIX-9] Заменено с проверки geoip:cn/ir — она рапортовала защиту,
    # которой нет (routing работает после аутентификации, поле ip = назначение).
    ACC=$(jq -r '.log.access // "<не задано>"' "$CONFIG")
    if [[ "$ACC" == "none" ]]; then
      ok "Xray access-лог отключён (log.access=none)"
    else
      fail "log.access=$ACC — Xray пишет 'IP клиента → адрес назначения'! Задай \"access\":\"none\""; ((ISSUES++))
    fi
    if grep -q 'if=\$log_probe' /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null; then
      ok "nginx fallback логирует только чужой SNI (IP клиентов не пишутся)"
    else
      fail "nginx fallback пишет IP ВСЕХ клиентов — нужен map \$log_probe + access_log ... if=\$log_probe"; ((ISSUES++))
    fi
    JCOUNT=$(journalctl -u xray --since "1 hour ago" --no-pager 2>/dev/null | grep -c "accepted" || true)
    JCOUNT=${JCOUNT:-0}
    [[ "$JCOUNT" -eq 0 ]] \
      && ok "В journald нет access-записей за последний час" \
      || { fail "В journald $JCOUNT access-записей за час — очисти: journalctl --rotate && journalctl --vacuum-time=1s"; ((ISSUES++)); }

    echo -e "\n${BOLD}[ 10 ] Лог Xray${NC}"; sep
    if [[ -f "$LOG" ]] && [[ -s "$LOG" ]]; then
      info "Строк в логе: $(wc -l < "$LOG")"
      if tail -5 "$LOG" | grep -qi "failed\|error\|panic\|rejected"; then
        warn "Последние ошибки:"
        tail -5 "$LOG" | sed 's/^/    /'
      else
        ok "Критических ошибок в последних строках нет"
      fi
    else
      ok "Лог пуст — ошибок нет"
    fi

    echo -e "\n${BOLD}[ 11 ] qrencode${NC}"; sep
    if command -v qrencode &>/dev/null; then
      ok "qrencode доступен ($(qrencode --version 2>&1 | head -1))"
    else
      warn "qrencode не установлен — xm qr работать не будет"
      warn "Установи: apt install qrencode"
    fi

    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    if [[ $ISSUES -eq 0 ]]; then
      echo -e "${GREEN}${BOLD}  ✅ Всё в порядке. Проблем не обнаружено.${NC}"
    else
      echo -e "${RED}${BOLD}  ❌ Обнаружено проблем: $ISSUES${NC}"
      echo -e "${YELLOW}  Исправь проблемы выше и запусти xm diag снова${NC}"
    fi
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"
    ;;

dpi|diag-dpi)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm diag-dpi${NC}"; exit 1; }
    QUICK=false; [[ "${2:-}" == "--quick" ]] && QUICK=true

    echo -e "\n${BOLD}${CYAN}[ Устойчивость к DPI и активному зондированию ]${NC}\n"

    DPI_CRIT=0; DPI_WARN=0
    dfail() { fail "$*"; DPI_CRIT=$((DPI_CRIT + 1)); }
    dwarn() { warn "$*"; DPI_WARN=$((DPI_WARN + 1)); }

    # Целимся в ПУБЛИЧНЫЙ порт: за фронтом Xray слушает loopback, и зонд на
    # его локальный порт померил бы не то, что видит сканер снаружи.
    LPORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    PORT=$(_front_public_port)
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    SERVER_IP=$(_get_server_ip)
    info "Цель: ${SERVER_IP}:${PORT} | домен-маска: ${SNI}"
    _front_enabled && [[ "$PORT" != "$LPORT" ]] \
      && info "Фронт по SNI: :${PORT} → 127.0.0.1:${LPORT} — зонды идут публичным путём"
    $QUICK && info "--quick: живые тесты через тоннель пропускаются"

# ══ A. Согласованность источников SNI ════════════════════════════════════════
    sep
    echo -e "${BOLD}A. Согласованность домена-маски${NC}"
    # Все зонды ниже гоняются по serverNames[0]. Если host/nginx-map расходятся —
    # живой клиент шлёт другой SNI, и тесты меряют не то, что видит DPI.
    SNI_HOST_D=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host // ""' "$CONFIG")
    NGX_SNI_D=$(_get_nginx_sni)
    DSYNC=0
    [[ -n "$SNI_HOST_D" && "$SNI_HOST_D" != "$SNI" ]] && { dfail "xhttpSettings.host=$SNI_HOST_D ≠ serverNames[0]=$SNI — URI клиента шлёт не тот SNI"; DSYNC=1; }
    [[ -n "$NGX_SNI_D"  && "$NGX_SNI_D"  != "$SNI" ]] && { dfail "nginx map=$NGX_SNI_D ≠ serverNames[0]=$SNI — fallback уводит не туда"; DSYNC=1; }
    if _has_tcp_inbound; then
      SNI_TCP_D=$(jq -r '.inbounds[1].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
      [[ "$SNI_TCP_D" != "$SNI" ]] && { dfail "TCP serverNames[0]=$SNI_TCP_D ≠ XHTTP=$SNI"; DSYNC=1; }
    fi
    [[ "$DSYNC" -eq 0 ]] \
      && ok "Все источники SNI согласованы ($SNI) — тесты ниже валидны" \
      || warn "Есть рассинхрон. Исправь: sudo xm set-sni $SNI — иначе результаты ниже вводят в заблуждение"

# ══ B. Активное зондирование ═════════════════════════════════════════════════
    sep
    echo -e "${BOLD}B. Активное зондирование (что видит сканер на нашем порту)${NC}"
    echo -e "  ${CYAN}Принцип: любой ответ нашего порта должен совпадать с ответом${NC}"
    echo -e "  ${CYAN}настоящего ${SNI}:443. Различие = признак, по которому нас находят.${NC}"

    # B1 — валидный SNI. Зонд прозрачно форвардится на fallback → реальный сайт,
    # поэтому ДОЛЖЕН получить настоящий сертификат.
    echo -e "\n  ${BOLD}B1. Зонд с валидным SNI ($SNI) — сертификат${NC}"
    OUR_CERT=$(echo | timeout 8 openssl s_client -connect "${SERVER_IP}:${PORT}" -servername "$SNI" -tls1_3 2>/dev/null \
      | openssl x509 -noout -issuer -subject -fingerprint -sha256 2>/dev/null || echo "")
    REAL_CERT=$(echo | timeout 8 openssl s_client -connect "${SNI}:443" -servername "$SNI" -tls1_3 2>/dev/null \
      | openssl x509 -noout -issuer -subject -fingerprint -sha256 2>/dev/null || echo "")
    if [[ -z "$OUR_CERT" ]]; then
      dfail "Наш сервер НЕ отдал сертификат по TLS 1.3 — зонд получает сбой вместо валидного хендшейка. ПАЛИТ сервер."
      warn "Проверь fallback: sudo xm diag → блок [6], и: ss -tlnp | grep 10443"
    else
      OUR_FP=$(echo "$OUR_CERT"  | grep -i "Fingerprint" | sed 's/.*=//' | tr -d '[:space:]')
      REAL_FP=$(echo "$REAL_CERT" | grep -i "Fingerprint" | sed 's/.*=//' | tr -d '[:space:]')
      OUR_ISS=$(echo "$OUR_CERT"  | grep -i "^issuer")
      REAL_ISS=$(echo "$REAL_CERT" | grep -i "^issuer")
      if [[ -n "$REAL_FP" && "$OUR_FP" == "$REAL_FP" ]]; then
        ok "Сертификат ИДЕНТИЧЕН реальному $SNI — зонд неотличим от настоящего сайта"
      elif [[ -n "$REAL_ISS" && "$OUR_ISS" == "$REAL_ISS" ]]; then
        ok "Issuer совпадает с $SNI (leaf отличается — обычное дело для CDN/гео)"
      elif [[ -n "$REAL_CERT" ]]; then
        dwarn "Issuer не совпадает с реальным $SNI — fallback может проксировать не туда"
        echo "$OUR_CERT"  | grep -iE "^issuer" | sed 's/^/      наш:  /'
        echo "$REAL_CERT" | grep -iE "^issuer" | sed 's/^/      сайт: /'
      else
        info "Эталон $SNI недоступен для сравнения, но наш хендшейк валиден — путь fallback жив"
      fi
    fi

    # B2/B3 — главные тесты на «молчаливый обрыв». Настоящий HTTPS-сервер на
    # чужой/пустой SNI отвечает по TLS (сертификат или alert). Если мы вместо
    # этого принимаем TCP и молча закрываем — это подпись «порт открыт, TLS не
    # говорит», по которой сканер отделяет прокси от веб-сервера за секунду.
    for CASE_N in B2 B3; do
      if [[ "$CASE_N" == "B2" ]]; then
        PSNI="example.com"; PLABEL="с ЧУЖИМ SNI (example.com)"
      else
        PSNI="-";           PLABEL="БЕЗ SNI"
      fi
      echo -e "\n  ${BOLD}${CASE_N}. Зонд ${PLABEL}${NC}"
      OUR_R=$(_tls_probe "${SERVER_IP}:${PORT}" "$PSNI")
      REAL_R=$(_tls_probe "${SNI}:443" "$PSNI")
      info "Наш сервер: $OUR_R   |   Реальный $SNI: $REAL_R"
      # Порядок веток важен: если эталон сам не отвечает с этого VPS, сравнивать
      # не с чем, и «у нас closed, у него closed» — не повод рапортовать «ок».
      if [[ "$REAL_R" == "closed" ]]; then
        dwarn "Эталон $SNI не отвечает с этого VPS — сравнивать не с чем. Проверь сеть VPS и повтори."
      elif [[ "$OUR_R" == "closed" ]]; then
        dfail "Мы принимаем TCP и молча закрываем, а $SNI отвечает по TLS ($REAL_R). Настоящий HTTPS-сервер так не делает — это подпись прокси. Исправь: ${BOLD}sudo xm harden${NC}"
      elif [[ "$OUR_R" == "$REAL_R" ]]; then
        ok "Реакция совпадает с реальным сайтом ($OUR_R) — по этому зонду неотличимо"
      else
        info "Реакции разные ($OUR_R vs $REAL_R), но обе на уровне TLS — сканеру не за что зацепиться"
      fi
    done

    # B4 — голый HTTP на TLS-порт. Настоящий веб-сервер отвечает 400 Bad Request.
    echo -e "\n  ${BOLD}B4. Открытый HTTP-запрос на TLS-порт${NC}"
    # curl при неудаче сам печатает "000" И возвращает !=0 — `|| echo 000`
    # склеил бы два кода в "000000" (см. FIX-14). Ошибку глушим отдельно.
    OUR_H=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://${SERVER_IP}:${PORT}/" 2>/dev/null) || true
    REAL_H=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "http://${SNI}:443/" 2>/dev/null) || true
    OUR_H=${OUR_H:-000}; REAL_H=${REAL_H:-000}
    info "Наш сервер: HTTP $OUR_H   |   Реальный $SNI: HTTP $REAL_H"
    if [[ "$REAL_H" == "000" ]]; then
      info "Эталон $SNI не ответил с этого VPS — сравнивать не с чем, тест пропускаю"
    elif [[ "$OUR_H" == "$REAL_H" ]]; then
      ok "Ответ совпадает с реальным сайтом"
    elif [[ "$OUR_H" == "000" ]]; then
      dwarn "Мы обрываем, $SNI отвечает $REAL_H — отличие. Лечится тем же: sudo xm harden"
    else
      info "Коды разные ($OUR_H vs $REAL_H) — слабый признак, критичным не считаю"
    fi

    # B5 — случайный путь ПОВЕРХ валидного TLS: --resolve гонит curl на наш IP,
    # но SNI/Host предъявляет настоящие.
    echo -e "\n  ${BOLD}B5. Случайный путь через валидный SNI${NC}"
    RAND_PATH="/$(openssl rand -hex 8)"
    OUR_RAND=$(curl -sk -o /dev/null -w "%{http_code}" --resolve "${SNI}:${PORT}:${SERVER_IP}" \
      "https://${SNI}:${PORT}${RAND_PATH}" --max-time 8 2>/dev/null) || true
    REAL_RAND=$(curl -s -o /dev/null -w "%{http_code}" "https://${SNI}${RAND_PATH}" --max-time 8 2>/dev/null) || true
    OUR_RAND=${OUR_RAND:-000}; REAL_RAND=${REAL_RAND:-000}
    info "Наш сервер: HTTP $OUR_RAND   |   Реальный $SNI: HTTP $REAL_RAND"
    if [[ "$OUR_RAND" == "000" ]]; then
      dfail "Наш сервер оборвал соединение — fallback до реального сайта не доходит"
    elif [[ "$OUR_RAND" == "$REAL_RAND" ]]; then
      ok "Ответ ($OUR_RAND) совпадает с реальным $SNI — по HTTP неотличимо"
    else
      dwarn "Ответ ($OUR_RAND) ≠ ответу реального сайта ($REAL_RAND) — часто гео/балансировка CDN, но проверь fallback"
    fi

    # B6 — порт 80
    echo -e "\n  ${BOLD}B6. Порт 80${NC}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${SERVER_IP}" --max-time 5 -H "Host: ${SNI}" 2>/dev/null) || true
    HTTP_CODE=${HTTP_CODE:-000}
    [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]] \
      && ok "Порт 80 → redirect $HTTP_CODE (как у обычного веб-сервера)" \
      || dwarn "Порт 80 вернул $HTTP_CODE (ожидался 301/302)"

    # B7 — ЗАГОЛОВКИ :80, а не только код. Совпадение кода ничего не даёт:
    # 301 отдают все, а вот `Server:` и цель редиректа — разные. Замерено на
    # живом сервере: мы отдавали `Server: nginx` и `Location: https://<наш IP>/`,
    # тогда как домен-маска отдаёт своё имя сервера и редирект НА ДОМЕН.
    # Редирект на голый IP — то, чего не делает ни один настоящий сайт: он
    # прямо говорит сканеру, что за этим адресом нет никакого виртуалхоста.
    echo -e "\n  ${BOLD}B7. Заголовки на :80 (Server и цель редиректа)${NC}"
    OUR_HDR=$(curl -sI --max-time 6 "http://${SERVER_IP}/" -H "Host: ${SNI}" 2>/dev/null) || true
    REAL_HDR=$(curl -sI --max-time 6 "http://${SNI}/" 2>/dev/null) || true
    OUR_SRV=$(printf '%s' "$OUR_HDR"  | grep -im1 '^server:'   | tr -d '\r' | sed 's/^[Ss]erver:[[:space:]]*//')
    REAL_SRV=$(printf '%s' "$REAL_HDR" | grep -im1 '^server:'   | tr -d '\r' | sed 's/^[Ss]erver:[[:space:]]*//')
    OUR_LOC=$(printf '%s' "$OUR_HDR"  | grep -im1 '^location:' | tr -d '\r' | sed 's/^[Ll]ocation:[[:space:]]*//')
    info "Server: наш «${OUR_SRV:-нет}» | $SNI «${REAL_SRV:-нет}»"
    if [[ -z "$REAL_SRV" ]]; then
      info "Эталон не отдал Server — сравнивать не с чем"
    elif [[ "$OUR_SRV" == "$REAL_SRV" ]]; then
      ok "Server совпадает с доменом-маской"
    else
      dwarn "Server отличается («${OUR_SRV:-нет}» вместо «${REAL_SRV}») — сканеру видно, что :80 обслуживает не тот сервер, чей сертификат отдаёт :$PORT"
      # Причина почти всегда одна и та же, и без неё вердикт читается как
      # «xm harden не сработал», хотя менять заголовок ему просто нечем.
      grep -rqs "headers_more" /usr/lib/nginx/modules/ /etc/nginx/modules-enabled/ 2>/dev/null \
        || info "      причина: модуль headers-more не установлен — ${BOLD}sudo xm harden${NC} поставит его и перезапустит nginx"
    fi
    if [[ "$OUR_LOC" =~ ^https://([0-9]{1,3}\.){3}[0-9]{1,3}/ ]]; then
      dfail "Redirect ведёт на голый IP ($OUR_LOC) — настоящий сайт редиректит на своё имя. Это прямая подпись «здесь нет вебсайта»."
    elif [[ -n "$OUR_LOC" ]]; then
      ok "Redirect ведёт на имя ($OUR_LOC), а не на IP"
    fi

    # B8 — НОМЕР ПОРТА. Никакая маскировка TLS не спасает, если сертификат
    # крупного сайта отдаётся на порту, на котором сайтов не бывает.
    echo -e "\n  ${BOLD}B8. Номер порта${NC}"
    # Сначала — открыт ли порт снаружи ВООБЩЕ. Все зонды выше шли с самого VPS
    # на его же внешний адрес, то есть через lo, а петлю ufw пропускает целиком.
    # Поэтому закрытый в файрволе порт выглядит здесь безупречно зелёным, и
    # только эта проверка отличает «сервер маскируется идеально» от «сервера
    # снаружи нет вовсе».
    if _ufw_active; then
      _ufw_allowed "$PORT" \
        && ok "UFW: публичный порт $PORT открыт" \
        || dfail "UFW: порт $PORT НЕ открыт — снаружи не подключится никто, хотя зонды выше прошли: они идут через loopback, мимо файрвола. Открой: ${BOLD}sudo ufw allow ${PORT}/tcp${NC}"
    fi
    if [[ "$PORT" == "443" ]]; then
      ok "Порт 443 — трафик неотличим от обычного HTTPS по одному только номеру"
      # Фронт увёл клиентов на 443, но пока старый порт открыт наружу, на нём
      # по-прежнему отдаётся сертификат маски — аномалия никуда не делась.
      if _front_enabled && [[ "$PORT" != "$LPORT" ]] \
         && ufw status 2>/dev/null | grep -qE "^${LPORT}(/tcp)?[[:space:]]+ALLOW"; then
        dwarn "Локальный порт $LPORT всё ещё открыт наружу в UFW — сертификат $SNI виден и на нём. Закрой, когда клиенты перейдут на 443: sudo ufw delete allow ${LPORT}/tcp"
      fi
    else
      dfail "Порт $PORT: сертификат $SNI на нестандартном порту. Настоящие сайты живут на 443, а $PORT — типичный порт прокси и первый кандидат при сканировании. Это отличие видно ДО любого анализа TLS."
      P443=$(ss -tlnp 2>/dev/null | tail -n +2 | awk '$4 ~ /:443$/ {print $NF}' | head -1)
      if [[ -z "$P443" ]]; then
        info "TCP/443 при этом СВОБОДЕН — перенос: ${BOLD}sudo xm set-port 443${NC} (URI придётся перевыпустить)"
        U443=$(ss -ulnp 2>/dev/null | tail -n +2 | awk '$4 ~ /:443$/ {print $NF}' | head -1)
        [[ -n "$U443" ]] && info "На UDP/443 есть служба — она не конфликтует: порт это пара (протокол, номер)"
      else
        info "TCP/443 занят ($P443) — либо освободи и sudo xm set-port 443, либо"
        info "раздели его по SNI: sudo xm front add <SNI соседа> <его порт>, затем sudo xm front on"
      fi
    fi

    # Второй inbound фронт обслуживать не может: маска у него та же, а по
    # одному SNI два потока не развести. Значит он либо открыт наружу своим
    # номером — и это ровно та аномалия, что описана выше, — либо закрыт, и
    # тогда это канал только для loopback-диагностики. Второе безопаснее, но
    # об этом надо сказать вслух: `xm qr --tcp` выдаёт рабочий на вид URI, а
    # `xm selftest --tcp` ходит через loopback и закрытого файрвола не видит.
    if _has_tcp_inbound && _ufw_active; then
      TCP_P=$(jq -r '.inbounds[1].port' "$CONFIG" 2>/dev/null)
      if _ufw_allowed "$TCP_P"; then
        [[ "$TCP_P" != "443" ]] && dwarn "TCP/Vision inbound открыт наружу на $TCP_P — сертификат $SNI на нестандартном порту, та же аномалия. Держи порт закрытым, если канал не нужен клиентам: sudo ufw delete allow ${TCP_P}/tcp"
      else
        info "TCP/Vision inbound на $TCP_P закрыт в UFW — снаружи недоступен. Для B8 это правильно, но учти: URI из ${BOLD}xm qr --tcp${NC} у клиента не заработает, а ${BOLD}xm selftest --tcp${NC} этого не покажет (идёт через loopback)"
      fi
    fi

# ══ C. Параметры REALITY ═════════════════════════════════════════════════════
    sep
    echo -e "${BOLD}C. Параметры REALITY${NC}"

    if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10443"; then
      ok "stream-fallback слушает 127.0.0.1:10443"
    else
      dfail "stream-fallback не слушает 127.0.0.1:10443 — REALITY dest мёртв, любой зонд получит обрыв"
    fi

    _ngx_mimic_on \
      && ok "nginx-fallback в режиме mimic (чужой SNI уходит на реальный сайт)" \
      || dwarn "nginx-fallback в режиме strict (чужой SNI → обрыв). Включить mimic: sudo xm harden"

    MAX_TD=$(jq -r '.inbounds[0].streamSettings.realitySettings.maxTimeDiff // 0' "$CONFIG")
    if [[ "$MAX_TD" -le 10000 ]]; then
      ok "maxTimeDiff: ${MAX_TD} мс — узкое окно, replay-зонд не пройдёт"
    elif [[ "$MAX_TD" -le 30000 ]]; then
      dwarn "maxTimeDiff: ${MAX_TD} мс — допустимо, но лучше 10000"
    else
      dwarn "maxTimeDiff: ${MAX_TD} мс — широкое окно для replay-атак, снизь до 10000"
    fi

    SID_N=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds | length' "$CONFIG" 2>/dev/null || echo 0)
    SID_EMPTY=$(jq -r '[.inbounds[0].streamSettings.realitySettings.shortIds[]? | select(. == "")] | length' "$CONFIG" 2>/dev/null || echo 0)
    if [[ "$SID_EMPTY" -gt 0 ]]; then
      dfail "Среди shortIds есть ПУСТОЙ — сервер примет клиента без shortId, это дыра в аутентификации REALITY"
    elif [[ "$SID_N" -ge 2 ]]; then
      ok "shortIds: $SID_N — пустых нет"
    else
      dwarn "shortIds: $SID_N — держи 2-3, чтобы менять клиентам shortId без смены ключа"
    fi

    # Размер Certificate у dest: превышение буфера REALITY рвёт хендшейк молча.
    CERT_EST=$(_check_cert_size "$SNI")
    if [[ "$CERT_EST" == "-1" ]]; then
      dwarn "Сертификат $SNI не получен — размер не проверить (сайт недоступен с VPS?)"
    elif [[ "$CERT_EST" -ge "$REALITY_CERT_LIMIT" ]]; then
      dfail "Certificate у $SNI ~${CERT_EST} б ≥ лимита REALITY (${REALITY_CERT_LIMIT}) — хендшейк будет рваться. sudo xm sni-scan"
    elif [[ "$CERT_EST" -ge "$REALITY_CERT_WARN" ]]; then
      dwarn "Certificate у $SNI ~${CERT_EST} б — близко к лимиту ${REALITY_CERT_LIMIT}"
    else
      ok "Certificate у $SNI ~${CERT_EST} б — с запасом ниже лимита REALITY"
    fi

    # ML-DSA-65: post-quantum подпись REALITY. Защищает от MITM тем, у кого
    # утёк публичный ключ. Цена — наш Certificate растёт примерно на 3.3 КБ,
    # поэтому у dest он должен быть НЕ МЕНЬШЕ ~3500 б, иначе размер ответа
    # начинает отличаться от настоящего сайта — новый признак вместо старого.
    if jq -e '.inbounds[0].streamSettings.realitySettings.mldsa65Seed // empty' "$CONFIG" >/dev/null 2>&1; then
      ok "ML-DSA-65 (post-quantum) включён"
      [[ "$CERT_EST" != "-1" && "$CERT_EST" -lt 3500 ]] && \
        dwarn "…но Certificate у $SNI всего ~${CERT_EST} б (<3500): наш ответ заметно длиннее настоящего сайта. Либо домен покрупнее, либо sudo xm pq off"
    else
      info "ML-DSA-65 выключен (штатно). Включить: sudo xm pq on — см. xm pq status"
    fi

# ══ D. Профиль трафика ═══════════════════════════════════════════════════════
    sep
    echo -e "${BOLD}D. Профиль трафика (статистика пакетов)${NC}"
    PADDING=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.xPaddingBytes // ""' "$CONFIG")
    [[ -n "$PADDING" ]] \
      && ok "xPaddingBytes: $PADDING — длины запросов размазаны" \
      || dwarn "xPaddingBytes не задан — длины XHTTP-запросов дают стабильный паттерн"

    XMODE=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.mode // "auto"' "$CONFIG")
    XPATH=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.path // ""' "$CONFIG")
    info "XHTTP mode: $XMODE | path: $XPATH"
    [[ "$XPATH" == "/" || -z "$XPATH" ]] && dwarn "path = «/» — слишком голо, возьми путь похожий на статику/API реального сайта"

    FP=$(_get_fp)
    case "$FP" in
      chrome|edge) ok "uTLS fingerprint: $FP — самый массовый фон" ;;
      randomized)  ok "uTLS fingerprint: randomized — вариативный" ;;
      firefox)     info "uTLS fingerprint: firefox — валиден, но реже в фоне" ;;
      *)           dwarn "uTLS fingerprint: $FP — проверь, что клиент его реально поддерживает" ;;
    esac

# ══ E. DNS ═══════════════════════════════════════════════════════════════════
    sep
    echo -e "${BOLD}E. DNS — где имя домена может уйти открытым текстом${NC}"
    echo -e "  ${CYAN}Клиент, не достучавшись до Secure DNS (а об ограничениях DoH/DoT у${NC}"
    echo -e "  ${CYAN}операторов сообщают с августа 2025), откатывается на обычный DNS.${NC}"
    echo -e "  ${CYAN}Дальше вопрос только в том, кто увидит имя домена — и увидит ли.${NC}"

    echo -e "\n  ${BOLD}E1. Резолвинг на сервере${NC}"
    if _dns_doh_on; then
      ok "dns-блок с DoH настроен: $(jq -r '[.dns.servers[]? | select(type=="string")] | join(", ")' "$CONFIG")"
      QSTRAT=$(jq -r '.dns.queryStrategy // "UseIP"' "$CONFIG")
      if _has_ipv6; then
        info "queryStrategy: $QSTRAT (у VPS есть IPv6)"
      elif [[ "$QSTRAT" == "UseIPv4" ]]; then
        ok "queryStrategy: UseIPv4 — у VPS нет IPv6, лишние AAAA не запрашиваются"
      else
        dwarn "queryStrategy=$QSTRAT, но IPv6 у VPS нет: клиент может получить AAAA, до которого сервер не дойдёт"
      fi
      jq -e '.dns.clientIp // empty' "$CONFIG" >/dev/null 2>&1 \
        && dfail "Задан dns.clientIp — сервер шлёт EDNS Client Subnet, то есть сам сообщает резолверу твою подсеть. Убери." \
        || ok "dns.clientIp не задан — EDNS Client Subnet не утекает"
      # Стаб системы — часть модели угроз, а не соседняя тема: измерено, что
      # в него попадают в том числе имена, пришедшие из тоннеля (см. E5).
      # Пока он ходит открытым UDP, каждое такое попадание — имя на проводе.
      if _resolved_dot_on; then
        ok "systemd-resolved: DNSOverTLS=yes — что попало в системный резолвер, уходит по :853, а не открытым UDP"
      else
        dwarn "systemd-resolved без строгого DoT: всё, что попадёт в системный резолвер (а туда попадает не только не-Xray), уйдёт с VPS открытым UDP/53. Исправить: ${BOLD}sudo xm harden${NC}"
      fi
    else
      dfail "dns-блок не настроен: Xray резолвит домены системным резолвером хостера ОТКРЫТЫМ ТЕКСТОМ — хостер видит полный список сайтов. Исправь: ${BOLD}sudo xm harden${NC}"
    fi

    echo -e "\n  ${BOLD}E2. Доступность DoH-резолверов с этого VPS${NC}"
    DOH_ALIVE=0
    for r in "${DOH_IPS[@]}"; do
      if RTT=$(_doh_probe "$r"); then ok "$r — ${RTT} мс"; DOH_ALIVE=$((DOH_ALIVE + 1))
      else warn "$r — не отвечает"; fi
    done
    [[ "$DOH_ALIVE" -eq 0 ]] && dfail "Ни один DoH-резолвер не доступен с VPS — DoH включать нельзя, сломается резолвинг"

    echo -e "\n  ${BOLD}E3. Перехват :53 из тоннеля${NC}"
    if _dns_hijack_on; then
      ok "routing :53 → dns-out: plain-DNS клиента до внешнего резолвера не доходит, сервер отвечает сам по DoH"
    else
      dfail "Перехвата :53 нет. Клиент с обычным DNS (а после блокировок DoH это большинство) шлёт запрос в тоннель, и наш VPS пересылает его открытым UDP. Исправь: ${BOLD}sudo xm harden${NC}"
    fi

    if ! $QUICK; then
      echo -e "\n  ${BOLD}E4-E5. Живые тесты через свой же тоннель${NC}"
      if _tunnel_up xhttp; then
        TCODE=$(_tunnel_code "https://api.ipify.org")
        [[ "$TCODE" == "200" ]] \
          && ok "Базовый трафик через тоннель проходит (HTTP 200)" \
          || dfail "Через тоннель трафик не идёт (код $TCODE) — сначала почини это: sudo xm selftest"

        # E4 — резолвер 192.0.2.1 (RFC 5737) не существует и не маршрутизируется.
        # Ответ может прийти ТОЛЬКО от перехвата на сервере. Бинарный тест.
        DNSR=$(_socks_dns "192.0.2.1" "example.com")
        case "$DNSR" in
          OK)      ok "E4: DNS-запрос на заведомо мёртвый 192.0.2.1:53 получил ответ → перехват работает, наружу не ушло" ;;
          TIMEOUT) dfail "E4: запрос на 192.0.2.1:53 ушёл наружу и умер по таймауту → перехвата НЕТ, plain-DNS клиента покидает VPS как есть" ;;
          *)       dwarn "E4: тест не отработал (SOCKS/python) — проверь вручную" ;;
        esac

        # E5 — утечка по факту, с атрибуцией. Два имени с РАЗНОЙ судьбой внутри
        # DoH, и разница между ними — это и есть диагноз:
        #   мёртвое имя (случайное под example.com) — DoH обязан вернуть NXDOMAIN;
        #   живое имя  (one.one.one.one)            — DoH обязан вернуть адрес.
        # Течёт только мёртвое → сервер сваливается в системный резолвер лишь
        # когда свой DoH не разрешил имя. Течёт и живое → своим DoH он для
        # исходящих соединений не пользуется вообще, и dns-блок декоративен.
        # one.one.one.one выбран потому, что он гарантированно резолвится и на
        # этом сервере не нужен больше никому: в дампе он однозначно наш.
        if command -v tcpdump &>/dev/null; then
          DEADN="x$(openssl rand -hex 5).example.com"
          LIVEN="one.one.one.one"
          SNIFF=$(mktemp /tmp/xm-dnssniff.XXXXXX)
          tcpdump -lnn -i any -s 256 'port 53' >"$SNIFF" 2>/dev/null &
          TPID=$!
          sleep 1
          if kill -0 "$TPID" 2>/dev/null; then
            _socks_connect "$LIVEN" 80 >/dev/null
            _socks_connect "$DEADN" 80 >/dev/null
            sleep 1
            kill "$TPID" 2>/dev/null; wait "$TPID" 2>/dev/null

            CL_LIVE=$(_dns_leak_class "$SNIFF" "$LIVEN")
            CL_DEAD=$(_dns_leak_class "$SNIFF" "$DEADN")

            case "${CL_LIVE}:${CL_DEAD}" in
              none:none)
                ok "E5: ни живое, ни несуществующее имя в системный резолвер не попали — сервер резолвит только своим DoH" ;;
              none:*)
                dwarn "E5: живое имя сервер резолвит своим DoH, но НЕСУЩЕСТВУЮЩЕЕ $(_e5_where "$CL_DEAD"). Течёт класс имён, который DoH не разрешил: опечатки, снятые с делегирования домены, всё заблокированное на уровне резолвера" ;;
              *)
                dfail "E5: даже ЖИВОЕ имя $(_e5_where "$CL_LIVE") — свой DoH для исходящих соединений сервер не использует, dns-блок в конфиге ни на что не влияет" ;;
            esac
            info "Имена теста: живое $LIVEN → $CL_LIVE, несуществующее $DEADN → $CL_DEAD"

            # Печатаем ВЕСЬ дамп по обоим именам. Раньше показывались первые две
            # строки, а решает вопрос как раз то, что за ними: есть ли пакет с
            # источником вне петли.
            if [[ "$CL_LIVE" != "none" || "$CL_DEAD" != "none" ]]; then
              echo -e "      ${BOLD}Дамп целиком по обоим именам:${NC}"
              grep -F -e "$LIVEN" -e "$DEADN" "$SNIFF" | sed 's/^/      /'
            fi
          else
            warn "E5: tcpdump не смог слушать — тест пропущен"
          fi
          rm -f "$SNIFF"
        else
          info "E5: tcpdump не установлен — тест на утечку пропущен (sudo apt install -y tcpdump)"
        fi
        _tunnel_down
      else
        _tunnel_down
        dwarn "Локальный клиент не поднялся — живые DNS-тесты пропущены (sudo xm selftest)"
      fi
    fi

# ══ G. Стабильность пути ═════════════════════════════════════════════════════
# Отдельный блок, потому что обрыв — это не только «неудобно»: сервер, который
# принимает TCP и рвёт соединение (а именно так он себя ведёт, когда dest не
# резолвится), выдаёт ту самую подпись прокси, ради ухода от которой сделан
# весь mimic. Нестабильность здесь = демаскировка.
    sep
    echo -e "${BOLD}G. Стабильность пути${NC}"

    # G1 — резолвинг dest. Он в nginx задан ИМЕНЕМ и резолвится в рантайме на
    # каждое протухание кэша. Замерено: при холодном резолвере первое соединение
    # до dest заняло 10.0 с, а в error.log лежат «could not be resolved».
    T0=$(date +%s%N)
    if getent hosts "$SNI" >/dev/null 2>&1; then
      T1=$(date +%s%N); RMS=$(( (T1 - T0) / 1000000 ))
      if [[ "$RMS" -lt 500 ]]; then ok "dest $SNI резолвится за ${RMS} мс"
      else dwarn "dest $SNI резолвится за ${RMS} мс — медленно; пока идёт резолвинг, REALITY не может дозвониться до dest и рвёт соединения"
      fi
    else
      dfail "dest $SNI НЕ резолвится с этого сервера — REALITY dest мёртв, каждый клиент и каждый зонд получают обрыв. Смотри: sudo xm watchdog now"
    fi

    NGX_RSLV=$(grep -hoE '^[[:space:]]*resolver[[:space:]]+[^;]+' /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null | head -1 | sed 's/^[[:space:]]*resolver[[:space:]]*//')
    if [[ "$NGX_RSLV" == 127.0.0.53* ]]; then
      _resolved_dot_on \
        && ok "nginx resolver: локальный стаб, и он на строгом DoT — имя dest не уходит открытым" \
        || dfail "nginx resolver = 127.0.0.53, но systemd-resolved БЕЗ строгого DoT: имя домена-маски уходит открытым UDP, и при тормозах стаба падает весь fallback. Исправь: ${BOLD}sudo xm harden${NC}"
    elif [[ -n "$NGX_RSLV" ]]; then
      dwarn "nginx resolver: $NGX_RSLV — открытый UDP/53 за адресом домена-маски мимо всех остальных настроек. Исправит: sudo xm harden"
    fi

    # G2 — почему рвался fallback. REALITY идёт к dest на каждое входящее
    # соединение, поэтому каждая строка здесь — это чей-то неудавшийся коннект.
    # Причины принципиально разные и лечатся по-разному, а в одной куче
    # (4738 строк на живом сервере) они неразличимы.
    #
    # Считаем в окне 24 ч. Счётчик за всё время сам по себе — не вердикт:
    # 16 сбросов домена-маски выглядят как авария, но растянутые на шесть
    # суток это раз в сутки, и мигание «каждые пару секунд» ими не объяснить.
    # Из-за такой подачи домен-маска один раз уже был обвинён напрасно.
    EL="/var/log/nginx/reality_fallback_error.log"
    if [[ -s "$EL" ]]; then
      EL_CUT=$(date -d '24 hours ago' '+%Y/%m/%d %H:%M:%S' 2>/dev/null) || EL_CUT=""
      # Один проход: накопительно, за сутки и метка последнего реального отказа.
      # Формат nginx — "2026/08/31 15:56:41", нули на месте, поэтому сравнение
      # строк работает как сравнение времени, без парсинга дат.
      read -r E_RESOLV E_RESET E_TMOUT E_NOHOST D_RESOLV D_RESET D_TMOUT D_ALL EL_LAST < <(
        awk -v cut="$EL_CUT" '
          { ts = $1 " " $2; rec = (cut != "" && ts >= cut) }
          /could not be resolved/ { r++; if (rec) dr++ }
          /reset by peer/         { s++; if (rec) ds++ }
          /upstream timed out/    { t++; if (rec) dt++ }
          /no host in upstream/   { n++; next }
          { last = ts; if (rec) da++ }
          END { printf "%d %d %d %d %d %d %d %d %s\n",
                       r, s, t, n, dr, ds, dt, da, (last == "" ? "-" : last) }
        ' "$EL")
      echo ""
      if [[ -z "$EL_CUT" ]]; then
        info "Отказы fallback, накопительно: ${E_RESOLV:-0} × резолвинг, $(( ${E_RESET:-0} + ${E_TMOUT:-0} )) × сброс/таймаут (окно за сутки посчитать не удалось)"
      else
        info "Отказы fallback за 24 ч: ${D_ALL:-0}. Всего в файле реальных: $(( ${E_RESOLV:-0} + ${E_RESET:-0} + ${E_TMOUT:-0} ))"
      fi
      [[ "${D_RESOLV:-0}" -gt 0 ]] \
        && dwarn "  ${D_RESOLV} × за сутки dest не резолвился — DNS-путь. Лечится: sudo xm harden + sudo xm tune (watchdog)" \
        || ok "  0 × отказов резолвинга за сутки"
      if [[ $(( ${D_RESET:-0} + ${D_TMOUT:-0} )) -gt 0 ]]; then
        dwarn "  $(( ${D_RESET:-0} + ${D_TMOUT:-0} )) × за сутки сам $SNI сбросил или не ответил — путь ОТ ЭТОГО VPS до домена-маски нестабилен."
        echo -e "      ${CYAN}Бьёт по приложениям, которые часто открывают новые соединения${NC}"
        echo -e "      ${CYAN}(мессенджеры): часть коннектов не проходит, клиент показывает${NC}"
        echo -e "      ${CYAN}«соединение» и переподключается. Подбор живого домена: sudo xm sni-scan${NC}"
      else
        ok "  0 × сбросов со стороны домена-маски за сутки"
      fi
      # Давность последнего отказа. Без неё счётчик за всё время читается как
      # авария: 16 сбросов выглядят страшно, а если они растянуты на шесть
      # суток — это раз в сутки, и мигание «каждые пару секунд» не объясняют.
      if [[ -n "${EL_LAST:-}" && "$EL_LAST" != "-" ]]; then
        EL_EP=$(date -d "${EL_LAST//\//-}" +%s 2>/dev/null)
        [[ -n "$EL_EP" ]] && info "  Последний реальный отказ: $EL_LAST ($(( ($(date +%s) - EL_EP) / 3600 )) ч назад)"
      fi
      [[ "${E_NOHOST:-0}" -gt 0 ]] \
        && info "  ${E_NOHOST} × пустой апстрим — следы старого режима strict (до mimic), не текущая проблема"
    fi

    # G3 — счётчики ядра: потери ДО того, как соединение доходит до Xray.
    echo ""
    _tune_counters

    # G4 — watchdog и таймаут хендшейка.
    echo ""
    systemctl is-active --quiet xray-watchdog.timer \
      && ok "watchdog активен — мёртвый резолвинг dest будет починен сам" \
      || dwarn "watchdog выключен: если dest перестанет резолвиться, VPN ляжет молча и до ручного вмешательства. Включить: ${BOLD}sudo xm tune${NC}"
    HS_D=$(jq -r '.policy.levels."0".handshake // 0' "$CONFIG" 2>/dev/null)
    [[ "${HS_D:-0}" -ge 8 ]] \
      && ok "policy.handshake: ${HS_D} с — переживает медленный резолвинг dest" \
      || dwarn "policy.handshake: ${HS_D} с — мало: в это окно входит и резолвинг dest, и TLS до CDN. Исправит: ${BOLD}sudo xm tune${NC}"
    _tune_on || dwarn "sysctl-профиль не применён — дефолтные буферы 208 КБ и нет MTU probing (мобильные клиенты виснут). Исправит: ${BOLD}sudo xm tune${NC}"

# ══ F. Поведение и логи ══════════════════════════════════════════════════════
    sep
    echo -e "${BOLD}F. Поведение и логи${NC}"
    # Настоящий сайт не банит сканеры. Если баним мы — это отличие, по которому
    # сервер отделяется от www.apple.com.
    if fail2ban-client status 2>/dev/null | grep -qi "reality\|xray"; then
      dwarn "Есть fail2ban-джейл по трафику REALITY — бан сканеров демаскирует сервер"
    else
      ok "Зонды не банятся (только rate-limit) — реакция как у настоящего CDN"
    fi

    ACC=$(jq -r '.log.access // "<не задано>"' "$CONFIG")
    [[ "$ACC" == "none" ]] \
      && ok "Xray access-лог выключен — «кто куда ходил» на диск не пишется" \
      || dfail "log.access=$ACC — Xray пишет IP клиента → адрес назначения. Задай \"access\":\"none\""

    PROBES=$(wc -l < /var/log/nginx/reality_fallback.log 2>/dev/null || echo 0)
    info "Зондов с чужим SNI в логе: $PROBES (свои клиенты сюда не пишутся)"

# ══ Итог ═════════════════════════════════════════════════════════════════════
    sep
    if [[ "$DPI_CRIT" -eq 0 && "$DPI_WARN" -eq 0 ]]; then
      echo -e "${GREEN}${BOLD}  Чисто: критичных нареканий и предупреждений нет.${NC}"
    else
      echo -e "  ${RED}${BOLD}Критично: $DPI_CRIT${NC}   ${YELLOW}${BOLD}Предупреждений: $DPI_WARN${NC}"
      echo ""
      echo -e "  Что делать по порядку:"
      echo -e "    ${BOLD}sudo xm harden${NC}        DoH + перехват :53 + mimic-fallback + строгий DoT на стабе"
    echo -e "    ${BOLD}sudo xm tune${NC}          сетевой стек, таймаут хендшейка, watchdog (блок G)"
      echo -e "    ${BOLD}sudo xm selftest${NC}      если что-то из живых тестов не прошло"
      echo -e "    ${BOLD}sudo xm sni-scan${NC}      если ругается на сертификат домена-маски"
      echo -e "    ${BOLD}sudo xm diag${NC}          общее состояние сервера"
    fi
    echo ""
    ;;

diag-ntp)
    echo -e "\n${BOLD}${CYAN}[ NTP / Time Sync ]${NC}\n"
    sep
    echo -e "${BOLD}Системное время:${NC} $(date)"
    echo -e "${BOLD}UTC:${NC}             $(date -u)"
    echo ""
    if systemctl is-active --quiet chrony; then
      ok "chrony запущен"
      echo ""
      echo -e "${BOLD}chrony tracking:${NC}"
      chronyc tracking 2>/dev/null | sed 's/^/  /' || echo "  недоступно"
      echo ""
      echo -e "${BOLD}Источники NTP:${NC}"
      chronyc sources -v 2>/dev/null | head -20 | sed 's/^/  /' || echo "  недоступно"
    elif systemctl is-active --quiet systemd-timesyncd; then
      warn "Работает systemd-timesyncd (менее точный чем chrony)"
      timedatectl status | sed 's/^/  /'
    else
      fail "Ни chrony ни systemd-timesyncd не запущены!"
      echo -e "  REALITY требует drift < 10 сек (maxTimeDiff=10000). Установи: apt install chrony"
    fi
    ;;

diag-ports)
    echo -e "\n${BOLD}${CYAN}[ Open Ports & Listeners ]${NC}\n"
    sep
    echo -e "${BOLD}Все слушающие TCP порты:${NC}"
    ss -tlnp | tail -n +2 | awk '{printf "  %-25s %s\n", $4, $6}' | sort -t: -k2 -n
    echo ""
    echo -e "${BOLD}Xray inbound'ы:${NC}"
    jq -r '.inbounds[] | "  Порт \(.port) — \(.streamSettings.network) / \(.streamSettings.security)"' \
      "$CONFIG" 2>/dev/null || echo "  конфиг недоступен"
    echo ""
    echo -e "${BOLD}UFW правила:${NC}"
    ufw status numbered 2>/dev/null | sed 's/^/  /' || echo "  UFW не активен"
    echo ""
    echo -e "${BOLD}Активные внешние соединения:${NC}"
    ss -tnp state established 2>/dev/null | awk 'NR>1 {print "  " $4 " → " $5}' \
      | grep -v "127.0.0.1" | head -20 || echo "  нет"
    ;;

diag-tls)
    echo -e "\n${BOLD}${CYAN}[ TLS / Certificate Check ]${NC}\n"

    DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" | sed 's/:443//')
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    SERVER_IP=$(_get_server_ip)

    sep
    # Эталон — реальный сайт из serverNames[0] (dest = локальный fallback)
    echo -e "${BOLD}Сертификат реального сайта (${SNI}):${NC}"
    echo | timeout 5 openssl s_client \
      -connect "${SNI}:443" -servername "$SNI" 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates 2>/dev/null \
      | sed 's/^/  /' || echo "  недоступно"

    sep
    echo -e "${BOLD}Сертификат от нашего сервера (SNI: ${SNI}):${NC}"
    SERVER_CERT=$(echo | timeout 5 openssl s_client \
      -connect "${SERVER_IP}:${PORT}" -servername "$SNI" 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "нет ответа")
    echo "$SERVER_CERT" | sed 's/^/  /'

    sep
    echo -e "${BOLD}TLS версия и шифр:${NC}"
    echo | timeout 5 openssl s_client \
      -connect "${SERVER_IP}:${PORT}" -servername "$SNI" 2>/dev/null \
      | grep -E "Protocol|Cipher" | sed 's/^/  /'

    echo ""
    info "Для полного fingerprint анализа: https://tlsfingerprint.io"
    ;;

diag-fw)
    echo -e "\n${BOLD}${CYAN}[ Firewall & Ban Status ]${NC}\n"

    sep
    echo -e "${BOLD}UFW:${NC}"
    if ufw status | grep -q "Status: active"; then
      ok "UFW активен"
      ufw status verbose 2>/dev/null | grep -E "^(To|--|[0-9])" | sed 's/^/  /'
    else
      fail "UFW не активен!"
    fi

    # Открытое правило без слушателя — не защита и не удобство, а лишняя
    # строка в чужом скане портов. Сверяем разрешённые правила с реальными
    # слушателями: IPv6-дубли («(v6)» во втором поле) пропускаем, чтобы не
    # ругаться дважды на одно и то же правило.
    sep
    echo -e "${BOLD}Правила UFW без слушателя:${NC}"
    LTCP=$(ss -tlnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -un)
    LUDP=$(ss -ulnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -un)
    UFW_JUNK=0
    while read -r uport uproto; do
      [[ -z "$uport" ]] && continue
      # Правило без протокола («443 ALLOW») открывает и tcp, и udp — такому
      # достаточно слушателя в любом из двух списков, иначе будет ложный крик.
      case "$uproto" in
        tcp) L="$LTCP" ;;
        udp) L="$LUDP" ;;
        *)   L="$LTCP"$'\n'"$LUDP"; uproto="tcp+udp" ;;
      esac
      grep -qx "$uport" <<<"$L" || {
        warn "${uport}/${uproto} открыт, но на этом порту никто не слушает"
        UFW_JUNK=$((UFW_JUNK + 1))
      }
    done < <(ufw status 2>/dev/null \
             | awk '$2=="ALLOW"{n=split($1,a,"/");
                     if (a[1] !~ /^[0-9]+$/) next;
                     if (n==2 && (a[2]=="tcp"||a[2]=="udp")) print a[1], a[2];
                     else if (n==1) print a[1], "any"}')
    if [[ "$UFW_JUNK" -eq 0 ]]; then
      ok "Каждое разрешённое правило соответствует живому слушателю"
    else
      info "Убрать: sudo ufw delete allow <порт>/<proto> — и проверить, что SSH при этом остался разрешён"
    fi

    sep
    echo -e "${BOLD}fail2ban:${NC}"
    if systemctl is-active --quiet fail2ban; then
      ok "fail2ban запущен"
      for jail in $(_jails); do
        if fail2ban-client status "$jail" &>/dev/null; then
          TOTAL=$(fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | awk '{print $NF}')
          CURRENT=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
          info "${jail}: сейчас $CURRENT, всего было $TOTAL"
        fi
      done
    else
      fail "fail2ban не запущен"
    fi

    sep
    echo -e "${BOLD}Последние SSH-попытки:${NC}"
    grep -i "failed\|invalid\|disconnect" /var/log/auth.log 2>/dev/null \
      | tail -10 | sed 's/^/    /' || echo "  лог недоступен"
    ;;

diag-log)
    echo -e "\n${BOLD}${CYAN}[ Xray Log Analysis ]${NC}\n"
    sep

    if [[ ! -f "$LOG" ]] || [[ ! -s "$LOG" ]]; then
      ok "Лог пуст — ошибок нет"; exit 0
    fi

    info "Всего строк: $(wc -l < "$LOG")"
    echo ""

    echo -e "${BOLD}Топ ошибок:${NC}"
    grep -i "error\|failed\|rejected\|panic" "$LOG" 2>/dev/null \
      | grep -oP '(error|failed|rejected|panic)[^>]*' \
      | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'

    echo ""
    echo -e "${BOLD}Последние 10 строк:${NC}"
    tail -10 "$LOG" | sed 's/^/  /'

    echo ""
    echo -e "${BOLD}Признаки DPI/блокировки:${NC}"
    HANDSHAKE_FAILS=$(grep -c "rejected\|handshake\|tls.*fail\|reality.*fail" "$LOG" 2>/dev/null || true)
    HANDSHAKE_FAILS=${HANDSHAKE_FAILS:-0}
    if [[ "$HANDSHAKE_FAILS" -gt 50 ]]; then
      warn "Много отклонённых handshake ($HANDSHAKE_FAILS) — возможное DPI или сканирование"
    elif [[ "$HANDSHAKE_FAILS" -gt 0 ]]; then
      info "Отклонённых handshake: $HANDSHAKE_FAILS (норма)"
    else
      ok "Признаков DPI-блокировки нет"
    fi
    ;;

# ─── Selftest ────────────────────────────────────────────────────────────────
selftest)
    if [[ $EUID -ne 0 ]]; then
      echo -e "${RED}Запусти от root: sudo xm selftest${NC}"; exit 1
    fi
    echo -e "${BOLD}${CYAN}[ Selftest: живой хендшейк через loopback ]${NC}"; sep
    if [[ "${2:-}" == "--tcp" ]]; then
      _has_tcp_inbound || { fail "TCP inbound отсутствует"; exit 1; }
      _selftest tcp
    elif [[ "${2:-}" == "--all" ]]; then
      _selftest xhttp; R1=$?
      _has_tcp_inbound && { sep; _selftest tcp; }
      exit $R1
    else
      _selftest xhttp
    fi
    ;;

# ─── Подбор домена-маски ─────────────────────────────────────────────────────
sni-scan)
    POOL=(www.cloudflare.com dl.google.com cdn.jsdelivr.net www.apple.com)
    CUR=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
    if [[ -n "$CUR" ]] && ! printf '%s\n' "${POOL[@]}" | grep -qx "$CUR"; then
      POOL=("$CUR" "${POOL[@]}")
    fi
    echo -e "${BOLD}${CYAN}[ Подбор домена-маски ]${NC}"; sep
    printf "  %-22s %9s %6s %8s  %s\n" "домен" "cert,б" "h2" "RTT,мс" "вердикт"
    BEST=""; BEST_SZ=999999
    for h in "${POOL[@]}"; do
      EST=$(_check_cert_size "$h")
      if [[ "$EST" == "-1" ]]; then
        printf "  %-22s %9s %6s %8s  ${RED}%s${NC}\n" "$h" "-" "-" "-" "НЕДОСТУПЕН"; continue
      fi
      T0=$(date +%s%N)
      HS=$(echo | timeout 8 openssl s_client -connect "$h:443" -servername "$h" \
           -tls1_3 -alpn h2 2>/dev/null)
      T1=$(date +%s%N); RTT=$(( (T1-T0)/1000000 ))
      H2=нет;  printf '%s' "$HS" | grep -qi "ALPN protocol: h2" && H2=да
      T13=нет; printf '%s' "$HS" | grep -q  "TLSv1.3"           && T13=да
      V="ГОДИТСЯ"; C="$GREEN"
      [[ "$EST" -ge "$REALITY_CERT_WARN"  ]] && { V="РИСК";       C="$YELLOW"; }
      [[ "$EST" -ge "$REALITY_CERT_LIMIT" ]] && { V="НЕ ГОДИТСЯ"; C="$RED"; }
      [[ "$H2" != "да" || "$T13" != "да"  ]] && { V="НЕТ h2/TLS1.3"; C="$RED"; }
      GOOD="$V"
      [[ "$h" == "$CUR" ]] && V="$V ← текущий"
      printf "  %-22s %9s %6s %8s  ${C}%s${NC}\n" "$h" "$EST" "$H2" "$RTT" "$V"
      if [[ "$GOOD" == "ГОДИТСЯ" && "$EST" -lt "$BEST_SZ" ]]; then BEST="$h"; BEST_SZ="$EST"; fi
    done
    sep
    if [[ -n "$BEST" ]]; then
      ok "Лучший кандидат: ${BOLD}$BEST${NC} (~${BEST_SZ} б)"
      [[ "$BEST" != "$CUR" ]] && echo -e "  Применить: ${BOLD}sudo xm set-sni $BEST${NC}"
    else
      fail "Ни один кандидат не прошёл — расширь POOL в xm.sh"
    fi
    ;;

tune)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm tune${NC}"; exit 1; }
    echo -e "\n${BOLD}${CYAN}[ Стабильность: сетевой стек и таймауты ]${NC}\n"

    if [[ "${2:-}" == "--check" ]]; then
      sep; echo -e "${BOLD}Текущее состояние${NC}"
      _tune_on && ok "sysctl-профиль: применён ($SYSCTL_FILE)" \
               || warn "sysctl-профиль: НЕ применён (дефолты ядра — буферы 208 КБ, нет MTU probing)"
      systemctl is-active --quiet xray-watchdog.timer \
        && ok "watchdog: включён (проверка сквозного пути каждые 2 мин)" \
        || warn "watchdog: выключен — сдохший резолвинг dest никто не заметит"
      HS=$(jq -r '.policy.levels."0".handshake // "нет"' "$CONFIG" 2>/dev/null)
      [[ "$HS" != "нет" && "$HS" -ge 8 ]] \
        && ok "policy.handshake: ${HS} с — хватает на медленный dest" \
        || warn "policy.handshake: ${HS} с — при тормозящем резолвинге dest хендшейк не успевает"
      sep
      echo -e "${BOLD}Счётчики ядра — вердикт по окну с прошлого замера${NC}"
      _tune_counters
      sep; info "Режим --check: ничего не изменено. Применить: ${BOLD}sudo xm tune${NC}"
      exit 0
    fi

    if [[ "${2:-}" == "--off" ]]; then
      rm -f "$SYSCTL_FILE" && ok "sysctl-профиль удалён (значения вернутся после перезагрузки)"
      systemctl disable --now xray-watchdog.timer >/dev/null 2>&1 || true
      rm -f "$WATCHDOG_SVC" "$WATCHDOG_TIMER"; systemctl daemon-reload
      ok "watchdog выключен и удалён"
      warn "policy.handshake не трогаю — верни вручную через xm edit, если нужно"
      exit 0
    fi

    # ── 1. sysctl ───────────────────────────────────────────────────────────
    sep; echo -e "${BOLD}Шаг 1: сетевой стек${NC}"
    _tune_write && ok "Профиль записан: $SYSCTL_FILE"
    _tune_apply || warn "Часть параметров ядро не приняло (см. выше) — остальные применены"

    # ── 2. policy.handshake ─────────────────────────────────────────────────
    # 4 секунды — дефолт Xray, и он рассчитан на dest в той же сети. У нас
    # dest = внешний CDN через nginx, то есть в эти секунды входит и резолвинг,
    # и TLS до Cloudflare/Akamai. Замерено: при холодном резолвере первое
    # соединение до dest занимало 10.0 с. С handshake=4 такой клиент не войдёт.
    sep; echo -e "${BOLD}Шаг 2: таймаут хендшейка${NC}"
    HS_NOW=$(jq -r '.policy.levels."0".handshake // 0' "$CONFIG" 2>/dev/null)
    if [[ "$HS_NOW" -ge 8 ]]; then
      ok "policy.handshake уже ${HS_NOW} с — не трогаю"
    else
      TBAK=$(_backup_config before_tune); ok "Бэкап: $TBAK"
      if jq '.policy.levels."0".handshake = 8' "$CONFIG" | _atomic_write_config \
         && xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
        systemctl restart xray
        ok "policy.handshake: ${HS_NOW} → 8 с, Xray перезапущен"
      else
        cp "$TBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
        fail "Конфиг не принят — откат из бэкапа"
      fi
    fi

    # ── 3. watchdog ─────────────────────────────────────────────────────────
    sep; echo -e "${BOLD}Шаг 3: watchdog сквозного пути${NC}"
    _wd_install
    if systemctl is-active --quiet xray-watchdog.timer; then
      ok "Таймер xray-watchdog активен — проверка каждые 2 мин"
      info "Проверяет: резолвится ли dest, слушает ли fallback :10443, слушает ли Xray свой порт"
    else
      fail "Таймер не поднялся — смотри: systemctl status xray-watchdog.timer"
    fi

    sep
    _counters_snap_write && ok "Точка отсчёта по счётчикам ядра обновлена"
    echo -e "  ${BOLD}Готово.${NC} Проверить: ${BOLD}sudo xm tune --check${NC}"
    echo -e "  Счётчики ядра накопительные, поэтому эффект считается от точки"
    echo -e "  отсчёта выше: вернись через сутки и сравни строку «За N ч ... с"
    echo -e "  прошлого замера» — накопительная доля будет меняться медленно."
    echo -e "  Откатить: ${BOLD}sudo xm tune --off${NC}"
    echo ""
    ;;

watchdog)
    case "${2:-status}" in
      --run)
        # Вызывается таймером. Молчит, когда всё в порядке: journald не должен
        # заполняться строками «всё хорошо» каждые две минуты.
        # `|| true` обязателен: _wd_check возвращает !=0, когда что-то чинил, а
        # для Type=oneshot это означало бы «юнит упал». Тогда каждое УСПЕШНОЕ
        # вмешательство watchdog помечалось бы в systemd как сбой.
        _wd_check || true ;;
      on)
        [[ $EUID -ne 0 ]] && { echo -e "${RED}sudo xm watchdog on${NC}"; exit 1; }
        _wd_install && ok "watchdog включён (каждые 2 мин)" ;;
      off)
        [[ $EUID -ne 0 ]] && { echo -e "${RED}sudo xm watchdog off${NC}"; exit 1; }
        systemctl disable --now xray-watchdog.timer >/dev/null 2>&1 || true
        rm -f "$WATCHDOG_SVC" "$WATCHDOG_TIMER"; systemctl daemon-reload
        ok "watchdog выключен" ;;
      now)
        [[ $EUID -ne 0 ]] && { echo -e "${RED}sudo xm watchdog now${NC}"; exit 1; }
        echo -e "\n${BOLD}Разовая проверка пути:${NC}"
        if _wd_check; then ok "Путь исправен: dest резолвится, fallback и Xray слушают"; fi ;;
      *)
        echo -e "\n${BOLD}${CYAN}[ Watchdog сквозного пути ]${NC}\n"
        systemctl is-active --quiet xray-watchdog.timer \
          && ok "Таймер активен" || warn "Таймер выключен (sudo xm watchdog on)"
        systemctl list-timers xray-watchdog.timer --no-pager 2>/dev/null | sed -n '1,3p' | sed 's/^/  /'
        echo -e "\n  ${BOLD}Срабатывания за 7 дней:${NC}"
        journalctl -u xray-watchdog.service --since "7 days ago" --no-pager 2>/dev/null \
          | grep -c 'watchdog:' | sed 's/^/    записей: /'
        journalctl -u xray-watchdog.service --since "7 days ago" --no-pager 2>/dev/null \
          | grep 'watchdog:' | tail -10 | sed 's/^/    /'
        echo "" ;;
    esac
    ;;

# ─────────────────────────────────────────────────────────────────────────────
# front — вывести inbound на публичный порт, разделив его по SNI с соседом.
#
# Когда 443 занят другой службой навсегда, а нестандартный порт — единственное
# «критично» в diag-dpi (B8), выбор не между «переехать» и «остаться», а между
# «остаться» и «поделить». Делит ssl_preread: SNI виден в ClientHello открытым
# текстом, до всякого расшифрования, и этого достаточно, чтобы развести потоки.
front)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm front${NC}"; exit 1; }
    FSUB="${2:-status}"
    FPORT=$(_front_port)
    OUR_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
    OUR_PORT=$(jq -r '.inbounds[0].port' "$CONFIG")

    case "$FSUB" in
      on)
        echo -e "\n${BOLD}${CYAN}[ Фронт на порту $FPORT ]${NC}\n"
        _front_state_init

        # 1. Модуль. Без ssl_preread разделить поток нечем — как и fallback.
        if ! nginx -V 2>&1 | grep -q -- "--with-stream_ssl_preread_module" \
           && ! grep -rqs "ssl_preread" /usr/lib/nginx/modules/; then
          fail "nginx собран без ssl_preread — фронт невозможен"
          info "Проверь: sudo grep -rl ssl_preread /usr/lib/nginx/modules/"
          exit 1
        fi

        # 2. stream-контекст. После setup.sh он есть; после чужой правки
        #    nginx.conf мог исчезнуть — возвращаем идемпотентно.
        if ! grep -q "stream-enabled/\*.conf" /etc/nginx/nginx.conf; then
          printf '\nstream {\n    include /etc/nginx/stream-enabled/*.conf;\n}\n' >> /etc/nginx/nginx.conf
          ok "В nginx.conf возвращён stream-контекст"
        fi

        # 3. Коллизия масок. Один и тот же SNI у нас и у соседа развести
        #    нечем: nginx видит одну строку в ClientHello и обязан выбрать
        #    одну ветку map — то есть один из двух каналов умрёт молча.
        while read -r rsni rup; do
          [[ "$rsni" == "$OUR_SNI" ]] && {
            fail "Маска соседа совпадает с нашей ($OUR_SNI) — по SNI их не различить"
            info "Смени одну из двух: sudo xm sni-scan, затем sudo xm set-sni <домен>"
            exit 1; }
        done < <(_front_routes)

        # 4. Порт. Занят кем-то, кроме nginx → фронт не поднимется.
        FBUSY=$(ss -tlnp 2>/dev/null | tail -n +2 | awk -v p=":$FPORT" '$4 ~ p"$" {print $NF}' | head -1)
        if [[ -n "$FBUSY" && "$FBUSY" != *nginx* ]]; then
          fail "TCP-порт $FPORT занят: $FBUSY"
          info "Освободи его: служба должна переехать на 127.0.0.1:<порт> и попасть"
          info "в маршруты фронта (sudo xm front add <её SNI> <её новый порт>),"
          info "иначе её клиенты потеряют сервер."
          exit 1
        fi

        # 5. Апстримы соседей. Не поднялись — не отказ: маршрут может быть
        #    заведён заранее, до переезда службы.
        while read -r rsni rup; do
          ss -tln 2>/dev/null | tail -n +2 | awk -v p=":$rup" '$4 ~ p"$"' | grep -q . \
            && ok "Маршрут $rsni → 127.0.0.1:$rup (слушает)" \
            || warn "Маршрут $rsni → 127.0.0.1:$rup — на порту никто не слушает"
        done < <(_front_routes)

        case "$(_front_worker_conn; echo $?)" in
          0) ok "nginx worker_connections → 4096 (фронт удваивает расход на соединение)" ;;
          2) ok "nginx worker_connections уже достаточен" ;;
          *) warn "worker_connections в nginx.conf не найден — проверь events{} вручную" ;;
        esac
        _ngx_rlimit_nofile; case $? in
          0) ok "nginx worker_rlimit_nofile → 16384 (без него воркер упирается в 1024 дескриптора)" ;;
          2) ok "nginx worker_rlimit_nofile уже достаточен" ;;
          *) warn "worker_rlimit_nofile выставить не удалось — при потолке 1024 nginx молча не примет часть соединений" ;;
        esac

        _front_apply || exit 1
        ok "Фронт поднят: $OUR_SNI и чужой SNI → 127.0.0.1:$OUR_PORT, соседи — по маршрутам"

        # Установка открывала в ufw порт inbound, а фронт слушает публичный —
        # это разные номера. Без правила сокет поднимется, `xm front status`
        # покажет «порт держит nginx», и все зонды diag-dpi пройдут (они идут
        # через loopback, мимо файрвола), а снаружи не подключится никто.
        _ufw_open "$FPORT" "Xray front (SNI)"; case $? in
          0) ok "UFW: открыт ${FPORT}/tcp — без этого правила фронт слушает, но снаружи закрыт" ;;
          1) ok "UFW: ${FPORT}/tcp уже открыт" ;;
          2) info "UFW не активен — правило не требуется" ;;
          *) fail "UFW не принял правило для ${FPORT}/tcp — открой вручную: sudo ufw allow ${FPORT}/tcp" ;;
        esac
        _front_fallback_limit 5000 \
          && ok "Лимит fallback снят с 200: за фронтом он общий на всех, а не по IP" \
          || info "Лимит fallback уже поднят"
        nginx -t &>/dev/null && systemctl reload nginx

        sep
        warn "URI клиентов содержат порт — старые ведут мимо фронта, на $OUR_PORT."
        echo -e "  Раздай новые:   ${BOLD}sudo xm qr --all${NC}"
        echo -e "  Убедись:        ${BOLD}sudo xm selftest${NC} и ${BOLD}sudo xm diag-dpi${NC} (тест B8)"
        echo -e "  И только потом: ${BOLD}sudo ufw delete allow ${OUR_PORT}/tcp${NC}"
        echo -e "                  ${CYAN}— пока порт открыт наружу, сертификат маски${NC}"
        echo -e "                  ${CYAN}  на нём виден сканеру, и B8 остаётся красным${NC}"
        echo ""
        ;;

      off)
        echo -e "\n${BOLD}${CYAN}[ Выключение фронта ]${NC}\n"
        _front_enabled || { info "Фронт и так выключен"; exit 0; }
        rm -f "$FRONT_NGX"
        if nginx -t 2>/dev/null && systemctl reload nginx; then
          ok "Фронт снят, порт $FPORT свободен"
        else
          fail "nginx -t не прошёл после снятия — разбирайся: sudo nginx -t"; exit 1
        fi
        _front_fallback_limit 200 && ok "Лимит fallback вернулся к 200 по IP" || true
        nginx -t &>/dev/null && systemctl reload nginx
        info "Маршруты сохранены в $FRONT_STATE — вернуть всё: sudo xm front on"
        warn "Клиентам снова нужен URI с портом $OUR_PORT: sudo xm qr --all"
        # `front on` подсказывал закрыть порт inbound снаружи. Если совет был
        # выполнен, после снятия фронта клиентам некуда идти вообще.
        _ufw_open "$OUR_PORT" "Xray XHTTP"; case $? in
          0) ok "UFW: вернул ${OUR_PORT}/tcp — клиенты снова ходят на него напрямую" ;;
          1) ok "UFW: ${OUR_PORT}/tcp уже открыт" ;;
          3) fail "UFW не принял правило — открой вручную: sudo ufw allow ${OUR_PORT}/tcp" ;;
        esac
        _ufw_active && _ufw_allowed "$FPORT" \
          && info "Правило ${FPORT}/tcp оставлено: за этот порт может вернуться соседняя служба. Убрать: sudo ufw delete allow ${FPORT}/tcp"
        while read -r rsni rup; do
          [[ -n "$rsni" ]] && warn "Служба $rsni осталась на 127.0.0.1:$rup — верни ей публичный порт сама"
        done < <(_front_routes)
        echo ""
        ;;

      add)
        ASNI="${3:-}"; APORT="${4:-}"
        [[ -z "$ASNI" || -z "$APORT" ]] && { echo -e "${BOLD}Использование:${NC} xm front add <sni> <локальный порт>"; exit 1; }
        [[ "$ASNI" =~ ^[a-zA-Z0-9._-]+$ ]] || { fail "Недопустимые символы в SNI"; exit 1; }
        [[ "$APORT" =~ ^[0-9]+$ ]] && [[ "$APORT" -ge 1 && "$APORT" -le 65535 ]] || { fail "Порт должен быть числом 1-65535"; exit 1; }
        [[ "$ASNI" == "$OUR_SNI" ]] && { fail "Это наша собственная маска — она уже ведёт на 127.0.0.1:$OUR_PORT"; exit 1; }
        _front_set_route "$ASNI" "$APORT"
        ok "Маршрут записан: $ASNI → 127.0.0.1:$APORT"
        if _front_enabled; then _front_apply && ok "Фронт пересобран"; else info "Фронт выключен — применится при: sudo xm front on"; fi
        ;;

      del)
        DSNI="${3:-}"
        [[ -z "$DSNI" ]] && { echo -e "${BOLD}Использование:${NC} xm front del <sni>"; exit 1; }
        _front_del_route "$DSNI" || { fail "Маршрута $DSNI нет"; exit 1; }
        ok "Маршрут $DSNI удалён"
        if _front_enabled; then _front_apply && ok "Фронт пересобран"; else info "Фронт выключен"; fi
        ;;

      *)
        echo -e "\n${BOLD}${CYAN}[ Фронт по SNI ]${NC}\n"
        if _front_enabled; then
          ok "Включён, порт $FPORT"
        else
          info "Выключен. Включить: sudo xm front on"
          [[ -f "$FRONT_STATE" ]] && info "Сохранённые маршруты есть — вернутся при включении"
        fi
        FHOLD=$(ss -tlnp 2>/dev/null | tail -n +2 | awk -v p=":$FPORT" '$4 ~ p"$" {print $NF}' | head -1)
        if [[ -z "$FHOLD" ]]; then
          _front_enabled && fail "На $FPORT никто не слушает — фронт не поднялся, проверь: sudo nginx -t"
        elif [[ "$FHOLD" == *nginx* ]]; then
          ok "Порт $FPORT держит nginx"
        else
          _front_enabled \
            && fail "Порт $FPORT перехвачен: $FHOLD — наш конфиг есть, а сокета нет" \
            || info "Порт $FPORT держит: $FHOLD"
        fi
        sep
        echo -e "${BOLD}Маршруты${NC}"
        printf "  %-34s %-18s %s\n" "SNI" "куда" "апстрим"
        printf "  %-34s %-18s %s\n" "$OUR_SNI" "127.0.0.1:$OUR_PORT" "наш XHTTP inbound"
        printf "  %-34s %-18s %s\n" "(чужой и пустой)" "127.0.0.1:$OUR_PORT" "mimic через наш fallback"
        while read -r rsni rup; do
          [[ -z "$rsni" ]] && continue
          ss -tln 2>/dev/null | tail -n +2 | awk -v p=":$rup" '$4 ~ p"$"' | grep -q . \
            && printf "  %-34s %-18s %s\n" "$rsni" "127.0.0.1:$rup" "слушает" \
            || printf "  %-34s %-18s %s\n" "$rsni" "127.0.0.1:$rup" "НЕ СЛУШАЕТ"
        done < <(_front_routes)
        if _has_tcp_inbound; then
          TCPP=$(jq -r '.inbounds[1].port' "$CONFIG")
          sep
          info "TCP/Vision inbound на $TCPP мимо фронта: у него та же маска, что у XHTTP,"
          info "а по одному SNI два потока не развести. Это запасной канал для диагностики."
          if _ufw_active && ! _ufw_allowed "$TCPP"; then
            info "Порт $TCPP закрыт в UFW — снаружи канала нет. Для маскировки это"
            info "правильно, но URI из xm qr --tcp у клиента не заработает."
          fi
        fi
        sep
        RLIM=$(grep -oE 'limit_conn[[:space:]]+reality_conn[[:space:]]+[0-9]+' /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null | grep -oE '[0-9]+$')
        [[ -n "$RLIM" ]] && info "Лимит fallback: $RLIM $(_front_enabled && echo '(общий: за фронтом ключ у всех 127.0.0.1)' || echo '(по IP клиента)')"
        [[ -f "$FRONT_LOG" ]] && info "Зонды на фронте: $(wc -l < "$FRONT_LOG") записей — sudo xm nginx-probes"
        echo ""
        ;;
    esac
    ;;

harden)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm harden${NC}"; exit 1; }
    MODE="${2:-apply}"
    echo -e "\n${BOLD}${CYAN}[ Хардening: DNS-over-HTTPS + перехват :53 + mimic-fallback ]${NC}\n"

    sep
    echo -e "${BOLD}Текущее состояние${NC}"
    _dns_doh_on    && ok "DoH на сервере: включён"          || warn "DoH на сервере: ВЫКЛЮЧЕН (резолвит системный резолвер хостера открытым текстом)"
    _dns_hijack_on && ok "Перехват :53 из тоннеля: включён" || warn "Перехват :53: ВЫКЛЮЧЕН (plain-DNS клиента уходит с VPS как есть)"
    _ngx_mimic_on  && ok "nginx-fallback: mimic (чужой SNI → ответ настоящего сайта)" \
                   || warn "nginx-fallback: strict (чужой SNI → молчаливый обрыв TCP — подпись прокси)"
    if _resolved_dot_on; then
      # Одного «DNSOverTLS=yes» мало: под строгим DoT число апстримов и есть
      # разница между «один провайдер лёг» и «резолвинга нет вообще».
      RDNS_S=$(_resolved_dns_line); RN_S=$(printf '%s' "$RDNS_S" | wc -w)
      [[ "${RN_S:-0}" -ge 3 ]] \
        && ok "Системный резолвер: строгий DoT, апстримов ${RN_S}" \
        || warn "Системный резолвер: строгий DoT, но апстримов ${RN_S:-0} — при недоступности одного резолвинг отказывает целиком, а это мёртвый dest. Профиль на четыре: ${BOLD}sudo xm harden --dot${NC}"
    else
      warn "Системный резолвер: открытый UDP/53 (всё, что попадёт в стаб, видит хостер)"
    fi
    # Только при живом перехвате :53: без dns-outbound это поле негде задавать,
    # и строка про него сбивала бы с толку.
    NONIP_CUR=""
    if _dns_hijack_on; then
      NONIP_CUR=$(_nonip_current)
      case "${NONIP_CUR:-}" in
        drop) ok "Запросы не-A/AAAA: drop — наружу не уходят. Ценой того, что Android не получает ответа на свои HTTPS/SVCB и ждёт таймаута" ;;
        "")   info "Запросы не-A/AAAA: поле не задано — поведение по умолчанию этой сборки Xray" ;;
        *)    warn "Запросы не-A/AAAA: ${NONIP_CUR} — не drop, часть запросов покидает VPS открытым UDP" ;;
      esac
    fi

    if [[ "$MODE" == "--check" ]]; then
      sep; info "Режим --check: ничего не изменено. Применить: ${BOLD}sudo xm harden${NC}"; exit 0
    fi

    # Наш профиль DoT поверх уже настроенного резолвера. Отдельной командой,
    # потому что шаг 2 в harden чужую конфигурацию намеренно не переписывает:
    # решение «заменить то, что настроил владелец» принимает владелец.
    if [[ "$MODE" == "--dot" ]]; then
      sep
      echo -e "${BOLD}Профиль DoT для системного резолвера${NC}"
      command -v resolvectl &>/dev/null || { fail "systemd-resolved не найден — применять некуда"; exit 1; }
      info "Было: $(_resolved_dns_line)"
      if ! _resolved_write_dot; then
        fail "DoT с нашими апстримами не поднялся — откат, прежняя конфигурация на месте"
        warn "Проверь вручную: sudo resolvectl query example.com, затем sudo resolvectl status"
        exit 1
      fi
      ok "Применено: четыре апстрима по :853 (Cloudflare ×2, Quad9, Google), FallbackDNS пуст"
      DOT_NEW=$(_resolved_dns_line)
      info "Стало: $DOT_NEW"
      # Drop-in'ы применяются в лексическом порядке имён, последнее присваивание
      # побеждает. Если у владельца есть файл, сортирующийся после нашего, наш
      # DNS= будет перекрыт — и это надо увидеть, а не считать, что применилось.
      [[ "$DOT_NEW" == "$(printf '%s' "$RESOLVED_DOT_CONF" | sed -n 's/^DNS=//p')" ]] \
        || warn "Эффективный список отличается от нашего — значит есть drop-in, который сортируется после ${RESOLVED_DROPIN##*/} и перекрывает DNS=. Смотри: sudo systemd-analyze cat-config systemd/resolved.conf"
      info "Файл: $RESOLVED_DROPIN — убирается вместе с sudo xm harden --off"
      exit 0
    fi

    # Точечная ручка вместо `--off`: поменять режим не-A/AAAA, не трогая DoH,
    # перехват :53, DoT и mimic. Нужна, чтобы проверять гипотезу «мигает из-за
    # HTTPS/SVCB» не ценой возврата всех утечек сразу.
    if [[ "$MODE" == "--nonip" ]]; then
      NONIP_NEW="${3:-}"
      sep
      echo -e "${BOLD}Режим запросов не-A/AAAA (HTTPS/SVCB, TXT)${NC}"
      # Без dns-outbound поле негде задавать, а проба показала бы «принимается»
      # для чего угодно: патч просто не нашёл бы, что патчить.
      _dns_hijack_on || { fail "Перехвата :53 нет — сначала ${BOLD}sudo xm harden${NC}"; exit 1; }
      if [[ -z "$NONIP_NEW" ]]; then
        echo -e "  Сейчас: ${BOLD}${NONIP_CUR:-<не задано>}${NC}"
        echo    "  Проверено на копии конфига этой сборкой Xray:"
        for v in drop skip reject; do
          _nonip_try "$v" && ok "  $v — принимается" || info "  $v — сборка отвергает"
        done
        echo ""
        echo -e "  ${BOLD}sudo xm harden --nonip drop${NC}   отбрасывать (приватно; Android ждёт таймаута)"
        echo -e "  ${BOLD}sudo xm harden --nonip skip${NC}   пропускать на исходный адрес — ${YELLOW}уходит открытым UDP${NC}"
        echo -e "  ${BOLD}sudo xm harden --nonip off${NC}    убрать поле, оставить поведение сборки по умолчанию"
        echo ""
        info "Это диагностическая ручка. Остальные шаги harden (DoH, перехват :53, DoT, mimic) она не трогает"
        warn "«Принимается» — про схему конфига, а не про поведение: Xray молча"
        warn "игнорирует часть неизвестных значений. Что реально изменилось, видно"
        warn "по симптому, а не по коду возврата."
        exit 0
      fi
      [[ "$NONIP_NEW" == "off" ]] && NONIP_NEW=""
      # Список значений не хардкодим: он менялся между сборками. Проверяет сам
      # Xray на копии конфига — здесь только отсекаем заведомый мусор.
      [[ -z "$NONIP_NEW" || "$NONIP_NEW" =~ ^[a-zA-Z]+$ ]] \
        || { fail "Значение — одно слово латиницей, либо off"; exit 1; }
      [[ "$NONIP_CUR" == "$NONIP_NEW" ]] && { ok "Уже ${NONIP_NEW:-<не задано>} — ничего не меняю"; exit 0; }

      NBAK=$(_backup_config before_nonip); ok "Бэкап: $NBAK"
      if ! _nonip_patch "$NONIP_NEW" | _atomic_write_config; then
        fail "jq-патч не сработал — конфиг не тронут"; exit 1
      fi
      if ! xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
        fail "Сборка Xray не приняла значение «${NONIP_NEW}» — откат"
        cp "$NBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"; exit 1
      fi
      systemctl restart xray; sleep 2
      if ! systemctl is-active --quiet xray; then
        fail "Xray не поднялся — откат"
        cp "$NBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
        systemctl restart xray; exit 1
      fi
      ok "nonIPQuery: ${NONIP_CUR:-<не задано>} → ${NONIP_NEW:-<не задано>}, Xray перезапущен"
      [[ "$NONIP_NEW" == "skip" ]] && \
        warn "skip — режим на время проверки: запросы не-A/AAAA теперь покидают VPS открытым UDP. Вернуть: sudo xm harden --nonip drop"
      exit 0
    fi

    if [[ "$MODE" == "--off" ]]; then
      sep
      echo -e "${BOLD}Откат${NC}"
      ok "Бэкап: $(_backup_config before_unharden)"
      if _harden_unpatch | _atomic_write_config && xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
        systemctl restart xray; ok "dns-блок, dns-out и перехват :53 убраны, Xray перезапущен"
      else
        fail "Откат конфига не удался — восстанови вручную: xm restore"; exit 1
      fi
      _ngx_fallback_mode strict && ok "nginx-fallback вернулся в strict"
      if [[ -f "$RESOLVED_DROPIN" ]]; then
        rm -f "$RESOLVED_DROPIN"; systemctl restart systemd-resolved 2>/dev/null
        ok "systemd-resolved: наш DoT-drop-in убран"
      fi
      if _ngx_resolver_public && nginx -t &>/dev/null && systemctl reload nginx; then
        ok "nginx-fallback: resolver вернулся на 1.1.1.1 8.8.8.8"
      fi
      warn "DNS снова резолвится открытым текстом — и системный, и nginx"
      exit 0
    fi

    # ── 1. Доступен ли DoH С ЭТОГО VPS ──────────────────────────────────────
    # Проверяем ДО правки конфига: если ни один резолвер не отвечает (хостер
    # режет :443 к ним, или VPS сам в РФ), включённый DoH убьёт весь резолвинг.
    sep
    echo -e "${BOLD}Шаг 1: доступность DoH-резолверов с этого VPS${NC}"
    DOH_OK=0
    for r in "${DOH_IPS[@]}"; do
      if RTT=$(_doh_probe "$r"); then
        ok "$r — отвечает (${RTT} мс)"; DOH_OK=$((DOH_OK + 1))
      else
        warn "$r — не отвечает по DoH (:443 закрыт/режется)"
      fi
    done
    if [[ "$DOH_OK" -eq 0 ]]; then
      fail "Ни один DoH-резолвер недоступен с этого VPS — включать DoH НЕЛЬЗЯ (сломается весь резолвинг)"
      warn "Проверь вручную: curl -v --max-time 6 https://1.1.1.1/dns-query"
      exit 1
    fi
    info "Доступно резолверов: $DOH_OK из ${#DOH_IPS[@]} — этого достаточно"

    # ── 2. Системный резолвер и его потребители ─────────────────────────────
    # Почему это в harden, который «про путь VPN»: замерено, что в системный
    # резолвер попадают в том числе имена, пришедшие из тоннеля (см. E5).
    # Пока стаб ходит открытым UDP, каждое такое попадание — имя на проводе,
    # и никакой dns-блок внутри Xray этого не отменяет.
    sep
    echo -e "${BOLD}Шаг 2: системный резолвер и его потребители${NC}"
    if ! command -v resolvectl &>/dev/null; then
      warn "systemd-resolved не найден — шаг пропущен, системный резолвинг остаётся открытым"
    elif [[ -f "$RESOLVED_DROPIN" ]] && [[ "$(cat "$RESOLVED_DROPIN")" == "$RESOLVED_DOT_CONF" ]] && _resolved_dot_on; then
      ok "systemd-resolved: наш профиль DoT актуален — не трогаю"
    elif [[ ! -f "$RESOLVED_DROPIN" ]] && _resolved_dot_on; then
      # DoT настроен не нами. Переписывать чужое молча нельзя, но и ставить
      # зелёную галочку на конфигурации, в которую не заглянули, тоже: под
      # строгим DoT число апстримов и есть разница между «один провайдер лёг»
      # и «резолвинга нет», а второе на этом сервере равно демаскировке.
      RDNS=$(_resolved_dns_line); RN=$(printf '%s' "$RDNS" | wc -w)
      ok "systemd-resolved: строгий DoT, настроен не нами — свой профиль не навязываю"
      info "Апстримы сейчас (${RN:-0}): ${RDNS:-не заданы явно, берутся с линка}"
      if [[ "${RN:-0}" -lt 3 ]]; then
        warn "Апстримов меньше трёх. Недоступность одного провайдера по :853 — это не"
        warn "замедление, а отказ резолвинга: dest перестаёт резолвиться, fallback теряет"
        warn "апстрим, и сервер начинает принимать TCP и рвать — подпись прокси."
        warn "Наш профиль (четыре апстрима, три провайдера): ${BOLD}sudo xm harden --dot${NC}"
      fi
    elif _resolved_write_dot; then
      ok "systemd-resolved: DNSOverTLS=yes, четыре апстрима по :853 (Cloudflare ×2, Quad9, Google)"
    else
      fail "DoT не поднялся (хостер режет :853?) — шаг откачен"
      warn "Системный резолвинг остаётся открытым; остальные шаги harden продолжаю"
    fi

    # Правим resolver в nginx только когда стабу есть чем ответить: иначе
    # fallback перестанет находить апстрим, и зонд получит обрыв вместо сайта.
    if [[ -f /etc/nginx/stream-enabled/reality-fallback.conf ]]; then
      if ! resolvectl query example.com &>/dev/null; then
        warn "Системный резолвер не отвечает — resolver в nginx не трогаю"
      elif ! _ngx_resolver_local; then
        ok "nginx-fallback: resolver уже локальный — не трогаю"
      elif nginx -t &>/dev/null && systemctl reload nginx; then
        ok "nginx-fallback: resolver → 127.0.0.53 valid=900s, открытых запросов к 1.1.1.1/8.8.8.8 больше нет"
      else
        fail "nginx -t не прошёл после правки resolver — откат"
        _ngx_resolver_public; nginx -t &>/dev/null && systemctl reload nginx
      fi
    fi

    # ── 3. Стратегия адресов под фактический стек VPS ───────────────────────
    # Если у VPS нет IPv6, AAAA-ответы бесполезны: клиент получит адрес,
    # до которого сервер не дойдёт → «сайт не открывается через VPN».
    if _has_ipv6; then
      QS="UseIP"; DS="UseIPv4v6"; info "IPv6 на VPS есть → queryStrategy=UseIP"
    else
      QS="UseIPv4"; DS="UseIPv4"; info "IPv6 на VPS нет → queryStrategy=UseIPv4 (без бесполезных AAAA)"
    fi

    # ── 4. Патч конфига с проверкой и откатом ───────────────────────────────
    sep
    echo -e "${BOLD}Шаг 3: конфиг Xray${NC}"
    HBAK=$(_backup_config before_harden); ok "Бэкап: $HBAK"

    _harden_restore() {
      cp "$HBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
      systemctl restart xray 2>/dev/null || true
    }

    # nonIPQuery=drop: запросы не-A/AAAA (HTTPS/SVCB, TXT) отбрасываются, а не
    # пересылаются наружу открытым текстом. Приватность важнее ECH-подсказок.
    # Поле старое (legacy), но на редких сборках может не приняться — тогда
    # второй заход без него.
    if ! _harden_patch "$QS" "$DS" "drop" | _atomic_write_config; then
      fail "jq-патч не сработал — конфиг не тронут"; exit 1
    fi
    if ! xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
      warn "Xray не принял nonIPQuery — повторяю без него"
      cp "$HBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
      _harden_patch "$QS" "$DS" "" | _atomic_write_config
      if ! xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
        fail "Конфиг невалиден — откат"; xray -test -config "$CONFIG" 2>&1 | tail -5 | sed 's/^/    /'
        _harden_restore; exit 1
      fi
    fi
    ok "config.json: dns(DoH) + outbound dns-out + routing :53 → dns-out"

    systemctl restart xray; sleep 2
    if ! systemctl is-active --quiet xray; then
      fail "Xray не поднялся с новым конфигом — откат"
      journalctl -u xray -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
      _harden_restore; exit 1
    fi
    ok "Xray перезапущен"

    # ── 5. Живая проверка: не сломали ли резолвинг ──────────────────────────
    sep
    echo -e "${BOLD}Шаг 4: живая проверка через свой же тоннель${NC}"
    if _tunnel_up xhttp; then
      CODE=$(_tunnel_code "https://api.ipify.org")
      _tunnel_down
      if [[ "$CODE" == "200" ]]; then
        ok "Трафик и резолвинг через тоннель работают (HTTP $CODE)"
      else
        fail "Через тоннель трафик не идёт (код $CODE) — откат конфига"
        _harden_restore
        warn "Конфиг возвращён. Разберись: sudo xm selftest, затем повтори xm harden"
        exit 1
      fi
    else
      _tunnel_down
      warn "Локальный клиент не поднялся — живую проверку пропускаю (проверь: sudo xm selftest)"
    fi

    # ── 6. nginx mimic ──────────────────────────────────────────────────────
    sep
    echo -e "${BOLD}Шаг 5: поведение fallback на чужой SNI${NC}"
    if _ngx_mimic_on; then
      ok "Уже в режиме mimic — ничего не меняю"
    elif _ngx_fallback_mode mimic; then
      ok "nginx-fallback: чужой/пустой SNI теперь уходит на реальный $(_get_nginx_sni) вместо обрыва"
      info "Релей идёт только на этот один домен — открытым SNI-релеем сервер не становится"
    else
      warn "Режим fallback не изменён (см. выше) — активное зондирование остаётся заметным"
    fi

    # ── 6. :80 — заголовки и цель редиректа (шаг 6 в выводе) ─────────────────────────────────
    sep
    echo -e "${BOLD}Шаг 6: порт 80${NC}"
    _ngx_headers_more; case $? in
      0) ok "Модуль headers-more поставлен, nginx перезапущен — теперь Server можно замаскировать" ;;
      2) : ;;
      *) warn "headers-more поставить не удалось — Server на :80 останется «nginx» (тест B7)"
         warn "Вручную: sudo apt install -y libnginx-mod-http-headers-more-filter && sudo systemctl restart nginx" ;;
    esac
    _ngx_http80_fix; H80_RC=$?
    case "$H80_RC" in
      0) ok ":80 приведён к виду домена-маски: редирект на имя, Server как у сайта, лог выключен" ;;
      2) ok ":80 уже в нужном виде — ничего не меняю" ;;
      *) warn ":80 остался как есть — см. сообщения выше (xm diag-dpi, тест B7)" ;;
    esac

    sep
    echo -e "${GREEN}${BOLD}  Готово.${NC}"
    echo -e "  Проверить эффект: ${BOLD}sudo xm diag-dpi${NC}"
    echo -e "  Откатить всё:     ${BOLD}sudo xm harden --off${NC}"
    echo -e "  ${YELLOW}Если приложение (мессенджер, Android) начнёт капризничать с DNS —${NC}"
    echo -e "  ${YELLOW}проверь nonIPQuery точечно: ${BOLD}sudo xm harden --nonip${NC}${YELLOW}. Полный откат${NC}"
    echo -e "  ${YELLOW}(--off) для этого не нужен: он заодно снимает DoH, DoT и mimic.${NC}"
    ;;

pq)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm pq ${2:-status}${NC}"; exit 1; }
    PQ_ACT="${2:-status}"
    PQ_SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    echo -e "\n${BOLD}${CYAN}[ ML-DSA-65 · post-quantum подпись REALITY ]${NC}\n"

    case "$PQ_ACT" in
      status)
        _pq_on && ok "Сейчас: ВКЛЮЧЕНО" || info "Сейчас: выключено"
        PQ_EST=$(_check_cert_size "$PQ_SNI")
        if [[ "$PQ_EST" == "-1" ]]; then
          warn "Размер сертификата $PQ_SNI не измерить — сайт недоступен с VPS"
        else
          info "Certificate у $PQ_SNI: ~${PQ_EST} б"
          if [[ "$PQ_EST" -lt 3500 ]]; then
            warn "Меньше 3500 б: с ML-DSA наш ответ станет заметно длиннее ответа настоящего сайта."
            warn "Это меняет одну зацепку для DPI на другую. Взвесь: MITM-стойкость против маскировки."
          elif [[ $((PQ_EST + 3400)) -ge "$REALITY_CERT_LIMIT" ]]; then
            warn "~${PQ_EST} + 3.3 КБ подписи ≥ лимита REALITY (${REALITY_CERT_LIMIT} б) — хендшейк может рваться."
          else
            ok "Размер подходит: и маскировка не страдает, и в лимит REALITY укладываемся"
          fi
        fi
        echo -e "\n  Включить:  ${BOLD}sudo xm pq on${NC}    Выключить: ${BOLD}sudo xm pq off${NC}"
        ;;

      on)
        if _pq_on; then ok "Уже включено. Ключи для клиентов: grep MLDSA65 $CLIENT_FILE"; exit 0; fi
        if ! xray help 2>&1 | grep -qi "mldsa65" && ! xray mldsa65 >/dev/null 2>&1; then
          fail "Эта сборка Xray не знает команды mldsa65 — обнови ядро: sudo xm update"; exit 1
        fi
        PQ_EST=$(_check_cert_size "$PQ_SNI")
        if [[ "$PQ_EST" != "-1" && $((PQ_EST + 3400)) -ge "$REALITY_CERT_LIMIT" ]]; then
          fail "Certificate $PQ_SNI ~${PQ_EST} б + 3.3 КБ подписи не влезает в лимит REALITY (${REALITY_CERT_LIMIT} б) — хендшейк сломается. Смени домен-маску: sudo xm sni-scan"
          exit 1
        fi
        if [[ "$PQ_EST" != "-1" && "$PQ_EST" -lt 3500 ]]; then
          warn "У $PQ_SNI сертификат ~${PQ_EST} б (<3500) — наш ответ станет длиннее настоящего сайта."
          read -rp "Всё равно включить? [y/N]: " C; [[ "$C" =~ ^[Yy]$ ]] || { info "Отменено."; exit 0; }
        fi

        PQBAK=$(_backup_config before_pq); ok "Бэкап: $PQBAK"

        _parse_mldsa "$(xray mldsa65 2>/dev/null)"
        if [[ ${#MLDSA_SEED} -lt 30 || ${#MLDSA_VERIFY} -lt 30 ]]; then
          fail "Не удалось распарсить вывод xray mldsa65 — включение отменено"; exit 1
        fi
        SEED0="$MLDSA_SEED"; VERIFY0="$MLDSA_VERIFY"
        SEED1=""; VERIFY1=""
        if _has_tcp_inbound; then
          _parse_mldsa "$(xray mldsa65 2>/dev/null)"
          SEED1="$MLDSA_SEED"; VERIFY1="$MLDSA_VERIFY"
        fi

        if _has_tcp_inbound && [[ -n "$SEED1" ]]; then
          JQ_PQ='.inbounds[0].streamSettings.realitySettings.mldsa65Seed = $s0
               | .inbounds[1].streamSettings.realitySettings.mldsa65Seed = $s1'
        else
          JQ_PQ='.inbounds[0].streamSettings.realitySettings.mldsa65Seed = $s0'
        fi
        if ! jq --arg s0 "$SEED0" --arg s1 "$SEED1" "$JQ_PQ" "$CONFIG" | _atomic_write_config; then
          fail "Не удалось записать config.json — ничего не изменено"; exit 1
        fi

        if ! xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
          fail "Xray не принял mldsa65Seed — откат"
          xray -test -config "$CONFIG" 2>&1 | tail -5 | sed 's/^/    /'
          cp "$PQBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"; exit 1
        fi
        systemctl restart xray; sleep 2

        # Клиент в selftest БЕЗ mldsa65Verify. Если он прошёл — обратная
        # совместимость на месте и старые клиенты не отвалятся.
        if _tunnel_up xhttp; then
          PQCODE=$(_tunnel_code "https://api.ipify.org"); _tunnel_down
        else
          _tunnel_down; PQCODE="000"
        fi
        if [[ "$PQCODE" != "200" ]]; then
          fail "После включения трафик через тоннель не идёт (код $PQCODE) — откат"
          cp "$PQBAK" "$CONFIG"; chmod 640 "$CONFIG"; chown root:nogroup "$CONFIG"
          systemctl restart xray; exit 1
        fi
        ok "Включено. Клиент БЕЗ mldsa65Verify по-прежнему работает (HTTP 200) — старые конфиги не сломались"

        # Verify-ключи длинные (~2.6 КБ) — храним в client-info.txt.
        sed -i '/^MLDSA65 VERIFY/d' "$CLIENT_FILE" 2>/dev/null
        {
          echo "MLDSA65 VERIFY: ${VERIFY0}"
          [[ -n "$VERIFY1" ]] && echo "MLDSA65 VERIFY2: ${VERIFY1}"
        } >> "$CLIENT_FILE"
        chmod 600 "$CLIENT_FILE"
        sep
        echo -e "${BOLD}Клиентам (по желанию — без этого тоже работает):${NC}"
        echo -e "  В настройках REALITY добавь поле ${BOLD}mldsa65Verify${NC} (в некоторых"
        echo -e "  клиентах — «Post-quantum» / параметр ${BOLD}pqv${NC} в ссылке)."
        echo -e "  Ключи лежат тут:  ${BOLD}grep MLDSA65 $CLIENT_FILE${NC}"
        echo -e "  Откатить:         ${BOLD}sudo xm pq off${NC}"
        ;;

      off)
        if ! _pq_on; then info "Уже выключено."; exit 0; fi
        _backup_config before_pqoff >/dev/null
        if jq 'del(.inbounds[].streamSettings.realitySettings.mldsa65Seed)' "$CONFIG" | _atomic_write_config \
           && xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
          systemctl restart xray
          sed -i '/^MLDSA65 VERIFY/d' "$CLIENT_FILE" 2>/dev/null
          ok "ML-DSA-65 выключен, Xray перезапущен"
        else
          fail "Не удалось выключить — восстанови: sudo xm restore"; exit 1
        fi
        ;;

      *) echo -e "  Использование: ${BOLD}xm pq status|on|off${NC}" ;;
    esac
    ;;

# ─── Обновление самого xm из git-чекаута ─────────────────────────────────────
# Заменяет ручной цикл «nano xm.sh → сохранил → скопировал». Источник правды —
# репозиторий, локальные правки на сервере не переживают обновление (и это
# правильно: правки надо коммитить, а не держать в единственном экземпляре
# на VPS). Ничего кроме /usr/local/bin/xm команда не трогает.
self-update)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm self-update${NC}"; exit 1; }
    SU_CHECK=false; SU_FORCE=false; SU_FROM=""
    shift
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --check) SU_CHECK=true ;;
        --force) SU_FORCE=true ;;
        --from)  shift; SU_FROM="${1:-}" ;;
        *) echo -e "${RED}Неизвестный аргумент: $1${NC}"
           echo    "  xm self-update [--check] [--force] [--from <url|путь>]"; exit 1 ;;
      esac
      shift
    done

    echo -e "\n${BOLD}${CYAN}[ Обновление xm из репозитория ]${NC}\n"
    command -v git >/dev/null 2>&1 || { fail "git не установлен: sudo apt install -y git"; exit 1; }

    # ── Откуда тянем ────────────────────────────────────────────────────────
    if [[ -n "$SU_FROM" ]]; then
      if [[ "$SU_FROM" == *://* || "$SU_FROM" == git@* ]]; then
        REPO="/opt/xray"
        if [[ -d "$REPO/.git" ]]; then
          info "Меняю remote у $REPO на $SU_FROM"
          git -C "$REPO" remote set-url origin "$SU_FROM" || { fail "не удалось сменить remote"; exit 1; }
        elif [[ -e "$REPO" ]]; then
          fail "$REPO уже существует и это не git-репозиторий — убери его или укажи другой путь"; exit 1
        else
          info "Клонирую $SU_FROM → $REPO"
          git clone --quiet "$SU_FROM" "$REPO" || { fail "клонирование не удалось"; exit 1; }
        fi
      else
        REPO="${SU_FROM%/}"
        [[ -d "$REPO/.git" && -f "$REPO/xm.sh" ]] || { fail "$REPO — не git-чекаут этого репозитория"; exit 1; }
      fi
    else
      REPO=$(_xm_repo) || {
        fail "Git-чекаут репозитория не найден"
        echo "  Он ищется по записи в $XM_SRC_FILE, затем в /opt/xray, /root/xray, /home/*/xray."
        echo "  Укажи явно или склонируй:"
        echo -e "    ${BOLD}sudo xm self-update --from https://github.com/<user>/xray.git${NC}"
        echo -e "    ${BOLD}sudo xm self-update --from /путь/к/чекауту${NC}"
        exit 1; }
    fi
    ok "Источник: $REPO"

    # Ветка: текущая; при detached HEAD или отсутствии её на origin — main.
    BR=$(git -C "$REPO" symbolic-ref --quiet --short HEAD 2>/dev/null || echo "")
    [[ -z "$BR" ]] && BR="main"
    git -C "$REPO" fetch --quiet origin 2>/dev/null || { fail "git fetch не прошёл — проверь сеть и доступ к репозиторию"; exit 1; }
    git -C "$REPO" rev-parse --verify --quiet "origin/$BR" >/dev/null 2>&1 || BR="main"
    git -C "$REPO" rev-parse --verify --quiet "origin/$BR" >/dev/null 2>&1 \
      || { fail "На origin нет ни текущей ветки, ни main"; exit 1; }
    info "Ветка: $BR"

    LOCAL_SHA=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)
    REMOTE_SHA=$(git -C "$REPO" rev-parse --short "origin/$BR" 2>/dev/null)
    AHEAD=$(git -C "$REPO" rev-list --count "HEAD..origin/$BR" 2>/dev/null || echo 0)

    if [[ "$AHEAD" -gt 0 ]]; then
      info "Новых коммитов: $AHEAD ($LOCAL_SHA → $REMOTE_SHA)"
      git -C "$REPO" log --oneline --no-decorate "HEAD..origin/$BR" | head -10 | sed 's/^/      /'
    else
      ok "Чекаут уже на $REMOTE_SHA — новых коммитов нет"
    fi

    # Установленный xm мог разойтись с репозиторием, даже когда коммитов нет:
    # правили руками на сервере. Сравниваем по факту, а не по git.
    DIVERGED=false
    [[ -f "$XM_BIN" ]] && ! cmp -s "$REPO/xm.sh" "$XM_BIN" && DIVERGED=true
    $DIVERGED && warn "Установленный $XM_BIN отличается от xm.sh в репозитории (правили руками?)"

    if $SU_CHECK; then
      sep
      if [[ "$AHEAD" -gt 0 ]] || $DIVERGED; then
        info "Есть что обновить. Применить: ${BOLD}sudo xm self-update${NC}"
      else
        ok "Всё актуально, делать нечего"
      fi
      exit 0
    fi

    # ── Локальные правки в чекауте ──────────────────────────────────────────
    if [[ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]]; then
      warn "В чекауте есть незакоммиченные изменения:"
      git -C "$REPO" status --short | head -10 | sed 's/^/      /'
      if $SU_FORCE; then
        warn "--force: выбрасываю их (git reset --hard)"
      else
        fail "Обновление остановлено, чтобы не потерять правки."
        echo "  Сохранить их:   cd $REPO && git stash"
        echo "  Или выбросить:  sudo xm self-update --force"
        exit 1
      fi
    fi

    if [[ "$AHEAD" -gt 0 ]] || $SU_FORCE; then
      git -C "$REPO" checkout --quiet "$BR" 2>/dev/null || true
      if ! git -C "$REPO" reset --hard --quiet "origin/$BR" 2>/dev/null; then
        fail "Не удалось перевести чекаут на origin/$BR"; exit 1
      fi
      ok "Чекаут на origin/$BR ($(git -C "$REPO" rev-parse --short HEAD))"
    fi

    # ── Установка ───────────────────────────────────────────────────────────
    [[ -f "$REPO/xm.sh" ]] || { fail "В $REPO нет xm.sh"; exit 1; }
    if ! bash -n "$REPO/xm.sh" 2>/dev/null; then
      fail "Новый xm.sh не проходит проверку синтаксиса — НЕ устанавливаю"
      bash -n "$REPO/xm.sh" 2>&1 | head -5 | sed 's/^/      /'
      exit 1
    fi
    ok "Синтаксис нового xm.sh в порядке"

    OLD_V=$(grep -m1 -oE 'xm — Xray Manager Helper +v[0-9.]+' "$XM_BIN" 2>/dev/null | grep -oE 'v[0-9.]+' || echo "?")
    if [[ -f "$XM_BIN" ]]; then
      mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
      XM_BAK="$BACKUP_DIR/xm_$(date +%Y%m%d_%H%M%S).bak"
      cp "$XM_BIN" "$XM_BAK"; ok "Бэкап текущего xm: $XM_BAK"
    fi

    # ВАЖНО: устанавливаем через mv, а не cp/install поверх файла.
    # bash читает скрипт ПО МЕРЕ выполнения — а сейчас выполняется как раз
    # /usr/local/bin/xm. Перезапись на месте меняет содержимое под открытым
    # дескриптором, и остаток текущего запуска пойдёт по новому смещению в
    # новом тексте: в лучшем случае синтаксическая ошибка, в худшем — кусок
    # чужой команды. mv в пределах одной ФС — это rename: у работающего
    # процесса остаётся старый inode, он доигрывает себя целым.
    install -m 755 "$REPO/xm.sh" "${XM_BIN}.new" || { fail "Не записать ${XM_BIN}.new"; exit 1; }
    mv -f "${XM_BIN}.new" "$XM_BIN" || { fail "Не удалось заменить $XM_BIN"; rm -f "${XM_BIN}.new"; exit 1; }
    NEW_V=$(grep -m1 -oE 'xm — Xray Manager Helper +v[0-9.]+' "$XM_BIN" 2>/dev/null | grep -oE 'v[0-9.]+' || echo "?")
    ok "Установлен $XM_BIN  (${OLD_V} → ${NEW_V})"

    mkdir -p "$(dirname "$XM_SRC_FILE")"
    echo "$REPO" > "$XM_SRC_FILE"; chmod 644 "$XM_SRC_FILE"

    # ── Что ещё стоит обновить ──────────────────────────────────────────────
    sep
    echo -e "${BOLD}Что ещё стоит проверить${NC}"

    CUR_X=$(xray version 2>/dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || echo "")
    LAT_X=$(_xray_latest_ver | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || echo "")
    if [[ -n "$CUR_X" && -n "$LAT_X" && "$CUR_X" != "$LAT_X" ]]; then
      warn "Xray-core $CUR_X → доступен $LAT_X          ${BOLD}sudo xm update${NC}"
    elif [[ -n "$CUR_X" ]]; then
      ok "Xray-core $CUR_X — актуальная версия"
    else
      info "Версию Xray-core не определить          sudo xm update --check"
    fi

    GEO="/usr/local/share/xray/geoip.dat"
    if [[ -f "$GEO" ]]; then
      GEO_AGE=$(( ( $(date +%s) - $(stat -c %Y "$GEO") ) / 86400 ))
      [[ "$GEO_AGE" -gt 30 ]] \
        && warn "geoip.dat не обновлялся $GEO_AGE дн.          ${BOLD}sudo xm update-geo${NC}" \
        || ok "geo-базы свежие ($GEO_AGE дн.)"
    fi

    if _dns_doh_on && _dns_hijack_on && _ngx_mimic_on; then
      ok "Анти-DPI хардening применён полностью"
    else
      warn "Хардening применён не весь                ${BOLD}sudo xm harden${NC}"
      _dns_doh_on    || echo "        · DoH на сервере выключен — домены резолвит хостер открытым текстом"
      _dns_hijack_on || echo "        · перехват :53 выключен"
      _ngx_mimic_on  || echo "        · nginx-fallback рвёт соединение на чужой SNI"
    fi

    sep
    echo -e "  Дальше:  ${BOLD}sudo xm diag-dpi${NC}   проверить устойчивость к DPI"
    echo -e "           ${BOLD}sudo xm neighbors${NC}  что ещё живёт на этом сервере"
    echo ""
    ;;

# ─── Кто ещё живёт на этом сервере ───────────────────────────────────────────
# Нужно, когда VPN стоит не на выделенной машине, а рядом с чем-то своим.
# Показывает чужие сервисы и — главное — что именно трогает каждая команда xm,
# чтобы не выяснять это методом «запустил и посмотрел, что отвалилось».
neighbors)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm neighbors${NC}"; exit 1; }
    echo -e "\n${BOLD}${CYAN}[ Соседи по серверу ]${NC}\n"

    sep
    echo -e "${BOLD}nginx · HTTP-сайты (sites-enabled)${NC}"
    OUR_DEFSRV=0; FOREIGN_DEFSRV=""
    if [[ -d /etc/nginx/sites-enabled ]]; then
      shopt -s nullglob
      for f in /etc/nginx/sites-enabled/*; do
        n=$(basename "$f")
        # default_server на :80 может быть только один на весь nginx. Если он
        # объявлен дважды — nginx -t падает и НЕ поднимается ни наш сайт, ни чужой.
        # Комментарии срезаем: закомментированный default_server конфликта не даёт.
        # Без якоря ^ — в однострочных конфигах listen стоит после "server {".
        if sed 's/#.*//' "$f" 2>/dev/null | grep -qE '\blisten\b[^;]*\bdefault_server\b'; then D=1; else D=0; fi
        if [[ "$n" == "fallback" ]]; then
          info "$n — наш (REALITY fallback, :80 → 301 https)"
          [[ "$D" -eq 1 ]] && OUR_DEFSRV=1
        else
          warn "$n — ЧУЖОЙ, xm его не трогает"
          [[ "$D" -eq 1 ]] && FOREIGN_DEFSRV="$FOREIGN_DEFSRV $n"
        fi
      done
      shopt -u nullglob
    else
      info "каталог /etc/nginx/sites-enabled отсутствует"
    fi
    if [[ "$OUR_DEFSRV" -eq 1 && -n "$FOREIGN_DEFSRV" ]]; then
      fail "КОНФЛИКТ: default_server на :80 объявлен и у нас, и в:$FOREIGN_DEFSRV"
      warn "nginx -t упадёт → не поднимется НИ ОДИН сайт. Убери default_server у одного из них."
    fi

    sep
    echo -e "${BOLD}nginx · stream (наш тракт REALITY)${NC}"
    if [[ -d /etc/nginx/stream-enabled ]]; then
      shopt -s nullglob
      for f in /etc/nginx/stream-enabled/*; do
        n=$(basename "$f")
        case "$n" in
          reality-fallback.conf) info "$n — наш (ssl_preread → $(_get_nginx_sni))" ;;
          front.conf)            info "$n — наш (фронт по SNI на :$(_front_port))" ;;
          *) warn "$n — ЧУЖОЙ в нашем каталоге. Проверь, что он не слушает 127.0.0.1:10443" ;;
        esac
      done
      shopt -u nullglob
    else
      info "каталог /etc/nginx/stream-enabled отсутствует"
    fi

    sep
    echo -e "${BOLD}Кто слушает порты${NC}"
    XP=$(jq -r '.inbounds[0].port' "$CONFIG" 2>/dev/null || echo "")
    XP2=$(jq -r '.inbounds[1].port // ""' "$CONFIG" 2>/dev/null || echo "")
    SSHP=$(_get_ssh_port)
    FRP=""; FRUP=""
    _front_enabled && { FRP=$(_front_port); FRUP=$(_front_routes | awk '{print $2}'); }
    echo    "  порт     процесс        чей"
    ss -tlnp 2>/dev/null | tail -n +2 | awk '
      { a=$4; sub(/.*:/, "", a); p="?";
        if (match($0, /users:\(\("[^"]+"/)) p=substr($0, RSTART+9, RLENGTH-10);
        print a, p }' | sort -n -u | while read -r port proc; do
      case "$port" in
        "$XP"|"$XP2") who="наш (xray)" ;;
        80|10443)     who="наш (nginx)" ;;
        "$FRP")       who="наш (nginx: фронт по SNI)" ;;
        "$SSHP")      who="системный (ssh)" ;;
        *) if [[ -n "$FRUP" ]] && grep -qx "$port" <<< "$FRUP"; then
             who="сосед за фронтом — переехал на loopback, xm его не трогает"
           else who="ЧУЖОЙ — не наш, xm его не трогает"; fi ;;
      esac
      printf "  %-8s %-14s %s\n" "$port" "$proc" "$who"
    done

    sep
    echo -e "${BOLD}Свои systemd-юниты (не из пакетов)${NC}"
    shopt -s nullglob
    FOUND_UNIT=0
    for u in /etc/systemd/system/*.service; do
      n=$(basename "$u")
      # Симлинк здесь — это алиас или enable-ссылка на юнит ИЗ ПАКЕТА:
      # sshd→ssh, syslog→rsyslog, chronyd→chrony, dbus-org.freedesktop.*,
      # iscsi, systemd-timesyncd. Соседом это не является, а в списке из
      # десятка таких строк тонут настоящие соседи. Отличаем по -L.
      [[ -L "$u" ]] && continue
      case "$n" in
        # xray@.service — шаблонный юнит официального установщика Xray,
        # ставится вместе с xray.service и тоже наш.
        xray.service|xray@*.service|xray-sni-watch.service|xray-watchdog.service) info "$n — наш" ;;
        *) warn "$n — ЧУЖОЙ ($(systemctl is-active "$n" 2>/dev/null))" ;;
      esac
      FOUND_UNIT=1
    done
    shopt -u nullglob
    [[ "$FOUND_UNIT" -eq 0 ]] && info "кастомных юнитов в /etc/systemd/system нет"

    sep
    echo -e "${BOLD}UFW${NC}"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      ufw status 2>/dev/null | tail -n +3 | sed 's/^/  /'
      warn "Если чужой сервис слушает наружу — его порт должен быть в этом списке"
    else
      warn "UFW не активен"
    fi

    sep
    echo -e "${BOLD}Что трогает каждая команда${NC}"
    echo -e "  ${GREEN}xm self-update${NC}   только /usr/local/bin/xm — больше ничего"
    echo -e "  ${GREEN}xm front${NC}         только stream-enabled/front.conf + worker_connections;"
    echo    "                   апстримы соседей — из /usr/local/etc/xray/front.conf"
    echo -e "  ${GREEN}xm harden${NC}        config.json + stream-enabled/reality-fallback.conf,"
    echo    "                   затем nginx reload — и только если nginx -t прошёл"
    echo -e "  ${GREEN}xm set-sni${NC}       то же самое плюс перезапуск xray"
    echo -e "  ${GREEN}xm update${NC}        бинарь xray + перезапуск xray"
    echo -e "  ${GREEN}xm diag*${NC}         ничего не меняет, только читает"
    echo -e "  ${RED}setup.sh --reinstall${NC}  ОПАСНО для соседей: переписывает nginx.conf,"
    echo    "                   сносит sites-enabled/default и всё из stream-enabled/,"
    echo    "                   включает ufw, переписывает fail2ban, генерирует новые"
    echo    "                   ключи REALITY (все выданные клиентам URI умирают)."
    echo ""
    ;;

# ─── Помощь ──────────────────────────────────────────────────────────────────
*)
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       xm — Xray Manager  v5.8            ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Сервис:${NC}"
    echo "  xm start / stop / restart / status"
    echo ""
    echo -e "${BOLD}Конфиг:${NC}"
    echo "  xm edit              Открыть в nano (с автобэкапом)"
    echo "  xm test              Проверить валидность"
    echo "  xm apply             Проверить + перезапустить"
    echo -e "  ${GREEN}xm set-sni <domain>${NC}  Сменить домен-маску во ВСЕХ местах (config+nginx) атомарно"
    echo -e "  ${GREEN}xm set-port <порт> [--tcp]${NC}  Сменить порт inbound (проверка занятости + UFW + откат)"
    echo -e "  ${GREEN}xm front${NC}             Разделить публичный порт по SNI с соседней службой"
    echo    "                       front on | off | add <sni> <порт> | del <sni> | status"
    echo ""
    echo -e "${BOLD}Бэкапы:${NC}"
    echo "  xm backup / restore / backups"
    echo ""
    echo -e "${BOLD}Клиенты:${NC}"
    echo -e "  ${GREEN}xm add [имя]${NC} / ${GREEN}del${NC} / clients      Добавить / удалить / список"
    echo    "  xm uri [имя|--tcp|--all]         VLESS URI (по умолч. — выбор клиента)"
    echo ""
    echo -e "${BOLD}${GREEN}QR-коды:${NC}"
    echo -e "  ${GREEN}xm qr [имя] [--tcp|--both|--all]${NC}   По умолч. — выбор клиента, XHTTP"
    echo ""
    echo -e "${BOLD}TCP inbound:${NC}"
    echo -e "  ${GREEN}xm add-tcp${NC}                       Добавить XTLS-Vision/TCP inbound"
    echo ""
    echo -e "${BOLD}${GREEN}Обновление:${NC}"
    echo -e "  ${GREEN}xm self-update [--check|--force]${NC}  Обновить сам xm из git-чекаута репозитория"
    echo    "  xm self-update --from <url|путь>  Указать/сменить источник (склонирует в /opt/xray)"
    echo -e "  ${GREEN}xm update [--check]${NC} / ${GREEN}update-geo${NC}   Xray-core / geoip.dat / geosite.dat"
    echo -e "  ${GREEN}xm autoupd on|off|now|log|status${NC}  Автопатчи безопасности ОС (20:30 МСК)"
    echo ""
    echo -e "${BOLD}Nginx:${NC}    xm nginx-status / nginx-log / nginx-reload / nginx-probes"
    echo -e "${BOLD}Fail2ban:${NC} xm ban-list / ban-ssh-stat / unban [IP]"
    echo -e "${BOLD}Логи:${NC}     xm log / log-live / log-clear"
    echo -e "${BOLD}Инфо:${NC}     xm info / paths / uuid / pubkey"
    echo ""
    echo -e "${BOLD}${GREEN}Анти-DPI и анонимность:${NC}"
    echo -e "  ${GREEN}xm harden${NC}                        DoH на сервере + перехват :53 + mimic-fallback"
    echo    "  xm harden --check | --off        Показать состояние / откатить"
    echo    "  xm harden --dot                  Наш профиль DoT (4 апстрима) поверх настроенного резолвера"
    echo    "  xm harden --nonip [drop|skip|off]  Режим запросов не-A/AAAA, без отката остального"
    echo -e "  ${GREEN}xm pq status|on|off${NC}              ML-DSA-65: post-quantum подпись REALITY"
    echo ""
    echo -e "${BOLD}${GREEN}Стабильность:${NC}"
    echo -e "  ${GREEN}xm tune${NC}                          Сетевой стек (BBR, буферы, MTU probing) + watchdog + таймауты"
    echo    "  xm tune --check | --off          Состояние и счётчики потерь / откат"
    echo -e "  ${GREEN}xm watchdog on|off|now|status${NC}    Присмотр за сквозным путём (резолвинг dest, fallback, слушатель)"
    echo ""
    echo -e "${BOLD}${GREEN}Диагностика:${NC}"
    echo -e "  ${GREEN}xm selftest [--tcp|--all]${NC}        Живой хендшейк через loopback — НАЧИНАЙ С НЕЁ"
    echo -e "  ${GREEN}xm diag-dpi [--quick]${NC}            Устойчивость к DPI: зонды, DNS-утечки, профиль трафика"
    echo -e "  ${GREEN}xm sni-scan${NC}                      Замер доменов-масок (cert/h2/RTT)"
    echo -e "  ${GREEN}xm reality-debug on|off${NC}          Почему REALITY отказывает (авто-off 15 мин)"
    echo -e "  ${GREEN}xm diag${NC}                          Полная диагностика"
    echo -e "  ${GREEN}xm neighbors${NC}                     Кто ещё живёт на сервере и что трогает xm"
    echo    "  Прочее: pubkey / diag-ntp / diag-ports / diag-tls / diag-fw / diag-log"
    ;;
esac