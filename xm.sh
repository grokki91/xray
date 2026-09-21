#!/usr/bin/env bash
# =============================================================================
#  xm — менеджер Xray. Список команд: xm help
# =============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/usr/local/etc/xray/backups"
LOG="/var/log/xray/error.log"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"
# Локальный журнал разбора проблем этой установки — не в репозитории, не в
# git-чекауте. Создаётся setup.sh, переустановку и self-update переживает.
# Общие, не привязанные к установке уроки живут отдельно, в репозитории:
# .claude/skills/xray-dpi/references/lessons.md
JOURNAL_FILE="/usr/local/etc/xray/journal.md"
XM_BIN="/usr/local/bin/xm"
# Путь к git-чекауту репозитория, из которого ставился xm. Пишется setup.sh и
# xm self-update — чтобы обновление знало, откуда тянуть, и не приходилось
# каждый раз вспоминать, куда именно был сделан clone.
XM_SRC_FILE="/usr/local/etc/xray/xm-source"

# Пороги размера TLS Certificate для совместимости с REALITY (см. setup.sh)
REALITY_CERT_WARN=7000
REALITY_CERT_LIMIT=8192

# Окно, в котором домен-маска годится ещё и под ML-DSA-65.
# Нижняя граница — тот же порог, что в diag-dpi (блок C): при более мелком
# сертификате +3.3 КБ подписи становятся заметной долей ответа, и мы меняем
# одну зацепку для DPI на другую.
# Верхняя — та же арифметика, что в xm pq: EST + 3400 должно остаться ниже
# лимита REALITY, иначе хендшейк порвётся. Считается от лимита, чтобы две
# константы не разъехались при правке одной.
REALITY_CERT_PQ_MIN=3500
REALITY_CERT_PQ_MAX=$((REALITY_CERT_LIMIT - 3400))

# Сколько хендшейков на домен делает sni-scan и с каким таймаутом.
# Десять, а не три: замер на живом сервере дал кандидатов с долей отказов
# 13% и 27%, и три пробы пропустили обоих — вероятность трёх удач подряд при
# 13% отказов равна 0.66, то есть команда уверенно рекомендовала худший домен.
# На десяти пробах те же кандидаты показывают потерю с вероятностью 0.75 и
# 0.96. Единицы процентов так по-прежнему не ловятся — для них блок G diag-dpi.
# Таймаут проб короче, чем у _check_cert_size: измеренные RTT здесь 28-56 мс,
# пять секунд — полсотни запасов, а на мёртвом домене экономят минуты.
SNI_PROBES=10
SNI_PROBE_TIMEOUT=5

# RealiTLScanner (XTLS, MPL-2.0) — поиск домена-маски в своей же сети.
# Версия и контрольные суммы прибиты намеренно: сторонний бинарник в
# инструменте безопасности не качается «последним» вслепую. При смене версии
# суммы обязаны меняться вместе с ней, иначе установка откажется ставить файл.
RTS_VER="v0.2.3"
RTS_BIN="/usr/local/lib/xm/RealiTLScanner"
RTS_SHA256_AMD64="a55595446de9f1c2e6c5c3cd766a7320a11115947df48f101749bb62c8055592"
RTS_SHA256_ARM64="27bdd3e53d4391c66c8df3391d3c3fb5eb2dc356125f2fb33ac58fcaaf8f88b3"

ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
fail() { echo -e "  ${RED}[✗]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
info() { echo -e "  ${CYAN}[-]${NC} $*"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────${NC}"; }

# Обёртки со счётчиком: находка попадает и на экран, и в итог diag-dpi.
# Определены глобально, потому что часть проверок печатается функциями, общими
# с другими командами (блок G — той же, что и xm tune). Пока обёртки жили
# внутри diag-dpi, находки таких функций шли мимо счётчика, и на экране красный
# [✗] соседствовал с «Критично: 0» — итог противоречил собственному выводу.
DPI_CRIT=0; DPI_WARN=0
dfail() { fail "$*"; DPI_CRIT=$((DPI_CRIT + 1)); }
dwarn() { warn "$*"; DPI_WARN=$((DPI_WARN + 1)); }

# ─── Вспомогательные ─────────────────────────────────────────────────────────

# Чтение поля из client-info.txt (формат "LABEL: value" с любыми пробелами)
_get_field() {
  local label="$1"
  grep -i "^${label}[[:space:]]*:" "$CLIENT_FILE" 2>/dev/null \
    | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '[:space:]'
}

# SNI из whitelist-map: строка строго вида "X   X;".
# Прежняя регулярка '^\s*\w+\s+\w+;' совпадала также с
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
# Браузер, не достучавшись до Secure DNS, откатывается на обычный DNS. Тогда
# имя домена видит провайдер (VPN выключен) либо хостер VPS: без dns-блока
# Xray резолвит системным резолвером открытым текстом. Оба канала закрывает
# перехват :53 из тоннеля с ответом по DoH — клиенту настраивать нечего.
#
# Резолверы заданы IP-литералом: иначе bootstrap-запрос «какой IP у
# dns.google» ушёл бы открытым. https+local:// идёт мимо routing — нет петли.
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

# Файл, который фактически задаёт DNS= — последний по порядку применения.
# Нужен, чтобы `--dot` правил существующий, а не заводил ВТОРОЙ drop-in,
# конкурирующий за одну и ту же настройку: побеждает лексикографически
# последний, и два источника правды здесь — отложенный сюрприз. Глоб в shell
# раскрывается в том же порядке, в каком файлы читает systemd.
_resolved_dns_file() {
  local f last=""
  for f in /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf; do
    [[ -f "$f" ]] || continue
    grep -qE '^[[:space:]]*DNS=[^[:space:]]' "$f" && last="$f"
  done
  [[ -n "$last" ]] || return 1
  echo "$last"
}

# Наш список апстримов одной строкой — для сравнения и для точечной правки.
_resolved_dot_dns() { printf '%s' "$RESOLVED_DOT_CONF" | sed -n 's/^DNS=//p'; }

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
# Android с 11-й версии спрашивает HTTPS/SVCB (тип 65) перед каждым
# соединением. При drop запрос отбрасывается молча, и на телефоне это
# выглядит как «соединение — переподключение». Отдельная ручка нужна, чтобы
# проверять эту гипотезу, не снося вместе с ней DoH, DoT и mimic.
#
# Цена skip: запрос не-A/AAAA покидает VPS открытым UDP. Утечка узкая (тип 65,
# не имена сайтов), но это утечка — режим диагностический.
#
# Набор допустимых значений между сборками менялся, поэтому проверяем его
# на копии конфига через `xray -test` (_nonip_try).

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

# nginx резолвит апстрим fallback мимо системного резолвера — открытый UDP/53
# раз в полминуты, постоянный маячок против остального harden. Переводим на
# стаб: после шага DoT он ходит по :853 и кэш общий с машиной.
#
# valid=900s, а не 30s: этот резолвинг — часть тракта REALITY (dest задан
# именем), и каждое истечение кэша — окно, в котором неудачный запрос роняет
# fallback целиком. Со строгим DoT промах вероятнее: при недоступном :853
# резолвед не имеет права свалиться в открытый UDP. Адреса CDN меняются
# несопоставимо медленнее. Возврат 0 — изменили, 1 — менять было нечего.
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
# Это не косметика: на :443 мы совпадаем с настоящим сайтом по всем зондам, а
# :80 рядом отвечал `Server: nginx` и редиректом на голый IP — так не делает
# ни один сайт, и одного curl -I хватает, чтобы это увидеть (diag-dpi, B7).
#
# Правим точечно sed по директивам: файл могли отредактировать руками.

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

# ─── Локальные правила доступа ───────────────────────────────────────────────
#
# Порт своей службы рядом с VPN — не наружу, а с одного интерфейса или адреса.
# Вся сложность в том, чтобы правило не пропало: setup.sh --reinstall заново
# включает ufw со своими портами, а `ufw reset` сносит всё и молча. Источник
# правды лежит в /usr/local/etc/xray, и установка прогоняет его после своих.
#
# Правило — это тройка (интерфейс, источник, порт), и ничего больше: имя
# службы в выводе диагностики никому не нужно. У чистой установки файла нет,
# сама по себе эта механика не включается.
ACCESS_STATE="/usr/local/etc/xray/access.conf"

_access_state_init() {
  [[ -f "$ACCESS_STATE" ]] && return 0
  mkdir -p "$(dirname "$ACCESS_STATE")"
  cat > "$ACCESS_STATE" <<'AEOF'
# Локальные правила доступа. Читает `xm access apply` и секция UFW в setup.sh —
# в этом весь смысл файла: он переживает переустановку и сброс ufw.
#
# Формат строки:
#   RULE <интерфейс|-> <источник CIDR|-> <порт> <tcp|udp>
# «-» значит «любой». Правки руками допустимы, но лучше `xm access add` —
# там валидация, а сюда значения уходят в командную строку ufw.
AEOF
  chmod 600 "$ACCESS_STATE"
}

# Объявленные правила: строки "RULE <iface> <src> <порт> <proto>" → 4 поля.
_access_rules() {
  [[ -f "$ACCESS_STATE" ]] || return 0
  awk '$1=="RULE" && NF==5 {print $2, $3, $4, $5}' "$ACCESS_STATE"
}

# Валидация обязательна и строгая: значения идут аргументами в ufw, и всё, что
# не прошло проверку, до него не доезжает. Проверяет и `add`, и `apply` —
# второй потому, что файл разрешено править руками.
_access_valid() {
  local iface="$1" src="$2" port="$3" proto="$4"
  [[ "$iface" == "-" || "$iface" =~ ^[a-zA-Z0-9._-]{1,15}$ ]] \
    || { fail "Интерфейс: буквы, цифры, . _ - (до 15 знаков) или «-»"; return 1; }
  [[ "$src" == "-" \
     || "$src" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ \
     || "$src" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] \
    || { fail "Источник: адрес или CIDR (IPv4/IPv6) либо «-»"; return 1; }
  [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]] \
    || { fail "Порт: число 1-65535"; return 1; }
  [[ "$proto" == "tcp" || "$proto" == "udp" ]] \
    || { fail "Протокол: tcp или udp"; return 1; }
  return 0
}

# Аргументы для ufw. Порядок слов у него фиксирован, а `from any` пишем даже
# для «любого источника»: без него форма `allow to any port N` невалидна, и
# пришлось бы держать две разные ветки сборки команды и, главное, две разные
# строки для `ufw delete` — они должны совпадать с добавленными дословно.
_access_ufw_args() {
  local iface="$1" src="$2" port="$3" proto="$4"
  local -a a=(allow)
  [[ "$iface" != "-" ]] && a+=(in on "$iface")
  [[ "$src" == "-" ]] && a+=(from any) || a+=(from "$src")
  a+=(to any port "$port" proto "$proto")
  printf '%s\n' "${a[@]}"
}

# Человекочитаемая область действия — для вывода status и diag.
_access_scope() {
  local iface="$1" src="$2" out=""
  [[ "$iface" != "-" ]] && out="на $iface" || out="на любом интерфейсе"
  [[ "$src" != "-" ]] && out="$out с $src" || out="$out с любого адреса"
  echo "$out"
}

# Есть ли правило в живом ufw. Сверяем колонки To/From из `ufw status`:
# IPv6-дубль («(v6)» в To) не совпадёт и в расчёт не идёт — нам достаточно
# знать, что правило вообще доехало.
_access_in_ufw() {
  local iface="$1" src="$2" port="$3" proto="$4" want_to want_from
  want_to="${port}/${proto}"
  [[ "$iface" != "-" ]] && want_to="${want_to} on ${iface}"
  want_from="Anywhere"
  [[ "$src" != "-" ]] && want_from="$src"
  ufw status 2>/dev/null | awk -v t="$want_to" -v f="$want_from" '
    index($0, "ALLOW") > 0 {
      i = index($0, "ALLOW")
      to = substr($0, 1, i - 1); sub(/[[:space:]]+$/, "", to)
      rest = substr($0, i)
      sub(/^ALLOW[[:space:]]+(IN|OUT)?[[:space:]]*/, "", rest)
      sub(/[[:space:]]*#.*$/, "", rest); sub(/[[:space:]]+$/, "", rest)
      if (to == t && rest == f) found = 1
    }
    END { exit found ? 0 : 1 }'
}

# Прогон всех объявленных правил через ufw. Идемпотентно: на уже существующее
# правило ufw отвечает «Skipping adding existing rule» и кодом 0, так что
# apply можно гонять сколько угодно — в том числе из setup.sh при каждой
# переустановке.
_access_apply() {
  local iface src port proto ok_n=0 bad=0
  local -a A
  while read -r iface src port proto; do
    [[ -z "$iface" ]] && continue
    if ! _access_valid "$iface" "$src" "$port" "$proto"; then
      fail "Строка пропущена: RULE $iface $src $port $proto"
      bad=$((bad + 1)); continue
    fi
    mapfile -t A < <(_access_ufw_args "$iface" "$src" "$port" "$proto")
    if ufw "${A[@]}" comment 'xm access' >/dev/null 2>&1; then
      ok_n=$((ok_n + 1))
    else
      fail "UFW не принял: ${port}/${proto} $(_access_scope "$iface" "$src")"
      bad=$((bad + 1))
    fi
  done < <(_access_rules)
  ACCESS_OK_N="$ok_n"; ACCESS_BAD_N="$bad"
  [[ "$bad" -eq 0 ]]
}

# ─── Фронт: демультиплексор по SNI на публичном порту ────────────────────────
#
# Номер порта виден сканеру до всякого анализа TLS, а 443 держит только один
# сокет. Фронт — тот же приём, что в reality-fallback.conf: ssl_preread читает
# SNI, не терминируя TLS, и разводит поток по локальным службам. Соседу на том
# же 443 перевыпускать клиентам ничего не нужно (diag-dpi, B8).
#
# Отдельным файлом, а не правкой fallback: setup.sh --reinstall чистит
# stream-enabled/ целиком, поэтому источник правды в FRONT_STATE, и возврат
# после переустановки стоит одной команды — sudo xm front on.
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
    echo "    listen 0.0.0.0:${port} backlog=${NGX_BACKLOG};"
    echo "    listen [::]:${port} backlog=${NGX_BACKLOG};"
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
# harden закрывает утечки, tune чинит обрывы: соединения терялись в очереди
# accept ещё до того, как их видел Xray (ListenOverflows/ListenDrops), а
# ретрансмиты доходили до 7.7%. Правкой конфига Xray это не лечится.
#
# Чего здесь сознательно нет, и это часть анти-DPI: серверный TFO, отключённые
# timestamps и нестандартный initcwnd. Каждое из них — отличие от домена-маски
# на уровне TCP, ещё до TLS, то есть стабильная подпись сервера.
SYSCTL_FILE="/etc/sysctl.d/99-xray-tune.conf"
# nginx НЕ наследует net.core.somaxconn: backlog он задаёт сам в listen(),
# по умолчанию 511. Поэтому sysctl-профиль применяется, а очередь accept
# продолжает переполняться — замерено 375 overflows за сутки уже ПОСЛЕ tune,
# при somaxconn=8192 и Xray (Go, somaxconn наследует) на 8192.
NGX_BACKLOG=8192
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

# Фактический backlog слушающих сокетов nginx и Xray. Для LISTEN-сокета
# Send-Q в ss — это и есть backlog. Счётчик overflows видит последствие,
# но не называет причину; здесь она видна прямо.
_backlog_report() {
  local smc out
  smc=$(sysctl -n net.core.somaxconn 2>/dev/null)
  [[ -z "$smc" ]] && return 0
  out=$(ss -tlnpH 2>/dev/null | awk -v m="$smc" '
    /"nginx"|"xray"/ && $3+0 < m {
      printf "      %-24s backlog=%-6s %s\n", $4, $3, ($0 ~ /"nginx"/ ? "nginx" : "xray") }')
  if [[ -z "$out" ]]; then
    ok "backlog слушающих сокетов не ниже somaxconn (${smc})"; return 0
  fi
  dwarn "backlog ниже somaxconn (${smc}) — на эти сокеты sysctl-профиль не подействовал:"
  printf '%s\n' "$out"
  echo -e "      ${CYAN}nginx задаёт backlog сам (по умолчанию 511) и somaxconn не наследует.${NC}"
  echo -e "      ${CYAN}Чинит: ${BOLD}sudo xm tune${NC}"
}

# Проставить backlog в listen-директивах nginx. Идемпотентно: строки, где
# backlog уже есть, не трогаются. Шаблон правится тоже — иначе xm set-sni
# перегенерирует fallback из него и вернёт 511.
_ngx_backlog_fix() {
  local f bak changed=0 rc=0
  local files=("$FRONT_NGX"
               /etc/nginx/stream-enabled/reality-fallback.conf
               /etc/nginx/reality-fallback.conf.tmpl
               /etc/nginx/sites-available/fallback)
  mkdir -p "$BACKUP_DIR" 2>/dev/null; chmod 700 "$BACKUP_DIR" 2>/dev/null
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    grep -E '^[[:space:]]*listen[[:space:]]' "$f" | grep -qv 'backlog=' || continue
    bak="$BACKUP_DIR/$(basename "$f")_$(date +%Y%m%d_%H%M%S).bak"; cp "$f" "$bak"
    sed -i -E "/^[[:space:]]*listen[[:space:]]/{ /backlog=/! s/[[:space:]]*;[[:space:]]*\$/ backlog=${NGX_BACKLOG};/ }" "$f"
    # Шаблон в конфиг nginx не подключён, проверять его через nginx -t нечем.
    if [[ "$f" == *.tmpl ]]; then changed=1; continue; fi
    if nginx -t &>/dev/null; then
      changed=1
    else
      cp "$bak" "$f"
      warn "backlog в $(basename "$f") nginx не принял — файл возвращён из $bak"
      nginx -t 2>&1 | tail -3 | sed 's/^/      /'
      rc=1
    fi
  done
  if [[ "$changed" -eq 0 ]]; then
    [[ "$rc" -eq 0 ]] && ok "backlog в конфигах nginx уже проставлен"
    return $rc
  fi
  systemctl reload nginx || { fail "nginx reload не удался"; return 1; }
  # Reload переоткрывает сокет не всегда, а backlog живёт на самом сокете.
  # Поэтому проверяем по факту, а не по успеху reload.
  sleep 1
  if ss -tlnpH 2>/dev/null | awk '/"nginx"/{print $3}' | grep -qv "^${NGX_BACKLOG}$"; then
    info "reload не переставил backlog на живых сокетах — перезапускаю nginx"
    systemctl restart nginx; sleep 1
  fi
  ok "backlog в listen nginx → ${NGX_BACKLOG}"
  return $rc
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
  local s_t s_r s_x s_o s_l s_d s_u d_age=0 d_tx=0 d_retr=0 d_lo=0 d_ld=0 d_to=0 d_u=0
  local w_ok=0 w_label=""
  if [[ -r "$COUNTERS_SNAP" ]] \
     && read -r s_t s_r s_x s_o s_l s_d s_u < "$COUNTERS_SNAP" \
     && [[ -n "${s_t:-}" ]]; then
    d_age=$(( $(date +%s) - s_t ))
    d_tx=$((   ${tx:-0} - ${s_x:-0} )); d_retr=$(( ${retr:-0} - ${s_r:-0} ))
    d_lo=$((   ${lo:-0} - ${s_l:-0} )); d_ld=$((  ${ld:-0}  - ${s_d:-0} ))
    d_to=$((   ${to:-0} - ${s_o:-0} )); d_u=$((   ${udperr:-0} - ${s_u:-0} ))
    # Поле могло пропасть из вывода nstat — отрицательная дельта тогда не
    # вердикт, а артефакт. Детектором перезагрузки служат ретрансмиты ниже.
    [[ "$d_lo" -lt 0 ]] && d_lo=0; [[ "$d_ld" -lt 0 ]] && d_ld=0
    [[ "$d_to" -lt 0 ]] && d_to=0; [[ "$d_u"  -lt 0 ]] && d_u=0
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

  local src cum_pct tx_rate=-1
  if [[ -n "${retr:-}" && -n "${tx:-}" && "${tx:-0}" -gt 0 ]]; then
    cum_pct=$(awk -v r="$retr" -v t="$tx" 'BEGIN{printf "%.2f", r*100/t}')
  fi
  if [[ "$w_ok" -eq 1 ]]; then
    pct=$(awk -v r="$d_retr" -v t="$d_tx" 'BEGIN{printf "%.2f", r*100/t}'); src="$w_label"
  else
    pct="$cum_pct"; src="накопительно с загрузки"
  fi

  # Доля ретрансмитов — отношение, и на малом знаменателе оно перестаёт быть
  # вердиктом. Замерено на живом сервере: почти простаивающая машина под
  # постоянным сканированием даёт 12 исходящих сегментов в секунду и РОВНЫЙ фон
  # ретрансмитов, от трафика не зависящий, — за 85 минут трафик по пятиминуткам
  # менялся в 11 раз, ретрансмиты в 1.3 (σ 6% от среднего). Процент при этом
  # читается как катастрофа, хотя в абсолюте это 2.3 ретрансмита в секунду и к
  # путям до клиентов отношения не имеет: ровный фон при скачущем трафике — это
  # ответы сканерам, а не потери последней мили. Порог 50 сегм/с взят как низ
  # правдоподобного: один клиент, качающий видео, даёт на порядок больше.
  [[ "$w_ok" -eq 1 && "$d_age" -gt 0 ]] && tx_rate=$(( d_tx / d_age ))
  if [[ "$tx_rate" -ge 0 && "$tx_rate" -lt 50 ]]; then
    dwarn "Ретрансмиты ${src}: ${pct}% при исходящем потоке ${tx_rate} сегм/с — знаменатель почти пуст, это не вердикт о потерях до клиентов"
    info "  В абсолюте: $(( d_retr * 3600 / d_age )) ретрансмитов в час. Ровный фон при скачущем трафике = ответы сканерам, а не последняя миля"
    info "  Разделить одно от другого: ${BOLD}nstat -az TcpExtTCPSynRetrans TcpExtTCPFastRetrans TcpRetransSegs${NC} дважды с интервалом 5 мин"
  elif [[ -n "${pct:-}" ]]; then
    if   awk -v p="$pct" 'BEGIN{exit !(p<1)}'; then ok    "Ретрансмиты ${src}: ${pct}% — норма"
    elif awk -v p="$pct" 'BEGIN{exit !(p<3)}'; then dwarn "Ретрансмиты ${src}: ${pct}% — заметные потери на пути к клиентам"
    elif [[ "$cc" == "bbr" ]]; then
      # BBR уже стоит, а потери всё равно высокие — значит дело не в
      # алгоритме. Обычно это либо реальные потери на последней миле у
      # клиентов (мобильный интернет), либо PMTU blackhole: пакеты полного
      # размера не проходят, ICMP Too Big режется, и ядро молча ретранслирует.
      dfail "Ретрансмиты ${src}: ${pct}% при уже включённом BBR — алгоритм ни при чём. Проверь MTU probing ниже и учти, что часть потерь может быть на стороне клиентских сетей"
    else
      dfail "Ретрансмиты ${src}: ${pct}% при cc=${cc:-?} — на потерях CUBIC режет окно вдвое каждый раз. Включи BBR: ${BOLD}sudo xm tune${NC}"
    fi
    [[ "$w_ok" -eq 1 && -n "${cum_pct:-}" ]] \
      && info "  Накопительно с загрузки: ${cum_pct}% (${retr} из ${tx}) — история, не текущее состояние"
  fi

  if [[ -n "${to:-}" ]]; then
    [[ "$w_ok" -eq 1 ]] && info "TCP-таймауты ${src}: ${d_to} (накопительно с загрузки: ${to})" \
                        || info "TCP-таймауты ${src}: ${to}"
  fi

  # overflows и drops — РАЗНЫЕ отказы, и лечатся они по-разному. Overflows —
  # соединение установлено, но accept его не забрал. Drops растут и без
  # overflows: тогда до accept-очереди дело не дошло вовсе, и советовать
  # somaxconn бессмысленно. Один текст на оба случая противоречил собственным
  # числам («переполнялась» при overflows=0) и уводил не туда.
  local q_lo q_ld
  if [[ "$w_ok" -eq 1 ]]; then q_lo="$d_lo"; q_ld="$d_ld"; else q_lo="${lo:-0}"; q_ld="${ld:-0}"; fi
  if [[ "$q_lo" -gt 0 ]]; then
    dwarn "Очередь accept переполнялась ${src}: overflows=${q_lo}, drops=${q_ld} — клиент считает, что подключился, сервер молча выбросил"
  elif [[ "$q_ld" -gt 0 ]]; then
    dwarn "Подключения отброшены listening-сокетом ${src}: drops=${q_ld} при overflows=0 — accept-очередь не переполнялась, отказ раньше: полная SYN-очередь при выключенных syncookies или нехватка памяти на пике. Смотреть: ${BOLD}sudo sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog${NC}"
  else
    ok "Очередь accept не переполнялась ${src}"
  fi
  [[ "$w_ok" -eq 1 && $(( ${lo:-0} + ${ld:-0} )) -gt $(( q_lo + q_ld )) ]] \
    && info "  Накопительно с загрузки: overflows=${lo:-0}, drops=${ld:-0} — было до последней правки"
  _backlog_report

  # UDP-буфер — тоже по окну: снапшот хранит это поле с самого начала, но
  # вердикт давался по счётчику с загрузки, то есть предупреждение висело за
  # давно прошедший пик.
  local q_u; [[ "$w_ok" -eq 1 ]] && q_u="$d_u" || q_u="${udperr:-0}"
  [[ "$q_u" -gt 0 ]] && dwarn "UDP-датаграмм потеряно по буферу ${src}: ${q_u} — приёмный буфер не разгребался вовремя" \
                     || ok "UDP-буфер без потерь ${src}"
  [[ "$w_ok" -eq 1 && "${udperr:-0}" -gt "$q_u" ]] \
    && info "  Накопительно с загрузки: ${udperr} — история, не текущее состояние"
  info "Congestion control: ${cc:-?}, qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null)"
  info "MTU probing: $(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null) (нужен 1 — иначе мобильные клиенты виснут на PMTU blackhole)"
}

# ─── Watchdog ────────────────────────────────────────────────────────────────
#
# REALITY дозванивается до dest на каждое входящее соединение, а dest в nginx
# задан именем и резолвится в рантайме: сдохший резолвинг = сдохший VPN сразу
# для всех. Сервер при этом принимает TCP и рвёт соединение — ровно та подпись
# прокси, ради ухода от которой сделан mimic. Xray жив, systemd ничего не
# перезапустит, поэтому проверяем сквозной путь, а не статус юнитов.
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

# ─── Автообновления пакетов ──────────────────────────────────────────────────
#
# Не только -security: та ветка чинит дыры, но оставляет nginx, curl и openssl
# на версии дня установки. -updates доносит патч-версии в пределах релиза.
# -backports и -proposed не берём: оттуда приезжают версии, которых нет у
# большинства машин релиза, а нам нужно быть как все — в том числе по баннерам.
#
# Xray сюда не попадает: он не apt-пакет, обновляется через xm update.
# Перезагрузка не автоматическая — момент выбирает владелец, напоминание
# печатает xm diag.
UU_POLICY="/etc/apt/apt.conf.d/50unattended-upgrades"
UU_PERIODIC="/etc/apt/apt.conf.d/20auto-upgrades"
UU_TIMER_DIR="/etc/systemd/system/apt-daily-upgrade.timer.d"
UU_LIST_DIR="/etc/systemd/system/apt-daily.timer.d"

# Политика пишется целиком и идемпотентно — как sysctl-профиль в _tune_write.
# Расписание живёт здесь же, а не в setup.sh: два владельца одного набора
# файлов расходятся ровно до первой правки, которая попала только в один из них.
_autoupd_write() {
  cat > "$UU_POLICY" <<'UUEOF'
// Политика автообновлений. Создана xm autoupd apply.
// Правки руками переживут только до следующего запуска — меняй xm.sh.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
UUEOF
  chmod 644 "$UU_POLICY"

  cat > "$UU_PERIODIC" <<'UUEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
UUEOF
  chmod 644 "$UU_PERIODIC"

  # Таймзона задаётся в самом таймере — системное время VPS не трогаем.
  mkdir -p "$UU_TIMER_DIR" "$UU_LIST_DIR"
  cat > "$UU_TIMER_DIR/override.conf" <<'UUEOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* 20:30:00 Europe/Moscow
RandomizedDelaySec=20m
Persistent=true
UUEOF
  cat > "$UU_LIST_DIR/override.conf" <<'UUEOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* 20:00:00 Europe/Moscow
RandomizedDelaySec=10m
Persistent=true
UUEOF
  chmod 644 "$UU_TIMER_DIR/override.conf" "$UU_LIST_DIR/override.conf"
}

# Синтаксическая ошибка в любом файле /etc/apt/apt.conf.d ломает НЕ только
# автообновления, а каждую команду apt на машине — включая ту, которой пришлось
# бы это чинить. Поэтому бэкап → apt-config dump (он разбирает весь каталог
# целиком) → откат при отказе. Проверено: на битом файле dump выходит с кодом
# 100 и печатает «Syntax error <файл>:<строка>».
_autoupd_apply() {
  local stamp bak_policy bak_periodic
  stamp=$(date +%Y%m%d_%H%M%S)
  mkdir -p "$BACKUP_DIR"
  bak_policy="$BACKUP_DIR/50unattended-upgrades_$stamp.bak"
  bak_periodic="$BACKUP_DIR/20auto-upgrades_$stamp.bak"
  [[ -f "$UU_POLICY"   ]] && cp "$UU_POLICY"   "$bak_policy"
  [[ -f "$UU_PERIODIC" ]] && cp "$UU_PERIODIC" "$bak_periodic"

  _autoupd_write

  if apt-config dump >/dev/null 2>&1; then
    rm -f "$bak_policy" "$bak_periodic"
    systemctl daemon-reload
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
    return 0
  fi

  # Откат безусловный: неработающий apt дороже автообновлений.
  if [[ -f "$bak_policy" ]]; then cp "$bak_policy" "$UU_POLICY"; else rm -f "$UU_POLICY"; fi
  if [[ -f "$bak_periodic" ]]; then cp "$bak_periodic" "$UU_PERIODIC"; else rm -f "$UU_PERIODIC"; fi
  rm -f "$bak_policy" "$bak_periodic"
  return 1
}

# Какие ветки реально приняты apt'ом сейчас — не то, что записано в наш файл,
# а итог разбора всего каталога: соседний файл с той же директивой мог её
# переопределить, и тогда -updates в нашем файле ни на что не влияет.
_autoupd_origins() {
  apt-config dump 2>/dev/null \
    | sed -n 's/^Unattended-Upgrade::Allowed-Origins:: "\(.*\)";$/\1/p'
}

# ─── ML-DSA-65: post-quantum подпись REALITY ─────────────────────────────────
#
# Сервер подписывает сертификат и сырые Hello post-quantum ключом, клиент с
# mldsa65Verify это проверяет. Смысл — MITM: публичный ключ REALITY раздаётся
# в URI и утечь может элементарно.
#
# Цена: наш Certificate растёт примерно на 3.3 КБ, и при маленьком сертификате
# у dest длина ответа начинает отличаться от настоящего сайта — одна зацепка
# для DPI меняется на другую. Включать имеет смысл при cert от ~3500 б.
# Клиенты без mldsa65Verify работают как раньше: проверка не требуется.
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

# ─── ASN: правдоподобен ли домен-маска для нашей сети ────────────────────────
#
# Мисматч ASN у REALITY есть всегда: наш адрес не может быть edge'ем чужого
# домена. Лечится не подбором другого CDN, а ценой проверки для цензора.
# Дешевле всего ему домен, который раздаёт собственная сеть владельца
# (www.cloudflare.com → AS13335): хватает статического списка диапазонов.
# Мы узнаём этот случай так же дёшево — по второму уровню имени в названии
# сети его edge'а. Домен в нашей сети не даёт сигнала вовсе.

# _asn_info <ip> → "ASN|BGP-префикс|имя сети". Team Cymru отдаёт всё тремя
# полями за один запрос, отдельного обращения за префиксом не нужно.
_asn_info() {
  local ip="$1" line
  command -v whois &>/dev/null || return 1
  line=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
  [[ "$line" == *"|"* ]] || return 1
  # В имени сети Cymru отдаёт «HANDLE - Организация, CC», а когда handle не
  # зарегистрирован — подставляет туда сам номер AS. Срезаем его: иначе строка
  # печатается как «AS64500 AS64500 - Организация».
  awk -F'|' '{ for (i = 1; i <= NF; i++) gsub(/^[ \t]+|[ \t]+$/, "", $i)
               sub(/^AS[0-9]+[ \t]*-[ \t]*/, "", $7)
               if ($1 ~ /^[0-9]+$/) print $1 "|" $3 "|" $7 }' <<< "$line"
}

# Второй уровень имени: www.cloudflare.com → cloudflare. Нужен для сверки
# с названием сети — эвристика «домен раздаёт сам владелец».
_domain_label() {
  awk -F. '{ if (NF >= 2) print tolower($(NF-1)); else print tolower($0) }' <<< "$1"
}

# Скачать RealiTLScanner с проверкой суммы. Идемпотентно: файл с верной суммой
# не перекачивается. Коды: 0 — готов, 1 — не скачался/архитектура, 2 — сумма.
_rts_ensure() {
  local arch want url tmp sum
  case "$(uname -m)" in
    x86_64)  arch="amd64"; want="$RTS_SHA256_AMD64" ;;
    aarch64) arch="arm64"; want="$RTS_SHA256_ARM64" ;;
    *)       return 1 ;;
  esac
  if [[ -x "$RTS_BIN" ]]; then
    sum=$(sha256sum "$RTS_BIN" 2>/dev/null | awk '{print $1}')
    [[ "$sum" == "$want" ]] && return 0
  fi
  mkdir -p "$(dirname "$RTS_BIN")"
  tmp=$(mktemp) || return 1
  url="https://github.com/XTLS/RealiTLScanner/releases/download/${RTS_VER}/RealiTLScanner-linux-${arch}"
  curl -fsSL --max-time 180 -o "$tmp" "$url" 2>/dev/null || { rm -f "$tmp"; return 1; }
  sum=$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')
  [[ "$sum" == "$want" ]] || { rm -f "$tmp"; return 2; }
  chmod 755 "$tmp"; mv "$tmp" "$RTS_BIN"
}

# _ip_in_cidr <ip> <cidr> — адрес внутри диапазона? Без DNS и без внешних
# утилит: 32 бита укладываются в арифметику bash.
_ip_in_cidr() {
  local ip="$1" cidr="$2" base bits mask a b c d ipn basen
  [[ "$ip"   =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  [[ "$cidr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || return 1
  base="${cidr%/*}"; bits="${cidr#*/}"
  [[ "$bits" -le 32 ]] || return 1
  IFS=. read -r a b c d <<< "$ip";   ipn=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  IFS=. read -r a b c d <<< "$base"; basen=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( (ipn & mask) == (basen & mask) ))
}

# _rts_candidates <cidr> <свой-ip> [лимит] → имена доменов по одному в строке.
#
# Свой адрес исключается обязательно: наш же сервер ответит сертификатом
# ТЕКУЩЕЙ маски, и кандидат «сам на себя» попал бы в список отличным соседом.
_rts_candidates() {
  local cidr="$1" self="$2" lim="${3:-12}" out d ip
  out=$(mktemp /tmp/xm-rts.XXXXXX.csv) || return 1
  "$RTS_BIN" -addr "$cidr" -port 443 -thread 16 -timeout 5 -out "$out" >/dev/null 2>&1
  # CSV: IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,
  #      CERT_DOMAIN,CERT_ISSUER,GEO_CODE. CERT_LENGTH вида "2728(certs count: 3)".
  # Разделитель-запятая безопасен, хотя CERT_ISSUER закавычен и запятую
  # содержит («Let's Encrypt, US»): он идёт ДЕСЯТЫМ, а читаем мы поля до
  # девятого — в них запятая невозможна (имя хоста, версия TLS, число).
  # Wildcard отбрасываем: в SNI нужен конкретный хост, «*.example.com» в dest
  # не подставить.
  awk -F',' -v lim="$REALITY_CERT_WARN" -v self="$self" '
    NR == 1 { next }
    $1 == self { next }
    $3 ~ /1\.3/ && $4 == "h2" {
      d = $9; gsub(/"/, "", d); gsub(/^[ \t]+|[ \t]+$/, "", d)
      if (d == "" || d ~ /^\*/ || d !~ /\./) next
      if (d ~ /\.(local|internal|lan|invalid)$/) next
      n = $6; sub(/\(.*/, "", n); n += 0
      if (n <= 0 || n >= lim) next
      print n "\t" d
    }' "$out" 2>/dev/null | sort -n | awk -F'\t' '!seen[$2]++ { print $2 }' \
  | while read -r d; do
      # Сертификат найден в нашем диапазоне — но dest у REALITY ходит ПО ИМЕНИ,
      # и где лежит имя, скан не говорит. Сосед, который сам работает через
      # REALITY, отдаёт украденный сертификат CDN: без этой проверки
      # www.cloudflare.com попал бы в список «соседей», резолвясь при этом в
      # чужую сеть, то есть ровно в тот мисматч ASN, от которого мы и уходим.
      # Оставляем только имена с адресом внутри сканированного диапазона —
      # и не своим: dest на самого себя это петля.
      for ip in $(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u); do
        [[ "$ip" == "$self" ]] && continue
        if _ip_in_cidr "$ip" "$cidr"; then echo "$d"; break; fi
      done
    done | head -"$lim"
  rm -f "$out"
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

# ─────────────────────────────────────────────────────────────────────────────
# set-port — сменить порт inbound с проверкой занятости, UFW и откатом.
#
# Номер порта DPI и сканер видят до всякого анализа TLS: сертификат крупного
# сайта на 8443 обесценивает маскировку REALITY, а сами эти номера — первые в
# списке любого сканера прокси. 443 стоит разового перевыпуска URI.
#
# Занятость проверяется только по TCP: служба на UDP с тем же номером нам не
# мешает — частый случай, когда 443/udp занят, а 443/tcp свободен.
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
    apply)
      [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm autoupd apply${NC}"; exit 1; }
      command -v unattended-upgrade >/dev/null 2>&1 \
        || warn "Пакет unattended-upgrades не установлен — политику запишу, но применять её некому: sudo apt install -y unattended-upgrades"
      if _autoupd_apply; then
        ok "Политика записана, таймеры включены"
        echo -e "\n${BOLD}Ветки, принятые apt:${NC}"
        _autoupd_origins | sed 's/^/  /'
        info "Что реально поставится сегодня: sudo xm autoupd now"
      else
        fail "apt отверг записанную политику — файлы возвращены как были"
        apt-config dump 2>&1 >/dev/null | head -3 | sed 's/^/    /'
        exit 1
      fi
      ;;
    on)   systemctl enable --now apt-daily.timer apt-daily-upgrade.timer; ok "Включено" ;;
    off)  systemctl disable --now apt-daily-upgrade.timer; ok "Выключено" ;;
    now)  unattended-upgrade --dry-run -v 2>&1 | tail -20 ;;
    log)  tail -40 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null || echo "Лог пуст" ;;
    *)    systemctl list-timers apt-daily-upgrade.timer --no-pager | sed 's/^/  /'
      # Ветки важнее расписания: таймер может исправно ходить каждый вечер и
      # ставить при этом одни security-патчи. Ровно так это и выглядело до
      # того, как в политику добавили -updates.
      echo -e "\n${BOLD}Ветки, из которых ставятся обновления:${NC}"
      UUO=$(_autoupd_origins)
      if [[ -z "$UUO" ]]; then
        warn "ни одной — автообновления не поставят ничего. Применить: sudo xm autoupd apply"
      else
        sed 's/^/  /' <<< "$UUO"
        grep -q -- '-updates' <<< "$UUO" \
          || warn "только security: обычные обновления не приезжают. Применить: sudo xm autoupd apply"
      fi
      [[ -f /var/run/reboot-required ]] && warn "Требуется перезагрузка (обновлено ядро/libc) — перезагрузи в удобное время"
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

# Журнал разбора проблем этой установки. Отдельно от $LOG (это вывод Xray) —
# сюда идут выводы и решения самого разбора, вручную, а не построчно из
# процесса. Файл заводит setup.sh; add создаёт его и здесь же, если сервер
# получил эту команду через self-update раньше, чем переустановку.
journal)
    case "${2:-show}" in
      add)
        [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm journal add \"текст\"${NC}"; exit 1; }
        JTEXT="${3:-}"
        [[ -z "$JTEXT" ]] && { echo -e "${RED}Пусто: sudo xm journal add \"текст\"${NC}"; exit 1; }
        [[ -f "$JOURNAL_FILE" ]] || install -m 600 -o root -g root /dev/null "$JOURNAL_FILE"
        ( umask 077; printf '\n## %s\n%s\n' "$(date -Is)" "$JTEXT" >> "$JOURNAL_FILE" )
        ok "Добавлено: $JOURNAL_FILE"
        ;;
      show)
        if [[ -f "$JOURNAL_FILE" ]]; then
          cat "$JOURNAL_FILE"
        else
          echo "Журнала ещё нет. Создастся сам при первом: sudo xm journal add \"текст\""
        fi
        ;;
      *)
        echo -e "${RED}xm journal [show|add \"текст\"]${NC}"; exit 1 ;;
    esac
    ;;

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
    echo "  Журнал:      $JOURNAL_FILE"
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
    # Заменено с проверки geoip:cn/ir — она рапортовала защиту,
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

    # A2 — правдоподобен ли домен-маска для НАШЕЙ сети. Блок A выше проверяет,
    # что все источники называют один домен; здесь — стоит ли вообще называть
    # именно его. Мисматч ASN у REALITY неустраним, вопрос в цене проверки.
    echo -e "\n  ${BOLD}A2. Домен-маска против нашего ASN${NC}"
    if ! command -v whois &>/dev/null; then
      info "whois не установлен — ASN не проверить. Поставить: ${BOLD}sudo apt install -y whois${NC}"
    else
      A_EDGE_IP=$(getent ahostsv4 "$SNI" 2>/dev/null | awk '{print $1}' | sort -u | head -1)
      A_OUR=""; A_THEIR=""
      [[ -n "$SERVER_IP" ]]  && A_OUR=$(_asn_info "$SERVER_IP" 2>/dev/null)
      [[ -n "$A_EDGE_IP" ]]  && A_THEIR=$(_asn_info "$A_EDGE_IP" 2>/dev/null)
      if [[ -z "$A_OUR" || -z "$A_THEIR" ]]; then
        info "ASN не определился (whois.cymru.com недоступен?) — проверка пропущена"
      else
        IFS='|' read -r A_OUR_AS  A_OUR_PFX  A_OUR_NAME  <<< "$A_OUR"
        IFS='|' read -r A_TH_AS   A_TH_PFX   A_TH_NAME   <<< "$A_THEIR"
        info "Наш AS${A_OUR_AS} ${A_OUR_NAME} | edge домена-маски AS${A_TH_AS} ${A_TH_NAME}"
        if [[ "$A_OUR_AS" == "$A_TH_AS" ]]; then
          ok "Домен-маска живёт в нашей же сети — мисматча ASN нет, признака цензору не даём"
        else
          # Один класс на любой мисматч, а не два. Для проверки цензору ASN не
          # нужен вовсе: он резолвит имя из SNI и сравнивает с адресом, куда
          # идёт соединение. Это одно сравнение и когда домен раздаёт сам
          # владелец, и когда его раздаёт сторонний CDN, — делить их на
          # «критично» и «предупреждение» значило бы выдавать за разные классы
          # одну и ту же проверку. Вдобавок закрыть мисматч нечем, кроме соседа
          # по сети, которого у многих просто нет: вечное «Критично», которое
          # нельзя убрать, обесценивает счётчик рядом с настоящими находками —
          # утечкой DNS или открытым портом.
          dwarn "Домен-маска в чужой сети — мисматч ASN. Цензору хватит резолва имени и сравнения с адресом соединения, ничего дороже не нужно. Убрать признак: ${BOLD}sudo xm sni-scan --local${NC}"
          [[ -n "$(_domain_label "$SNI")" ]] \
            && grep -qiF -- "$(_domain_label "$SNI")" <<< "$A_TH_NAME" \
            && info "Домен раздаёт собственная сеть владельца — на другой глобальный CDN менять смысла нет, там та же картина"
        fi
      fi
    fi

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
    # склеил бы два кода в "000000". Ошибку глушим отдельно.
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
      # "no host in upstream" — следы режима strict, снятого вместе с
      # переходом на mimic. Не считаем и не печатаем, но пропускаем через
      # next: иначе эти строки попадут в общий счётчик отказов и в метку
      # последнего отказа, состарив картину на месяцы назад.
      read -r E_RESOLV E_RESET E_TMOUT D_RESOLV D_RESET D_TMOUT D_ALL EL_LAST < <(
        awk -v cut="$EL_CUT" '
          { ts = $1 " " $2; rec = (cut != "" && ts >= cut) }
          /could not be resolved/ { r++; if (rec) dr++ }
          /reset by peer/         { s++; if (rec) ds++ }
          /upstream timed out/    { t++; if (rec) dt++ }
          /no host in upstream/   { next }
          { last = ts; if (rec) da++ }
          END { printf "%d %d %d %d %d %d %d %s\n",
                       r, s, t, dr, ds, dt, da, (last == "" ? "-" : last) }
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

    # Объявленные локальные правила. Здесь важно не «открыто ли», а «не
    # потерялось ли»: setup.sh --reinstall и `ufw reset` сносят их молча, и
    # обнаруживается это обычно по неработающей службе, а не по выводу diag.
    if [[ -f "$ACCESS_STATE" ]]; then
      sep
      echo -e "${BOLD}Локальные правила доступа:${NC}"
      AC_MISS=0
      while read -r ai as ap apr; do
        [[ -z "$ai" ]] && continue
        if _access_in_ufw "$ai" "$as" "$ap" "$apr"; then
          ok "${ap}/${apr} $(_access_scope "$ai" "$as")"
        else
          fail "${ap}/${apr} $(_access_scope "$ai" "$as") — объявлено, а в ufw НЕТ"
          AC_MISS=$((AC_MISS + 1))
        fi
      done < <(_access_rules)
      [[ "$AC_MISS" -gt 0 ]] && info "Вернуть: sudo xm access apply"
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
    # Пул массовых CDN-имён: домен-маска должна быть тем, обращение к чему с
    # этого адреса никого не удивит. Узкий пул = узкий выбор — на четырёх
    # именах в окно ML-DSA могло не попасть ни одно, и менять было бы не на что.
    #
    # www.microsoft.com в пул не входит: cert+OCSP ≈ 9085 б против буфера
    # REALITY ~8192 б (замерено, см. setup.sh), то есть вердикт «НЕ ГОДИТСЯ»
    # известен заранее. Держать его здесь значило тратить SNI_PROBES
    # хендшейков с таймаутом на кандидата, который не может победить.
    POOL=(www.apple.com swcdn.apple.com dl.google.com
          cdn.jsdelivr.net www.cloudflare.com)

    # --local [CIDR] — искать соседей в своей сети вместо глобального пула.
    # Любой домен отсюда мисматча ASN не даёт вовсе, тогда как весь пул выше
    # даёт его по определению. Диапазон по умолчанию — своя /24: 256 адресов
    # уходят за полминуты и заведомо принадлежат тому же хостеру.
    LOCAL_MODE=0; LOCAL_CIDR=""
    declare -a LOCAL_SET=()
    if [[ "${2:-}" == "--local" ]]; then
      LOCAL_MODE=1; LOCAL_CIDR="${3:-}"
    fi

    if [[ "$LOCAL_MODE" -eq 1 ]]; then
      echo -e "${BOLD}${CYAN}[ Подбор домена-маски в своей сети ]${NC}"
      # Бинарник сканера ставится в /usr/local/lib/xm — без root это упёрлось бы
      # в отказ mv и было бы названо «не скачался», то есть не своей причиной.
      if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Запусти от root: sudo xm sni-scan --local${NC}"; exit 1
      fi
      MY_IP=$(_get_server_ip)
      if [[ -z "$MY_IP" || "$MY_IP" == "SERVER_IP" ]]; then
        fail "Не определить свой внешний адрес"; exit 1
      fi
      [[ -z "$LOCAL_CIDR" ]] && LOCAL_CIDR="${MY_IP%.*}.0/24"
      if [[ ! "$LOCAL_CIDR" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
        fail "Диапазон задаётся как CIDR, например 198.51.100.0/24"; exit 1
      fi
      LOCAL_BITS="${LOCAL_CIDR#*/}"
      # Шире /16 — это десятки тысяч обращений к чужим адресам и часы работы.
      # Такой диапазон не «сеть по соседству», а заявка на жалобу хостеру.
      if [[ "$LOCAL_BITS" -lt 16 || "$LOCAL_BITS" -gt 32 ]]; then
        fail "Диапазон должен быть между /16 и /32 — шире это часы сканирования чужих адресов"; exit 1
      fi

      if command -v whois &>/dev/null; then
        MY_ASN_LINE=$(_asn_info "$MY_IP" 2>/dev/null)
        if [[ -n "$MY_ASN_LINE" ]]; then
          IFS='|' read -r M_AS M_PFX M_NAME <<< "$MY_ASN_LINE"
          info "Наша сеть: AS${M_AS} ${M_NAME} (анонс ${M_PFX})"
          [[ "$LOCAL_CIDR" != "$M_PFX" ]] \
            && info "Весь анонс целиком: ${BOLD}sudo xm sni-scan --local ${M_PFX}${NC}"
        fi
      else
        warn "whois не установлен — ASN не покажу. Поставить: sudo apt install -y whois"
      fi

      info "Качаю RealiTLScanner ${RTS_VER} (XTLS, MPL-2.0)..."
      _rts_ensure; RTS_RC=$?
      case "$RTS_RC" in
        0) : ;;
        2) fail "Контрольная сумма RealiTLScanner не сошлась — бинарник НЕ установлен."
           fail "Это либо подмена файла, либо новая сборка под тем же тегом. Разберись прежде чем запускать."; exit 1 ;;
        *) fail "RealiTLScanner не скачался (сеть или неподдерживаемая архитектура)"; exit 1 ;;
      esac

      warn "Сканирую ${LOCAL_CIDR}. Это обращения к чужим адресам — у части хостеров против правил."
      # 16 потоков, таймаут 5 с: худший случай — все адреса мертвы. Для /24 это
      # полторы минуты, для предложенного выше анонса может быть и полчаса.
      LOCAL_SEC=$(( (1 << (32 - LOCAL_BITS)) * 5 / 16 ))
      if [[ "$LOCAL_SEC" -lt 120 ]]; then
        info "До двух минут..."
      else
        info "Адресов $(( 1 << (32 - LOCAL_BITS) )) — до $(( LOCAL_SEC / 60 )) мин"
      fi
      mapfile -t LOCAL_SET < <(_rts_candidates "$LOCAL_CIDR" "$MY_IP" 10)
      if [[ ${#LOCAL_SET[@]} -eq 0 ]]; then
        sep
        fail "Соседей с TLS1.3 + h2, компактным сертификатом и именем, которое резолвится обратно в ${LOCAL_CIDR}, нет."
        info "Попробуй весь анонс хостера или оставь глобальный домен: sudo xm sni-scan"
        exit 1
      fi
      ok "Кандидатов найдено: ${#LOCAL_SET[@]} — замеряю их так же, как глобальные"
      POOL=("${LOCAL_SET[@]}")
    else
      echo -e "${BOLD}${CYAN}[ Подбор домена-маски ]${NC}"
    fi

    CUR=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
    # В локальном режиме текущую маску не подмешиваем: она почти всегда из чужой
    # сети, а таблица должна состоять из соседей — иначе «лучшим соседом» может
    # оказаться глобальный CDN, выигравший пару миллисекунд RTT. Если текущая
    # маска и есть сосед — скан найдёт её сам и пометит «← текущий».
    if [[ "$LOCAL_MODE" -eq 0 && -n "$CUR" ]] && ! printf '%s\n' "${POOL[@]}" | grep -qx "$CUR"; then
      POOL=("$CUR" "${POOL[@]}")
    fi
    info "$SNI_PROBES хендшейков на домен, ${#POOL[@]} доменов — одна-три минуты"
    sep
    printf "  %-24s %8s %4s %7s %6s  %s\n" "домен" "cert,б" "h2" "RTT,мс" "проб" "вердикт"
    BEST=""; BEST_RTT=999999; BEST_EST=0; BEST_FAIL=999
    BEST_PQ=""; BEST_PQ_RTT=999999; BEST_PQ_EST=0; BEST_PQ_FAIL=999
    for h in "${POOL[@]}"; do
      EST=$(_check_cert_size "$h")
      if [[ "$EST" == "-1" ]]; then
        printf "  %-24s %8s %4s %7s %6s  ${RED}%s${NC}\n" "$h" "-" "-" "-" "-" "НЕДОСТУПЕН"; continue
      fi

      # Несколько хендшейков вместо одного. Домен, который рвёт каждое второе
      # соединение, на единственной удачной попытке выглядел безупречно —
      # ровно та картина, из-за которой нестабильный dest и уезжал в конфиг.
      OK_N=0; RTT_SUM=0; H2=нет; T13=нет
      for _ in $(seq 1 "$SNI_PROBES"); do
        T0=$(date +%s%N)
        HS=$(echo | timeout "$SNI_PROBE_TIMEOUT" openssl s_client -connect "$h:443" -servername "$h" \
             -tls1_3 -alpn h2 2>/dev/null)
        T1=$(date +%s%N)
        [[ -z "$HS" ]] && continue
        OK_N=$((OK_N + 1)); RTT_SUM=$(( RTT_SUM + (T1 - T0) / 1000000 ))
        printf '%s' "$HS" | grep -qi "ALPN protocol: h2" && H2=да
        printf '%s' "$HS" | grep -q  "TLSv1.3"           && T13=да
      done
      if [[ "$OK_N" -eq 0 ]]; then
        printf "  %-24s %8s %4s %7s %6s  ${RED}%s${NC}\n" \
               "$h" "$EST" "-" "-" "0/$SNI_PROBES" "НЕ ОТВЕЧАЕТ"; continue
      fi
      RTT=$(( RTT_SUM / OK_N ))

      # ELIG=1 — кандидата можно выбрать. РИСК и потери проб оставляют домен
      # в таблице, но из выбора убирают: это данные для глаз, не рекомендация.
      V="ГОДИТСЯ"; C="$GREEN"; PQ=0; ELIG=1
      if   [[ "$EST" -ge "$REALITY_CERT_LIMIT" ]]; then V="НЕ ГОДИТСЯ"; C="$RED";    ELIG=0
      elif [[ "$EST" -ge "$REALITY_CERT_WARN"  ]]; then V="РИСК";       C="$YELLOW"; ELIG=0
      elif [[ "$EST" -ge "$REALITY_CERT_PQ_MIN" && "$EST" -le "$REALITY_CERT_PQ_MAX" ]]; then
        V="ГОДИТСЯ +PQ"; PQ=1
      fi
      [[ "$H2" != "да" || "$T13" != "да" ]] && { V="НЕТ h2/TLS1.3"; C="$RED"; ELIG=0; PQ=0; }
      FAIL_N=$(( SNI_PROBES - OK_N ))
      [[ "$FAIL_N" -gt 0 ]] && { V="$V, РВЁТ"; C="$YELLOW"; }

      VP="$V"; [[ "$h" == "$CUR" ]] && VP="$V ← текущий"
      printf "  %-24s %8s %4s %7s %6s  ${C}%s${NC}\n" \
             "$h" "$EST" "$H2" "$RTT" "$OK_N/$SNI_PROBES" "$VP"

      # Ранжируем сперва по потерям, и только при равенстве — по RTT. Порядок
      # именно такой: домен, который рвёт соединения, дороже любых сэкономленных
      # миллисекунд, потому что каждый обрыв — это непрошедший коннект клиента.
      # Размер сертификата в ранжировании не участвует вовсе: он важен только
      # порогами, внутри допустимого диапазона сотня байт не даёт ничего.
      # Домен с потерями не выбрасываем, а ставим ниже: если потери есть у всех,
      # выбирать всё равно придётся, и «ни один не прошёл» — не ответ.
      if [[ "$ELIG" -eq 1 ]]; then
        if [[ "$FAIL_N" -lt "$BEST_FAIL" \
           || ( "$FAIL_N" -eq "$BEST_FAIL" && "$RTT" -lt "$BEST_RTT" ) ]]; then
          BEST="$h"; BEST_RTT="$RTT"; BEST_EST="$EST"; BEST_FAIL="$FAIL_N"
        fi
        if [[ "$PQ" -eq 1 ]] \
           && [[ "$FAIL_N" -lt "$BEST_PQ_FAIL" \
              || ( "$FAIL_N" -eq "$BEST_PQ_FAIL" && "$RTT" -lt "$BEST_PQ_RTT" ) ]]; then
          BEST_PQ="$h"; BEST_PQ_RTT="$RTT"; BEST_PQ_EST="$EST"; BEST_PQ_FAIL="$FAIL_N"
        fi
      fi
    done
    sep
    # Два кандидата, а не один, когда они расходятся: выбор между «RTT до dest
    # ниже» и «доступен ML-DSA» — это размен, а не вычисление. Прежняя версия
    # такой размен делала молча (брала минимальный сертификат) и тем закрывала
    # ML-DSA навсегда; повторять это, поменяв только критерий, нет смысла.
    if [[ -n "$BEST_PQ" && -n "$BEST" && "$BEST_PQ" != "$BEST" ]]; then
      ok "Стабильнее всех: ${BOLD}$BEST${NC} (~${BEST_EST} б, RTT ${BEST_RTT} мс, потерь ${BEST_FAIL}/${SNI_PROBES}) — ML-DSA недоступен"
      ok "С окном ML-DSA: ${BOLD}$BEST_PQ${NC} (~${BEST_PQ_EST} б, RTT ${BEST_PQ_RTT} мс, потерь ${BEST_PQ_FAIL}/${SNI_PROBES})"
      echo -e "  Применить: ${BOLD}sudo xm set-sni <домен>${NC}; после второго — ещё ${BOLD}sudo xm pq on${NC}"
    elif [[ -n "$BEST_PQ" ]]; then
      ok "Лучший кандидат: ${BOLD}$BEST_PQ${NC} (~${BEST_PQ_EST} б, RTT ${BEST_PQ_RTT} мс, потерь ${BEST_PQ_FAIL}/${SNI_PROBES}) — попадает в окно ML-DSA"
      [[ "$BEST_PQ" != "$CUR" ]] \
        && echo -e "  Применить: ${BOLD}sudo xm set-sni $BEST_PQ${NC}, затем ${BOLD}sudo xm pq on${NC}"
    elif [[ -n "$BEST" ]]; then
      ok "Лучший кандидат: ${BOLD}$BEST${NC} (~${BEST_EST} б, RTT ${BEST_RTT} мс, потерь ${BEST_FAIL}/${SNI_PROBES})"
      info "В окно ML-DSA (${REALITY_CERT_PQ_MIN}–${REALITY_CERT_PQ_MAX} б) не попал никто — xm pq останется недоступен"
      [[ "$BEST" != "$CUR" ]] && echo -e "  Применить: ${BOLD}sudo xm set-sni $BEST${NC}"
    elif [[ "$LOCAL_MODE" -eq 1 ]]; then
      fail "Ни один сосед не прошёл замер — возьми диапазон шире (весь анонс хостера) или оставь глобальный домен"
    else
      fail "Ни один кандидат не прошёл — расширь POOL в xm.sh"
    fi
    if [[ "$LOCAL_MODE" -eq 1 ]]; then
      info "Смысл соседа — в отсутствии мисматча ASN, а не в RTT. Но малонагруженный сайт, к которому наш адрес стучится круглосуточно, — своя аномалия: выбирай тот, что похож на живой сервис."
    else
      info "Все кандидаты выше — чужие сети, то есть мисматч ASN по определению. Искать соседа: ${BOLD}sudo xm sni-scan --local${NC}"
    fi
    [[ -n "$BEST" && "$BEST_FAIL" -gt 0 ]] \
      && warn "Даже лучший кандидат потерял ${BEST_FAIL} из ${SNI_PROBES} проб — путь ОТ ЭТОГО VPS до масок нестабилен, дело может быть не в домене"
    info "Доля отказов в единицы процентов ${SNI_PROBES} пробами не ловится. Её считает xm diag-dpi, блок G: «отказы fallback за 24 ч»"
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
    # somaxconn сам по себе на nginx не действует — правим его listen отдельно,
    # иначе очередь accept продолжит переполняться при применённом профиле.
    _ngx_backlog_fix || true

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

# access — порты своих служб, которые должны уцелеть после переустановки.
#
# Команда намеренно ничего не знает о том, что за служба за портом: её работа —
# помнить тройку (интерфейс, источник, порт) и возвращать её в ufw после того,
# как setup.sh --reinstall или `ufw reset` всё переписали.
access)
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запусти от root: sudo xm access${NC}"; exit 1; }
    ASUB="${2:-status}"

    # Разбор общий для add и del: <порт>/<proto> [интерфейс|-] [источник|-].
    # --force ловим в любой позиции, иначе он уехал бы в интерфейс.
    _access_parse() {
      ASPEC="${1:-}"; AIFACE="${2:--}"; ASRC="${3:--}"
      [[ "$AIFACE" == "--force" ]] && AIFACE="-"
      [[ "$ASRC"   == "--force" ]] && ASRC="-"
      [[ -z "$AIFACE" ]] && AIFACE="-"
      [[ -z "$ASRC"   ]] && ASRC="-"
      if [[ "$ASPEC" != */* ]]; then
        echo -e "${BOLD}Использование:${NC} xm access $ASUB <порт>/<tcp|udp> [интерфейс|-] [источник CIDR|-]"
        echo    "  xm access $ASUB 8080/tcp wg0              — только с интерфейса wg0"
        echo    "  xm access $ASUB 8080/tcp - 203.0.113.5    — только с одного адреса"
        return 1
      fi
      APORT="${ASPEC%%/*}"; APROTO="${ASPEC##*/}"
      return 0
    }

    case "$ASUB" in
      add)
        _access_parse "${3:-}" "${4:-}" "${5:-}" || exit 1
        AFORCE=false
        for a in "$@"; do [[ "$a" == "--force" ]] && AFORCE=true; done

        # Правило без интерфейса и без источника — это «наружу всему миру», и
        # почти всегда не то, чего хотели. У службы за таким портом обычно нет
        # своего TLS, а лишний открытый порт с чужим баннером сканер находит
        # первым же проходом (diag-dpi, блок B) — вся маскировка REALITY при
        # этом обесценивается соседней строкой в выводе nmap.
        if [[ "$AIFACE" == "-" && "$ASRC" == "-" ]]; then
          fail "Без интерфейса и без источника порт открывается всему интернету"
          info "Ограничь интерфейсом (туннель, локальный бридж) или адресом —"
          info "тогда снаружи порта не видно вообще, и сканеру нечего находить."
          $AFORCE || { info "Если нужно именно так: повтори команду с --force"; exit 1; }
          warn "--force: ${APORT}/${APROTO} будет открыт всему интернету"
        fi

        _access_valid "$AIFACE" "$ASRC" "$APORT" "$APROTO" || exit 1
        _access_state_init

        # Повторный add тем же правилом не должен плодить строки. Фильтруем
        # awk'ом по точному совпадению, а не sed'ом: в источнике есть «/» от
        # CIDR, и он ломает разделитель шаблона.
        ATMP=$(mktemp)
        awk -v r="RULE $AIFACE $ASRC $APORT $APROTO" '$0 != r' "$ACCESS_STATE" > "$ATMP"
        cat "$ATMP" > "$ACCESS_STATE"; rm -f "$ATMP"
        echo "RULE $AIFACE $ASRC $APORT $APROTO" >> "$ACCESS_STATE"
        ok "Объявлено: ${APORT}/${APROTO} $(_access_scope "$AIFACE" "$ASRC")"

        if _access_apply; then
          if ufw status 2>/dev/null | grep -q "Status: active"; then
            ok "UFW: применено (правил в ufw: $ACCESS_OK_N)"
          else
            info "UFW не активен — правило сохранено и применится при включении"
          fi
        else
          warn "Часть правил не применилась — sudo xm access status"
        fi
        info "Файл переживает переустановку: $ACCESS_STATE"
        echo ""
        ;;

      del)
        _access_parse "${3:-}" "${4:-}" "${5:-}" || exit 1
        [[ -f "$ACCESS_STATE" ]] || { fail "Объявленных правил нет"; exit 1; }
        grep -qx "RULE $AIFACE $ASRC $APORT $APROTO" "$ACCESS_STATE" \
          || { fail "Такого правила нет — посмотри: sudo xm access status"; exit 1; }

        ATMP=$(mktemp)
        awk -v r="RULE $AIFACE $ASRC $APORT $APROTO" '$0 != r' "$ACCESS_STATE" > "$ATMP"
        cat "$ATMP" > "$ACCESS_STATE"; rm -f "$ATMP"
        ok "Убрано из объявленных: ${APORT}/${APROTO} $(_access_scope "$AIFACE" "$ASRC")"

        mapfile -t AARGS < <(_access_ufw_args "$AIFACE" "$ASRC" "$APORT" "$APROTO")
        if ufw delete "${AARGS[@]}" >/dev/null 2>&1; then
          ok "UFW: правило снято"
        else
          warn "UFW правило не снял — проверь вручную: sudo ufw status numbered"
        fi
        echo ""
        ;;

      apply)
        [[ -f "$ACCESS_STATE" ]] || { info "Объявленных правил нет — нечего применять"; exit 0; }
        if _access_apply; then
          ok "Применено правил: $ACCESS_OK_N"
        else
          fail "Не применилось: $ACCESS_BAD_N (применено: $ACCESS_OK_N)"
          exit 1
        fi
        ufw status 2>/dev/null | grep -q "Status: active" \
          || info "UFW не активен — правила вступят в силу при включении"
        echo ""
        ;;

      clear)
        [[ -f "$ACCESS_STATE" ]] || { info "Объявленных правил нет"; exit 0; }
        echo -e "\n${BOLD}${CYAN}[ Снятие всех локальных правил ]${NC}\n"
        while read -r ai as ap apr; do
          [[ -n "$ai" ]] && info "${ap}/${apr} $(_access_scope "$ai" "$as")"
        done < <(_access_rules)
        read -rp "Снять их в ufw и забыть? Введи ДА: " ACLR
        [[ "$ACLR" == "ДА" ]] || { info "Отменено, ничего не изменено"; exit 0; }
        while read -r ai as ap apr; do
          [[ -z "$ai" ]] && continue
          mapfile -t AARGS < <(_access_ufw_args "$ai" "$as" "$ap" "$apr")
          ufw delete "${AARGS[@]}" >/dev/null 2>&1 \
            && ok "UFW: снято ${ap}/${apr}" \
            || warn "UFW не снял ${ap}/${apr} — проверь: sudo ufw status numbered"
        done < <(_access_rules)
        rm -f "$ACCESS_STATE"
        ok "Объявленных правил больше нет"
        echo ""
        ;;

      *)
        echo -e "\n${BOLD}${CYAN}[ Локальные правила доступа ]${NC}\n"
        if [[ ! -f "$ACCESS_STATE" ]]; then
          info "Правил нет — ни одного лишнего порта проект не открывает"
          sep
          echo -e "${BOLD}Добавить${NC}"
          echo    "  xm access add 8080/tcp wg0              только с интерфейса wg0"
          echo    "  xm access add 8080/tcp - 203.0.113.5    только с одного адреса"
          echo ""
          exit 0
        fi
        # Построчно, а не таблицей: область действия пишется по-русски, а
        # printf выравнивает по БАЙТАМ — кириллица в колонках разъезжается.
        AMISS=0
        while read -r ai as ap apr; do
          [[ -z "$ai" ]] && continue
          ADESC="${ap}/${apr} — $(_access_scope "$ai" "$as")"
          # Слушателя ищем по номеру порта в конце локального адреса: правило
          # разрешает порт, а на каком адресе служба его держит — её дело.
          if [[ "$apr" == "udp" ]]; then ALST=$(ss -uln 2>/dev/null | tail -n +2)
          else ALST=$(ss -tln 2>/dev/null | tail -n +2); fi
          if echo "$ALST" | awk -v pp=":$ap" '$4 ~ pp"$"' | grep -q .; then ALIVE=1; else ALIVE=0; fi
          if ! _access_in_ufw "$ai" "$as" "$ap" "$apr"; then
            fail "$ADESC · объявлено, а в ufw НЕТ"
            AMISS=$((AMISS + 1))
          elif [[ "$ALIVE" -eq 0 ]]; then
            warn "$ADESC · в ufw есть, но на порту никто не слушает"
          else
            ok "$ADESC · в ufw есть, слушатель есть"
          fi
        done < <(_access_rules)
        sep
        [[ "$AMISS" -gt 0 ]] \
          && warn "Правил нет в ufw: $AMISS — вернуть: sudo xm access apply" \
          || ok "Все объявленные правила стоят в ufw"
        info "Объявления живут в $ACCESS_STATE и переживают setup.sh --reinstall"
        info "Убрать одно: sudo xm access del <порт>/<proto> [интерфейс|-] [источник|-]"
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
      DOT_F=$(_resolved_dns_file) || DOT_F=""
      if [[ -n "$DOT_F" && "$DOT_F" != "$RESOLVED_DROPIN" ]]; then
        # DNS= уже задан чужим файлом. Свой рядом класть нельзя: два drop-in
        # спорят за одну настройку, и кто победит — вопрос имени файла.
        # Правим ровно одну строку в существующем, остальное не трогаем.
        info "DNS= задаёт $DOT_F — правлю в нём одну строку, второй drop-in не завожу"
        DOT_BAK="${DOT_F}.bak_$(date +%Y%m%d_%H%M%S)"
        cp "$DOT_F" "$DOT_BAK"
        sed -i -E "s|^([[:space:]]*)DNS=.*|\\1DNS=$(_resolved_dot_dns)|" "$DOT_F"
        systemctl restart systemd-resolved 2>/dev/null; sleep 1
        if ! { _resolved_dot_on && resolvectl query example.com &>/dev/null; }; then
          fail "Резолвинг с новыми апстримами не поднялся — откат"
          cp "$DOT_BAK" "$DOT_F"; systemctl restart systemd-resolved 2>/dev/null
          warn "Прежняя конфигурация на месте. Бэкап: $DOT_BAK"
          exit 1
        fi
        ok "Апстримы в $DOT_F заменены на четыре (Cloudflare ×2, Quad9, Google)"
        info "Бэкап: $DOT_BAK — это НЕ наш файл, ${BOLD}xm harden --off${NC} его не тронет"
      elif _resolved_write_dot; then
        ok "Применено: четыре апстрима по :853 (Cloudflare ×2, Quad9, Google), FallbackDNS пуст"
        info "Файл: $RESOLVED_DROPIN — убирается вместе с sudo xm harden --off"
      else
        fail "DoT с нашими апстримами не поднялся — откат, прежняя конфигурация на месте"
        warn "Проверь вручную: sudo resolvectl query example.com, затем sudo resolvectl status"
        exit 1
      fi
      DOT_NEW=$(_resolved_dns_line)
      info "Стало: $DOT_NEW"
      # Файлы применяются в лексическом порядке имён, последнее присваивание
      # побеждает. Если правка перекрыта файлом с именем позже — это надо
      # увидеть, а не считать, что применилось.
      [[ "$DOT_NEW" == "$(_resolved_dot_dns)" ]] \
        || warn "Эффективный список отличается от заданного — значит DNS= перекрывает файл с именем, сортирующимся позже. Смотри: sudo systemd-analyze cat-config systemd/resolved.conf"
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

    # Проверяем ВСЁ, что делает harden, а не три шага из пяти. Прежняя версия
    # не смотрела ни на строгий DoT, ни на резолвер nginx — и печатала
    # «применён полностью» на сервере, где diag-dpi одновременно ругался и на
    # открытый UDP/53 у стаба, и на resolver 1.1.1.1 в fallback. Ложное
    # «всё хорошо» здесь дороже отсутствия строки: пользователь не запускает
    # harden именно потому, что ему сказали, что он не нужен.
    NGX_RSLV_LOCAL=0
    grep -qE '^[[:space:]]*resolver[[:space:]]+127\.0\.0\.53' \
         /etc/nginx/stream-enabled/reality-fallback.conf 2>/dev/null && NGX_RSLV_LOCAL=1

    if _dns_doh_on && _dns_hijack_on && _ngx_mimic_on \
       && _resolved_dot_on && [[ "$NGX_RSLV_LOCAL" == "1" ]]; then
      ok "Анти-DPI хардening применён полностью"
    else
      warn "Хардening применён не весь                ${BOLD}sudo xm harden${NC}"
      _dns_doh_on    || echo "        · DoH на сервере выключен — домены резолвит хостер открытым текстом"
      _dns_hijack_on || echo "        · перехват :53 выключен"
      _ngx_mimic_on  || echo "        · nginx-fallback рвёт соединение на чужой SNI"
      _resolved_dot_on || echo "        · системный резолвер без строгого DoT — уходит открытым UDP/53"
      [[ "$NGX_RSLV_LOCAL" == "1" ]] || echo "        · nginx-fallback резолвит домен-маску публичным DNS мимо стаба"
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
    echo -e "  ${GREEN}xm access${NC}        только правила ufw из /usr/local/etc/xray/access.conf"
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
    echo -e "${BOLD}${CYAN}xm — менеджер Xray${NC}   sudo xm <команда>"
    echo ""
    echo -e "${BOLD}Клиенты${NC}     add [имя] · del · clients"
    echo    "            uri [имя|--tcp|--all] · qr [имя] [--tcp|--both|--all]"
    echo -e "${BOLD}Сервис${NC}      start · stop · restart · status · log · log-live · log-clear"
    echo -e "${BOLD}Конфиг${NC}      edit · test · apply · backup · restore · backups"
    echo -e "            ${GREEN}set-sni <домен>${NC}          домен-маска в config+nginx, с откатом"
    echo -e "            ${GREEN}set-port <порт> [--tcp]${NC}  порт inbound (443 предпочтителен)"
    echo -e "            ${GREEN}add-tcp${NC}                  второй inbound XTLS-Vision/TCP"
    echo -e "${BOLD}${GREEN}Анти-DPI${NC}    harden [--check|--off|--dot|--nonip drop|skip|off]"
    echo    "                                     DoH, строгий DoT, перехват :53, mimic"
    echo    "            tune [--check|--off]     сетевой стек, таймауты, watchdog"
    echo    "            watchdog on|off|now|status"
    echo    "            pq status|on|off         post-quantum подпись REALITY"
    echo -e "${BOLD}Порт 443${NC}    front on|off|status|add <sni> <порт>|del <sni>   делить 443 по SNI"
    echo    "            access status|add <порт>/<proto> [iface|-] [src|-]|del|apply|clear"
    echo -e "${BOLD}${GREEN}Проверка${NC}    ${GREEN}selftest [--tcp|--all]${NC}   живой хендшейк — начинай с неё"
    echo -e "            ${GREEN}diag${NC} · ${GREEN}diag-dpi [--quick]${NC} · sni-scan [--local [CIDR]] · neighbors"
    echo    "            reality-debug on|off · diag-ntp|diag-ports|diag-tls|diag-fw|diag-log"
    echo -e "${BOLD}Обновление${NC}  ${GREEN}self-update [--check|--force|--from <url>]${NC}  xm из репозитория"
    echo    "            update [--check] · update-geo · autoupd on|off|now|log|status"
    echo -e "${BOLD}Прочее${NC}      info · paths · uuid · pubkey · journal [show|add \"текст\"]"
    echo    "            nginx-status|nginx-log|nginx-reload|nginx-probes"
    echo    "            ban-list · ban-ssh-stat · unban <ip> · log-access"
    ;;
esac