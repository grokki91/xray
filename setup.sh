#!/usr/bin/env bash
# Xray-core · VLESS + REALITY + XHTTP · автоустановка · Ubuntu 22.04/24.04
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}▸ $*${NC}"; }

usage() {
  cat <<'USAGE'
sudo bash setup.sh [опции]

  --sni <домен>   домен-маска (по умолчанию подбирается замером)
  --port <порт>   порт XHTTP (по умолчанию 443)
  --scan-local    искать маску среди соседей по своей сети (+1.5 мин)
  --no-tcp        без второго inbound (XTLS-Vision/TCP)
  --reinstall     переустановка: новые ключи, выданные URI умрут
USAGE
}

SNI_ARG=""; PORT_ARG=""; SCAN_LOCAL=false; DUAL_INBOUND=true; REINSTALL=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sni)   SNI_ARG="${2:-}";  [[ -n "$SNI_ARG"  ]] || error "--sni требует домен";  shift 2 ;;
    --port)  PORT_ARG="${2:-}"; [[ -n "$PORT_ARG" ]] || error "--port требует номер"; shift 2 ;;
    --scan-local) SCAN_LOCAL=true;    shift ;;
    --no-tcp)     DUAL_INBOUND=false; shift ;;
    --reinstall)  REINSTALL=true;     shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            usage; error "Неизвестный аргумент: $1" ;;
  esac
done

[[ $EUID -ne 0 ]] && error "Запусти от root: sudo bash $0"

OS_VER=$(lsb_release -rs 2>/dev/null || echo "?")
case "$OS_VER" in
  24.04|22.04) ;;
  *) warn "Непроверенная версия ОС: $OS_VER — возможны сюрпризы" ;;
esac

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"
JOURNAL_FILE="/usr/local/etc/xray/journal.md"
XM_SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)/xm.sh"

# Парсинг ключей xray x25519: метки вывода менялись между версиями Xray.
_parse_xray_keys() {
  local output="$1"
  # Якорь по началу строки обязателен: в новых версиях Public key называется
  # Password, а само base64-значение может содержать слово public/private.
  PRIVATE_KEY=$(echo "$output" | grep -iE "^[[:space:]]*private"          | awk '{print $NF}' | head -1 | tr -d '[:space:]')
  PUBLIC_KEY=$(echo "$output"  | grep -iE "^[[:space:]]*(public|password)" | awk '{print $NF}' | head -1 | tr -d '[:space:]')

  # Валидация: ключ X25519 в base64url — 43 символа
  if [[ ${#PRIVATE_KEY} -lt 30 ]]; then
    error "Не удалось распарсить PrivateKey (длина ${#PRIVATE_KEY}).\nВывод xray x25519:\n$output"
  fi
  if [[ ${#PUBLIC_KEY} -lt 30 ]]; then
    error "Не удалось распарсить PublicKey (длина ${#PUBLIC_KEY}).\nВывод xray x25519:\n$output"
  fi
}

# QR в терминал: UTF8-блоки живут в любом ssh/tmux, -l L даёт код покороче.
_print_qr() {
  local uri="$1"
  local label="${2:-QR-код}"
  if command -v qrencode &>/dev/null; then
    echo -e "\n${BOLD}${CYAN}┌─────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  ${label}${NC}"
    echo -e "${BOLD}${CYAN}└─────────────────────────────────────────┘${NC}"
    qrencode -t UTF8 -m 1 -l L -s 2 "$uri" \
      || warn "QR не сгенерирован (URI слишком длинный? Попробуй: qrencode -t UTF8 -l L '...')"
  else
    warn "qrencode не найден — QR недоступен. Установи: apt install qrencode"
  fi
}

# Внешний IP с проверкой формата: источник может отдать HTML или пустоту.
_fetch_server_ip() {
  local ip
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me" \
    "https://api64.ipify.org"; do
    # "|| true": иначе pipefail обрывает функцию на первом же источнике.
    ip=$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "$ip"
      return 0
    fi
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ ${#ip} -gt 4 ]]; then
      echo "$ip"
      return 0
    fi
  done
  echo "ТВОЙ_IP"
  return 1
}

# =============================================================================
# Оценка размера TLS Certificate у dest. В ряде версий Xray буфер приёма
# Certificate ~8192 б: большая цепочка или OCSP-staple рвут REALITY-хендшейк
# молча, хотя curl к сайту отвечает 200. Печатает байты или -1 (недоступен).
# =============================================================================
REALITY_CERT_WARN=7000     # запас до лимита; между warn и limit — риск на части версий
REALITY_CERT_LIMIT=8192    # захардкоженный буфер REALITY в ряде версий Xray-core

# =============================================================================
# DoH на сервере + перехват :53 из тоннеля: без dns-блока Xray резолвит
# системным резолвером хостера открытым текстом. Резолверы заданы
# IP-литералом (нет открытого bootstrap), https+local:// — мимо routing,
# иначе перехват :53 зациклился бы сам на себе.
# =============================================================================
DOH_LIST='["https+local://1.1.1.1/dns-query","https+local://9.9.9.9/dns-query","https+local://8.8.8.8/dns-query"]'
DOH_IPS=(1.1.1.1 9.9.9.9 8.8.8.8)

# Отвечает ли резолвер по DoH именно с этого VPS (RFC 8484 wireformat GET).
_doh_probe() {
  local ip="$1" b64 code
  b64=$(python3 -c '
import base64, struct, sys
q = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0)
for l in sys.argv[1].split("."): q += bytes([len(l)]) + l.encode()
q += b"\x00" + struct.pack(">HH", 1, 1)
print(base64.urlsafe_b64encode(q).rstrip(b"=").decode())' example.com 2>/dev/null) || return 1
  [[ -z "$b64" ]] && return 1
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
         -H 'accept: application/dns-message' \
         "https://${ip}/dns-query?dns=${b64}" 2>/dev/null) || code="000"
  [[ "$code" == "200" ]]
}

_has_ipv6() { ip -6 route get 2001:4860:4860::8888 &>/dev/null; }

# Держит ли порт кто-то, кроме нашего же xray: на переустановке он ещё слушает,
# и без этой оговорки установка отказалась бы занимать собственный порт.
PORT_BUSY_BY=""; PORT_BUSY_LINE=""
_port_taken() {
  PORT_BUSY_LINE=$(ss -tlnp 2>/dev/null | grep -E ":$1([^0-9]|$)" | head -1 || true)
  [[ -n "$PORT_BUSY_LINE" ]] || return 1
  PORT_BUSY_BY=$(grep -oP 'users:\(\("\K[^"]+' <<< "$PORT_BUSY_LINE" || echo '?')
  [[ "$PORT_BUSY_BY" == "xray" ]] && return 1
  return 0
}

_check_cert_size() {
  local host="$1"
  local raw tmpd cert size total=0 ocsp_add=0 framing=0 ncerts=0

  raw=$(echo | timeout 10 openssl s_client -connect "${host}:443" \
        -servername "$host" -showcerts -status 2>/dev/null) || raw=""
  if [[ -z "$raw" ]]; then echo "-1"; return 0; fi

  tmpd=$(mktemp -d)
  # Разбиваем цепочку на отдельные PEM (описательные строки s:/i: openssl x509
  # игнорирует — проверено). Каждый BEGIN..END попадает в свой файл.
  printf '%s\n' "$raw" | awk -v d="$tmpd" '
    /-----BEGIN CERTIFICATE-----/ {c++}
    c>0 {print > (d "/cert" c ".pem")}
  '
  for cert in "$tmpd"/cert*.pem; do
    [[ -f "$cert" ]] || continue
    # || size=0 — иначе под set -o pipefail упавший openssl уронил бы функцию
    size=$(openssl x509 -in "$cert" -outform DER 2>/dev/null | wc -c) || size=0
    if [[ "${size:-0}" -gt 0 ]]; then
      total=$((total + size)); ncerts=$((ncerts + 1))
    fi
  done
  rm -rf "$tmpd"
  [[ "$ncerts" -eq 0 ]] && { echo "-1"; return 0; }

  # OCSP staple: точный размер из текста не достать, но факт наличия — да.
  # Типичный single-cert OCSP ~1500 б; закладываем консервативно (оценка верхняя).
  printf '%s' "$raw" | grep -qi "OCSP Response Data" && ocsp_add=1600
  # Служебные поля Certificate: 4+1+3 + по 6 на каждый cert (len+ext_len).
  framing=$((10 + ncerts * 6))
  echo $((total + ocsp_add + framing)); return 0
}

SELFTEST_HINT=""

# _sni_probe <host> → "cert|ocsp|alpn_h2|tls13|x25519|rtt|redirect".
# TLS1.3 обязателен для REALITY, ALPN h2 — для XHTTP. Конвейеры прикрыты
# "|| true": пустой grep под pipefail уронил бы скрипт. cert=-1 — недоступен.
_sni_probe() {
  local host="$1" raw n b o total h13 tls13 alpn2 x25519 t0 t1 rtt loc
  raw=$(echo | timeout 10 openssl s_client -connect "${host}:443" -servername "$host" \
        -showcerts -status 2>/dev/null) || raw=""
  if [[ -z "$raw" ]]; then echo "-1|0|нет|нет|нет|-1|"; return 0; fi

  n=$(printf '%s\n' "$raw" | grep -c "BEGIN CERTIFICATE" || true); n=${n:-0}
  b=$(printf '%s\n' "$raw" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
      | grep -vE 'BEGIN|END' | tr -d '\n' | wc -c || true); b=${b:-0}
  o=0; printf '%s' "$raw" | grep -qi "OCSP Response Data" && o=1600 || true
  total=$(( b*3/4 + o + 10 + n*6 ))

  h13=$(echo | timeout 8 openssl s_client -connect "${host}:443" -servername "$host" \
        -tls1_3 -alpn h2 2>/dev/null) || h13=""
  tls13="нет"; alpn2="нет"; x25519="нет"
  printf '%s' "$h13" | grep -q  "TLSv1.3"                      && tls13="да"   || true
  printf '%s' "$h13" | grep -qi "ALPN protocol: h2"            && alpn2="да"   || true
  printf '%s' "$h13" | grep -qi "TLS1.3 group: *x25519"        && x25519="да"  || true

  t0=$(date +%s%N)
  echo | timeout 8 openssl s_client -connect "${host}:443" -servername "$host" >/dev/null 2>&1 || true
  t1=$(date +%s%N); rtt=$(( (t1 - t0) / 1000000 ))

  loc=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 8 "https://${host}" 2>/dev/null \
        | awk -F/ '{print $3}' || true)
  [[ "$loc" == "$host" ]] && loc=""

  echo "${total}|${o}|${alpn2}|${tls13}|${x25519}|${rtt}|${loc}"
}

# =============================================================================
# Домен-маска в своей же сети. Мисматч ASN у REALITY есть всегда: наш адрес
# не может быть edge'ем чужого домена, и у глобального CDN эта проверка
# стоит цензору один статический список. Сосед по нашей сети сигнала не даёт
# вовсе — но он малонагружен, круглосуточный поток TLS к нему сам аномалия,
# и завтра он может исчезнуть. Поэтому это --scan-local, а не умолчание.
# =============================================================================
RTS_VER="v0.2.3"
RTS_BIN="/usr/local/lib/xm/RealiTLScanner"
# Суммы прибиты: сторонний бинарник, «последнее» вслепую не качаем.
RTS_SHA256_AMD64="a55595446de9f1c2e6c5c3cd766a7320a11115947df48f101749bb62c8055592"
RTS_SHA256_ARM64="27bdd3e53d4391c66c8df3391d3c3fb5eb2dc356125f2fb33ac58fcaaf8f88b3"

# _asn_info <ip> → "ASN|префикс|имя сети", пусто если не определилось.
_asn_info() {
  local ip="$1" line
  line=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1) || line=""
  [[ "$line" == *"|"* ]] || return 1
  # Cymru подставляет номер AS вместо незарегистрированного handle — срезаем.
  awk -F'|' '{ for (i = 1; i <= NF; i++) gsub(/^[ \t]+|[ \t]+$/, "", $i)
               sub(/^AS[0-9]+[ \t]*-[ \t]*/, "", $7)
               if ($1 ~ /^[0-9]+$/) print $1 "|" $3 "|" $7 }' <<< "$line"
}

# RealiTLScanner (XTLS, MPL-2.0) с проверкой суммы; повторный вызов не качает.
# Коды: 0 — готов, 1 — не скачался/чужая архитектура, 2 — сумма не сошлась.
_rts_ensure() {
  local arch want url tmp sum
  case "$(uname -m)" in
    x86_64)  arch="amd64"; want="$RTS_SHA256_AMD64" ;;
    aarch64) arch="arm64"; want="$RTS_SHA256_ARM64" ;;
    *)       return 1 ;;
  esac
  if [[ -x "$RTS_BIN" ]]; then
    sum=$(sha256sum "$RTS_BIN" 2>/dev/null | awk '{print $1}') || sum=""
    [[ "$sum" == "$want" ]] && return 0
  fi
  mkdir -p "$(dirname "$RTS_BIN")"
  tmp=$(mktemp) || return 1
  url="https://github.com/XTLS/RealiTLScanner/releases/download/${RTS_VER}/RealiTLScanner-linux-${arch}"
  curl -fsSL --max-time 180 -o "$tmp" "$url" 2>/dev/null || { rm -f "$tmp"; return 1; }
  sum=$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}') || sum=""
  [[ "$sum" == "$want" ]] || { rm -f "$tmp"; return 2; }
  chmod 755 "$tmp"; mv "$tmp" "$RTS_BIN"
}

# _ip_in_cidr <ip> <cidr> — адрес внутри диапазона, на арифметике bash.
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
# Свой адрес исключаем: иначе на повторном прогоне сервер предложит сам себя.
_rts_candidates() {
  local cidr="$1" self="$2" lim="${3:-12}" out d ip
  out=$(mktemp /tmp/rts.XXXXXX.csv) || return 1
  "$RTS_BIN" -addr "$cidr" -port 443 -thread 16 -timeout 5 -out "$out" >/dev/null 2>&1 || true
  # Берём только TLS1.3 + h2 и не-wildcard имя. Запятая как разделитель
  # безопасна: закавыченный CERT_ISSUER идёт десятым, а нам нужны поля до
  # девятого — в них запятой не бывает.
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
      # dest ходит по ИМЕНИ, а скан говорит только про адрес: сосед на REALITY
      # отдаёт украденный сертификат CDN и увёл бы нас обратно в чужой ASN.
      # Оставляем имена, которые резолвятся внутрь диапазона и не в нас самих.
      for ip in $(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u); do
        [[ "$ip" == "$self" ]] && continue
        if _ip_in_cidr "$ip" "$cidr"; then echo "$d"; break; fi
      done
    done | head -"$lim"
  rm -f "$out"
}

# _selftest_vless <xhttp|tcp> <uuid> <port> <sni> <sid> <pubkey> [path] [mode]
# Главная проверка: REALITY при провале хендшейка не пишет в лог ничего, так
# что «в логах пусто» не доказывает ничего. Поднимаем свой VLESS-клиент на
# loopback и ходим через собственный сервер. Печатает HTTP-код, 000 = не прошло.
_selftest_vless() {
  local net="$1" uuid="$2" port="$3" sni="$4" sid="$5" pub="$6" path="${7:-}" mode="${8:-}"
  local sport tmpcfg log code cpid
  [[ ${#pub} -lt 30 ]] && { echo "000"; return 0; }
  sport=$(( 20000 + RANDOM % 10000 ))
  tmpcfg=$(mktemp /tmp/xray-selftest.XXXXXX.json)
  log=$(mktemp /tmp/xray-selftest.XXXXXX.log)

  if [[ "$net" == "xhttp" ]]; then
    jq -n --arg uuid "$uuid" --arg pub "$pub" --arg sni "$sni" --arg sid "$sid" \
          --arg p "$path" --arg m "$mode" --argjson port "$port" --argjson sp "$sport" '{
      log:{loglevel:"warning"},
      inbounds:[{listen:"127.0.0.1",port:$sp,protocol:"socks",settings:{udp:false}}],
      outbounds:[{protocol:"vless",
        settings:{vnext:[{address:"127.0.0.1",port:$port,users:[{id:$uuid,encryption:"none"}]}]},
        streamSettings:{network:"xhttp",security:"reality",
          realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pub,shortId:$sid},
          xhttpSettings:{path:$p,host:$sni,mode:$m}}}]}' > "$tmpcfg"
  else
    jq -n --arg uuid "$uuid" --arg pub "$pub" --arg sni "$sni" --arg sid "$sid" \
          --argjson port "$port" --argjson sp "$sport" '{
      log:{loglevel:"warning"},
      inbounds:[{listen:"127.0.0.1",port:$sp,protocol:"socks",settings:{udp:false}}],
      outbounds:[{protocol:"vless",
        settings:{vnext:[{address:"127.0.0.1",port:$port,
          users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},
        streamSettings:{network:"tcp",security:"reality",
          realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pub,shortId:$sid}}}]}' > "$tmpcfg"
  fi

  xray run -c "$tmpcfg" >"$log" 2>&1 &
  cpid=$!
  sleep 2
  # Без `|| echo "000"`: curl и сам печатает 000, получалось бы "000000".
  code=$(curl -s -x "socks5h://127.0.0.1:${sport}" --max-time 15 -o /dev/null \
         -w '%{http_code}' https://api.ipify.org 2>/dev/null) || true
  code=${code:-000}
  kill "$cpid" 2>/dev/null || true
  wait "$cpid" 2>/dev/null || true
  if [[ "$code" != "200" ]]; then
    SELFTEST_HINT=$(grep -iE "failed|EOF|reject|reality" "$log" 2>/dev/null | tail -2 || true)
  else
    SELFTEST_HINT=""
  fi
  rm -f "$tmpcfg" "$log"
  echo "$code"
}

# _switch_sni <domain> — перевод всего стека на другой домен-маску: config.json
# (serverNames + xhttpSettings.host) + nginx map из шаблона + рестарт. 1 = не вышло.
_switch_sni() {
  local new="$1" tmp
  [[ "$new" =~ ^[a-zA-Z0-9._-]+$ ]] || return 1
  tmp=$(mktemp "$(dirname "$XRAY_CONFIG")/config.XXXXXX.json")
  jq --arg s "$new" '
      .inbounds[0].streamSettings.realitySettings.serverNames = [$s]
    | .inbounds[0].streamSettings.xhttpSettings.host = $s
    | if (.inbounds|length) > 1
      then .inbounds[1].streamSettings.realitySettings.serverNames = [$s] else . end
  ' "$XRAY_CONFIG" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  jq empty "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  chmod 640 "$tmp"; chown root:nogroup "$tmp"; mv "$tmp" "$XRAY_CONFIG"

  if [[ -f /etc/nginx/reality-fallback.conf.tmpl ]]; then
    sed "s/__DEST_SNI__/${new}/g" /etc/nginx/reality-fallback.conf.tmpl \
      > /etc/nginx/stream-enabled/reality-fallback.conf
    nginx -t &>/dev/null || return 1
    systemctl reload nginx || return 1
  fi
  xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK" || return 1
  systemctl restart xray; sleep 2
  systemctl is-active --quiet xray || return 1
  return 0
}

# =============================================================================
# 0. УЖЕ УСТАНОВЛЕНО / ПЕРЕУСТАНОВКА
# =============================================================================
if [[ -f "$XRAY_CONFIG" ]] && ! $REINSTALL; then
  warn "Xray уже установлен."
  echo "  Обновить:      sudo xm self-update"
  echo "  Команды:       xm help"
  echo "  Переустановка: sudo bash $0 --reinstall   (новые ключи, старые URI умрут)"
  exit 0
fi

# --reinstall переписывает общесистемное — nginx.conf, sites-enabled,
# stream-enabled/ целиком, ufw, fail2ban — и задевает соседей по серверу.
if [[ -f "$XRAY_CONFIG" ]] && $REINSTALL; then
  warn "Ключи REALITY генерируются заново: все выданные URI и QR умрут."
  warn "Переписываются nginx.conf, sites-enabled, stream-enabled/, ufw, fail2ban."
  command -v xm &>/dev/null && echo "  Кто ещё на сервере: sudo xm neighbors"
  echo "  Обновиться без переустановки: sudo xm self-update"
  read -rp "Введи ПЕРЕУСТАНОВИТЬ: " REINST_CONFIRM
  [[ "$REINST_CONFIRM" == "ПЕРЕУСТАНОВИТЬ" ]] || { info "Отменено."; exit 0; }
fi

# =============================================================================
# 1. ПАРАМЕТРЫ
# =============================================================================
header "Параметры"

# www.microsoft.com исключён навсегда: cert+OCSP ~9 КБ при буфере REALITY
# ~8192 б — хендшейк рвётся молча. Порядок не важен, ниже живой замер.
SNI_POOL=(www.cloudflare.com dl.google.com cdn.jsdelivr.net www.apple.com)
DEST_SNI="$SNI_ARG"
declare -a SNI_OK=()

if [[ -z "$DEST_SNI" ]]; then
  declare -a SNI_LOCAL=()
  if $SCAN_LOCAL; then
    # whois нужен раньше секции зависимостей. Не встал — скан пропускается.
    if ! command -v whois &>/dev/null; then
      info "Ставлю whois (нужен для определения ASN)..."
      apt-get update -qq 2>/dev/null || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends whois 2>/dev/null || true
    fi

    MY_IP=$(_fetch_server_ip 2>/dev/null) || MY_IP=""
    if [[ -z "$MY_IP" || "$MY_IP" == "ТВОЙ_IP" ]]; then
      warn "Не определить свой внешний адрес — сканирование пропущено"
    else
      # ASN только для показа: диапазон скана берётся из своего же адреса.
      MY_ASN=""; MY_PREFIX=""; MY_ASNAME=""
      IFS='|' read -r MY_ASN MY_PREFIX MY_ASNAME <<< "$(_asn_info "$MY_IP" 2>/dev/null || echo '||')"
      [[ -n "$MY_ASN" ]] && info "Наша сеть: AS${MY_ASN} ${MY_ASNAME} (анонс ${MY_PREFIX})"

      # /24 вокруг своего адреса, а не весь BGP-анонс: 256 адресов уходят за
      # полминуты. Диапазон пошире — xm sni-scan --local <CIDR>.
      MY_24="${MY_IP%.*}.0/24"
      info "Качаю RealiTLScanner ${RTS_VER} (XTLS, MPL-2.0)..."
      if _rts_ensure; then
        RTS_RC=0
      else
        RTS_RC=$?
      fi
      case "$RTS_RC" in
        0) info "Сканирую ${MY_24} — до полутора минут..."
           mapfile -t SNI_LOCAL < <(_rts_candidates "$MY_24" "$MY_IP" 8 2>/dev/null || true)
           if [[ ${#SNI_LOCAL[@]} -gt 0 ]]; then
             success "Найдено соседей в своей сети: ${#SNI_LOCAL[@]}"
           else
             warn "В своей /24 подходящих соседей нет — остаётся глобальный пул"
           fi ;;
        2) warn "Сумма RealiTLScanner не сошлась — бинарник не установлен" ;;
        *) warn "RealiTLScanner не скачался (сеть или неподдерживаемая архитектура)" ;;
      esac
    fi
    echo ""
  fi

  # Локальные кандидаты идут первыми: при прочих равных выбирается сосед.
  SNI_POOL=("${SNI_LOCAL[@]}" "${SNI_POOL[@]}")

  info "Замер кандидатов — ~20 сек"
  printf "  %-22s %8s %6s %5s %7s %7s  %s\n" "домен" "cert,б" "OCSP" "h2" "TLS1.3" "RTT,мс" "вердикт"

  declare -a SNI_OK_LOCAL=()
  for h in "${SNI_POOL[@]}"; do
    IS_LOCAL=0
    for l in ${SNI_LOCAL[@]+"${SNI_LOCAL[@]}"}; do [[ "$l" == "$h" ]] && { IS_LOCAL=1; break; }; done
    IFS='|' read -r P_CERT P_OCSP P_ALPN P_TLS13 P_X25519 P_RTT P_REDIR <<< "$(_sni_probe "$h")"
    if [[ "$P_CERT" == "-1" ]]; then
      printf "  %-22s %8s %6s %5s %7s %7s  ${RED}%s${NC}\n" "$h" "-" "-" "-" "-" "-" "НЕДОСТУПЕН"
      continue
    fi
    V="ГОДИТСЯ"; C="$GREEN"
    [[ "$P_CERT" -ge "$REALITY_CERT_WARN"  ]] && { V="РИСК";       C="$YELLOW"; }
    [[ "$P_CERT" -ge "$REALITY_CERT_LIMIT" ]] && { V="НЕ ГОДИТСЯ"; C="$RED"; }
    # TLS1.3 — без него REALITY не работает, h2 — без него не живёт XHTTP.
    [[ "$P_TLS13" != "да" ]] && { V="НЕТ TLS1.3"; C="$RED"; }
    [[ "$P_ALPN"  != "да" ]] && { V="НЕТ h2";     C="$RED"; }
    # RTT платится на каждом входящем: REALITY ходит к dest всегда.
    [[ "$P_RTT" -gt 150 && "$V" == "ГОДИТСЯ" ]] && { V="МЕДЛЕННЫЙ"; C="$YELLOW"; }
    [[ -n "$P_REDIR" && "$V" == "ГОДИТСЯ" ]] && { V="РЕДИРЕКТ→$P_REDIR"; C="$YELLOW"; }
    VP="$V"; [[ "$IS_LOCAL" -eq 1 ]] && VP="$V · СВОЙ ASN"
    printf "  %-22s %8s %6s %5s %7s %7s  ${C}%s${NC}\n" \
      "$h" "$P_CERT" "$([[ ${P_OCSP:-0} -gt 0 ]] && echo да || echo нет)" \
      "$P_ALPN" "$P_TLS13" "$P_RTT" "$VP"
    if [[ "$V" == "ГОДИТСЯ" ]]; then
      SNI_OK+=("$P_CERT $h")
      [[ "$IS_LOCAL" -eq 1 ]] && SNI_OK_LOCAL+=("$P_CERT $h")
    fi
  done
  echo ""

  # Сосед по своей сети выигрывает у любого CDN: запас до лимита REALITY —
  # вопрос пары килобайт, а мисматч ASN проверяется одним сравнением. Внутри
  # группы берём наименьший cert — больше запас.
  if [[ ${#SNI_OK_LOCAL[@]} -gt 0 ]]; then
    DEST_SNI=$(printf '%s\n' "${SNI_OK_LOCAL[@]}" | sort -n | head -1 | awk '{print $2}')
    success "Домен-маска: ${BOLD}$DEST_SNI${NC} — сосед по нашей сети, мисматча ASN нет"
  elif [[ ${#SNI_OK[@]} -gt 0 ]]; then
    DEST_SNI=$(printf '%s\n' "${SNI_OK[@]}" | sort -n | head -1 | awk '{print $2}')
    success "Домен-маска: ${BOLD}$DEST_SNI${NC} — наибольший запас до лимита REALITY"
  else
    DEST_SNI=""
    warn "Ни один кандидат не прошёл замер — проверь сеть VPS"
  fi
else
  info "Домен-маска: ${BOLD}$DEST_SNI${NC} (--sni)"
fi

[[ "$DEST_SNI" =~ ^[a-zA-Z0-9._-]+$ ]] \
  || error "Домен-маска не выбрана. Задай вручную: --sni <домен>"

# Path случайный из пула: иначе он один и тот же у всех установок из этого
# репозитория. Внутри TLS его не видно; сменить — xm edit.
PATH_POOL=(/api/v2/assets/stream /video/hls/playlist.m3u8 /static/js/chunk-main.js
           /cdn-cgi/trace /download/update)
XHTTP_PATH="${PATH_POOL[RANDOM % ${#PATH_POOL[@]}]}"
XHTTP_MODE="auto"; SINGBOX_METHOD="GET"
UTLS_FP="chrome"

XRAY_PORT="${PORT_ARG:-443}"
[[ "$XRAY_PORT" =~ ^[0-9]+$ ]] && [[ "$XRAY_PORT" -ge 1 ]] && [[ "$XRAY_PORT" -le 65535 ]] \
  || error "Некорректный порт: $XRAY_PORT"

# Занятый порт ловим здесь, пока ничего не изменено: иначе установка упадёт на
# запуске сервиса, уже переписав nginx. 443 предпочтителен — TLS на другом
# порту при пустом 443 сканер видит ещё до анализа хендшейка.
if _port_taken "$XRAY_PORT"; then
  grep -q docker <<< "$PORT_BUSY_LINE" \
    && warn "Порт держит docker — он публикует порты в обход ufw: sudo iptables -t nat -L DOCKER -n"
  error "Порт ${XRAY_PORT} занят (${PORT_BUSY_BY}).
       Освободи порт или поставь на другой: --port <порт>
       Поделить 443 по SNI с соседней службой умеет sudo xm front on."
fi

# Второй inbound включён по умолчанию: XHTTP — транспорт Xray-core, клиенты на
# ядре sing-box (Hiddify, NekoBox) могут его не поддерживать и молча отваливаться
# по таймауту. XTLS-Vision понимают все, по устойчивости к DPI он не уступает.
XRAY_PORT2=8443
if $DUAL_INBOUND; then
  # 10443 занят локальным REALITY fallback.
  while [[ "$XRAY_PORT2" == "$XRAY_PORT" || "$XRAY_PORT2" == "10443" ]] \
     || _port_taken "$XRAY_PORT2"; do
    XRAY_PORT2=$((XRAY_PORT2 + 1))
  done
fi

PORTS_INFO="$XRAY_PORT"
$DUAL_INBOUND && PORTS_INFO="$XRAY_PORT + TCP $XRAY_PORT2"
info "Порты: ${PORTS_INFO} · path ${XHTTP_PATH} · mode ${XHTTP_MODE} · fp ${UTLS_FP}"

# =============================================================================
# 2. ЗАВИСИМОСТИ
# =============================================================================
header "Зависимости"

# force-confold: иначе unattended-upgrades вешает установку на диалоге про
# уже изменённый 20auto-upgrades. Свою политику допишет xm autoupd apply.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
  curl wget unzip uuid-runtime openssl ufw whois \
  nginx libnginx-mod-stream libnginx-mod-http-headers-more-filter \
  fail2ban jq python3 python3-cryptography \
  chrony qrencode unattended-upgrades tcpdump
# whois — ASN через whois.cymru.com (diag-dpi, подбор соседей).
# python3-cryptography — _derive_pubkey в xm.sh (xm pubkey, xm diag).
# libnginx-mod-stream — ssl_preread для REALITY-fallback.
# headers-more — подмена заголовка Server: server_tokens off убирает только
# версию, слово nginx остаётся, и :80 отличается от домена-маски одним curl -I.
# tcpdump — живой тест утечки DNS (xm diag-dpi, E5).
success "Зависимости установлены"

# SSH-порт нужен до UFW, иначе правило откроет не тот порт.
SSH_PORT=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config 2>/dev/null \
  | awk '{print $2}' | head -1 || echo "")

if [[ -z "$SSH_PORT" ]]; then
  SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd \
    | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || echo "")
fi

SSH_PORT=${SSH_PORT:-22}
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [[ "$SSH_PORT" -ge 1 ]] && [[ "$SSH_PORT" -le 65535 ]] \
  || SSH_PORT=22

# =============================================================================
# 4. NTP — CHRONY
# =============================================================================
header "Время (chrony)"

systemctl stop systemd-timesyncd 2>/dev/null || true
systemctl disable systemd-timesyncd 2>/dev/null || true

cat > /etc/chrony/chrony.conf <<'CHRONYEOF'
pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
# Без "local stratum 10": иначе chronyd считает дрейфующее время
# синхронизированным, и REALITY (maxTimeDiff) молча отклоняет клиентов.
CHRONYEOF

systemctl enable chrony
systemctl restart chrony

for i in {1..10}; do
  if chronyc makestep 2>/dev/null; then
    break
  fi
  [[ $i -lt 10 ]] && sleep 2 || warn "chronyc makestep не завершился за 20 сек — продолжаем"
done

DRIFT=$(chronyc tracking 2>/dev/null | grep "System time" | awk '{print $4}' || echo "0")
success "Chrony: дрейф ${DRIFT} сек"

# =============================================================================
# 5. XRAY-CORE
# =============================================================================
header "Xray-core"

bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
success "Xray: $(xray version | head -1)"

# =============================================================================
# 6. ГЕНЕРАЦИЯ КЛЮЧЕЙ
# =============================================================================
header "Ключи"

USER_UUID=$(xray uuid)
KEY_OUTPUT=$(xray x25519)
_parse_xray_keys "$KEY_OUTPUT"

SHORT_ID_1=$(openssl rand -hex 8)
SHORT_ID_2=$(openssl rand -hex 8)
SHORT_ID_3=$(openssl rand -hex 4)

if $DUAL_INBOUND; then
  KEY_OUTPUT2=$(xray x25519)
  _parse_xray_keys "$KEY_OUTPUT2"
  PRIVATE_KEY2="$PRIVATE_KEY"
  PUBLIC_KEY2="$PUBLIC_KEY"
  # Возвращаем первую пару: _parse_xray_keys пишет в те же переменные.
  _parse_xray_keys "$KEY_OUTPUT"
  SHORT_ID_TCP_1=$(openssl rand -hex 8)
  SHORT_ID_TCP_2=$(openssl rand -hex 4)
fi

success "Ключи сгенерированы"

# =============================================================================
# 7. ПРОВЕРКА ДОСТУПНОСТИ DEST
# =============================================================================
header "Проверка домена-маски"

HTTP_CODE=$(curl -svo /dev/null "https://${DEST_SNI}" \
  --max-time 10 --connect-timeout 5 \
  -w "%{http_code}" 2>/dev/null || echo "000")

# HTTP-код сам по себе не приговор: REALITY нужен живой TLS, а не 200.
[[ "$HTTP_CODE" =~ ^[23] ]] \
  || warn "dest ${DEST_SNI} отвечает HTTP $HTTP_CODE — проверь, что домен живой"

# Решает TLS: не собрался хендшейк — REALITY форвардит зонды в никуда, и сервер
# виден как прокси первым же сканом. Размер сертификата — второй барьер.
CERT_EST=$(_check_cert_size "$DEST_SNI")
if [[ "$CERT_EST" == "-1" ]]; then
  error "TLS-хендшейк с ${DEST_SNI}:443 не собрался — доменом-маской он быть не может.
       Возьми другой: --sni <домен>"
elif [[ "$CERT_EST" -ge "$REALITY_CERT_LIMIT" ]]; then
  # Обхода нет намеренно: с таким dest клиент ловит таймаут, а в логах пусто.
  error "Certificate ~${CERT_EST} б ≥ лимита REALITY (${REALITY_CERT_LIMIT} б) — хендшейк
       будет рваться молча. Возьми домен покомпактнее: --sni <домен>"
elif [[ "$CERT_EST" -ge "$REALITY_CERT_WARN" ]]; then
  warn "Certificate ~${CERT_EST} б — близко к лимиту ${REALITY_CERT_LIMIT} б"
else
  success "Certificate ~${CERT_EST} б — запас до лимита ${REALITY_CERT_LIMIT} б есть"
fi

# =============================================================================
# 8. ЛОГИ + LOGROTATE
# =============================================================================
# install, а не mkdir+chown: mkdir -p на существующем каталоге права не меняет,
# и Xray от nobody падает с exit 23, который юнит запрещает рестартовать.
# `xray -test` этого не ловит — ошибка существует только в рантайме.
XRAY_USER=$(systemctl show -p User --value xray 2>/dev/null || true)
XRAY_USER=${XRAY_USER:-nobody}
XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)

install -d -m 750 -o "$XRAY_USER" -g "$XRAY_GROUP" "$XRAY_LOG_DIR"
install -m 640 -o "$XRAY_USER" -g "$XRAY_GROUP" /dev/null "$XRAY_LOG_DIR/error.log"

# Проверяем факт записи от имени сервиса: ACL и chattr +i правами не видны.
if ! sudo -u "$XRAY_USER" test -w "$XRAY_LOG_DIR/error.log"; then
  error "Пользователь $XRAY_USER не может писать в $XRAY_LOG_DIR/error.log.
       Смотри: sudo ls -la $XRAY_LOG_DIR  и  sudo lsattr -d $XRAY_LOG_DIR"
fi
success "Логи: $XRAY_LOG_DIR ($XRAY_USER:$XRAY_GROUP)"

cat > /etc/logrotate.d/xray <<'LOGROTEOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    # copytruncate, а не kill -USR1: для Go-рантайма SIGUSR1 = Term, процесс
    # умирает и клиентские соединения рвутся каждые сутки.
    copytruncate
}
LOGROTEOF
success "logrotate: 14 дней"

# =============================================================================
# 9. NGINX — REALITY FALLBACK (stream + ssl_preread)
# REALITY dest = 127.0.0.1:10443 с PROXY protocol v2 (xver=2, см. §11), здесь
# nginx читает SNI, не терминируя TLS (сертификат сайта проходит насквозь),
# проксирует только на разрешённый SNI и видит реальный IP клиента.
# :80 — обычный 301-редирект, как у любого веб-сервера.
# =============================================================================

# ssl_preread нельзя искать в `nginx -V`: в Ubuntu stream — отдельный
# динамический модуль, его configure-флагов в основном бинарнике нет.
# Проверяем по факту, тремя способами от дешёвого к точному.
_has_ssl_preread() {
  # 1) Статическая сборка (nginx.org / свой билд) — флаг реально виден
  if nginx -V 2>&1 | grep -q -- "--with-stream_ssl_preread_module"; then return 0; fi
  # 2) Динамический модуль: имя директивы лежит строкой внутри .so
  if grep -rqs "ssl_preread" /usr/lib/nginx/modules/; then return 0; fi
  # 3) Функциональная проверка: минимальный stream-конфиг через nginx -t
  local t rc=1
  t=$(mktemp /tmp/ngx-preread.XXXXXX.conf)
  {
    cat /etc/nginx/modules-enabled/*.conf 2>/dev/null || true
    echo "events {}"
    echo "stream { server { listen 127.0.0.1:65535; ssl_preread on; proxy_pass 127.0.0.1:1; } }"
  } > "$t"
  if nginx -t -c "$t" &>/dev/null; then rc=0; fi
  rm -f "$t"
  return "$rc"
}

# Без ssl_preread stream-fallback невозможен в принципе. Проверяем ДО записи
# конфигов, чтобы не падать на nginx -t с уже переписанным nginx.conf.
if ! _has_ssl_preread; then
  error "nginx собран без ssl_preread — REALITY fallback невозможен.
       Проверь:  sudo grep -rl ssl_preread /usr/lib/nginx/modules/
       Поставь:  sudo apt install -y libnginx-mod-stream
       Либо возьми nginx с nginx.org (там ssl_preread вкомпилен статически)."
fi

header "Nginx (REALITY fallback)"

mkdir -p /var/www/fallback
cat > /var/www/fallback/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f5f5f7; display: flex; align-items: center;
           justify-content: center; min-height: 100vh; color: #1d1d1f; }
    .container { text-align: center; padding: 2rem; }
    h1 { font-size: 2rem; font-weight: 600; margin-bottom: 1rem; }
    p  { font-size: 1rem; color: #6e6e73; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Service Unavailable</h1>
    <p>The requested resource is temporarily unavailable. Please try again later.</p>
  </div>
</body>
</html>
HTMLEOF

chown -R www-data:www-data /var/www/fallback

# --- :80 → 301 -----------------------------------------------------------
# Заголовок Server снимаем с живого домена-маски: server_tokens off убирает
# только версию, слово nginx остаётся, и :80 выдаёт себя одним curl -I.
# Каждый шаг гасится явно: под pipefail пустой grep уронил бы установку.
DEST_SRV=""
for scheme in https http; do
  DEST_SRV=$( { curl -sI --max-time 8 "${scheme}://${DEST_SNI}/" 2>/dev/null || true; } \
             | { grep -im1 '^server:' || true; } | tr -d '\r' \
             | sed 's/^[Ss]erver:[[:space:]]*//') || DEST_SRV=""
  [[ -n "$DEST_SRV" ]] && break || true
done
# Значение уходит в конфиг через sed — всё лишнее отбрасываем целиком.
[[ "$DEST_SRV" =~ ^[A-Za-z0-9._/\ -]{1,64}$ ]] || DEST_SRV=""

if [[ -n "$DEST_SRV" ]] && grep -rqs "headers_more" /usr/lib/nginx/modules/ /etc/nginx/modules-enabled/ 2>/dev/null; then
  NGX_SRV_LINE="more_set_headers \"Server: __DEST_SRV__\";"
else
  NGX_SRV_LINE="# headers-more недоступен — Server остаётся nginx (см. xm diag-dpi, тест B7)"
  [[ -z "$DEST_SRV" ]] \
    && warn "Не удалось прочитать Server у $DEST_SNI — заголовок не маскирую" \
    || warn "Модуль headers-more не найден — заголовок Server не маскируется"
fi

cat > /etc/nginx/sites-available/fallback <<'NGINXEOF'
server {
    listen 80 default_server backlog=8192;
    listen [::]:80 default_server backlog=8192;
    server_name _;
    server_tokens off;
    __NGX_SRV_LINE__

    # Редирект на имя домена-маски, а не на $host: при запросе по IP в
    # Location попадал наш адрес — так не делает ни один настоящий сайт.
    return 301 https://__DEST_SNI__$request_uri;

    # Лог выключен: адреса всех, кто трогал :80, ценности не несут — зонды
    # видны в reality_fallback.log, свои клиенты на :80 не ходят.
    access_log off;
}
NGINXEOF

sed -i "s|__NGX_SRV_LINE__|${NGX_SRV_LINE}|; s/__DEST_SRV__/${DEST_SRV}/; s/__DEST_SNI__/${DEST_SNI}/" \
  /etc/nginx/sites-available/fallback

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/fallback /etc/nginx/sites-enabled/fallback

# Старая http-бутафория от прошлых версий.
rm -f /etc/nginx/conf.d/rate-limit.conf

# --- STREAM: REALITY fallback ------------------------------------------------
# stream-блок объявляется в top-level nginx.conf — include добавляем один раз.
mkdir -p /etc/nginx/stream-enabled
# Конфиги прошлых версий сносим до записи новых: в них лежал set_real_ip_from,
# которого нет в пакетах Ubuntu, и nginx -t ронял весь nginx целиком.
rm -f /etc/nginx/stream-enabled/*
if ! grep -q "stream-enabled/\*.conf" /etc/nginx/nginx.conf; then
  cat >> /etc/nginx/nginx.conf <<'NGXSTREAM'

# REALITY fallback: stream-контекст для ssl_preread SNI-проксирования.
# Добавлено setup.sh. Не удалять — сюда подключается stream-enabled/*.conf.
stream {
    include /etc/nginx/stream-enabled/*.conf;
}
NGXSTREAM
fi

# Quoted-heredoc, чтобы shell не тронул nginx-переменные; SNI подставляем sed.
cat > /etc/nginx/stream-enabled/reality-fallback.conf <<'STREAMEOF'
# Режим mimic: любой SNI, включая чужой и пустой, уходит на наш же dest.
# Пустой апстрим означал бы «принял TCP и молча закрыл» — готовую подпись
# прокси для одного коннекта сканера. Открытым релеем сервер не становится:
# справа константа, выбрать хост назначения извне нельзя (xm diag-dpi, блок B).
map $ssl_preread_server_name $reality_upstream {
    default        __DEST_SNI__;
    __DEST_SNI__   __DEST_SNI__;
}

# Через fallback идёт весь легитимный трафик, а не только зонды: без этого
# фильтра в лог попадали бы реальные IP клиентов. Пишем только чужой SNI.
map $ssl_preread_server_name $log_probe {
    default        1;
    __DEST_SNI__   0;
}

# $proxy_protocol_addr, а не $remote_addr: realip-модуля в пакетах Ubuntu нет,
# а PROXY v2 отдаёт тот же реальный IP клиента и без него.
limit_conn_zone $proxy_protocol_addr zone=reality_conn:10m;

log_format reality_fallback '$proxy_protocol_addr [$time_local] '
                            'SNI="$ssl_preread_server_name" '
                            'status=$status sent=$bytes_sent';

# Апстрим задан именем и резолвится в рантайме → нужен resolver.
resolver 1.1.1.1 8.8.8.8 valid=30s ipv6=off;
resolver_timeout 5s;

server {
    # proxy_protocol обязателен: xver=2 в REALITY шлёт сюда PROXY v2.
    # backlog=8192 под xm tune: системный somaxconn nginx не наследует.
    listen 127.0.0.1:10443 proxy_protocol backlog=8192;

    # Читаем SNI из ClientHello БЕЗ терминации TLS.
    ssl_preread on;

    # 200, а не 20: через fallback идёт весь трафик, а не только зонды.
    limit_conn reality_conn 200;

    proxy_pass $reality_upstream:443;
    proxy_connect_timeout 5s;

    access_log /var/log/nginx/reality_fallback.log reality_fallback if=$log_probe;
    error_log  /var/log/nginx/reality_fallback_error.log error;
}
STREAMEOF

# Шаблон лежит вне stream-enabled/, иначе nginx подхватит его как конфиг.
# Из него _switch_sni регенерирует конфиг при смене домена-маски.
cp /etc/nginx/stream-enabled/reality-fallback.conf /etc/nginx/reality-fallback.conf.tmpl
chmod 600 /etc/nginx/reality-fallback.conf.tmpl
sed -i "s/__DEST_SNI__/${DEST_SNI}/g" /etc/nginx/stream-enabled/reality-fallback.conf

# Отдельной строкой: внутри &&-списка падение nginx -t не прервало бы скрипт.
nginx -t || error "nginx -t не прошёл — см. /etc/nginx/stream-enabled/reality-fallback.conf"
systemctl enable nginx
systemctl restart nginx
success "Nginx: ssl_preread на 127.0.0.1:10443"

# Маршруты фронта переустановку переживают, конфиг nginx — нет. Автоматически
# не поднимаем: порт inbound выбран заново, соседняя служба могла переехать.
if [[ -f /usr/local/etc/xray/front.conf ]]; then
  warn "Маршруты фронта по SNI на месте, конфиг nginx вычищен: sudo xm front on"
fi

# =============================================================================
# 10. FAIL2BAN
# =============================================================================
# Джейла по трафику REALITY нет намеренно: бан сканеров демаскирует (реальный
# сайт Censys не блэкхолит) и задел бы своих клиентов — их хендшейки идут через
# тот же fallback. Флуд отсекает limit_conn в nginx, как у CDN.
cat > /etc/fail2ban/jail.d/sshd-xray.conf <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
findtime = 600
bantime  = 3600
ignoreip = 127.0.0.1/8
EOF

systemctl enable fail2ban
systemctl restart fail2ban
success "fail2ban: sshd на порту $SSH_PORT"

# =============================================================================
# 10c. ЕЖЕНЕДЕЛЬНАЯ РЕВАЛИДАЦИЯ ДОМЕНА-МАСКИ
# Сертификаты ротируются: выросшая цепочка или новый OCSP staple у dest рвут
# хендшейк молча. Результат виден в xm info.
# =============================================================================
cat > /usr/local/bin/xray-sni-watch <<'WATCHEOF'
#!/usr/bin/env bash
CFG=/usr/local/etc/xray/config.json
FLAG=/var/lib/xray-sni-watch.flag
H=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // ""' "$CFG" 2>/dev/null)
[[ -z "$H" ]] && exit 0
R=$(echo | timeout 10 openssl s_client -connect "$H:443" -servername "$H" -showcerts -status 2>/dev/null)
if [[ -z "$R" ]]; then
  echo "$(date -Is) $H НЕДОСТУПЕН по :443 — REALITY fallback сломан" > "$FLAG"; exit 0
fi
N=$(printf '%s\n' "$R" | grep -c "BEGIN CERTIFICATE"); N=${N:-0}
B=$(printf '%s\n' "$R" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
    | grep -vE 'BEGIN|END' | tr -d '\n' | wc -c); B=${B:-0}
O=0; printf '%s' "$R" | grep -qi "OCSP Response Data" && O=1600
T=$((B*3/4+O+10+N*6))
if [[ "$T" -ge 7000 ]]; then
  echo "$(date -Is) $H: Certificate ~${T} б при лимите 8192 — смени домен: xm sni-scan" > "$FLAG"
else
  rm -f "$FLAG"
fi
WATCHEOF
chmod 755 /usr/local/bin/xray-sni-watch

cat > /etc/systemd/system/xray-sni-watch.service <<'EOF'
[Unit]
Description=REALITY dest certificate size watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/bin/xray-sni-watch
EOF

cat > /etc/systemd/system/xray-sni-watch.timer <<'EOF'
[Unit]
Description=Weekly REALITY dest certificate check
[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now xray-sni-watch.timer
success "Ревалидация домена-маски: еженедельно"

# =============================================================================
# 11. CONFIG.JSON
# maxTimeDiff 10 сек (chrony держит drift < 1 с) — узкое окно для replay.
# xPaddingBytes 100-1460 — шире разброс размеров против статистики DPI.
# =============================================================================
header "Конфиг Xray"

# Каталог может отсутствовать: install-release.sh создаёт его только когда
# реально ставит бинарник. Права 755 root:root — как у официального
# установщика; секреты закрыты правами самих файлов.
mkdir -p "$(dirname "$XRAY_CONFIG")"
chown root:root "$(dirname "$XRAY_CONFIG")"
chmod 755 "$(dirname "$XRAY_CONFIG")"

XHTTP_INBOUND=$(jq -n \
  --arg     uuid       "$USER_UUID" \
  --arg     privKey    "$PRIVATE_KEY" \
  --arg     sni        "$DEST_SNI" \
  --arg     sid1       "$SHORT_ID_1" \
  --arg     sid2       "$SHORT_ID_2" \
  --arg     sid3       "$SHORT_ID_3" \
  --arg     path       "$XHTTP_PATH" \
  --arg     mode       "$XHTTP_MODE" \
  --argjson port       "$XRAY_PORT" \
  '{
    listen: "0.0.0.0",
    port: $port,
    protocol: "vless",
    settings: {
      clients: [{ id: $uuid, comment: "user-xhttp" }],
      decryption: "none"
    },
    streamSettings: {
      network: "xhttp",
      security: "reality",
      realitySettings: {
        show: false,
        # dest — локальный nginx stream-fallback, он проксирует хендшейк на
        # реальный $sni:443. xver=2 → PROXY v2 с настоящим IP клиента.
        dest: "127.0.0.1:10443",
        xver: 2,
        serverNames: [$sni],
        privateKey: $privKey,
        maxTimeDiff: 10000,
        shortIds: [$sid1, $sid2, $sid3]
      },
      xhttpSettings: {
        path: $path,
        host: $sni,
        mode: $mode,
        headers: { "Cache-Control": "no-store" },
        # Старых имён SplitHTTP (maxUploadSize и т.п.) здесь нет: Xray 26.x
        # молча их игнорирует и создаёт ложное впечатление настроенных лимитов.
        xPaddingBytes: "100-1460"
      }
    },
    sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
  }')

if $DUAL_INBOUND; then
  TCP_INBOUND=$(jq -n \
    --arg     uuid      "$USER_UUID" \
    --arg     privKey   "$PRIVATE_KEY2" \
    --arg     sni       "$DEST_SNI" \
    --arg     sid1      "$SHORT_ID_TCP_1" \
    --arg     sid2      "$SHORT_ID_TCP_2" \
    --argjson port      "$XRAY_PORT2" \
    '{
      listen: "0.0.0.0",
      port: $port,
      protocol: "vless",
      settings: {
        clients: [{ id: $uuid, flow: "xtls-rprx-vision", comment: "user-tcp" }],
        decryption: "none"
      },
      streamSettings: {
        network: "tcp",
        security: "reality",
        realitySettings: {
          show: false,
          # см. XHTTP inbound; SNI тот же, whitelist в nginx уже подходит.
          dest: "127.0.0.1:10443",
          xver: 2,
          serverNames: [$sni],
          privateKey: $privKey,
          maxTimeDiff: 10000,
          shortIds: [$sid1, $sid2]
        },
        tcpSettings: { header: { type: "none" } }
      },
      sniffing: { enabled: true, destOverride: ["http","tls","quic"] }
    }')

  INBOUNDS_JSON=$(jq -n \
    --argjson a "$XHTTP_INBOUND" \
    --argjson b "$TCP_INBOUND" \
    '[$a, $b]')
else
  INBOUNDS_JSON=$(jq -n --argjson a "$XHTTP_INBOUND" '[$a]')
fi

jq -n \
  --argjson inbounds "$INBOUNDS_JSON" \
  --arg     logDir   "$XRAY_LOG_DIR" \
  '{
    # access: "none" — иначе Xray пишет в journald полный лог «кто куда ходил»,
    # и loglevel его не фильтрует.
    log: { loglevel: "error", access: "none", dnsLog: false, error: ($logDir + "/error.log") },
    inbounds: $inbounds,
    outbounds: [
      { protocol: "freedom", tag: "direct", settings: { domainStrategy: "UseIPv4v6" } },
      { protocol: "blackhole", tag: "block" }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      # geoip:cn/ir здесь нет: `ip` в routing — адрес назначения, а не
      # источника, и правило применяется уже после аутентификации.
      rules: [
        { type: "field", ip: ["geoip:private"], outboundTag: "block" },
        { type: "field", protocol: ["bittorrent"], outboundTag: "block" }
      ]
    },
    policy: {
      # handshake=8, а не дефолтные 4: в окно входит и дозвон REALITY до dest.
      # При холодном резолвере это занимало 10 с — с 4 клиент бы не вошёл.
      levels: { "0": { handshake: 8, connIdle: 300, uplinkOnly: 2, downlinkOnly: 5, bufferSize: 512 } },
      system: { statsInboundUplink: false, statsInboundDownlink: false }
    }
  }' > "$XRAY_CONFIG"

# В файле приватный ключ REALITY: 640 root:nogroup — пишет root, читает nobody
# (от него работает Xray), остальные не видят. chmod до chown, чтобы между ними
# не было окна с неверными правами.
chmod 640 "$XRAY_CONFIG"
chown root:nogroup "$XRAY_CONFIG"
success "config.json записан (640 root:nogroup)"

# =============================================================================
# 11b. DNS: DoH на сервере + перехват :53 из тоннеля
# Резолверы проверяем ДО правки конфига: если хостер режет :443 к ним,
# включённый DoH убьёт резолвинг без единой ошибки в логе.
# =============================================================================

DOH_OK=0
for r in "${DOH_IPS[@]}"; do
  _doh_probe "$r" && DOH_OK=$((DOH_OK + 1)) || true
done

if [[ "$DOH_OK" -eq 0 ]]; then
  warn "DoH недоступен с этого VPS — dns-блок не добавлен, домены резолвит"
  warn "системный резолвер хостера открытым текстом. Позже: sudo xm harden"
else
  # Без IPv6 AAAA бесполезны: клиент получит адрес, до которого сервер не дойдёт.
  if _has_ipv6; then DNS_QS="UseIP";   DNS_DS="UseIPv4v6"
  else               DNS_QS="UseIPv4"; DNS_DS="UseIPv4"; fi

  # nonIPQuery=drop: HTTPS/SVCB и TXT не уходят наружу открытым текстом.
  # На редких сборках поле не принимается — тогда второй заход без него.
  _write_dns_cfg() {
    local nonip="$1" tmp
    tmp=$(mktemp "$(dirname "$XRAY_CONFIG")/config.XXXXXX.json")
    jq --argjson doh "$DOH_LIST" --arg qs "$DNS_QS" --arg ds "$DNS_DS" --arg nonip "$nonip" '
        .dns = { servers: $doh, queryStrategy: $qs, disableCache: false, tag: "dns-in" }
      | .outbounds = ([ .outbounds[]? | select(.protocol != "dns") ]
                    + [ { protocol: "dns", tag: "dns-out" }
                        + (if $nonip == "" then {} else { settings: { nonIPQuery: $nonip } } end) ])
      | .routing.rules = ([ { type: "field", port: 53, network: "tcp,udp", outboundTag: "dns-out" } ]
                        + [ .routing.rules[]? | select(.outboundTag != "dns-out") ])
      | (.outbounds[] | select(.protocol == "freedom")).settings.domainStrategy = $ds
    ' "$XRAY_CONFIG" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    jq empty "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    chmod 640 "$tmp"; chown root:nogroup "$tmp"; mv "$tmp" "$XRAY_CONFIG"
    xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK"
  }

  # mktemp даёт 600 (в файле приватный ключ), без .json — чтобы Xray не принял
  # временный файл за конфиг.
  CFG_NODNS=$(mktemp "$(dirname "$XRAY_CONFIG")/config.nodns.XXXXXX")
  cat "$XRAY_CONFIG" > "$CFG_NODNS"
  if _write_dns_cfg "drop"; then
    success "DNS: DoH ($DOH_OK резолвера) + перехват :53"
  else
    cat "$CFG_NODNS" > "$XRAY_CONFIG"
    if _write_dns_cfg ""; then
      success "DNS: DoH ($DOH_OK резолвера) + перехват :53"
    else
      warn "dns-блок не принят этой сборкой Xray — конфиг без него"
      cat "$CFG_NODNS" > "$XRAY_CONFIG"
    fi
  fi
  chmod 640 "$XRAY_CONFIG"; chown root:nogroup "$XRAY_CONFIG"
  rm -f "$CFG_NODNS"
fi

# dns-блок закрывает путь Xray, но не системный стаб — он ходит открытым UDP.
# Перевод стаба на DoT живёт в xm harden: там есть проверка и откат.
info "Системный резолвер открыт — закрыть: sudo xm harden"

xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK" \
  || error "Конфиг невалиден: xray -test -config $XRAY_CONFIG"
success "xray -test: Configuration OK"

# =============================================================================
# 12b. УСТАНОВКА xm В PATH (до запуска сервиса — нужен для диагностики сбоя)
# =============================================================================
header "Менеджер xm"

XM_TARGET="/usr/local/bin/xm"

if [[ -f "$XM_SCRIPT_SRC" ]]; then
  cp "$XM_SCRIPT_SRC" "$XM_TARGET"
  chmod +x "$XM_TARGET"
  success "xm установлен: $XM_TARGET"
elif [[ -f "$(dirname "$0")/xm.sh" ]]; then
  cp "$(dirname "$0")/xm.sh" "$XM_TARGET"
  chmod +x "$XM_TARGET"
  success "xm установлен: $XM_TARGET"
else
  warn "xm.sh не найден рядом с setup.sh"
  warn "Скопируй xm.sh вручную: sudo cp xm.sh /usr/local/bin/xm && sudo chmod +x /usr/local/bin/xm"
fi

# Источник правды — репозиторий, а не копия на VPS: отсюда xm self-update
# тянет коммиты и переустанавливает бинарь.
XM_REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -d "$XM_REPO_DIR/.git" ]]; then
  echo "$XM_REPO_DIR" > /usr/local/etc/xray/xm-source
  chmod 644 /usr/local/etc/xray/xm-source
  success "Обновления: sudo xm self-update (из $XM_REPO_DIR)"
else
  warn "Не git-чекаут — источник обновлений не записан."
  warn "Позже: sudo xm self-update --from <url>"
fi

# =============================================================================
# 13. FIREWALL (UFW)
# =============================================================================
header "Файрвол"

ufw allow "${SSH_PORT}/tcp"   comment 'SSH'         2>/dev/null || true
ufw allow 80/tcp              comment 'HTTP->HTTPS'  2>/dev/null || true
ufw allow "${XRAY_PORT}/tcp"  comment 'Xray XHTTP'  2>/dev/null || true
$DUAL_INBOUND && ufw allow "${XRAY_PORT2}/tcp" comment 'Xray TCP' 2>/dev/null || true

if ! ufw status | grep -q "Status: active"; then
  ufw --force enable && success "UFW включён"
else
  ufw reload && success "UFW перезагружен"
fi
# Порты своих служб объявляются через xm access и лежат вне /etc — возвращаем
# их на место после того, как установка открыла свои.
if [[ -x "$XM_TARGET" && -f /usr/local/etc/xray/access.conf ]]; then
  "$XM_TARGET" access apply >/dev/null 2>&1 \
    && success "Локальные правила доступа применены" \
    || warn "Часть локальных правил не применилась: sudo xm access status"
fi

# =============================================================================
# 14. SYSTEMD
# =============================================================================
header "Запуск"

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
  success "Xray запущен"
else
  # Причину печатаем на месте: `xray -test` проходит и тогда, когда процесс не
  # может занять порт или создать лог — эти ошибки существуют лишь в рантайме.
  echo ""
  warn "─── journalctl -u xray (последние 30 строк) ───"
  journalctl -u xray -n 30 --no-pager 2>/dev/null | sed 's/^/  /' || true
  echo ""
  warn "─── запуск от имени nobody (точный текст ошибки) ───"
  timeout 5 sudo -u nobody "$(command -v xray)" run -config "$XRAY_CONFIG" 2>&1 \
    | head -20 | sed 's/^/  /' || true
  echo ""
  warn "─── кто занял порт ${XRAY_PORT} ───"
  ss -tlnp 2>/dev/null | grep -E ":${XRAY_PORT}([^0-9]|$)" | sed 's/^/  /' \
    || echo "  (никто — значит дело не в порте)"
  error "Xray не запустился — причина выше"
fi

ss -tlnp | grep -q ":${XRAY_PORT}" || warn "Порт ${XRAY_PORT} не слушается"

# =============================================================================
# 14b. SELFTEST — ГЛАВНАЯ ПРОВЕРКА
# Локальный VLESS-клиент ходит через собственный сервер. Не прошло — берём
# следующий домен-маску из прошедших замер, и всё это до выдачи URI и QR.
# =============================================================================
header "Selftest"

SELFTEST_OK=false
SELFTEST_SNI="$DEST_SNI"

declare -a RETRY_POOL=("$DEST_SNI")
for entry in ${SNI_OK[@]+"${SNI_OK[@]}"}; do
  cand=$(echo "$entry" | awk '{print $2}')
  [[ -n "$cand" && "$cand" != "$DEST_SNI" ]] && RETRY_POOL+=("$cand")
done

for cand in "${RETRY_POOL[@]}"; do
  if [[ "$cand" != "$SELFTEST_SNI" ]]; then
    warn "Пробую следующий домен-маску: $cand"
    _switch_sni "$cand" || { warn "Не удалось переключить на $cand — пропускаю"; continue; }
    SELFTEST_SNI="$cand"
  fi
  CODE=$(_selftest_vless xhttp "$USER_UUID" "$XRAY_PORT" "$SELFTEST_SNI" \
         "$SHORT_ID_1" "$PUBLIC_KEY" "$XHTTP_PATH" "$XHTTP_MODE")
  if [[ "$CODE" == "200" ]]; then
    success "XHTTP: трафик прошёл (HTTP 200)"
    SELFTEST_OK=true
    DEST_SNI="$SELFTEST_SNI"
    break
  fi
  warn "XHTTP selftest не прошёл (код: $CODE), домен $SELFTEST_SNI"
  [[ -n "${SELFTEST_HINT:-}" ]] && echo "$SELFTEST_HINT" | sed 's/^/    /'
done

if $SELFTEST_OK && $DUAL_INBOUND; then
  CODE2=$(_selftest_vless tcp "$USER_UUID" "$XRAY_PORT2" "$DEST_SNI" \
          "$SHORT_ID_TCP_1" "$PUBLIC_KEY2")
  [[ "$CODE2" == "200" ]] \
    && success "TCP/Vision: трафик прошёл (HTTP 200)" \
    || warn "TCP/Vision не прошёл ($CODE2) — sudo xm selftest --tcp"
fi

if ! $SELFTEST_OK; then
  warn "Рабочего хендшейка нет ни с одним доменом-маской — сервер, скорее"
  warn "всего, не работает (пустой лог у REALITY это не опровергает)."
  warn "Разбор: sudo xm selftest · sudo xm sni-scan · sudo xm set-sni <домен>"
fi

# =============================================================================
# 14c. СТАБИЛЬНОСТЬ: сетевой стек + watchdog
# После selftest намеренно: watchdog умеет перезапускать xray и nginx и мешал бы
# разбору нерабочей установки. Реализация — в xm.sh, чтобы xm tune --off
# откатывал ровно то, что поставила установка.
# =============================================================================
if command -v xm &>/dev/null; then
  xm tune >/dev/null 2>&1 \
    && success "Сетевой стек и watchdog настроены" \
    || warn "xm tune с замечаниями — проверь: sudo xm tune"
else
  warn "xm недоступен — сетевой профиль не применён. Позже: sudo xm tune"
fi

# =============================================================================
# 14d. АВТООБНОВЛЕНИЯ ПАКЕТОВ ОС
# Реализация в xm.sh: иначе политика живёт в двух файлах, и правка не приезжает
# на уже поднятые машины — setup.sh второй раз не запускают.
# =============================================================================
if command -v xm &>/dev/null; then
  xm autoupd apply >/dev/null 2>&1 \
    && success "Автообновления пакетов ОС включены" \
    || warn "Автообновления не настроены — проверь: sudo xm autoupd"
else
  warn "xm недоступен — автообновления не настроены. Позже: sudo xm autoupd apply"
fi

# =============================================================================
# 16. IP + ДАННЫЕ КЛИЕНТА
# =============================================================================

# "|| true": при полном провале функция вернёт 1 и под set -e убила бы скрипт,
# так и не дойдя до фолбэка "ТВОЙ_IP".
SERVER_IP=$(_fetch_server_ip) || true
[[ "$SERVER_IP" == "ТВОЙ_IP" ]] \
  && warn "Внешний IP не определился — впиши его вручную в $CLIENT_FILE"

ENCODED_PATH=$(python3 -c \
  "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" \
  "$XHTTP_PATH")

VLESS_URI_XHTTP="vless://${USER_UUID}@${SERVER_IP}:${XRAY_PORT}?encryption=none&security=reality&sni=${DEST_SNI}&fp=${UTLS_FP}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID_1}&type=xhttp&path=${ENCODED_PATH}&host=${DEST_SNI}&mode=${XHTTP_MODE}#MyServer-XHTTP"

TCP_SECTION=""
VLESS_URI_TCP=""
if $DUAL_INBOUND; then
  VLESS_URI_TCP="vless://${USER_UUID}@${SERVER_IP}:${XRAY_PORT2}?encryption=none&security=reality&sni=${DEST_SNI}&fp=${UTLS_FP}&pbk=${PUBLIC_KEY2}&sid=${SHORT_ID_TCP_1}&type=tcp&flow=xtls-rprx-vision#MyServer-TCP"
  TCP_SECTION="
───────────────────────────────────────────────────────
ВТОРОЙ INBOUND: VLESS+REALITY+TCP (XTLS-Vision)
───────────────────────────────────────────────────────
PORT2        : ${XRAY_PORT2}
PUBLIC KEY2  : ${PUBLIC_KEY2}
SHORT ID TCP : ${SHORT_ID_TCP_1} / ${SHORT_ID_TCP_2}
VLESS URI (TCP):
${VLESS_URI_TCP}"
fi

mkdir -p "$(dirname "$CLIENT_FILE")"
# Метки без пробела перед двоеточием: _get_pubkey в xm.sh ищет их по "^LABEL:".
cat > "$CLIENT_FILE" <<EOF
═══════════════════════════════════════════════════════
  Xray VLESS+REALITY+XHTTP · Client Info v5.5
  Сгенерировано: $(date)
═══════════════════════════════════════════════════════
SERVER IP: ${SERVER_IP}
PORT: ${XRAY_PORT}
UUID: ${USER_UUID}
PUBLIC KEY: ${PUBLIC_KEY}
SHORT ID: ${SHORT_ID_1}
SNI: ${DEST_SNI}
PATH: ${XHTTP_PATH}
MODE: ${XHTTP_MODE}
FINGERPRINT: ${UTLS_FP}
SSH PORT: ${SSH_PORT}

ALL SHORT IDs (XHTTP):
  ${SHORT_ID_1}
  ${SHORT_ID_2}
  ${SHORT_ID_3}

───────────────────────────────────────────────────────
VLESS URI (XHTTP):
───────────────────────────────────────────────────────
${VLESS_URI_XHTTP}

───────────────────────────────────────────────────────
sing-box JSON (XHTTP)
XHTTP — транспорт Xray-core: клиенты на ядре sing-box
(Hiddify, NekoBox) могут его не поддерживать — подключение
висит и отваливается по таймауту. Для них — профиль
TCP/XTLS-Vision ниже.
───────────────────────────────────────────────────────
{
  "type": "vless", "tag": "proxy-xhttp",
  "server": "${SERVER_IP}", "server_port": ${XRAY_PORT},
  "uuid": "${USER_UUID}",
  "tls": {
    "enabled": true, "server_name": "${DEST_SNI}",
    "utls": { "enabled": true, "fingerprint": "${UTLS_FP}" },
    "reality": { "enabled": true, "public_key": "${PUBLIC_KEY}", "short_id": "${SHORT_ID_1}" }
  },
  "transport": {
    "type": "xhttp", "path": "${XHTTP_PATH}",
    "host": "${DEST_SNI}", "method": "${SINGBOX_METHOD}", "mode": "${XHTTP_MODE}"
  }
}
${TCP_SECTION}

───────────────────────────────────────────────────────
UUID — это доступ к прокси. Приватного ключа REALITY здесь
нет, но передавать файл можно только по защищённому каналу.
───────────────────────────────────────────────────────
EOF

chmod 600 "$CLIENT_FILE"
chown root:root "$CLIENT_FILE"
success "Данные клиентов: $CLIENT_FILE"

# 17. ЖУРНАЛ РАЗБОРА ПРОБЛЕМ — детали этой установки, которым не место в
# репозитории. Создаётся один раз, переустановку и self-update переживает.
if [[ ! -f "$JOURNAL_FILE" ]]; then
  cat > "$JOURNAL_FILE" <<'EOF'
# Журнал этой установки

Локальные заметки о разборе проблем на этом сервере: что не работало, что
проверялось, чем кончилось. Пополняется через `xm journal add "текст"`,
читается через `xm journal`. Отсюда ничего не публикуется и не коммитится —
файл живёт только на этом сервере.
EOF
  chmod 600 "$JOURNAL_FILE"
  chown root:root "$JOURNAL_FILE"
fi

# =============================================================================
# 18. ИТОГ
# =============================================================================
header "Готово"

echo -e "  ${BOLD}${SERVER_IP}:${XRAY_PORT}${NC}  ·  SNI ${DEST_SNI}  ·  path ${XHTTP_PATH}"
$DUAL_INBOUND && echo -e "  ${BOLD}${SERVER_IP}:${XRAY_PORT2}${NC}  ·  TCP / XTLS-Vision"

echo ""
echo -e "${GREEN}${BOLD}VLESS URI (XHTTP):${NC}"
echo "$VLESS_URI_XHTTP"
_print_qr "$VLESS_URI_XHTTP" "QR XHTTP"

if $DUAL_INBOUND; then
  echo ""
  echo -e "${GREEN}${BOLD}VLESS URI (TCP):${NC}"
  echo "$VLESS_URI_TCP"
  _print_qr "$VLESS_URI_TCP" "QR TCP (XTLS-Vision)"
fi

jq -e '.dns.servers // empty' "$XRAY_CONFIG" >/dev/null 2>&1 \
  || warn "DoH с этого VPS не поднялся — домены резолвятся открытым текстом: sudo xm harden"

echo ""
echo -e "  Данные клиентов: ${BOLD}$CLIENT_FILE${NC}  (UUID — это доступ)"
echo -e "  QR ещё раз:      ${BOLD}xm qr --both${NC}"
echo -e "  Проверка:        ${BOLD}xm diag${NC}  ·  устойчивость к DPI: ${BOLD}xm diag-dpi${NC}"
echo -e "  Все команды:     ${BOLD}xm help${NC}"
