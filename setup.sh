#!/usr/bin/env bash
# =============================================================================
#  Xray-core · VLESS + REALITY + XHTTP  ·  Auto Setup  v5.7
#  Ubuntu 24.04 LTS
#
#  Исправления v5 (относительно v4):
#   - xm.sh автоматически копируется в /usr/local/bin/xm
#   - SSH-порт определяется динамически (не хардкод 22)
#   - ufw enable только ПОСЛЕ открытия SSH-порта
#   - fail2ban logfile создаётся до старта сервиса
#   - Защита от повторного запуска (--reinstall для принудительного)
#   - Проверка совпадения портов XHTTP и TCP
#   - chronyc makestep с retry-циклом
#   - ENCODED_PATH через sys.argv (нет shell-инъекций)
#
#  Исправления v5.1:
#   - Надёжный парсинг ключей xray x25519 (поддержка всех версий Xray)
#   - Валидация длины публичного ключа перед записью в URI
#
#  Исправления v5.2:
#   - qrencode добавлен в зависимости
#   - Функция _print_qr: QR-код прямо в терминал после установки
#   - QR выводится для каждого VLESS URI в итоговом блоке
#
#  Исправления v5.3 (security hardening):
#   - [FIX-1] config.json chmod 600 сразу после записи (приватный ключ REALITY)
#   - [FIX-2] Временные файлы через mktemp (атомарный mv, нет race condition)
#   - [FIX-3] Валидация формата SERVER_IP (IPv4/IPv6, не HTML-мусор)
#   - [FIX-4] Nginx rate limiting на fallback (limit_req_zone)
#   - [FIX-5] maxTimeDiff снижен до 10000 мс (chrony держит < 1 сек)
#   - [FIX-6] Блокировка geoip:cn + geoip:ir в routing (сканирующие AS)
#   - [FIX-7] xPaddingBytes расширен до 100-1460 (меньше статистических паттернов)
#
#  Исправления v5.4 (REALITY compatibility):
#   - [FIX-8] Проверка РАЗМЕРА TLS Certificate у dest/SNI (openssl s_client):
#             домены с большой цепочкой/OCSP staple (www.microsoft.com)
#             переполняют захардкоженный буфер REALITY (~8192 б) и РВУТ
#             хендшейк, хотя curl отвечает 200. HTTP-код это не ловит.
#             Добавлена оценка размера сертификата в секции 7.
#   - [FIX-8] Дефолтный список SNI заменён на домены с компактными
#             сертификатами; microsoft.com убран из дефолтов (оставлен
#             последней опцией как наглядный пример «слишком большого» cert).
#
#  Исправления v5.7 (анти-DPI: ответ на блокировки DoH/DoT):
#   - [FIX-15] nginx REALITY fallback переведён в режим mimic: зонд с чужим
#             или отсутствующим SNI получает ответ НАСТОЯЩЕГО сайта, а не
#             молчаливый обрыв TCP. Прежнее поведение ("порт открыт, TLS не
#             говорит") — готовая подпись прокси для любого сканера.
#   - [FIX-16] Секция 11b: dns-блок с DoH по IP-литералу + outbound dns-out +
#             routing-правило :53 → dns-out. Раньше dns-блока не было вообще:
#             Xray резолвил домены системным резолвером хостера ОТКРЫТЫМ
#             текстом, то есть хостер видел полный список посещаемых сайтов.
#             Плюс plain-DNS клиента (а после блокировок DoH/DoT их
#             большинство) пересылался с VPS наружу как есть. Теперь сервер
#             перехватывает :53 из тоннеля и отвечает сам по DoH.
#             Доступность DoH проверяется ДО правки конфига — иначе включение
#             убило бы весь резолвинг без единой ошибки в логе.
#   - queryStrategy подбирается по фактическому стеку VPS (нет IPv6 → UseIPv4,
#     без бесполезных AAAA, до которых сервер всё равно не дойдёт).
#   - Бэкапы config.json теперь 600 (внутри приватный ключ REALITY).
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n"; }

[[ $EUID -ne 0 ]] && error "Запусти скрипт от root: sudo bash $0"

# Скрипт писался под 24.04. На focal (20.04) сборка nginx старее (1.18) и
# набор stream-модулей уже — см. FIX-10. Работает, но об этом надо знать.
OS_VER=$(lsb_release -rs 2>/dev/null || echo "?")
case "$OS_VER" in
  24.04|22.04) ;;
  20.04) echo -e "${YELLOW}[WARN]${NC} Ubuntu 20.04: стандартная поддержка закончилась (только ESM),
       nginx 1.18 без stream_realip. Скрипт учитывает это, но обновление
       до 22.04/24.04 рекомендуется." ;;
  *) echo -e "${YELLOW}[WARN]${NC} Непроверенная версия ОС: $OS_VER — возможны сюрпризы" ;;
esac

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"
XM_SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)/xm.sh"

# =============================================================================
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: надёжный парсинг ключей xray x25519
# Поддерживает все известные форматы вывода Xray:
#   "Private key: xxx"  /  "PrivateKey: xxx"
#   "Public key: xxx"   /  "Password (PublicKey): xxx"  /  "PublicKey: xxx"
# =============================================================================
_parse_xray_keys() {
  local output="$1"
  # [FIX] Якорим парсинг по МЕТКЕ в начале строки (^label), а не по подстроке где угодно.
  #
  # ПОЧЕМУ ЭТО ВАЖНО (уязвимость/несовместимость):
  #   В новых версиях Xray-core вывод `xray x25519` изменился:
  #     старый:  "Private key: xxx" / "Public key: yyy"
  #     новый:   "PrivateKey: xxx"  / "Password: yyy" / "Hash32: zzz"
  #   Здесь "Password" — это и есть бывший Public key (переименован намеренно,
  #   чтобы им не делились: по публичному ключу теоретически можно активно
  #   пробить REALITY-сервер). Старый `grep -i "ublic"` на строку "Password:"
  #   НЕ срабатывал → PUBLIC_KEY оставался пустым → установка падала на валидации.
  #   Теперь ловим "Public" ИЛИ "Password".
  #
  #   Якорь ^[[:space:]]* также исключает ложное совпадение, если само base64-
  #   значение ключа случайно содержит подстроку "public"/"private": метка всегда
  #   стоит в начале строки, а значение ключа — никогда.
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

# =============================================================================
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: вывод QR-кода прямо в терминал
# -t UTF8  — Unicode-блоки, работают в любом терминале (ssh/tmux/screen/VSCode)
# -m 1     — quiet zone 1 модуль (достаточно для сканирования с экрана)
# -l L     — минимальная коррекция ошибок (меньше QR для длинных URI)
# =============================================================================
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

# =============================================================================
# [FIX-3] ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: получение и валидация внешнего IP
# Защита от ситуации когда ipify/ifconfig.me вернул HTML или пустую строку.
# Пробуем несколько источников, проверяем формат IPv4/IPv6 перед использованием.
# =============================================================================
_fetch_server_ip() {
  local ip
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me" \
    "https://api64.ipify.org"; do
    # [FIX] "|| true": под set -euo pipefail упавший curl роняет пайп (pipefail),
    # присваивание возвращает !=0 и функция выходит на ПЕРВОМ источнике —
    # резервные ifconfig.me / api64 не опрашивались вообще.
    ip=$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    # Проверяем IPv4: четыре октета по 1-3 цифры
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "$ip"
      return 0
    fi
    # Проверяем IPv6: содержит двоеточия, минимум 4 символа, только hex и ':'
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ ${#ip} -gt 4 ]]; then
      echo "$ip"
      return 0
    fi
  done
  # Ни один источник не вернул валидный IP
  echo "ТВОЙ_IP"
  return 1
}

# =============================================================================
# [FIX-8] ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: оценка размера TLS Certificate у dest/SNI
#
# ПОЧЕМУ (это НЕ то же, что HTTP-доступность):
#   При fallback REALITY пересылает клиенту TLS-хендшейк реального сайта.
#   В ряде версий Xray-core на приём Certificate-сообщения (цепочка серверных
#   сертификатов) стоит захардкоженный буфер ~8192 байт. Большая цепочка и/или
#   OCSP-stapling (классика — www.microsoft.com) переполняют его и РВУТ
#   REALITY-хендшейк целиком, хотя `curl https://сайт` отвечает 200. Проверка
#   только по HTTP-коду (секция 7 / xm add-tcp) этот случай не видит: сервер
#   выглядит здоровым, а клиент ловит "handshake failed".
#
# ЧТО МЕРЯЕМ (верхняя оценка размера записи):
#   сумма DER всех сертификатов из -showcerts + запас на OCSP staple (если есть)
#   + служебные поля Certificate-сообщения.
# Печатает в stdout число байт, либо "-1" если сайт недоступен по :443.
# Всегда return 0 — сигнал об ошибке идёт через "-1", чтобы не сработал set -e.
# =============================================================================
REALITY_CERT_WARN=7000     # запас до лимита; между warn и limit — риск на части версий
REALITY_CERT_LIMIT=8192    # захардкоженный буфер REALITY в ряде версий Xray-core

# =============================================================================
# DNS: DoH-резолверы для сервера
#
# ЗАЧЕМ: с августа 2025 массово сообщают об ограничениях DoH/DoT у российских
# операторов. Проверить это со стороны сервера нельзя, но и не нужно: описанная
# ниже утечка существует независимо от них. Браузер/ОС, не достучавшись до
# Secure DNS, откатывается на ОБЫЧНЫЙ DNS.
# Дальше имя домена видит либо провайдер (VPN выключен), либо — если ничего
# не делать — хостер VPS, потому что Xray без dns-блока резолвит системным
# резолвером открытым текстом. Оба канала закрываются DoH на сервере плюс
# перехватом :53 из тоннеля: клиенту при этом ничего настраивать не нужно.
#
# Резолверы заданы IP-ЛИТЕРАЛОМ — нет bootstrap-запроса «а какой IP у
# dns.google», который ушёл бы открытым. https+local:// = мимо routing,
# поэтому перехват :53 не зацикливается на самом себе.
# =============================================================================
DOH_LIST='["https+local://1.1.1.1/dns-query","https+local://9.9.9.9/dns-query","https+local://8.8.8.8/dns-query"]'
DOH_IPS=(1.1.1.1 9.9.9.9 8.8.8.8)

# Отвечает ли резолвер по DoH ИМЕННО С ЭТОГО VPS (RFC 8484 wireformat GET —
# он есть у всех, в отличие от JSON-API).
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

# =============================================================================
# _sni_probe <host> → "cert_б|ocsp_б|alpn_h2|tls13|x25519|rtt_мс|redirect_host"
# cert_б = -1 если хост недоступен. Расширение _check_cert_size: одного размера
# сертификата мало — dest обязан уметь TLS1.3 (иначе REALITY не работает в
# принципе) и ALPN h2 (иначе XHTTP не поднимется поверх HTTP/2).
# Все конвейеры прикрыты "|| true": под set -euo pipefail пустой grep роняет
# присваивание и убивает весь скрипт.
# =============================================================================
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
# _selftest_vless <xhttp|tcp> <uuid> <port> <sni> <sid> <pubkey> [path] [mode]
#
# ЗАЧЕМ ЭТО ГЛАВНАЯ ПРОВЕРКА: REALITY при провале хендшейка НЕ ПИШЕТ НИЧЕГО
# в лог — это штатная ветка протокола («не наш клиент, закрываем»), а не
# ошибка. Поэтому «в логах пусто» ничего не доказывает. Здесь мы поднимаем
# настоящий VLESS-клиент на loopback и ходим через собственный сервер:
# сеть, провайдер и клиентское приложение исключены, ответ бинарный.
# Печатает HTTP-код (200 = всё работает), 000 = не прошло.
# =============================================================================
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
  # [FIX-14] `|| echo "000"` внутри $( ) СКЛЕИВАЛСЯ с выводом самого curl:
  # при неудаче curl печатает "000" в stdout И возвращает !=0, после чего
  # echo добавляет ещё "000" → в переменную попадало "000000". Это не валидный
  # HTTP-статус, и при разборе он сбивает с толку («что за код такой?»).
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

# =============================================================================
# _switch_sni <domain> — перевод ВСЕГО стека на другой домен-маску:
# config.json (serverNames XHTTP+TCP + xhttpSettings.host) + nginx map
# (регенерация из шаблона) + рестарт. Нужен авто-подбору в секции 14b.
# Возврат 1 = применить не удалось.
# =============================================================================
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
# 0. ЗАЩИТА ОТ ПОВТОРНОГО ЗАПУСКА
# =============================================================================
if [[ -f "$XRAY_CONFIG" ]] && [[ "${1:-}" != "--reinstall" ]]; then
  echo -e "${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${YELLOW}║  Xray уже установлен (найден $XRAY_CONFIG)  ║${NC}"
  echo -e "${YELLOW}║  Повторный запуск сгенерирует новые ключи —         ║${NC}"
  echo -e "${YELLOW}║  все подключённые клиенты перестанут работать!      ║${NC}"
  echo -e "${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "Для принудительной переустановки запусти:"
  echo -e "  ${BOLD}sudo bash $0 --reinstall${NC}"
  echo ""
  echo -e "Управление: ${BOLD}xm help${NC}  |  Диагностика: ${BOLD}xm diag${NC}"
  exit 0
fi

# =============================================================================
# 1. ИНТЕРАКТИВНЫЙ ВВОД
# =============================================================================
header "Настройка параметров"

# Пул кандидатов. www.microsoft.com исключён НАВСЕГДА: cert+OCSP ≈ 9085 б при
# буфере REALITY ~8192 б — хендшейк рвётся молча (замерено на живом сервере).
# Порядок не важен: ниже идёт живой замер и выбор по факту.
SNI_POOL=(www.cloudflare.com dl.google.com cdn.jsdelivr.net www.apple.com)

echo -e "${BOLD}Подбор домена-маски (SNI / dest)${NC}"
info "Замеряю кандидатов: cert, OCSP, ALPN h2, TLS1.3, RTT — ~20 сек..."
echo ""
printf "  %-22s %8s %6s %5s %7s %7s  %s\n" "домен" "cert,б" "OCSP" "h2" "TLS1.3" "RTT,мс" "вердикт"

declare -a SNI_OK=()
for h in "${SNI_POOL[@]}"; do
  IFS='|' read -r P_CERT P_OCSP P_ALPN P_TLS13 P_X25519 P_RTT P_REDIR <<< "$(_sni_probe "$h")"
  if [[ "$P_CERT" == "-1" ]]; then
    printf "  %-22s %8s %6s %5s %7s %7s  ${RED}%s${NC}\n" "$h" "-" "-" "-" "-" "-" "НЕДОСТУПЕН"
    continue
  fi
  V="ГОДИТСЯ"; C="$GREEN"
  [[ "$P_CERT" -ge "$REALITY_CERT_WARN"  ]] && { V="РИСК";       C="$YELLOW"; }
  [[ "$P_CERT" -ge "$REALITY_CERT_LIMIT" ]] && { V="НЕ ГОДИТСЯ"; C="$RED"; }
  # TLS1.3 обязателен: REALITY работает только поверх него.
  # ALPN h2 обязателен: XHTTP живёт внутри HTTP/2.
  [[ "$P_TLS13" != "да" ]] && { V="НЕТ TLS1.3"; C="$RED"; }
  [[ "$P_ALPN"  != "да" ]] && { V="НЕТ h2";     C="$RED"; }
  # RTT платится на КАЖДОМ входящем соединении (REALITY идёт к dest всегда).
  [[ "$P_RTT" -gt 150 && "$V" == "ГОДИТСЯ" ]] && { V="МЕДЛЕННЫЙ"; C="$YELLOW"; }
  [[ -n "$P_REDIR" && "$V" == "ГОДИТСЯ" ]] && { V="РЕДИРЕКТ→$P_REDIR"; C="$YELLOW"; }
  printf "  %-22s %8s %6s %5s %7s %7s  ${C}%s${NC}\n" \
    "$h" "$P_CERT" "$([[ ${P_OCSP:-0} -gt 0 ]] && echo да || echo нет)" \
    "$P_ALPN" "$P_TLS13" "$P_RTT" "$V"
  [[ "$V" == "ГОДИТСЯ" ]] && SNI_OK+=("$P_CERT $h")
done
echo ""

# Лучший = наименьший cert среди прошедших ВСЕ проверки (больше запас до лимита)
if [[ ${#SNI_OK[@]} -gt 0 ]]; then
  DEST_SNI=$(printf '%s\n' "${SNI_OK[@]}" | sort -n | head -1 | awk '{print $2}')
  success "Рекомендация: ${BOLD}$DEST_SNI${NC} — наибольший запас до лимита REALITY"
else
  DEST_SNI=""
  warn "Ни один кандидат не прошёл — введи домен вручную (и проверь сеть VPS)"
fi

read -rp "Домен [Enter=${DEST_SNI:-введи вручную}]: " SNI_INPUT
DEST_SNI=${SNI_INPUT:-$DEST_SNI}
[[ -z "$DEST_SNI" ]] && error "Домен-маска не выбран"

if [[ ! "$DEST_SNI" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  error "Недопустимые символы в SNI: $DEST_SNI"
fi
info "SNI/dest: ${BOLD}$DEST_SNI${NC}"

echo ""
echo -e "${BOLD}Выбери HTTP path:${NC}"
echo "  1) /api/v2/assets/stream"
echo "  2) /video/hls/playlist.m3u8"
echo "  3) /static/js/chunk-main.js"
echo "  4) /cdn-cgi/trace"
echo "  5) /download/update"
echo "  6) Ввести вручную"
read -rp "Выбор [1-6, Enter=1]: " PATH_CHOICE
PATH_CHOICE=${PATH_CHOICE:-1}

case "$PATH_CHOICE" in
  1) XHTTP_PATH="/api/v2/assets/stream" ;;
  2) XHTTP_PATH="/video/hls/playlist.m3u8" ;;
  3) XHTTP_PATH="/static/js/chunk-main.js" ;;
  4) XHTTP_PATH="/cdn-cgi/trace" ;;
  5) XHTTP_PATH="/download/update" ;;
  6) read -rp "Введи path (начиная с /): " XHTTP_PATH ;;
  *) XHTTP_PATH="/api/v2/assets/stream" ;;
esac

if [[ "$XHTTP_PATH" =~ [\"\'\\$\`] ]] || [[ "$XHTTP_PATH" != /* ]]; then
  error "Недопустимые символы в path или path не начинается с /: $XHTTP_PATH"
fi
info "Path: ${BOLD}$XHTTP_PATH${NC}"

echo ""
echo -e "${BOLD}Режим XHTTP:${NC}"
echo "  1) auto        (H2 или H1.1, авто)"
echo "  2) stream-one  (один долгоживущий поток)"
read -rp "Выбор [1-2, Enter=1]: " MODE_CHOICE
MODE_CHOICE=${MODE_CHOICE:-1}

case "$MODE_CHOICE" in
  1) XHTTP_MODE="auto";       SINGBOX_METHOD="GET"  ;;
  2) XHTTP_MODE="stream-one"; SINGBOX_METHOD="POST" ;;
  *) XHTTP_MODE="auto";       SINGBOX_METHOD="GET"  ;;
esac
info "Mode: ${BOLD}$XHTTP_MODE${NC}"

echo ""
echo -e "${BOLD}uTLS fingerprint:${NC}"
echo "  1) chrome"
echo "  2) edge"
echo "  3) firefox"
echo "  4) randomized"
read -rp "Выбор [1-4, Enter=1]: " FP_CHOICE
FP_CHOICE=${FP_CHOICE:-1}

case "$FP_CHOICE" in
  1) UTLS_FP="chrome" ;;
  2) UTLS_FP="edge" ;;
  3) UTLS_FP="firefox" ;;
  4) UTLS_FP="randomized" ;;
  *) UTLS_FP="chrome" ;;
esac
info "uTLS fingerprint: ${BOLD}$UTLS_FP${NC}"

echo ""
read -rp "Основной порт XHTTP [Enter=443]: " PORT_INPUT
XRAY_PORT=${PORT_INPUT:-443}
[[ "$XRAY_PORT" =~ ^[0-9]+$ ]] && [[ "$XRAY_PORT" -ge 1 ]] && [[ "$XRAY_PORT" -le 65535 ]] \
  || error "Некорректный порт: $XRAY_PORT"
info "Порт XHTTP: ${BOLD}$XRAY_PORT${NC}"

# Xray сам предупреждает при старте: "Listening on non-443 ports may get your
# IP blocked by the GFW". Сканер видит TLS на нестандартном порту при пустом
# 443 — картина, которой у настоящего сайта не бывает.
if [[ "$XRAY_PORT" != "443" ]]; then
  P443=$(ss -tlnp 2>/dev/null | grep -E ':443([^0-9]|$)' | head -1 || true)
  if [[ -z "$P443" ]]; then
    warn "Порт 443 свободен, а выбран ${XRAY_PORT} — REALITY на нестандартном порту заметен."
    read -rp "Использовать 443? [Y/n]: " USE443
    [[ "${USE443:-y}" =~ ^[Yy]$ ]] && { XRAY_PORT=443; info "Порт изменён на ${BOLD}443${NC}"; }
  else
    warn "Порт 443 занят: $(echo "$P443" | grep -oP 'users:\(\("\K[^"]+' || echo '?')"
    if echo "$P443" | grep -q docker; then
      warn "Это docker-proxy. Docker публикует порты СВОИМИ правилами iptables"
      warn "В ОБХОД UFW — контейнер открыт наружу независимо от ufw-правил."
      warn "Проверь что там: sudo iptables -t nat -L DOCKER -n"
    fi
  fi
fi

echo ""
echo -e "${BOLD}Добавить второй inbound — VLESS+REALITY+TCP (XTLS-Vision)?${NC}"
echo -e "${YELLOW}Настоятельно рекомендуется. XHTTP — транспорт Xray-core; клиенты${NC}"
echo -e "${YELLOW}на ядре sing-box (Hiddify, NekoBox) могут его не поддерживать и${NC}"
echo -e "${YELLOW}отваливаться по таймауту без единой строчки в логах. XTLS-Vision${NC}"
echo -e "${YELLOW}понимают все клиенты, а по устойчивости к DPI он не уступает.${NC}"
read -rp "Добавить? [Y/n]: " DUAL_CHOICE
DUAL_CHOICE=${DUAL_CHOICE:-y}

DUAL_INBOUND=false
XRAY_PORT2=8443
if [[ "$DUAL_CHOICE" =~ ^[Yy]$ ]]; then
  DUAL_INBOUND=true
  while true; do
    read -rp "Порт для TCP/XTLS-Vision [Enter=8443]: " PORT2_INPUT
    XRAY_PORT2=${PORT2_INPUT:-8443}
    [[ "$XRAY_PORT2" =~ ^[0-9]+$ ]] || { warn "Некорректный порт: $XRAY_PORT2"; continue; }
    if [[ "$XRAY_PORT2" -eq "$XRAY_PORT" ]]; then
      warn "Порт TCP ($XRAY_PORT2) совпадает с портом XHTTP ($XRAY_PORT) — выбери другой"
      continue
    fi
    if [[ "$XRAY_PORT2" -eq 10443 ]]; then
      warn "Порт 10443 зарезервирован под локальный REALITY fallback — выбери другой"
      continue
    fi
    break
  done
  info "Второй inbound: порт ${BOLD}$XRAY_PORT2${NC}"
fi

echo ""
echo -e "${YELLOW}Продолжить установку? [y/N]:${NC} "
read -rp "" CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Отменено."; exit 0; }

# =============================================================================
# 2. ЗАВИСИМОСТИ
# =============================================================================
header "Установка зависимостей"

# DEBIAN_FRONTEND + force-confold: unattended-upgrades спрашивает про уже
# изменённый 20auto-upgrades и вешает установку на интерактивном диалоге.
# Оставляем локальную версию — секция 10b всё равно перезапишет её своей.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
  curl wget unzip uuid-runtime openssl ufw \
  nginx libnginx-mod-stream fail2ban jq python3 python3-cryptography \
  chrony qrencode unattended-upgrades
# python3-cryptography: нужен _derive_pubkey в xm.sh (xm pubkey, xm diag [3b],
# вычисление publicKey из privateKey). Без него ключи считать нечем — остаётся
# только фолбэк на client-info.txt, который расходится после ручных правок.
# qrencode: рисует QR-код прямо в терминал (режим UTF8).
# libnginx-mod-stream: TCP/stream-модуль nginx — нужен для настоящего
# REALITY-fallback (ssl_preread + proxy_protocol). Пакет сам включает модуль
# через /etc/nginx/modules-enabled/*.conf.
success "Зависимости установлены"

# =============================================================================
# 3. ОПРЕДЕЛЕНИЕ SSH-ПОРТА (до UFW — критично!)
# =============================================================================
header "Определение SSH-порта"

SSH_PORT=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config 2>/dev/null \
  | awk '{print $2}' | head -1 || echo "")

if [[ -z "$SSH_PORT" ]]; then
  SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd \
    | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || echo "")
fi

SSH_PORT=${SSH_PORT:-22}

[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [[ "$SSH_PORT" -ge 1 ]] && [[ "$SSH_PORT" -le 65535 ]] \
  || SSH_PORT=22

info "SSH-порт: ${BOLD}$SSH_PORT${NC}"

# =============================================================================
# 4. NTP — CHRONY
# =============================================================================
header "Настройка NTP (chrony)"

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
# [FIX] Убран "local stratum 10".
# Он заставлял chronyd объявлять себя авторитетным источником времени
# (stratum 10) ДАЖЕ когда реальной синхронизации с пулом нет. Последствия:
#   - при недоступности NTP-пула сервер продолжал считать своё дрейфующее
#     время «синхронизированным», из-за чего REALITY (maxTimeDiff=10000)
#     мог молча начать отклонять клиентов при расхождении часов;
#   - "local" превращает хост в потенциальный NTP-источник (лишняя поверхность).
# Без этой строки chrony честно показывает "не синхронизирован", пока не
# получит реальный upstream — а xm diag-ntp это увидит.
CHRONYEOF

systemctl enable chrony
systemctl restart chrony

info "Ожидание синхронизации времени..."
for i in {1..10}; do
  if chronyc makestep 2>/dev/null; then
    break
  fi
  [[ $i -lt 10 ]] && sleep 2 || warn "chronyc makestep не завершился за 20 сек — продолжаем"
done

DRIFT=$(chronyc tracking 2>/dev/null | grep "System time" | awk '{print $4}' || echo "0")
success "Chrony запущен. Дрейф: ${DRIFT} сек"

# =============================================================================
# 5. XRAY-CORE
# =============================================================================
header "Установка Xray-core"

bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
success "Xray: $(xray version | head -1)"

# =============================================================================
# 6. ГЕНЕРАЦИЯ КЛЮЧЕЙ
# =============================================================================
header "Генерация ключей"

USER_UUID=$(xray uuid)
info "UUID: $USER_UUID"

# Используем надёжный парсинг — поддерживает все версии Xray
KEY_OUTPUT=$(xray x25519)
info "Вывод xray x25519 (для отладки):"
echo "$KEY_OUTPUT" | sed 's/^/  /'

_parse_xray_keys "$KEY_OUTPUT"
# После вызова PRIVATE_KEY и PUBLIC_KEY установлены и провалидированы

SHORT_ID_1=$(openssl rand -hex 8)
SHORT_ID_2=$(openssl rand -hex 8)
SHORT_ID_3=$(openssl rand -hex 4)
info "Public key: $PUBLIC_KEY"
info "ShortIds: $SHORT_ID_1 / $SHORT_ID_2 / $SHORT_ID_3"

if $DUAL_INBOUND; then
  KEY_OUTPUT2=$(xray x25519)
  # Временно переименуем чтобы не затереть первую пару
  _parse_xray_keys "$KEY_OUTPUT2"
  PRIVATE_KEY2="$PRIVATE_KEY"
  PUBLIC_KEY2="$PUBLIC_KEY"
  # Восстанавливаем первую пару из вывода
  _parse_xray_keys "$KEY_OUTPUT"
  SHORT_ID_TCP_1=$(openssl rand -hex 8)
  SHORT_ID_TCP_2=$(openssl rand -hex 4)
  info "TCP Public key: $PUBLIC_KEY2"
fi

success "Ключи сгенерированы"

# =============================================================================
# 7. ПРОВЕРКА ДОСТУПНОСТИ DEST
# =============================================================================
header "Проверка доступности dest: $DEST_SNI"

HTTP_CODE=$(curl -svo /dev/null "https://${DEST_SNI}" \
  --max-time 10 --connect-timeout 5 \
  -w "%{http_code}" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" =~ ^[23] || "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
  success "dest ${DEST_SNI} доступен (HTTP $HTTP_CODE)"
else
  warn "dest ${DEST_SNI} — код ответа: $HTTP_CODE"
  warn "REALITY форвардит зонды на этот хост. Если он недоступен — сервер виден как прокси!"
  read -rp "Продолжить? [y/N]: " DEST_CONFIRM
  [[ "$DEST_CONFIRM" =~ ^[Yy]$ ]] || error "Выбери другой dest и перезапусти."
fi

# [FIX-8] Дополнительно к HTTP-доступности — проверка РАЗМЕРА TLS-сертификата.
# HTTP 200 не гарантирует сборку REALITY-хендшейка (см. _check_cert_size).
info "Проверка размера TLS-сертификата $DEST_SNI (совместимость с REALITY)..."
CERT_EST=$(_check_cert_size "$DEST_SNI")
if [[ "$CERT_EST" == "-1" ]]; then
  warn "Не удалось снять сертификат $DEST_SNI по :443 — пропускаю проверку размера"
elif [[ "$CERT_EST" -ge "$REALITY_CERT_LIMIT" ]]; then
  # Обхода нет намеренно. Прежний "[y/N]" позволял поставить заведомо нерабочий
  # домен: клиент ловит таймаут, в логах сервера ПУСТО (REALITY молчит), и
  # диагностика начинается с нуля. Установка с таким dest бессмысленна.
  error "Оценка Certificate: ${CERT_EST} б ≥ лимита REALITY (${REALITY_CERT_LIMIT} б).
       REALITY-хендшейк будет рваться МОЛЧА: у клиента таймаут, в логах ничего.
       Выбери домен с компактным сертификатом (см. таблицу выше) и перезапусти."
elif [[ "$CERT_EST" -ge "$REALITY_CERT_WARN" ]]; then
  warn "Оценка Certificate: ${CERT_EST} б — близко к лимиту (${REALITY_CERT_LIMIT} б). Возможны сбои на части версий Xray."
else
  success "Размер Certificate ~${CERT_EST} б — с запасом ниже лимита REALITY (${REALITY_CERT_LIMIT} б)"
fi

# =============================================================================
# 8. ЛОГИ + LOGROTATE
# =============================================================================
# [FIX-14] Каталог мало создать — нужно ГАРАНТИРОВАТЬ, что пользователь сервиса
# сможет создать в нём файл, и что сам error.log уже существует с правильным
# владельцем.
#
# ПОЧЕМУ ЭТО НЕ ЛОВИЛОСЬ: `xray -test` проверяет только схему конфига и даёт
# "Configuration OK" даже когда процесс физически не может открыть лог. Ошибка
# существует лишь в рантайме, от пользователя nobody (User=nobody в юните от
# XTLS/Xray-install). Xray падает с exit 23, а RestartPreventExitStatus=23 в
# юните запрещает рестарт — в журнале одна строка "permission denied".
#
# ПОЧЕМУ mkdir НЕ ХВАТАЛО: mkdir -p на существующем каталоге права не меняет.
# После ручного удаления *.log каталог оставался незаписываемым для nobody, и
# создать error.log заново было нечем. install -d/-m применяет права и к уже
# существующему пути — поэтому здесь именно install, а не mkdir+chown.
XRAY_USER=$(systemctl show -p User --value xray 2>/dev/null || true)
XRAY_USER=${XRAY_USER:-nobody}
XRAY_GROUP=$(id -gn "$XRAY_USER" 2>/dev/null || echo nogroup)

install -d -m 750 -o "$XRAY_USER" -g "$XRAY_GROUP" "$XRAY_LOG_DIR"
install -m 640 -o "$XRAY_USER" -g "$XRAY_GROUP" /dev/null "$XRAY_LOG_DIR/error.log"

# Проверяем ФАКТ доступа от имени сервиса, а не права «на бумаге»:
# ACL, chattr +i или нестандартный владелец каталога сюда тоже попадут.
if ! sudo -u "$XRAY_USER" test -w "$XRAY_LOG_DIR/error.log"; then
  error "Пользователь $XRAY_USER не может писать в $XRAY_LOG_DIR/error.log.
       Смотри: sudo ls -la $XRAY_LOG_DIR  и  sudo lsattr -d $XRAY_LOG_DIR"
fi
success "Лог-директория: $XRAY_LOG_DIR ($XRAY_USER:$XRAY_GROUP, error.log создан)"

cat > /etc/logrotate.d/xray <<'LOGROTEOF'
/var/log/xray/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    # [FIX] copytruncate вместо postrotate + kill -USR1.
    # Xray-core (Go) ловит только SIGINT/SIGTERM. SIGUSR1 для Go-рантайма —
    # сигнал с дефолтным действием "Term": процесс УМИРАЕТ, systemd его
    # перезапускает, все клиентские соединения рвутся — каждые сутки.
    # Плюс без "create" новый лог-файл не создавался: после первой ротации
    # запись в лог прекращалась совсем.
    # copytruncate: logrotate копирует файл и обнуляет оригинал — открытый
    # дескриптор Xray остаётся валидным, сигналы и рестарт не нужны вообще.
    copytruncate
}
LOGROTEOF
success "logrotate настроен (14 дней)"

# =============================================================================
# 9. NGINX — НАСТОЯЩИЙ REALITY FALLBACK (stream + ssl_preread)
# [FIX-4 переработан] Раньше nginx на :8080/:80 в тракт Xray НЕ входил:
#   REALITY dest указывал прямо на внешний $sni:443, а rate-limit/fail2ban
#   фильтровали несуществующий трафик (бутафория).
# Теперь REALITY dest = 127.0.0.1:10443 c PROXY protocol v2 (xver=2, см. §11),
#   а здесь nginx через stream+ssl_preread:
#     - читает SNI, НЕ терминируя TLS (сертификат реального сайта проходит
#       насквозь — REALITY по-прежнему «одалживает» чужой валидный TLS);
#     - проксирует ТОЛЬКО на наш разрешённый SNI (whitelist → не открытый релей);
#     - видит РЕАЛЬНЫЙ IP клиента (proxy_protocol) → limit_conn и логи работают
#       по настоящему адресу, а не по 127.0.0.1.
#   :80 оставляем как обычный 301-редирект (стандартное поведение веб-сервера).
# =============================================================================

# =============================================================================
# [FIX-11] Наличие ssl_preread НЕЛЬЗЯ определять по `nginx -V`.
#
# ПОЧЕМУ: в Debian/Ubuntu stream собирается ОТДЕЛЬНЫМ проходом как динамический
# модуль (пакет libnginx-mod-stream), и его configure-флагов в `nginx -V`
# основного бинарника НЕТ — там только аргументы сборки nginx-core. Прежняя
# проверка падала ВСЕГДА, даже когда модуль установлен и полностью рабочий
# (замерено: Ubuntu 20.04, nginx 1.18.0-0ubuntu1.7, libnginx-mod-stream стоит).
# Проверяем по факту, тремя способами от дешёвого к точному.
# =============================================================================
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

header "Настройка Nginx REALITY fallback (stream/ssl_preread)"

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

# --- HTTP vhost: только :80 → 301 (обычное поведение веб-сервера) -------------
# Прежний внутренний vhost на :8080 удалён: в тракт REALITY он не входил.
cat > /etc/nginx/sites-available/fallback <<'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    return 301 https://$host$request_uri;
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/fallback /etc/nginx/sites-enabled/fallback

# Подчищаем старую http-бутафорию, если осталась от прошлых версий/запусков.
rm -f /etc/nginx/conf.d/rate-limit.conf

# --- STREAM: настоящий REALITY fallback --------------------------------------
# nginx-модуль stream включается сам после установки libnginx-mod-stream
# (см. /etc/nginx/modules-enabled/*.conf). Сам stream-блок объявляется в
# top-level контексте nginx.conf — добавляем include ОДИН раз (идемпотентно).
mkdir -p /etc/nginx/stream-enabled
# [FIX-11] Сносим конфиги от прошлых версий скрипта ДО записи новых.
# В версиях < v5.5 здесь лежал set_real_ip_from, а ngx_stream_realip_module
# в пакетах Ubuntu отсутствует → `nginx -t` падал с
#   "set_real_ip_from" directive is not allowed here
# и ронял ВЕСЬ nginx, включая свежесгенерированный конфиг. Свой файл скрипт
# всё равно перезаписывает ниже; каталог создаётся только этим скриптом.
rm -f /etc/nginx/stream-enabled/*
if ! grep -q "stream-enabled/\*.conf" /etc/nginx/nginx.conf; then
  cat >> /etc/nginx/nginx.conf <<'NGXSTREAM'

# [FIX] REALITY fallback: stream-контекст для ssl_preread SNI-проксирования.
# Добавлено setup.sh. Не удалять — сюда подключается stream-enabled/*.conf.
stream {
    include /etc/nginx/stream-enabled/*.conf;
}
NGXSTREAM
fi

# Конфиг stream-fallback. Пишем через quoted-heredoc (чтобы shell не тронул
# nginx-переменные $ssl_preread_server_name и т.п.), а наш SNI подставляем
# отдельно через sed по плейсхолдеру __DEST_SNI__.
cat > /etc/nginx/stream-enabled/reality-fallback.conf <<'STREAMEOF'
# [FIX-15] Любой SNI (в т.ч. чужой и отсутствующий) уходит на ОДИН И ТОТ ЖЕ
# наш dest-SNI — режим mimic.
#
# ПОЧЕМУ НЕ ПУСТОЙ default, КАК БЫЛО: пустой апстрим = nginx принимает TCP и
# молча закрывает. Настоящий HTTPS-сервер на чужой SNI отвечает либо
# сертификатом, либо TLS-alert; принять соединение и закрыть его без единого
# байта TLS — поведение нетипичное и хорошо заметное. Сканеру (Censys/Shodan)
# хватает одного коннекта, чтобы увидеть «порт открыт, TLS не говорит» — это
# готовая подпись прокси, и REALITY со всей своей маскировкой тут не помогает.
# Теперь зонд получает ответ НАСТОЯЩЕГО сайта — то есть ровно то, что он
# получил бы, постучавшись на реальный edge этого домена.
#
# Открытым SNI-релеем сервер при этом НЕ становится: значение справа —
# константа, один и тот же домен для любого запроса. Выбрать хост назначения
# извне нельзя. Проверка: sudo xm diag-dpi → блок B.
# Вернуть прежнее поведение: sudo xm harden --off
map $ssl_preread_server_name $reality_upstream {
    default        __DEST_SNI__;
    __DEST_SNI__   __DEST_SNI__;
}

# [FIX-9] Флаг логирования. REALITY дозванивается до dest на КАЖДОЕ входящее
# соединение, а не только при провале аутентификации — значит через fallback
# идёт весь легитимный трафик. Без этого фильтра в лог попадали реальные IP
# всех клиентов и хранились 14 дней. Теперь на диск пишется только чужой/
# пустой SNI, т.е. чистые сканы.
map $ssl_preread_server_name $log_probe {
    default        1;
    __DEST_SNI__   0;
}

# [FIX-10] Ключ лимита и поле лога — $proxy_protocol_addr, а НЕ $remote_addr.
#
# ПОЧЕМУ: $remote_addr в stream подменяется реальным адресом клиента только
# модулем ngx_stream_realip_module (директива set_real_ip_from). Этот модуль
# требует сборки с --with-stream_realip_module, которого НЕТ в пакетах nginx
# для Ubuntu — libnginx-mod-stream привозит ssl_preread, но не realip.
# Итог прежней версии: nginx -t падал с
#   "set_real_ip_from" directive is not allowed here
# (парсер находил ОДНОИМЁННУЮ директиву http-модуля и отвергал её в stream).
#
# $proxy_protocol_addr отдаёт ядро stream при listen ... proxy_protocol —
# доп. модулей не нужно, значение то же: реальный IP клиента из PROXY v2.
# Переменная доступна с фазы post-accept, то есть раньше limit_conn
# (фаза preaccess), так что порядок вычисления корректен.
limit_conn_zone $proxy_protocol_addr zone=reality_conn:10m;

log_format reality_fallback '$proxy_protocol_addr [$time_local] '
                            'SNI="$ssl_preread_server_name" '
                            'status=$status sent=$bytes_sent';

# Апстрим задан именем и резолвится в рантайме → нужен resolver.
resolver 1.1.1.1 8.8.8.8 valid=30s ipv6=off;
resolver_timeout 5s;

server {
    # xver=2 в REALITY → сюда приходит PROXY protocol v2. Без proxy_protocol
    # nginx не распарсит заголовок и порвёт хендшейк.
    listen 127.0.0.1:10443 proxy_protocol;

    # Читаем SNI из ClientHello БЕЗ терминации TLS.
    ssl_preread on;

    # [FIX-9] Было 20 — и резало СВОИ же XHTTP-соединения, т.к. через fallback
    # идёт весь трафик, а не только зонды. 200 — заведомо выше нормального
    # клиента, но всё ещё отсекает флуд.
    limit_conn reality_conn 200;

    proxy_pass $reality_upstream:443;
    proxy_connect_timeout 5s;

    access_log /var/log/nginx/reality_fallback.log reality_fallback if=$log_probe;
    error_log  /var/log/nginx/reality_fallback_error.log error;
}
STREAMEOF

# Сохраняем шаблон с плейсхолдером ВНЕ stream-enabled/ (иначе nginx подхватит
# его как конфиг и упадёт на __DEST_SNI__). Из шаблона регенерируется конфиг
# при смене домена-маски — см. _switch_sni и секцию 14b.
cp /etc/nginx/stream-enabled/reality-fallback.conf /etc/nginx/reality-fallback.conf.tmpl
chmod 600 /etc/nginx/reality-fallback.conf.tmpl
# Подставляем реальный SNI (валидирован ранее как ^[a-zA-Z0-9._-]+$ — sed-safe).
sed -i "s/__DEST_SNI__/${DEST_SNI}/g" /etc/nginx/stream-enabled/reality-fallback.conf

# [FIX] Под set -e падение nginx -t внутри &&-списка НЕ прерывает скрипт,
# и ниже печатался бы success при сломанном конфиге.
nginx -t || error "nginx -t не прошёл — см. /etc/nginx/stream-enabled/reality-fallback.conf"
systemctl enable nginx
systemctl restart nginx
success "Nginx REALITY fallback настроен (stream/ssl_preread, dest=127.0.0.1:10443)"

# =============================================================================
# 10. FAIL2BAN
# =============================================================================
header "Настройка fail2ban"

# [FIX-9] Джейл nginx-reality-flood удалён:
#   1) не работал — fail2ban на Ubuntu 22.04 идёт с backend=systemd, свой
#      файл он не читал (Total failed: 0 при 9537 строках в логе);
#   2) при «починке» банил бы СВОИХ клиентов — их хендшейки тоже идут
#      через fallback;
#   3) бан сканеров сам по себе демаскирует: настоящий www.apple.com
#      не блэкхолит Censys/Shodan, а мы бы блэкхолили. Это отличие,
#      по которому сервер отделяется от реального сайта.
# Флуд теперь отсекает limit_conn 200 в nginx (без бана, как у CDN).
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
success "fail2ban настроен (SSH на порту $SSH_PORT)"

# =============================================================================
# 10b. АВТОМАТИЧЕСКИЕ SECURITY-ПАТЧИ ОС
# =============================================================================
header "Настройка автоматических security-обновлений"

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'UUEOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
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

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'UUEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
UUEOF

# Таймзона задаётся в самом таймере — системное время VPS не меняем
mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
cat > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf <<'UUEOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* 20:30:00 Europe/Moscow
RandomizedDelaySec=20m
Persistent=true
UUEOF

mkdir -p /etc/systemd/system/apt-daily.timer.d
cat > /etc/systemd/system/apt-daily.timer.d/override.conf <<'UUEOF'
[Timer]
OnCalendar=
OnCalendar=*-*-* 20:00:00 Europe/Moscow
RandomizedDelaySec=10m
Persistent=true
UUEOF

systemctl daemon-reload
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
success "Security-патчи: ежедневно 20:30 МСК (без автоперезагрузки)"

# =============================================================================
# 10c. ЕЖЕНЕДЕЛЬНАЯ РЕВАЛИДАЦИЯ ДОМЕНА-МАСКИ
# Сертификаты сайтов ротируются. Если у текущего dest вырастет цепочка или
# появится OCSP staple — REALITY начнёт рвать хендшейки МОЛЧА, и следующая
# диагностика опять начнётся с «клиент не работает, в логах пусто».
# =============================================================================
header "Ревалидация домена-маски (watchdog)"

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
success "Watchdog домена-маски: еженедельно (флаг виден в xm info)"

# =============================================================================
# 11. CONFIG.JSON
# [FIX-5] maxTimeDiff снижен до 10000 мс (10 сек).
#         Chrony держит drift < 1 сек. 60 сек было избыточно и давало
#         слишком широкое окно для replay перехваченных handshake.
# [FIX-6] В routing добавлена блокировка geoip:cn и geoip:ir —
#         сети, из которых идёт активное сканирование REALITY-серверов.
#         geoip файлы поставляются с Xray по умолчанию.
# [FIX-7] xPaddingBytes расширен до "100-1460" (прежде было "100-1000").
#         Более широкий диапазон хуже поддаётся статистическому
#         fingerprinting при анализе размеров пакетов DPI.
# =============================================================================
header "Запись конфигурации Xray"

# [FIX-12] Каталог конфига может отсутствовать: официальный install-release.sh
# создаёт /usr/local/etc/xray только когда РЕАЛЬНО ставит бинарник. Если версия
# уже актуальна ("info: No new version"), он выходит раньше и каталог не трогает.
# После полной очистки (rm -rf /usr/local/etc/xray) редирект `> $XRAY_CONFIG`
# падал с "No such file or directory" и под set -e убивал установку на середине.
# 750 root:nogroup: xray работает от nobody (нужен traverse через группу),
# остальные локальные пользователи каталог даже не перечислят.
mkdir -p "$(dirname "$XRAY_CONFIG")"
# [FIX-13] Права как у официального установщика — 755 root:root.
# 750 root:nogroup выигрыша не даёт: секреты закрыты правами самих файлов —
# config.json 640 root:nogroup (приватный ключ REALITY) и client-info.txt
# 600 root:root. Зато нестандартные права на каталоге, через который Xray
# ходит от пользователя nobody, — лишняя переменная при разборе «не стартует».
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
        # [FIX] dest теперь указывает на локальный nginx stream-fallback,
        # а не напрямую на внешний сайт. nginx через ssl_preread проксирует
        # хендшейк на реальный $sni:443 (сертификат проходит насквозь).
        dest: "127.0.0.1:10443",
        # [FIX] xver=2 → REALITY шлёт nginx PROXY protocol v2 с РЕАЛЬНЫМ IP
        # клиента, поэтому limit_conn/логи/fail2ban работают по адресу клиента.
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
        # [FIX-9] maxUploadSize / maxConcurrentUploads / waitUploadWritten
        # удалены: это старые имена SplitHTTP, Xray 26.x их молча игнорирует
        # (проверено — мусорное значение в maxUploadSize даёт Configuration OK,
        # тогда как мусор в живом xPaddingBytes даёт ошибку). Создавали ложное
        # впечатление настроенных лимитов.
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
          # [FIX] см. XHTTP inbound: dest → локальный nginx stream-fallback,
          # xver=2 для передачи реального IP клиента. SNI тот же, поэтому
          # существующего whitelist в reality-fallback.conf достаточно.
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
    # [FIX-9] access по умолчанию = Console → journald, и loglevel его НЕ
    # фильтрует. Замерено: 316 строк "from <IP клиента> accepted tcp:<IP
    # назначения>:443" за 2 часа. Это полный лог «кто куда ходил».
    log: { loglevel: "error", access: "none", dnsLog: false, error: ($logDir + "/error.log") },
    inbounds: $inbounds,
    outbounds: [
      { protocol: "freedom", tag: "direct", settings: { domainStrategy: "UseIPv4v6" } },
      { protocol: "blackhole", tag: "block" }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      # [FIX-9] Правило geoip:cn/ir удалено. Поле `ip` в routing — это АДРЕС
      # НАЗНАЧЕНИЯ, а не источника; плюс routing применяется уже ПОСЛЕ успешной
      # VLESS-аутентификации, куда зонд физически не доходит. От сканов оно не
      # защищало вообще, зато закрывало клиентам CN/IR-ресурсы.
      rules: [
        { type: "field", ip: ["geoip:private"], outboundTag: "block" },
        { type: "field", protocol: ["bittorrent"], outboundTag: "block" }
      ]
    },
    policy: {
      levels: { "0": { handshake: 4, connIdle: 300, uplinkOnly: 2, downlinkOnly: 5, bufferSize: 512 } },
      system: { statsInboundUplink: false, statsInboundDownlink: false }
    }
  }' > "$XRAY_CONFIG"

# [FIX-1] Ограничиваем права на config.json сразу после записи.
# Файл содержит приватный ключ REALITY — читать должен только root.
# По умолчанию официальный xray-install создаёт файл с правами 644,
# что позволяет любому локальному пользователю прочитать ключ.
# Xray запускается от пользователя nobody (группа nogroup) — см. systemd unit.
# 640 + root:nogroup: только root пишет, nobody читает через группу, остальные не видят.
# chmod ПЕРЕД chown — чтобы между ними не было окна с неправильными правами.
chmod 640 "$XRAY_CONFIG"
chown root:nogroup "$XRAY_CONFIG"
success "config.json записан и защищён (chmod 640, root:nogroup)"

# =============================================================================
# 11b. DNS: DoH на сервере + перехват :53 из тоннеля
#
# Проверяем ДОСТУПНОСТЬ резолверов до правки конфига: если ни один DoH с этого
# VPS не отвечает (хостер режет :443 к ним), включённый DoH убьёт весь
# резолвинг и сервер «перестанет работать» без единой ошибки в логе.
# =============================================================================
header "DNS: DoH + перехват :53"

DOH_OK=0
for r in "${DOH_IPS[@]}"; do
  if _doh_probe "$r"; then info "DoH $r — отвечает"; DOH_OK=$((DOH_OK + 1))
  else warn "DoH $r — не отвечает с этого VPS"; fi
done

if [[ "$DOH_OK" -eq 0 ]]; then
  warn "Ни один DoH-резолвер не доступен с VPS — dns-блок НЕ добавляю."
  warn "Иначе сломается резолвинг. Домены будет резолвить системный резолвер"
  warn "хостера открытым текстом. Разберись с сетью и запусти: sudo xm harden"
else
  # Нет IPv6 → AAAA бесполезны: клиент получит адрес, до которого сервер не
  # дойдёт, и это выглядит как «сайт не открывается через VPN».
  if _has_ipv6; then
    DNS_QS="UseIP";     DNS_DS="UseIPv4v6"; info "IPv6 на VPS есть → queryStrategy=UseIP"
  else
    DNS_QS="UseIPv4";   DNS_DS="UseIPv4";   info "IPv6 на VPS нет → queryStrategy=UseIPv4"
  fi

  # nonIPQuery=drop: запросы не-A/AAAA (HTTPS/SVCB, TXT) отбрасываются, а не
  # пересылаются наружу открытым текстом. Поле старое, но на редких сборках
  # может не приняться — тогда второй заход без него.
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

  # mktemp сразу даёт 600 — в файле приватный ключ REALITY, cp дал бы 644.
  # Без расширения .json: в каталоге конфигов лишний *.json — лишний риск.
  CFG_NODNS=$(mktemp "$(dirname "$XRAY_CONFIG")/config.nodns.XXXXXX")
  cat "$XRAY_CONFIG" > "$CFG_NODNS"
  if _write_dns_cfg "drop"; then
    success "DNS: DoH ($DOH_OK резолвера) + перехват :53 → dns-out"
  else
    warn "Xray не принял nonIPQuery — повторяю без него"
    cat "$CFG_NODNS" > "$XRAY_CONFIG"
    if _write_dns_cfg ""; then
      success "DNS: DoH ($DOH_OK резолвера) + перехват :53 → dns-out"
    else
      warn "dns-блок не принят этой сборкой Xray — возвращаю конфиг без него"
      cat "$CFG_NODNS" > "$XRAY_CONFIG"
    fi
  fi
  chmod 640 "$XRAY_CONFIG"; chown root:nogroup "$XRAY_CONFIG"
  rm -f "$CFG_NODNS"
fi

# =============================================================================
# 12. ВАЛИДАЦИЯ КОНФИГА
# =============================================================================
header "Валидация конфига"

if xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK"; then
  success "xray -test: Configuration OK"
else
  error "Конфиг невалиден: xray -test -config $XRAY_CONFIG"
fi

# =============================================================================
# 12b. УСТАНОВКА xm В PATH (до запуска сервиса — нужен для диагностики сбоя)
# =============================================================================
header "Установка xm (Xray Manager)"

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

# =============================================================================
# 13. FIREWALL (UFW)
# =============================================================================
header "Настройка UFW"

ufw allow "${SSH_PORT}/tcp"   comment 'SSH'         2>/dev/null || true
ufw allow 80/tcp              comment 'HTTP->HTTPS'  2>/dev/null || true
ufw allow "${XRAY_PORT}/tcp"  comment 'Xray XHTTP'  2>/dev/null || true
$DUAL_INBOUND && ufw allow "${XRAY_PORT2}/tcp" comment 'Xray TCP' 2>/dev/null || true

if ! ufw status | grep -q "Status: active"; then
  ufw --force enable && success "UFW включён"
else
  ufw reload && success "UFW перезагружен"
fi
ufw status numbered

# =============================================================================
# 14. SYSTEMD
# =============================================================================
header "Запуск сервиса"

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
  success "Xray запущен"
else
  # [FIX-13] Печатаем причину НА МЕСТЕ. `xray -test` проверяет только схему
  # конфига и проходит успешно, даже когда процесс не может занять порт или
  # создать лог-файл: эти ошибки существуют лишь в рантайме. Запуск от nobody
  # (пользователь сервиса) даёт точный текст, journalctl — историю рестартов,
  # ss — имя процесса-конкурента за порт. Без этого разбор начинается с нуля.
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

ss -tlnp | grep -q ":${XRAY_PORT}" \
  && success "Порт ${XRAY_PORT} прослушивается" \
  || warn "Порт ${XRAY_PORT} не найден — проверь вручную"

# =============================================================================
# 14b. SELFTEST — ГЛАВНАЯ ПРОВЕРКА УСТАНОВКИ
# Поднимаем локальный VLESS-клиент и ходим через собственный сервер. Если
# трафик не прошёл — автоматически пробуем следующий домен-маску из тех, что
# прошли замер в секции 1. Всё это ДО выдачи URI и QR, чтобы не раздавать
# клиентам заведомо нерабочий конфиг.
# =============================================================================
header "Selftest: живой REALITY-хендшейк через loopback"

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
  info "XHTTP через 127.0.0.1:${XRAY_PORT} (SNI: $SELFTEST_SNI)..."
  CODE=$(_selftest_vless xhttp "$USER_UUID" "$XRAY_PORT" "$SELFTEST_SNI" \
         "$SHORT_ID_1" "$PUBLIC_KEY" "$XHTTP_PATH" "$XHTTP_MODE")
  if [[ "$CODE" == "200" ]]; then
    success "XHTTP: трафик прошёл (HTTP 200) — REALITY-хендшейк рабочий"
    SELFTEST_OK=true
    DEST_SNI="$SELFTEST_SNI"
    break
  fi
  warn "XHTTP selftest не прошёл (код: $CODE), домен $SELFTEST_SNI"
  [[ -n "${SELFTEST_HINT:-}" ]] && echo "$SELFTEST_HINT" | sed 's/^/    /'
done

if $SELFTEST_OK && $DUAL_INBOUND; then
  info "TCP/XTLS-Vision через 127.0.0.1:${XRAY_PORT2}..."
  CODE2=$(_selftest_vless tcp "$USER_UUID" "$XRAY_PORT2" "$DEST_SNI" \
          "$SHORT_ID_TCP_1" "$PUBLIC_KEY2")
  [[ "$CODE2" == "200" ]] \
    && success "TCP/Vision: трафик прошёл (HTTP 200)" \
    || warn "TCP/Vision не прошёл (код: $CODE2) — проверь: sudo xm selftest --tcp"
fi

if ! $SELFTEST_OK; then
  warn "═══════════════════════════════════════════════════════════"
  warn "  Ни один домен-маска не дал рабочего хендшейка."
  warn "  Установка завершится, но сервер, скорее всего, НЕ работает."
  warn "  Напоминание: пустой лог у REALITY — норма, а не признак здоровья."
  warn "  Диагностика:  sudo xm selftest  |  sudo xm sni-scan"
  warn "  Смена домена: sudo xm set-sni <домен>"
  warn "═══════════════════════════════════════════════════════════"
fi

# =============================================================================
# 15. (перенесено выше — см. блок перед секцией 13)
# [FIX-13] xm ставится ДО запуска сервиса: при падении на старте Xray скрипт
# выходит по set -e, и раньше xm просто не успевал установиться — диагностика
# начиналась с "xm: command not found" именно в тот момент, когда он нужен.
# =============================================================================

# =============================================================================
# 16. IP + ДАННЫЕ КЛИЕНТА
# =============================================================================

# [FIX-3] Используем функцию с валидацией формата IP
# [FIX] "|| true": при полном провале функция делает return 1, и под set -e
# скрипт умирал прямо здесь — фолбэк на "ТВОЙ_IP" был недостижим.
SERVER_IP=$(_fetch_server_ip) || true
if [[ "$SERVER_IP" == "ТВОЙ_IP" ]]; then
  warn "Не удалось автоматически определить внешний IP!"
  warn "Укажи IP вручную в файле $CLIENT_FILE после установки."
fi

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

header "Сохранение данных для клиентов"
mkdir -p "$(dirname "$CLIENT_FILE")"
# ВАЖНО: метки записаны БЕЗ пробела перед двоеточием,
# чтобы _get_pubkey в xm.sh мог их надёжно найти по паттерну "^LABEL:"
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
⚠ XHTTP — транспорт Xray-core. Клиенты на ядре sing-box
(Hiddify, NekoBox) могут его НЕ поддерживать: симптом —
подключение висит и отваливается по таймауту, в логах
сервера при этом ПУСТО (REALITY отказы не логирует).
Для таких клиентов используй профиль TCP/XTLS-Vision ниже.
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
ВНИМАНИЕ: файл содержит учётные данные клиента —
UUID и параметры подключения (ПУБЛИЧНЫЙ ключ, shortId, SNI).
Приватного ключа REALITY здесь НЕТ (он только в config.json),
но по UUID можно подключиться как клиент и пользоваться прокси.
Передавай только по защищённому каналу (scp, age и т.п.)
───────────────────────────────────────────────────────
EOF

# client-info.txt читает только root — UUID и ключи не нужны другим пользователям
chmod 600 "$CLIENT_FILE"
chown root:root "$CLIENT_FILE"
success "Данные клиента: $CLIENT_FILE"

# =============================================================================
# 17. ИТОГ
# =============================================================================
header "✅ Установка завершена"

echo -e "${BOLD}Сервер:${NC}      ${SERVER_IP}:${XRAY_PORT}"
echo -e "${BOLD}UUID:${NC}        ${USER_UUID}"
echo -e "${BOLD}Public key:${NC}  ${PUBLIC_KEY}"
echo -e "${BOLD}Short ID:${NC}    ${SHORT_ID_1}"
echo -e "${BOLD}SNI:${NC}         ${DEST_SNI}"
echo -e "${BOLD}Path:${NC}        ${XHTTP_PATH}"
echo -e "${BOLD}Mode:${NC}        ${XHTTP_MODE}"
echo -e "${BOLD}uTLS FP:${NC}     ${UTLS_FP}"
echo -e "${BOLD}SSH порт:${NC}    ${SSH_PORT}"
if $DUAL_INBOUND; then
  echo -e "${BOLD}TCP порт:${NC}    ${XRAY_PORT2}  |  PubKey: ${PUBLIC_KEY2}"
fi
echo ""
echo -e "${GREEN}${BOLD}VLESS URI (XHTTP):${NC}"
echo "$VLESS_URI_XHTTP"
_print_qr "$VLESS_URI_XHTTP" "QR XHTTP · Hiddify / v2rayNG / Shadowrocket"

if $DUAL_INBOUND; then
  echo ""
  echo -e "${GREEN}${BOLD}VLESS URI (TCP):${NC}"
  echo "$VLESS_URI_TCP"
  _print_qr "$VLESS_URI_TCP" "QR TCP (XTLS-Vision)"
fi

echo ""
echo -e "${BOLD}Сервисы:${NC}"
echo -e "  Xray:     $(systemctl is-active xray)"
echo -e "  Nginx:    $(systemctl is-active nginx)"
echo -e "  Fail2ban: $(systemctl is-active fail2ban)"
echo -e "  Chrony:   $(systemctl is-active chrony)"
echo ""
echo -e "${BOLD}NTP drift:${NC}"
chronyc tracking 2>/dev/null | grep "System time" | sed 's/^/  /' || echo "  (синхронизируется...)"
echo ""
echo -e "${BOLD}DNS:${NC}"
if jq -e '.dns.servers // empty' "$XRAY_CONFIG" >/dev/null 2>&1; then
  echo -e "  Резолвинг на сервере идёт по DoH, :53 из тоннеля перехватывается."
  echo -e "  Клиенту настраивать Secure DNS не нужно — и блокировки DoH/DoT"
  echo -e "  у провайдера на него больше не влияют, пока VPN включён."
else
  echo -e "  ${YELLOW}dns-блок не добавлен (DoH был недоступен с VPS).${NC}"
  echo -e "  ${YELLOW}Домены резолвит системный резолвер хостера открытым текстом.${NC}"
  echo -e "  ${YELLOW}Повтори позже: ${BOLD}sudo xm harden${NC}"
fi
echo ""
echo -e "${YELLOW}Устойчивость к DPI:  ${BOLD}xm diag-dpi${NC}"
echo -e "${YELLOW}Диагностика сервера: ${BOLD}xm diag${NC}"
echo -e "${YELLOW}Данные клиента:      ${BOLD}cat $CLIENT_FILE${NC}"
echo -e "${YELLOW}QR-коды повторно:    ${BOLD}xm qr${NC}  |  Оба: ${BOLD}xm qr --both${NC}"
echo ""
echo -e "${YELLOW}⚠  $CLIENT_FILE содержит учётные данные клиента (UUID + параметры).${NC}"
echo -e "${YELLOW}   Приватного ключа REALITY в нём нет, но по UUID можно войти в прокси.${NC}"
echo -e "${YELLOW}   Передавай только по защищённому каналу!${NC}"