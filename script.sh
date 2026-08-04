#!/usr/bin/env bash
# =============================================================================
#  Xray-core · VLESS + REALITY + XHTTP  ·  Auto Setup  v5.5
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

echo -e "${BOLD}Выбери целевой домен (SNI / dest):${NC}"
# [FIX-8] microsoft.com/login.microsoftonline.com убраны из дефолтов: у них
# большая цепочка/OCSP staple, из-за чего REALITY-хендшейк ломается (буфер ~8192 б).
# Дефолты ниже — с компактными сертификатами; выбор ВСЁ РАВНО проверяется
# _check_cert_size в секции 7 (список не «слепая вера», а стартовая точка).
echo "  1) www.apple.com        (компактный cert)"
echo "  2) dl.google.com        (компактный cert, большой traffic pool)"
echo "  3) www.cloudflare.com   (компактный cert, TLS1.3/H2)"
echo "  4) www.microsoft.com    (⚠ большой cert/OCSP — как правило НЕ подходит, оставлен для наглядности проверки)"
echo "  5) Ввести вручную"
read -rp "Выбор [1-5, Enter=1]: " SNI_CHOICE
SNI_CHOICE=${SNI_CHOICE:-1}

case "$SNI_CHOICE" in
  1) DEST_SNI="www.apple.com" ;;
  2) DEST_SNI="dl.google.com" ;;
  3) DEST_SNI="www.cloudflare.com" ;;
  4) DEST_SNI="www.microsoft.com" ;;
  5) read -rp "Введи домен: " DEST_SNI ;;
  *) DEST_SNI="www.apple.com" ;;
esac

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

echo ""
echo -e "${BOLD}Добавить второй inbound — VLESS+REALITY+TCP (XTLS-Vision)?${NC}"
read -rp "Добавить? [y/N]: " DUAL_CHOICE
DUAL_CHOICE=${DUAL_CHOICE:-n}

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

apt-get update -qq
apt-get install -y --no-install-recommends \
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
  warn "Оценка Certificate: ${CERT_EST} б ≥ лимита REALITY (${REALITY_CERT_LIMIT} б)."
  warn "REALITY-хендшейк, скорее всего, будет РВАТЬСЯ (клиент: handshake failed)."
  read -rp "Домен рискованный. Всё равно использовать? [y/N]: " CERT_CONFIRM
  [[ "$CERT_CONFIRM" =~ ^[Yy]$ ]] || error "Выбери домен с компактным сертификатом и перезапусти."
elif [[ "$CERT_EST" -ge "$REALITY_CERT_WARN" ]]; then
  warn "Оценка Certificate: ${CERT_EST} б — близко к лимиту (${REALITY_CERT_LIMIT} б). Возможны сбои на части версий Xray."
else
  success "Размер Certificate ~${CERT_EST} б — с запасом ниже лимита REALITY (${REALITY_CERT_LIMIT} б)"
fi

# =============================================================================
# 8. ЛОГИ + LOGROTATE
# =============================================================================
mkdir -p "$XRAY_LOG_DIR"
chown nobody:nogroup "$XRAY_LOG_DIR"
success "Лог-директория: $XRAY_LOG_DIR"

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
# Разрешаем проксировать ТОЛЬКО на наш dest-SNI. Любой другой SNI (или его
# отсутствие) → пустой апстрим → соединение обрывается. Это не даёт превратить
# nginx в открытый SNI-релей на произвольный хост.
map $ssl_preread_server_name $reality_upstream {
    default        "";
    __DEST_SNI__   __DEST_SNI__;
}

# [FIX-9] Флаг логирования. REALITY дозванивается до dest на КАЖДОЕ входящее
# соединение, а не только при провале аутентификации — значит через fallback
# идёт весь легитимный трафик. Без этого фильтра в лог попадали реальные IP
# всех клиентов (замерено: 8522 из 9537 строк — один свой клиент) и хранились
# 14 дней. Теперь на диск пишется только чужой/пустой SNI, т.е. чистые сканы.
map $ssl_preread_server_name $log_probe {
    default        1;
    __DEST_SNI__   0;
}

limit_conn_zone $binary_remote_addr zone=reality_conn:10m;

log_format reality_fallback '$remote_addr [$time_local] '
                            'SNI="$ssl_preread_server_name" '
                            'status=$status sent=$bytes_sent';

# Апстрим задан именем и резолвится в рантайме → нужен resolver.
resolver 1.1.1.1 8.8.8.8 valid=30s ipv6=off;
resolver_timeout 5s;

server {
    # xver=2 в REALITY → сюда приходит PROXY protocol v2. Без proxy_protocol
    # nginx не распарсит заголовок и порвёт хендшейк.
    listen 127.0.0.1:10443 proxy_protocol;

    # realip подменяет $remote_addr (127.0.0.1) адресом из PROXY v2 →
    # limit_conn считает по реальному клиенту, а не глобально на весь сервер.
    set_real_ip_from 127.0.0.1;

    # Читаем SNI из ClientHello БЕЗ терминации TLS.
    ssl_preread on;

    # [FIX-9] Было 20 — и резало СВОИ же XHTTP-соединения (21 срыв в error.log),
    # т.к. через fallback идёт весь трафик, а не только зонды. 200 — заведомо
    # выше нормального клиента, но всё ещё отсекает флуд.
    limit_conn reality_conn 200;

    proxy_pass $reality_upstream:443;
    proxy_connect_timeout 5s;

    access_log /var/log/nginx/reality_fallback.log reality_fallback if=$log_probe;
    error_log  /var/log/nginx/reality_fallback_error.log error;
}
STREAMEOF

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
# 12. ВАЛИДАЦИЯ КОНФИГА
# =============================================================================
header "Валидация конфига"

if xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK"; then
  success "xray -test: Configuration OK"
else
  error "Конфиг невалиден: xray -test -config $XRAY_CONFIG"
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

systemctl is-active --quiet xray \
  && success "Xray запущен" \
  || error "Xray не запустился: journalctl -u xray -n 50"

ss -tlnp | grep -q ":${XRAY_PORT}" \
  && success "Порт ${XRAY_PORT} прослушивается" \
  || warn "Порт ${XRAY_PORT} не найден — проверь вручную"

# =============================================================================
# 15. УСТАНОВКА xm В PATH
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
  warn "Скопируй xm.sh вручную: cp xm.sh /usr/local/bin/xm && chmod +x /usr/local/bin/xm"
fi

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
sing-box JSON (XHTTP):
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
echo -e "${YELLOW}Диагностика сервера: ${BOLD}xm diag${NC}"
echo -e "${YELLOW}Данные клиента:      ${BOLD}cat $CLIENT_FILE${NC}"
echo -e "${YELLOW}QR-коды повторно:    ${BOLD}xm qr${NC}  |  Оба: ${BOLD}xm qr --both${NC}"
echo ""
echo -e "${YELLOW}⚠  $CLIENT_FILE содержит учётные данные клиента (UUID + параметры).${NC}"
echo -e "${YELLOW}   Приватного ключа REALITY в нём нет, но по UUID можно войти в прокси.${NC}"
echo -e "${YELLOW}   Передавай только по защищённому каналу!${NC}"