#!/usr/bin/env bash
# =============================================================================
#  Xray-core · VLESS + REALITY + XHTTP  ·  Auto Setup  v5
#  Ubuntu 22.04 LTS · uTLS Chrome
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
  # Извлекаем приватный ключ: берём последнее слово строки,
  # содержащей "rivate" (покрывает "Private key", "PrivateKey" и т.п.)
  PRIVATE_KEY=$(echo "$output" | grep -i "rivate" | awk '{print $NF}' | head -1 | tr -d '[:space:]')
  # Извлекаем публичный ключ: строка содержит "ublic" (Public key / PublicKey / Password(PublicKey))
  PUBLIC_KEY=$(echo "$output"  | grep -i "ublic"  | awk '{print $NF}' | head -1 | tr -d '[:space:]')

  # Валидация: ключ X25519 в base64url — 43 символа
  if [[ ${#PRIVATE_KEY} -lt 30 ]]; then
    error "Не удалось распарсить PrivateKey (длина ${#PRIVATE_KEY}).\nВывод xray x25519:\n$output"
  fi
  if [[ ${#PUBLIC_KEY} -lt 30 ]]; then
    error "Не удалось распарсить PublicKey (длина ${#PUBLIC_KEY}).\nВывод xray x25519:\n$output"
  fi
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
echo "  1) www.microsoft.com"
echo "  2) login.microsoftonline.com"
echo "  3) www.apple.com"
echo "  4) cdn.apple.com"
echo "  5) Ввести вручную"
read -rp "Выбор [1-5, Enter=1]: " SNI_CHOICE
SNI_CHOICE=${SNI_CHOICE:-1}

case "$SNI_CHOICE" in
  1) DEST_SNI="www.microsoft.com" ;;
  2) DEST_SNI="login.microsoftonline.com" ;;
  3) DEST_SNI="www.apple.com" ;;
  4) DEST_SNI="cdn.apple.com" ;;
  5) read -rp "Введи домен: " DEST_SNI ;;
  *) DEST_SNI="www.microsoft.com" ;;
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
  1) XHTTP_MODE="auto";       WAIT_UPLOAD="false"; SINGBOX_METHOD="GET"  ;;
  2) XHTTP_MODE="stream-one"; WAIT_UPLOAD="true";  SINGBOX_METHOD="POST" ;;
  *) XHTTP_MODE="auto";       WAIT_UPLOAD="false"; SINGBOX_METHOD="GET"  ;;
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
  nginx fail2ban jq python3 chrony
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
local stratum 10
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
    sharedscripts
    postrotate
        systemctl is-active --quiet xray && \
          kill -USR1 $(systemctl show -p MainPID xray | cut -d= -f2) 2>/dev/null || true
    endscript
}
LOGROTEOF
success "logrotate настроен (14 дней)"

# =============================================================================
# 9. NGINX FALLBACK
# =============================================================================
header "Настройка Nginx fallback"

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

cat > /etc/nginx/sites-available/fallback <<'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 127.0.0.1:8080;
    server_name _;
    root /var/www/fallback;
    index index.html;
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    location / { try_files $uri $uri/ =404; }
    access_log /var/log/nginx/fallback_access.log;
    error_log  /var/log/nginx/fallback_error.log warn;
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/fallback /etc/nginx/sites-enabled/fallback
nginx -t && systemctl enable nginx && systemctl restart nginx
success "Nginx fallback настроен"

# =============================================================================
# 10. FAIL2BAN
# =============================================================================
header "Настройка fail2ban"

touch /var/log/nginx/fallback_access.log
chown www-data:www-data /var/log/nginx/fallback_access.log

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

[nginx-4xx]
enabled  = true
port     = http,https
filter   = nginx-4xx
logpath  = /var/log/nginx/fallback_access.log
maxretry = 20
findtime = 60
bantime  = 1800
EOF

mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/nginx-4xx.conf <<'F2BFEOF'
[Definition]
failregex = ^<HOST> - .* "(GET|POST|HEAD|OPTIONS|PUT|DELETE) .* HTTP/.*" (4\d{2}) .*$
ignoreregex =
F2BFEOF

systemctl enable fail2ban
systemctl restart fail2ban
success "fail2ban настроен (SSH на порту $SSH_PORT)"

# =============================================================================
# 11. CONFIG.JSON
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
  --argjson waitUp     "$WAIT_UPLOAD" \
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
        dest: ($sni + ":443"),
        xver: 0,
        serverNames: [$sni],
        privateKey: $privKey,
        maxTimeDiff: 60000,
        shortIds: [$sid1, $sid2, $sid3]
      },
      xhttpSettings: {
        path: $path,
        host: $sni,
        mode: $mode,
        headers: {
          "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
          "Accept-Encoding": "gzip, deflate, br",
          "Cache-Control": "no-cache"
        },
        maxUploadSize: 1000000,
        maxConcurrentUploads: 10,
        waitUploadWritten: $waitUp,
        xPaddingBytes: "100-1000"
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
          dest: ($sni + ":443"),
          xver: 0,
          serverNames: [$sni],
          privateKey: $privKey,
          maxTimeDiff: 60000,
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
    log: { loglevel: "error", error: ($logDir + "/error.log") },
    inbounds: $inbounds,
    outbounds: [
      { protocol: "freedom", tag: "direct", settings: { domainStrategy: "UseIPv4v6" } },
      { protocol: "blackhole", tag: "block" }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
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

success "config.json записан"

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
SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
         || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
         || echo "ТВОЙ_IP")

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
  Xray VLESS+REALITY+XHTTP · Client Info v5.1
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
ВНИМАНИЕ: этот файл содержит приватный ключ REALITY.
Передавай только по защищённому каналу (scp, age и т.п.)
───────────────────────────────────────────────────────
EOF

chmod 600 "$CLIENT_FILE"
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
if $DUAL_INBOUND; then
  echo ""
  echo -e "${GREEN}${BOLD}VLESS URI (TCP):${NC}"
  echo "$VLESS_URI_TCP"
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
echo ""
echo -e "${YELLOW}⚠  $CLIENT_FILE содержит приватный ключ REALITY.${NC}"
echo -e "${YELLOW}   Передавай только по защищённому каналу!${NC}"
