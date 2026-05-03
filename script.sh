#!/usr/bin/env bash
# =============================================================================
#  Xray-core · VLESS + REALITY + XHTTP  ·  Auto Setup
#  Ubuntu 22.04 LTS · Port 443 · uTLS Chrome
#
#  Исправления v2:
#   - xver: 0  (убран PROXY Protocol — нет upstream proxy)
#   - flow=""  убран из URI и клиентских JSON
#   - sing-box JSON: убраны несуществующие idle_timeout / ping_timeout
#   - sing-box JSON: method зависит от mode (POST для stream-one, GET для auto)
#   - serverNames: только выбранный SNI (без hardcoded доменов)
#   - bufferSize: 512 (KB, не 4096)
#   - URL-encode: safe='' чтобы кодировались & = # в пути
# =============================================================================

set -euo pipefail

# ─── Цвета ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n"; }

# ─── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запусти скрипт от root: sudo bash $0"

# ─── Переменные путей ────────────────────────────────────────────────────────
XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"

# =============================================================================
# 1. ИНТЕРАКТИВНЫЙ ВВОД
# =============================================================================
header "Настройка параметров"

# SNI / dest
echo -e "${BOLD}Выбери целевой домен (SNI / dest):${NC}"
echo "  1) www.microsoft.com     (рекомендуется)"
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
info "SNI/dest: ${BOLD}$DEST_SNI${NC}"

# Path
echo ""
echo -e "${BOLD}Выбери HTTP path:${NC}"
echo "  1) /api/v2/assets/stream     (SPA/API стиль)"
echo "  2) /video/hls/playlist.m3u8  (стриминг)"
echo "  3) /static/js/chunk-main.js  (webpack CDN)"
echo "  4) /cdn-cgi/trace            (Cloudflare стиль)"
echo "  5) /download/update          (апдейт стиль)"
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
info "Path: ${BOLD}$XHTTP_PATH${NC}"

# XHTTP mode
echo ""
echo -e "${BOLD}Режим XHTTP:${NC}"
echo "  1) auto        (H2 или H1.1, авто — рекомендуется)"
echo "  2) stream-one  (один долгоживущий поток, выше скорость)"
read -rp "Выбор [1-2, Enter=1]: " MODE_CHOICE
MODE_CHOICE=${MODE_CHOICE:-1}

case "$MODE_CHOICE" in
  1) XHTTP_MODE="auto";       WAIT_UPLOAD="false"; SINGBOX_METHOD="GET"  ;;
  2) XHTTP_MODE="stream-one"; WAIT_UPLOAD="true";  SINGBOX_METHOD="POST" ;;
  *) XHTTP_MODE="auto";       WAIT_UPLOAD="false"; SINGBOX_METHOD="GET"  ;;
esac
info "Mode: ${BOLD}$XHTTP_MODE${NC}, waitUploadWritten: ${BOLD}$WAIT_UPLOAD${NC}, sing-box method: ${BOLD}$SINGBOX_METHOD${NC}"

# uTLS fingerprint
echo ""
echo -e "${BOLD}uTLS fingerprint:${NC}"
echo "  1) chrome       (рекомендуется — самый массовый)"
echo "  2) edge         (практически идентичен chrome)"
echo "  3) firefox      (уникальный FP)"
echo "  4) randomized   (реальный FP + вариации)"
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

# Порт
echo ""
read -rp "Порт [Enter=443]: " PORT_INPUT
XRAY_PORT=${PORT_INPUT:-443}
info "Порт: ${BOLD}$XRAY_PORT${NC}"

echo ""
echo -e "${YELLOW}Продолжить установку? [y/N]:${NC} "
read -rp "" CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Отменено."; exit 0; }

# =============================================================================
# 2. СИСТЕМНЫЕ ЗАВИСИМОСТИ
# =============================================================================
header "Установка зависимостей"

apt-get update -qq
apt-get install -y --no-install-recommends curl wget unzip uuid-runtime openssl ufw
success "Зависимости установлены"

# =============================================================================
# 3. УСТАНОВКА XRAY-CORE
# =============================================================================
header "Установка Xray-core"

bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
success "Xray установлен: $(xray version | head -1)"

# =============================================================================
# 4. ГЕНЕРАЦИЯ КЛЮЧЕЙ
# =============================================================================
header "Генерация ключей"

USER_UUID=$(xray uuid)
info "UUID: $USER_UUID"

KEY_OUTPUT=$(xray x25519)

# Поддержка обоих форматов:
#   Xray < 26.x:  "Private key: ..."  /  "Public key: ..."
#   Xray >= 26.x: "PrivateKey: ..."   /  "Password (PublicKey): ..."
PRIVATE_KEY=$(echo "$KEY_OUTPUT" | awk '/PrivateKey:|Private key:/ {print $NF}')
PUBLIC_KEY=$(echo  "$KEY_OUTPUT" | awk '/Password \(PublicKey\):|Public key:/ {print $NF}')

# Проверка что ключи не пустые
[[ -z "$PRIVATE_KEY" ]] && error "Не удалось получить PrivateKey из 'xray x25519'. Вывод команды:\n$KEY_OUTPUT"
[[ -z "$PUBLIC_KEY"  ]] && error "Не удалось получить PublicKey из 'xray x25519'. Вывод команды:\n$KEY_OUTPUT"

info "Private key: ${PRIVATE_KEY:0:10}... (скрыт)"
info "Public key:  $PUBLIC_KEY"

# Три непустых shortId
SHORT_ID_1=$(openssl rand -hex 8)
SHORT_ID_2=$(openssl rand -hex 8)
SHORT_ID_3=$(openssl rand -hex 4)
info "ShortIds: $SHORT_ID_1 / $SHORT_ID_2 / $SHORT_ID_3"

success "Ключи сгенерированы"

# =============================================================================
# 5. ДИРЕКТОРИЯ ЛОГОВ
# =============================================================================
mkdir -p "$XRAY_LOG_DIR"
chown nobody:nogroup "$XRAY_LOG_DIR"
success "Лог-директория: $XRAY_LOG_DIR"

# =============================================================================
# 6. ЗАПИСЬ CONFIG.JSON
# =============================================================================
header "Запись конфигурации"

cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "loglevel": "error",
    "error": "${XRAY_LOG_DIR}/error.log"
  },

  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${USER_UUID}",
            "comment": "user-xhttp"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",

        "realitySettings": {
          "show": false,
          "dest": "${DEST_SNI}:443",
          "xver": 0,
          "serverNames": [
            "${DEST_SNI}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "maxTimeDiff": 60000,
          "shortIds": [
            "${SHORT_ID_1}",
            "${SHORT_ID_2}",
            "${SHORT_ID_3}"
          ]
        },

        "xhttpSettings": {
          "path": "${XHTTP_PATH}",
          "host": "${DEST_SNI}",
          "mode": "${XHTTP_MODE}",
          "headers": {
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache"
          },
          "maxUploadSize": 1000000,
          "maxConcurrentUploads": 10,
          "waitUploadWritten": ${WAIT_UPLOAD},
          "xPaddingBytes": "100-1000"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],

  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": { "domainStrategy": "UseIPv4v6" }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "block"
      }
    ]
  },

  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "bufferSize": 512
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false
    }
  }
}
EOF

success "config.json записан"

# =============================================================================
# 7. ВАЛИДАЦИЯ КОНФИГА
# =============================================================================
header "Валидация конфига"

if xray -test -config "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK"; then
  success "xray -test: Configuration OK"
else
  error "Конфиг невалиден. Проверь: xray -test -config $XRAY_CONFIG"
fi

# =============================================================================
# 8. FIREWALL
# =============================================================================
header "Настройка UFW"

ufw allow 22/tcp   comment 'SSH'    2>/dev/null || true
ufw allow "${XRAY_PORT}/tcp" comment 'Xray XHTTP' 2>/dev/null || true

if ! ufw status | grep -q "Status: active"; then
  ufw --force enable
  success "UFW включён"
else
  ufw reload
  success "UFW перезагружен"
fi

ufw status numbered

# =============================================================================
# 9. SYSTEMD
# =============================================================================
header "Запуск сервиса"

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2

if systemctl is-active --quiet xray; then
  success "Xray запущен и работает"
else
  error "Xray не запустился. Лог: journalctl -u xray -n 50"
fi

if ss -tlnp | grep -q ":${XRAY_PORT}"; then
  success "Порт ${XRAY_PORT} прослушивается"
else
  warn "Порт ${XRAY_PORT} не найден в ss -tlnp — проверь вручную"
fi

# =============================================================================
# 10. ОПРЕДЕЛЕНИЕ ПУБЛИЧНОГО IP
# =============================================================================
SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null \
         || curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null \
         || echo "ТВОЙ_IP")

# =============================================================================
# 11. СОХРАНЕНИЕ ДАННЫХ КЛИЕНТА
# =============================================================================
header "Сохранение данных для клиентов"

# URL-encode path: safe='' кодирует все спецсимволы включая / & = #
ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${XHTTP_PATH}', safe=''))")

# flow убран из URI — для XHTTP не используется
VLESS_URI="vless://${USER_UUID}@${SERVER_IP}:${XRAY_PORT}?encryption=none&security=reality&sni=${DEST_SNI}&fp=${UTLS_FP}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID_1}&type=xhttp&path=${ENCODED_PATH}&host=${DEST_SNI}&mode=${XHTTP_MODE}#MyServer-XHTTP"

cat > "$CLIENT_FILE" <<EOF
═══════════════════════════════════════════════════════
  Xray VLESS+REALITY+XHTTP  ·  Client Info
  Сгенерировано: $(date)
═══════════════════════════════════════════════════════

SERVER IP    : ${SERVER_IP}
PORT         : ${XRAY_PORT}
UUID         : ${USER_UUID}
PUBLIC KEY   : ${PUBLIC_KEY}
SHORT ID     : ${SHORT_ID_1}
SNI          : ${DEST_SNI}
PATH         : ${XHTTP_PATH}
MODE         : ${XHTTP_MODE}
FINGERPRINT  : ${UTLS_FP}

ALL SHORT IDs (можно использовать любой в клиенте):
  ${SHORT_ID_1}
  ${SHORT_ID_2}
  ${SHORT_ID_3}

───────────────────────────────────────────────────────
VLESS URI (импорт в Hiddify / v2rayNG):
───────────────────────────────────────────────────────
${VLESS_URI}

───────────────────────────────────────────────────────
sing-box JSON (Hiddify Next — ручной импорт):
───────────────────────────────────────────────────────
{
  "type": "vless",
  "tag": "proxy-xhttp",
  "server": "${SERVER_IP}",
  "server_port": ${XRAY_PORT},
  "uuid": "${USER_UUID}",
  "tls": {
    "enabled": true,
    "server_name": "${DEST_SNI}",
    "utls": {
      "enabled": true,
      "fingerprint": "${UTLS_FP}"
    },
    "reality": {
      "enabled": true,
      "public_key": "${PUBLIC_KEY}",
      "short_id": "${SHORT_ID_1}"
    }
  },
  "transport": {
    "type": "xhttp",
    "path": "${XHTTP_PATH}",
    "host": "${DEST_SNI}",
    "method": "${SINGBOX_METHOD}",
    "mode": "${XHTTP_MODE}"
  }
}

───────────────────────────────────────────────────────
v2rayNG JSON (Android — альтернатива):
───────────────────────────────────────────────────────
{
  "v": "2",
  "ps": "MyServer-XHTTP",
  "add": "${SERVER_IP}",
  "port": "${XRAY_PORT}",
  "id": "${USER_UUID}",
  "net": "xhttp",
  "path": "${XHTTP_PATH}",
  "host": "${DEST_SNI}",
  "tls": "reality",
  "sni": "${DEST_SNI}",
  "fp": "${UTLS_FP}",
  "pbk": "${PUBLIC_KEY}",
  "sid": "${SHORT_ID_1}",
  "flow": ""
}

═══════════════════════════════════════════════════════
ДИАГНОСТИКА
═══════════════════════════════════════════════════════
systemctl status xray
journalctl -u xray -f
tail -50 /var/log/xray/error.log
ss -tlnp | grep ${XRAY_PORT}
xray -test -config /usr/local/etc/xray/config.json
openssl s_client -connect ${SERVER_IP}:${XRAY_PORT} -servername ${DEST_SNI}
EOF

chmod 644 "$CLIENT_FILE"
success "Данные клиента сохранены: $CLIENT_FILE"

# =============================================================================
# 12. ИТОГОВЫЙ ВЫВОД
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
echo ""
echo -e "${GREEN}${BOLD}VLESS URI:${NC}"
echo "$VLESS_URI"
echo ""
echo -e "${CYAN}Полные данные для клиентов сохранены в: ${BOLD}${CLIENT_FILE}${NC}"
echo -e "${YELLOW}Совет: скопируй файл клиенту через scp или cat ${CLIENT_FILE}${NC}"
