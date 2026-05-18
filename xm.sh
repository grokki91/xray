#!/usr/bin/env bash
# =============================================================================
#  xm — Xray Manager Helper  v5.1
#  Использование: xm [команда]
#
#  Исправления v5.1:
#   - _get_pubkey: надёжный парсинг без привязки к пробелам/форматированию
#   - _get_field: универсальная функция чтения любого поля из client-info.txt
#   - _make_uri_xhttp и _make_uri_tcp читают ключи напрямую из config.json
#     (приватный ключ → xray x25519 → публичный); client-info.txt как fallback
#   - Добавлена команда "pubkey" для ручной диагностики
#
#  Команды:
#   Сервис:    start / stop / restart / status
#   Конфиг:    edit / test / apply
#   Бэкапы:    backup / restore / backups
#   Клиенты:   clients / add-client / del-client / uri
#   TCP:       add-tcp
#   Nginx:     nginx-status / nginx-log / nginx-reload / nginx-probes
#   Fail2ban:  ban-list / ban-ssh-stat / unban
#   Логи:      log / log-live / log-clear
#   Инфо:      info / paths / uuid / pubkey
#   Диагностика: diag / diag-dpi / diag-ntp / diag-ports / diag-tls / diag-fw / diag-log
# =============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/usr/local/etc/xray/backups"
LOG="/var/log/xray/error.log"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"

ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
fail() { echo -e "  ${RED}[✗]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
info() { echo -e "  ${CYAN}[-]${NC} $*"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────${NC}"; }

# ─── Вспомогательные ─────────────────────────────────────────────────────────

# Надёжное чтение поля из client-info.txt.
# Работает с любым форматом: "LABEL: value", "LABEL : value", "LABEL  : value"
# Использование: _get_field "PUBLIC KEY"  → значение после двоеточия
_get_field() {
  local label="$1"
  grep -i "^${label}[[:space:]]*:" "$CLIENT_FILE" 2>/dev/null \
    | head -1 \
    | sed 's/^[^:]*:[[:space:]]*//' \
    | tr -d '[:space:]'
}

# Читаем публичный ключ для XHTTP inbound (первый inbound).
# Сначала пробуем вычислить из приватного ключа в config.json — самый надёжный способ.
# Fallback: client-info.txt.
_get_pubkey_xhttp() {
  local privkey pub
  privkey=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // ""' "$CONFIG" 2>/dev/null)
  if [[ -n "$privkey" && ${#privkey} -ge 30 ]]; then
    pub=$(echo "$privkey" | xray x25519 -i /dev/stdin 2>/dev/null \
          | grep -i "ublic" | awk '{print $NF}' | tr -d '[:space:]' || echo "")
    # xray x25519 не умеет читать stdin — используем временный файл
    if [[ -z "$pub" ]]; then
      local tmpf
      tmpf=$(mktemp)
      # xray x25519 принимает приватный ключ через флаг -i (некоторые версии не поддерживают)
      # Универсальный способ: xray x25519 всегда генерирует новую пару,
      # поэтому получаем публичный ключ через openssl из приватного
      pub=$(echo "$privkey" \
        | python3 -c "
import sys, base64, hashlib
# X25519 public key from private key (RFC 7748)
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = base64.urlsafe_b64decode(sys.stdin.read().strip() + '==')
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(base64.urlsafe_b64encode(pub_bytes).rstrip(b'=').decode())
except Exception:
    pass
" 2>/dev/null || echo "")
      rm -f "$tmpf"
    fi
    if [[ -n "$pub" && ${#pub} -ge 30 ]]; then
      echo "$pub"
      return
    fi
  fi
  # Fallback: client-info.txt
  _get_field "PUBLIC KEY"
}

# Публичный ключ для TCP inbound (второй inbound)
_get_pubkey_tcp() {
  local privkey pub
  privkey=$(jq -r '.inbounds[1].streamSettings.realitySettings.privateKey // ""' "$CONFIG" 2>/dev/null)
  if [[ -n "$privkey" && ${#privkey} -ge 30 ]]; then
    pub=$(echo "$privkey" \
      | python3 -c "
import sys, base64
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = base64.urlsafe_b64decode(sys.stdin.read().strip() + '==')
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(base64.urlsafe_b64encode(pub_bytes).rstrip(b'=').decode())
except Exception:
    pass
" 2>/dev/null || echo "")
    if [[ -n "$pub" && ${#pub} -ge 30 ]]; then
      echo "$pub"
      return
    fi
  fi
  # Fallback: client-info.txt (поле PUBLIC KEY2)
  _get_field "PUBLIC KEY2"
}

_get_server_ip() {
  local ip
  ip=$(_get_field "SERVER IP")
  if [[ -z "$ip" || "$ip" == "ТВОЙ_IP" ]]; then
    ip=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || echo "SERVER_IP")
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
  if [[ -z "$port" ]]; then
    port=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config 2>/dev/null \
      | awk '{print $2}' | head -1 || echo "")
  fi
  if [[ -z "$port" ]]; then
    port=$(ss -tlnp 2>/dev/null | grep sshd \
      | awk '{print $4}' | grep -oE '[0-9]+$' | head -1 || echo "")
  fi
  echo "${port:-22}"
}

_has_tcp_inbound() {
  [[ $(jq '.inbounds | length' "$CONFIG" 2>/dev/null || echo 0) -ge 2 ]]
}

# Безопасное URL-кодирование через python sys.argv
_url_encode() {
  python3 -c \
    "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" \
    "$1"
}

_make_uri_xhttp() {
  local uuid="$1" comment="$2"
  local sni port sid path_val mode pubkey fp server_ip encoded_path
  sni=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host // .inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
  port=$(jq -r '.inbounds[0].port' "$CONFIG")
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

# =============================================================================
case "$1" in

# ─── Сервис ──────────────────────────────────────────────────────────────────
start)    systemctl start xray;   echo -e "${GREEN}Xray запущен${NC}" ;;
stop)     systemctl stop xray;    echo -e "${YELLOW}Xray остановлен${NC}" ;;
restart)  systemctl restart xray; echo -e "${GREEN}Xray перезапущен${NC}" ;;
status)   systemctl status xray --no-pager ;;

# ─── Конфиг ──────────────────────────────────────────────────────────────────
edit)
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "$BACKUP_DIR/config_${STAMP}.json"
    echo -e "${GREEN}Бэкап: $BACKUP_DIR/config_${STAMP}.json${NC}"
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

# ─── Бэкапы ──────────────────────────────────────────────────────────────────
backup)
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "$BACKUP_DIR/config_${STAMP}.json"
    echo -e "${GREEN}Бэкап: $BACKUP_DIR/config_${STAMP}.json${NC}"
    ;;

restore)
    mkdir -p "$BACKUP_DIR"
    mapfile -t FILES < <(ls -t "$BACKUP_DIR"/*.json 2>/dev/null)
    [[ ${#FILES[@]} -eq 0 ]] && { echo -e "${RED}Нет бэкапов${NC}"; exit 1; }
    for i in "${!FILES[@]}"; do echo "  $((i+1))) ${FILES[$i]}"; done
    read -rp "Выбери [Enter=1]: " CHOICE; CHOICE=${CHOICE:-1}
    cp "${FILES[$((CHOICE-1))]}" "$CONFIG"
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
    echo "  Приватный ключ в config.json: ${PRIV0:0:8}...${PRIV0: -4} (длина: ${#PRIV0})"
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
      echo "  Приватный ключ в config.json: ${PRIV1:0:8}...${PRIV1: -4} (длина: ${#PRIV1})"
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

add-client)
    COMMENT="${2:-}"
    [[ -z "$COMMENT" ]] && read -rp "Имя клиента: " COMMENT
    NEW_UUID=$(xray uuid)
    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG" "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"

    jq --arg uuid "$NEW_UUID" --arg comment "$COMMENT" \
      '.inbounds[0].settings.clients += [{"id": $uuid, "comment": $comment}]' \
      "$CONFIG" > /tmp/xm_tmp.json && mv /tmp/xm_tmp.json "$CONFIG"

    if _has_tcp_inbound; then
      jq --arg uuid "$NEW_UUID" --arg comment "$COMMENT" \
        '.inbounds[1].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "comment": $comment}]' \
        "$CONFIG" > /tmp/xm_tmp.json && mv /tmp/xm_tmp.json "$CONFIG"
      echo -e "${GREEN}Добавлен в оба inbound${NC}"
    else
      echo -e "${GREEN}Клиент добавлен${NC}"
    fi

    echo -e "${BOLD}UUID:${NC}    $NEW_UUID"
    echo -e "${BOLD}Comment:${NC} $COMMENT"
    echo -e "\n${BOLD}VLESS URI (XHTTP):${NC}"
    _make_uri_xhttp "$NEW_UUID" "$COMMENT"
    if _has_tcp_inbound; then
      echo -e "\n${BOLD}VLESS URI (TCP):${NC}"
      _make_uri_tcp "$NEW_UUID" "$COMMENT"
    fi
    _apply
    ;;

del-client)
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

    jq --arg uuid "$TARGET_UUID" \
      'del(.inbounds[].settings.clients[] | select(.id == $uuid))' \
      "$CONFIG" > /tmp/xm_tmp.json && mv /tmp/xm_tmp.json "$CONFIG"

    echo -e "${GREEN}Клиент $TARGET_UUID удалён из всех inbound${NC}"
    _apply
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

# ─── Добавить TCP inbound ─────────────────────────────────────────────────────
add-tcp)
    echo -e "${BOLD}Добавление VLESS+REALITY+TCP (XTLS-Vision) inbound${NC}"
    echo ""

    if _has_tcp_inbound; then
      echo -e "${YELLOW}TCP inbound уже существует в конфиге.${NC}"
      jq -r '.inbounds[1] | "  Порт: \(.port)"' "$CONFIG"
      echo ""
      echo -e "Для получения URI: ${BOLD}xm uri --tcp${NC}"
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
      break
    done

    echo -e "${CYAN}Генерация ключей X25519...${NC}"
    KEY_OUTPUT=$(xray x25519)
    # Надёжный парсинг
    PRIV=$(echo "$KEY_OUTPUT" | grep -i "rivate" | awk '{print $NF}' | head -1 | tr -d '[:space:]')
    PUB=$(echo  "$KEY_OUTPUT" | grep -i "ublic"  | awk '{print $NF}' | head -1 | tr -d '[:space:]')
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
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" =~ ^[23] || "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
      ok "dest доступен (HTTP $HTTP_CODE)"
    else
      warn "dest вернул код $HTTP_CODE — продолжаем, но проверь вручную"
    fi

    CLIENTS_TCP=$(jq '[.inbounds[0].settings.clients[] |
      { id: .id, flow: "xtls-rprx-vision", comment: .comment }]' "$CONFIG")

    TCP_INBOUND=$(jq -n \
      --arg     sni     "$SNI" \
      --arg     priv    "$PRIV" \
      --arg     sid1    "$SID1" \
      --arg     sid2    "$SID2" \
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
            dest: ($sni + ":443"),
            xver: 0,
            serverNames: [$sni],
            privateKey: $priv,
            maxTimeDiff: 60000,
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
      "$CONFIG" > /tmp/xm_tmp.json && mv /tmp/xm_tmp.json "$CONFIG"

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

    touch /var/log/nginx/fallback_access.log 2>/dev/null || true

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
        systemctl restart xray
        exit 1
      fi
    else
      echo -e "${RED}Конфиг невалиден — откат к бэкапу${NC}"
      cp "$BACKUP_FILE" "$CONFIG"
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
      echo ""
    done < <(jq -c '.inbounds[0].settings.clients[]' "$CONFIG")

    echo -e "${YELLOW}Совет: добавь оба URI в клиент (XHTTP + TCP)${NC}"
    echo -e "${YELLOW}Hiddify автоматически выберет быстрейший${NC}"
    ;;

# ─── Nginx ───────────────────────────────────────────────────────────────────
nginx-status)  systemctl status nginx --no-pager ;;
nginx-log)     tail -30 /var/log/nginx/fallback_access.log 2>/dev/null || echo "Лог пуст" ;;
nginx-reload)  nginx -t && systemctl reload nginx && echo -e "${GREEN}Nginx перезагружен${NC}" ;;
nginx-probes)
    echo -e "${BOLD}Топ IP → fallback (потенциальные зонды):${NC}"
    awk '{print $1}' /var/log/nginx/fallback_access.log 2>/dev/null \
      | sort | uniq -c | sort -rn | head -20 || echo "Лог недоступен"
    ;;

# ─── Fail2ban ─────────────────────────────────────────────────────────────────
ban-list)
    echo -e "${BOLD}Забаненные IP (SSH):${NC}"
    fail2ban-client status sshd 2>/dev/null || echo "fail2ban не запущен"
    fail2ban-client status nginx-4xx &>/dev/null && {
      echo -e "\n${BOLD}Забаненные IP (nginx-4xx):${NC}"
      fail2ban-client status nginx-4xx
    } || true
    ;;

ban-ssh-stat)  fail2ban-client status 2>/dev/null || echo "fail2ban не запущен" ;;

unban)
    TARGET_IP="${2:-}"
    [[ -z "$TARGET_IP" ]] && read -rp "IP для разбана: " TARGET_IP
    for jail in sshd nginx-4xx; do
      fail2ban-client status "$jail" &>/dev/null && {
        fail2ban-client set "$jail" unbanip "$TARGET_IP" 2>/dev/null \
          && echo -e "${GREEN}${jail}: разбан${NC}" \
          || echo -e "${YELLOW}${jail}: IP не в бане${NC}"
      } || true
    done
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
    chronyc tracking 2>/dev/null | grep "System time" | sed 's/^/  /' || echo "  ?"
    ;;

paths)
    echo "  Конфиг:      $CONFIG"
    echo "  Бэкапы:      $BACKUP_DIR"
    echo "  Лог Xray:    $LOG"
    echo "  Клиент-файл: $CLIENT_FILE"
    echo "  Бинарник:    $(which xray)"
    echo "  Nginx conf:  /etc/nginx/sites-available/fallback"
    echo "  F2b jail:    /etc/fail2ban/jail.d/sshd-xray.conf"
    ;;

uuid) xray uuid ;;

# =============================================================================
# ─── ДИАГНОСТИКА ─────────────────────────────────────────────────────────────
# =============================================================================

diag)
    echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       Xray Full Diagnostic  v5.1         ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    ISSUES=0

    echo -e "${BOLD}[ 1 ] Сервисы${NC}"; sep
    for svc in xray nginx fail2ban chrony; do
      systemctl is-active --quiet "$svc" && ok "$svc запущен" || { fail "$svc НЕ запущен"; ((ISSUES++)); }
    done

    echo -e "\n${BOLD}[ 2 ] Порты${NC}"; sep
    XHTTP_PORT=$(jq -r '.inbounds[0].port' "$CONFIG" 2>/dev/null || echo "?")
    if ss -tlnp | grep -q ":${XHTTP_PORT}"; then
      ok "Порт $XHTTP_PORT (XHTTP) слушается"
    else
      fail "Порт $XHTTP_PORT не слушается"; ((ISSUES++))
    fi
    if _has_tcp_inbound; then
      TCP_PORT=$(jq -r '.inbounds[1].port' "$CONFIG")
      ss -tlnp | grep -q ":${TCP_PORT}" \
        && ok "Порт $TCP_PORT (TCP) слушается" \
        || { fail "Порт $TCP_PORT не слушается"; ((ISSUES++)); }
    fi
    ss -tlnp | grep -q ":80" \
      && ok "Порт 80 (nginx) слушается" \
      || warn "Порт 80 не слушается"

    SSH_P=$(_get_ssh_port)
    ss -tlnp | grep -q ":${SSH_P}" \
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
        elif awk "BEGIN {exit !($DRIFT_VAL < 60)}"; then
          ok "Дрейф < 60 сек — норма"
        else
          fail "Дрейф > 60 сек — REALITY будет отклонять клиентов!"; ((ISSUES++))
        fi
        info "Stratum: $(chronyc tracking 2>/dev/null | grep 'Stratum' | awk '{print $3}')"
      else
        warn "chrony работает, tracking недоступен"
      fi
    else
      fail "chrony не запущен"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 5 ] Доступность dest${NC}"; sep
    DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" | sed 's/:443//')
    info "dest: $DEST"
    HTTP_CODE=$(curl -svo /dev/null "https://${DEST}" \
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" =~ ^[23] || "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
      ok "dest ${DEST} доступен (HTTP $HTTP_CODE)"
    else
      fail "dest ${DEST} недоступен (код: $HTTP_CODE)"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 6 ] Nginx fallback${NC}"; sep
    FB_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 --max-time 3 2>/dev/null || echo "000")
    [[ "$FB_CODE" == "200" ]] \
      && ok "Nginx fallback отвечает 200" \
      || { fail "Nginx fallback не отвечает (код: $FB_CODE)"; ((ISSUES++)); }

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
      ufw status | grep -q "${SSH_P}" \
        && ok "SSH порт $SSH_P открыт в UFW" \
        || { fail "SSH порт $SSH_P не найден в UFW — риск потери доступа!"; ((ISSUES++)); }
    else
      fail "UFW не активен — сервер открыт!"; ((ISSUES++))
    fi

    echo -e "\n${BOLD}[ 9 ] Лог Xray${NC}"; sep
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

    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
    if [[ $ISSUES -eq 0 ]]; then
      echo -e "${GREEN}${BOLD}  ✅ Всё в порядке. Проблем не обнаружено.${NC}"
    else
      echo -e "${RED}${BOLD}  ❌ Обнаружено проблем: $ISSUES${NC}"
      echo -e "${YELLOW}  Исправь проблемы выше и запусти xm diag снова${NC}"
    fi
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"
    ;;

diag-dpi)
    echo -e "\n${BOLD}${CYAN}[ DPI / Active Probe Resistance ]${NC}\n"

    DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG" | sed 's/:443//')
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    SERVER_IP=$(_get_server_ip)

    sep
    echo -e "${BOLD}Тест 1: TLS handshake${NC}"
    TLS_OUT=$(echo | timeout 5 openssl s_client \
      -connect "${SERVER_IP}:${PORT}" -servername "$SNI" \
      -verify_return_error 2>&1 || true)
    if echo "$TLS_OUT" | grep -q "subject\s*=\|CN\s*="; then
      ok "TLS handshake прошёл"
      echo "$TLS_OUT" | grep "subject\|issuer" | head -2 | sed 's/^/    /'
    else
      warn "TLS handshake не удался (ожидаемо при корректном REALITY)"
      echo "$TLS_OUT" | tail -3 | sed 's/^/    /'
    fi

    sep
    echo -e "${BOLD}Тест 2: HTTP на порту 80${NC}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://${SERVER_IP}" --max-time 5 -H "Host: ${SNI}" 2>/dev/null || echo "000")
    [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]] \
      && ok "Порт 80 → redirect $HTTP_CODE" \
      || warn "Порт 80 вернул: $HTTP_CODE (ожидался 301/302)"

    sep
    echo -e "${BOLD}Тест 3: Nginx fallback${NC}"
    FB=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 --max-time 3 2>/dev/null || echo "000")
    [[ "$FB" == "200" ]] && ok "Fallback отвечает 200" || fail "Fallback не отвечает (код: $FB)"

    sep
    echo -e "${BOLD}Тест 4: Случайный путь${NC}"
    RAND_PATH="/$(openssl rand -hex 8)"
    RAND_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://${SERVER_IP}${RAND_PATH}" \
      --max-time 5 -H "Host: ${SNI}" 2>/dev/null || echo "000")
    if [[ "$RAND_CODE" == "404" ]]; then
      ok "Случайный путь → 404 (норма)"
    elif [[ "$RAND_CODE" == "400" ]]; then
      warn "Случайный путь → 400 — может указывать на xray напрямую"
    else
      info "Случайный путь → $RAND_CODE"
    fi

    sep
    echo -e "${BOLD}Тест 5: xPaddingBytes${NC}"
    PADDING=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.xPaddingBytes // ""' "$CONFIG")
    [[ -n "$PADDING" ]] && ok "xPaddingBytes: $PADDING" || warn "xPaddingBytes не задан"

    sep
    echo -e "${BOLD}Тест 6: uTLS fingerprint${NC}"
    FP=$(_get_fp)
    case "$FP" in
      chrome|edge)     ok "Fingerprint: $FP — высокий traffic pool" ;;
      randomized)      ok "Fingerprint: randomized — вариативный" ;;
      firefox)         info "Fingerprint: firefox — уникален, но валиден" ;;
      *)               warn "Fingerprint: $FP — проверь поддержку" ;;
    esac
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
      echo -e "  REALITY требует drift < 60 сек. Установи: apt install chrony"
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
    echo -e "${BOLD}Сертификат реального dest (${DEST}):${NC}"
    echo | timeout 5 openssl s_client \
      -connect "${DEST}:443" -servername "$DEST" 2>/dev/null \
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

    sep
    echo -e "${BOLD}fail2ban:${NC}"
    if systemctl is-active --quiet fail2ban; then
      ok "fail2ban запущен"
      for jail in sshd nginx-4xx; do
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
      | tail -10 | sed 's/^/  /' || echo "  лог недоступен"
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
    HANDSHAKE_FAILS=$(grep -c "rejected\|handshake\|tls.*fail\|reality.*fail" "$LOG" 2>/dev/null || echo 0)
    if [[ "$HANDSHAKE_FAILS" -gt 50 ]]; then
      warn "Много отклонённых handshake ($HANDSHAKE_FAILS) — возможное DPI или сканирование"
    elif [[ "$HANDSHAKE_FAILS" -gt 0 ]]; then
      info "Отклонённых handshake: $HANDSHAKE_FAILS (норма)"
    else
      ok "Признаков DPI-блокировки нет"
    fi
    ;;

# ─── Помощь ──────────────────────────────────────────────────────────────────
*)
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║       xm — Xray Manager  v5.1            ║${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Сервис:${NC}"
    echo "  xm start / stop / restart / status"
    echo ""
    echo -e "${BOLD}Конфиг:${NC}"
    echo "  xm edit              Открыть в nano (с автобэкапом)"
    echo "  xm test              Проверить валидность"
    echo "  xm apply             Проверить + перезапустить"
    echo ""
    echo -e "${BOLD}Бэкапы:${NC}"
    echo "  xm backup / restore / backups"
    echo ""
    echo -e "${BOLD}Клиенты:${NC}"
    echo "  xm clients                   Показать всех"
    echo "  xm add-client [имя]          Добавить (все inbound)"
    echo "  xm del-client                Удалить по UUID"
    echo "  xm uri                       VLESS URI — интерактивный выбор"
    echo "  xm uri --tcp                 TCP URI"
    echo "  xm uri [имя]                 URI по имени"
    echo "  xm uri --all                 Все URI всех клиентов"
    echo ""
    echo -e "${BOLD}TCP inbound:${NC}"
    echo -e "  ${GREEN}xm add-tcp${NC}           Добавить XTLS-Vision/TCP inbound"
    echo ""
    echo -e "${BOLD}Nginx:${NC}"
    echo "  xm nginx-status / nginx-log / nginx-reload / nginx-probes"
    echo ""
    echo -e "${BOLD}Fail2ban:${NC}"
    echo "  xm ban-list / ban-ssh-stat / unban [IP]"
    echo ""
    echo -e "${BOLD}Логи:${NC}"
    echo "  xm log / log-live / log-clear"
    echo ""
    echo -e "${BOLD}${GREEN}Диагностика:${NC}"
    echo -e "  ${GREEN}xm diag${NC}              Полная диагностика"
    echo -e "  ${GREEN}xm pubkey${NC}            Диагностика публичных ключей"
    echo -e "  ${GREEN}xm diag-dpi${NC}          Устойчивость к DPI"
    echo -e "  ${GREEN}xm diag-ntp${NC}          NTP / дрейф времени"
    echo -e "  ${GREEN}xm diag-ports${NC}        Открытые порты"
    echo -e "  ${GREEN}xm diag-tls${NC}          TLS сертификат"
    echo -e "  ${GREEN}xm diag-fw${NC}           Firewall и ban-статус"
    echo -e "  ${GREEN}xm diag-log${NC}          Анализ лога"
    echo ""
    echo -e "${BOLD}Инфо:${NC}"
    echo "  xm info / paths / uuid / pubkey"
    ;;
esac
