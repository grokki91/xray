#!/usr/bin/env bash
# =============================================================================
#  xm — Xray Manager Helper  v5.6
#  Использование: xm [команда]
#
#  Команды:
#   Сервис:      start / stop / restart / status
#   Конфиг:      edit / test / apply / set-sni
#   Бэкапы:      backup / restore / backups
#   Клиенты:     clients / add-client / del-client / uri / qr
#   TCP:         add-tcp
#   Обновление:  update [--check] / update-geo
#   Nginx:       nginx-status / nginx-log / nginx-reload / nginx-probes
#   Fail2ban:    ban-list / ban-ssh-stat / unban
#   Логи:        log / log-live / log-clear
#   Инфо:        info / paths / uuid / pubkey
#   Диагностика: diag / diag-dpi / diag-ntp / diag-ports / diag-tls / diag-fw / diag-log
# =============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/usr/local/etc/xray/backups"
LOG="/var/log/xray/error.log"
CLIENT_FILE="/usr/local/etc/xray/client-info.txt"

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

_url_encode() {
  python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
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
    mkdir -p "$BACKUP_DIR"; STAMP=$(date +%Y%m%d_%H%M%S)
    CFG_BACKUP="$BACKUP_DIR/config_${STAMP}_before_setsni.json"
    cp "$CONFIG" "$CFG_BACKUP"
    NGX_BACKUP=""
    [[ -f "$NGINX_CONF" ]] && { NGX_BACKUP="${NGINX_CONF}.${STAMP}.bak"; cp "$NGINX_CONF" "$NGX_BACKUP"; }
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
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" =~ ^[23] || "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
      ok "dest доступен (HTTP $HTTP_CODE)"
    else
      warn "dest вернул код $HTTP_CODE — продолжаем, но проверь вручную"
    fi
    # Сертификат сайта мог измениться — перепроверяем размер под REALITY
    _sni_cert_gate "$SNI" || warn "SNI $SNI сомнителен по размеру сертификата (см. выше) — TCP inbound может ловить handshake failed"

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
            dest: "127.0.0.1:10443",
            xver: 2,
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
      LATEST=$(curl -fsSL --proto '=https' --tlsv1.2 --max-time 10 \
        https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null \
        | jq -r '.tag_name // empty')
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
    mkdir -p "$BACKUP_DIR"
    UPD_BACKUP="$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S)_before_update.json"
    cp "$CONFIG" "$UPD_BACKUP"
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
nginx-log)     tail -30 /var/log/nginx/reality_fallback.log 2>/dev/null || echo "Лог пуст" ;;
nginx-reload)  nginx -t && systemctl reload nginx && echo -e "${GREEN}Nginx перезагружен${NC}" ;;
nginx-probes)
    echo -e "${BOLD}Активные зонды (соединения с чужим/пустым SNI):${NC}"
    echo -e "${CYAN}(легитимные клиенты сюда НЕ попадают — у них правильный SNI)${NC}"
    awk '{print $1}' /var/log/nginx/reality_fallback.log 2>/dev/null \
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
    for jail in sshd nginx-reality-flood; do
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
    echo -e "${BOLD}${CYAN}║       Xray Full Diagnostic  v5.6         ║${NC}"
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
      --max-time 8 --connect-timeout 4 -w "%{http_code}" 2>/dev/null || echo "000")
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
    # limit_conn без realip считает всех как 127.0.0.1 → лимит 20 действует
    # на весь сервер, а не на клиента, и отстреливает своих же (status=503).
    if grep -rq "set_real_ip_from" /etc/nginx/stream-enabled/ 2>/dev/null; then
      ok "set_real_ip_from настроен (limit_conn считает по реальному IP клиента)"
    else
      fail "set_real_ip_from не задан — limit_conn считает все соединения как 127.0.0.1, лимит действует на весь сервер"; ((ISSUES++))
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
      ufw status | grep -qE "(^|[^0-9])${SSH_P}/tcp" 
        && ok "SSH порт $SSH_P открыт в UFW" \
        || { fail "SSH порт $SSH_P не найден в UFW — риск потери доступа!"; ((ISSUES++)); }
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
    JCOUNT=$(journalctl -u xray --since "1 hour ago" --no-pager 2>/dev/null | grep -c "accepted" || echo 0)
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
    echo -e "\n${BOLD}${CYAN}[ DPI / Active Probe Resistance ]${NC}\n"

    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    SNI=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$CONFIG")
    SERVER_IP=$(_get_server_ip)

    sep
    echo -e "${BOLD}Тест 0: Синхронизация SNI (источники правды)${NC}"
    # Тесты ниже гоняют зонды по serverNames[0]. Если host/nginx-map расходятся —
    # живой клиент шлёт другой SNI, а тесты этого не заметят. Поэтому сверяем сначала.
    SNI_HOST_D=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host // ""' "$CONFIG")
    NGX_CONF_D="/etc/nginx/stream-enabled/reality-fallback.conf"
    NGX_SNI_D=$(grep -oE '^[[:space:]]*[a-zA-Z0-9._-]+[[:space:]]+[a-zA-Z0-9._-]+;' "$NGX_CONF_D" 2>/dev/null | grep -v 'default' | head -1 | awk '{print $1}')
    DSYNC=0
    [[ -n "$SNI_HOST_D" && "$SNI_HOST_D" != "$SNI" ]] && { fail "xhttpSettings.host=$SNI_HOST_D ≠ serverNames[0]=$SNI — URI клиента шлёт не тот SNI"; DSYNC=1; }
    [[ -n "$NGX_SNI_D"  && "$NGX_SNI_D"  != "$SNI" ]] && { fail "nginx map=$NGX_SNI_D ≠ serverNames[0]=$SNI — fallback уводит не туда"; DSYNC=1; }
    if _has_tcp_inbound; then
      SNI_TCP_D=$(jq -r '.inbounds[1].streamSettings.realitySettings.serverNames[0] // ""' "$CONFIG")
      [[ "$SNI_TCP_D" != "$SNI" ]] && { fail "TCP serverNames[0]=$SNI_TCP_D ≠ XHTTP=$SNI"; DSYNC=1; }
    fi
    [[ "$DSYNC" -eq 0 ]] \
      && ok "Все источники SNI согласованы ($SNI) — тесты ниже валидны" \
      || warn "Есть рассинхрон SNI (см. выше). Исправь: xm set-sni $SNI — иначе тесты ниже вводят в заблуждение"

    sep
    echo -e "${BOLD}Тест 1: Active probe resistance (главный тест REALITY)${NC}"
    # Зонд с целевым SNI прозрачно форвардится на fallback → реальный сайт, поэтому
    # ДОЛЖЕН получить успешный хендшейк с настоящим сертификатом. Сравниваем cert
    # нашего сервера с cert реального $SNI (fingerprint/issuer). -tls1_3 проверяет TLS 1.3.
    OUR_CERT=$(echo | timeout 6 openssl s_client \
      -connect "${SERVER_IP}:${PORT}" -servername "$SNI" -tls1_3 2>/dev/null \
      | openssl x509 -noout -issuer -subject -fingerprint -sha256 2>/dev/null || echo "")
    REAL_CERT=$(echo | timeout 6 openssl s_client \
      -connect "${SNI}:443" -servername "$SNI" -tls1_3 2>/dev/null \
      | openssl x509 -noout -issuer -subject -fingerprint -sha256 2>/dev/null || echo "")

    if [[ -z "$OUR_CERT" ]]; then
      fail "Наш сервер НЕ отдал сертификат по TLS 1.3 — зонд получает reset/сбой вместо валидного хендшейка. Это ПАЛИТ сервер для DPI!"
      warn "Проверь fallback: xm diag → блок [6], и: ss -tlnp | grep 10443"
    else
      OUR_FP=$(echo "$OUR_CERT"  | grep -i "Fingerprint" | sed 's/.*=//' | tr -d '[:space:]')
      REAL_FP=$(echo "$REAL_CERT" | grep -i "Fingerprint" | sed 's/.*=//' | tr -d '[:space:]')
      OUR_ISS=$(echo "$OUR_CERT"  | grep -i "^issuer")
      REAL_ISS=$(echo "$REAL_CERT" | grep -i "^issuer")
      echo "$OUR_CERT"  | grep -iE "^issuer|^subject" | sed 's/^/    наш:  /'
      [[ -n "$REAL_CERT" ]] && echo "$REAL_CERT" | grep -iE "^issuer|^subject" | sed 's/^/    сайт: /'

      if [[ -n "$REAL_FP" && "$OUR_FP" == "$REAL_FP" ]]; then
        ok "Сертификат ИДЕНТИЧЕН реальному $SNI (совпал fingerprint) — зонд неотличим от настоящего сайта"
      elif [[ -n "$REAL_ISS" && "$OUR_ISS" == "$REAL_ISS" ]]; then
        ok "Issuer совпадает с реальным $SNI (leaf-сертификат отличается — обычное дело для CDN/гео). Зонд видит валидный cert того же CA."
      elif [[ -n "$REAL_CERT" ]]; then
        warn "Issuer/сертификат НЕ совпадает с реальным $SNI — fallback может проксировать не на тот сайт. Сверь issuer выше."
      else
        info "Эталонный сертификат $SNI не получен (сайт недоступен для сравнения). Но наш сервер валидный хендшейк отдаёт — путь fallback жив."
      fi
    fi

    sep
    echo -e "${BOLD}Тест 2: HTTP на порту 80${NC}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "http://${SERVER_IP}" --max-time 5 -H "Host: ${SNI}" 2>/dev/null || echo "000")
    [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]] \
      && ok "Порт 80 → redirect $HTTP_CODE" \
      || warn "Порт 80 вернул: $HTTP_CODE (ожидался 301/302)"

    sep
    echo -e "${BOLD}Тест 3: REALITY fallback (nginx stream)${NC}"
    if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10443"; then
      ok "stream-fallback слушает 127.0.0.1:10443"
    else
      fail "stream-fallback не слушает 127.0.0.1:10443 — REALITY dest мёртв"
    fi

    sep
    echo -e "${BOLD}Тест 4: Ответ на случайный путь (сравнение с реальным сайтом)${NC}"
    # --resolve: curl идёт на наш IP:PORT, но предъявляет в TLS (SNI) и Host именно $SNI.
    # На случайный путь наш сервер должен отвечать тем же кодом, что и реальный сайт.
    RAND_PATH="/$(openssl rand -hex 8)"
    OUR_RAND=$(curl -sk -o /dev/null -w "%{http_code}" \
      --resolve "${SNI}:${PORT}:${SERVER_IP}" \
      "https://${SNI}:${PORT}${RAND_PATH}" --max-time 6 2>/dev/null || echo "000")
    REAL_RAND=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${SNI}${RAND_PATH}" --max-time 6 2>/dev/null || echo "000")
    info "Наш сервер: HTTP $OUR_RAND   |   Реальный $SNI: HTTP $REAL_RAND"
    if [[ "$OUR_RAND" == "000" ]]; then
      warn "Наш сервер оборвал соединение (000) — fallback до реального сайта не доходит. Зонд с валидным SNI получит аномалию."
    elif [[ "$OUR_RAND" == "$REAL_RAND" ]]; then
      ok "Ответ ($OUR_RAND) совпадает с реальным $SNI — по HTTP неотличимо"
    else
      warn "Ответ нашего сервера ($OUR_RAND) ≠ ответу реального сайта ($REAL_RAND). Часто это гео/балансировка CDN, но проверь, что fallback идёт на нужный сайт."
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

    sep
    echo -e "${BOLD}Тест 7: Реакция на зонды (поведение как у реального сайта)${NC}"
    # Настоящий сайт не банит сканеры. Если мы баним — это отличие,
    # по которому сервер отделяется от www.apple.com.
    if fail2ban-client status 2>/dev/null | grep -qi "reality\|xray"; then
      warn "Есть fail2ban-джейл по трафику REALITY — бан сканеров демаскирует сервер"
    else
      ok "Зонды не банятся (только rate-limit) — реакция как у настоящего CDN"
    fi
    PROBES=$(wc -l < /var/log/nginx/reality_fallback.log 2>/dev/null || echo 0)
    info "Зондов с чужим SNI в логе: $PROBES (свои клиенты сюда не пишутся)"

    sep
    echo -e "${BOLD}Тест 8: maxTimeDiff${NC}"
    MAX_TD=$(jq -r '.inbounds[0].streamSettings.realitySettings.maxTimeDiff // 0' "$CONFIG")
    if [[ "$MAX_TD" -le 10000 ]]; then
      ok "maxTimeDiff: ${MAX_TD} мс — оптимально"
    elif [[ "$MAX_TD" -le 30000 ]]; then
      warn "maxTimeDiff: ${MAX_TD} мс — допустимо, но можно снизить до 10000"
    else
      warn "maxTimeDiff: ${MAX_TD} мс — широкое окно для replay-атак, рекомендуется 10000"
    fi
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

    sep
    echo -e "${BOLD}fail2ban:${NC}"
    if systemctl is-active --quiet fail2ban; then
      ok "fail2ban запущен"
      for jail in sshd nginx-reality-flood; do
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
    echo -e "${BOLD}${CYAN}║       xm — Xray Manager  v5.6            ║${NC}"
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
    echo -e "  ${GREEN}xm autoupd on|off|now|log|status${NC}  Автопатчи безопасности ОС (20:30 МСК)"
    echo -e "  ${GREEN}xm update [--check]${NC} / ${GREEN}update-geo${NC}   Xray-core / geoip.dat / geosite.dat"
    echo ""
    echo -e "${BOLD}Nginx:${NC}    xm nginx-status / nginx-log / nginx-reload / nginx-probes"
    echo -e "${BOLD}Fail2ban:${NC} xm ban-list / ban-ssh-stat / unban [IP]"
    echo -e "${BOLD}Логи:${NC}     xm log / log-live / log-clear"
    echo -e "${BOLD}Инфо:${NC}     xm info / paths / uuid / pubkey"
    echo ""
    echo -e "${BOLD}${GREEN}Диагностика:${NC}"
    echo -e "  ${GREEN}xm diag${NC}                          Полная диагностика"
    echo -e "  ${GREEN}xm dpi${NC}                           Устойчивость к DPI"
    echo    "  Прочее: pubkey / diag-ntp / diag-ports / diag-tls / diag-fw / diag-log"
    ;;
esac