#!/usr/bin/env bash
# =============================================================================
#  xm — Xray Manager Helper
#  Использование: xm [команда]
# =============================================================================

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONFIG="/usr/local/etc/xray/config.json"
BACKUP_DIR="/usr/local/etc/xray/backups"
LOG="/var/log/xray/error.log"
CLIENT_FILE="/root/xray-client-info.txt"

case "$1" in

# ─── Сервис ──────────────────────────────────────────────────────────────────
start)    systemctl start xray;   echo -e "${GREEN}Xray запущен${NC}" ;;
stop)     systemctl stop xray;    echo -e "${YELLOW}Xray остановлен${NC}" ;;
restart)  systemctl restart xray; echo -e "${GREEN}Xray перезапущен${NC}" ;;
status)   systemctl status xray --no-pager ;;

# ─── Конфиг ──────────────────────────────────────────────────────────────────
edit)
    echo -e "${YELLOW}Создаю резервную копию...${NC}"
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "$BACKUP_DIR/config_${STAMP}.json"
    echo -e "${GREEN}Бэкап: $BACKUP_DIR/config_${STAMP}.json${NC}"
    nano "$CONFIG"
    ;;

test)
    xray -test -config "$CONFIG" && echo -e "${GREEN}Конфиг валиден${NC}" \
      || echo -e "${RED}Конфиг невалиден!${NC}"
    ;;

apply)
    # Проверить + перезапустить
    if xray -test -config "$CONFIG" 2>&1 | grep -q "Configuration OK"; then
        systemctl restart xray
        echo -e "${GREEN}Конфиг применён, Xray перезапущен${NC}"
    else
        echo -e "${RED}Конфиг невалиден — Xray не перезапущен${NC}"
        xray -test -config "$CONFIG"
    fi
    ;;

# ─── Бэкапы ──────────────────────────────────────────────────────────────────
backup)
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "$BACKUP_DIR/config_${STAMP}.json"
    echo -e "${GREEN}Бэкап сохранён: $BACKUP_DIR/config_${STAMP}.json${NC}"
    ;;

restore)
    mkdir -p "$BACKUP_DIR"
    FILES=($(ls -t "$BACKUP_DIR"/*.json 2>/dev/null))
    if [[ ${#FILES[@]} -eq 0 ]]; then
        echo -e "${RED}Нет бэкапов в $BACKUP_DIR${NC}"
        exit 1
    fi
    echo -e "${BOLD}Доступные бэкапы:${NC}"
    for i in "${!FILES[@]}"; do
        echo "  $((i+1))) ${FILES[$i]}"
    done
    read -rp "Выбери номер [Enter=1 (последний)]: " CHOICE
    CHOICE=${CHOICE:-1}
    SELECTED="${FILES[$((CHOICE-1))]}"
    cp "$SELECTED" "$CONFIG"
    echo -e "${GREEN}Восстановлен: $SELECTED${NC}"
    xm apply
    ;;

backups)
    mkdir -p "$BACKUP_DIR"
    echo -e "${BOLD}Бэкапы конфига:${NC}"
    ls -lh "$BACKUP_DIR"/*.json 2>/dev/null || echo "Бэкапов нет"
    ;;

# ─── Клиенты ─────────────────────────────────────────────────────────────────
clients)
    echo -e "${BOLD}Текущие клиенты:${NC}"
    jq -r '.inbounds[0].settings.clients[] | "  UUID: \(.id)  |  \(.comment // "без комментария")"' "$CONFIG"
    ;;

add-client)
    # xm add-client "ivan-laptop"
    COMMENT="${2:-}"
    if [[ -z "$COMMENT" ]]; then
        read -rp "Имя клиента (comment): " COMMENT
    fi
    NEW_UUID=$(xray uuid)
    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG" "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"

    jq --arg uuid "$NEW_UUID" --arg comment "$COMMENT" \
      '.inbounds[0].settings.clients += [{"id": $uuid, "comment": $comment}]' \
      "$CONFIG" > /tmp/xray_cfg_tmp.json && mv /tmp/xray_cfg_tmp.json "$CONFIG"

    # Читаем параметры для URI из конфига
    SNI=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.host' "$CONFIG")
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    PBK=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG")
    SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG")
    PATH_VAL=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.path' "$CONFIG")
    MODE=$(jq -r '.inbounds[0].streamSettings.xhttpSettings.mode' "$CONFIG")
    PUBLIC_KEY=$(grep "PUBLIC KEY" "$CLIENT_FILE" 2>/dev/null | awk '{print $NF}')
    SERVER_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || echo "SERVER_IP")
    ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PATH_VAL}', safe=''))")

    echo -e "${GREEN}Клиент добавлен!${NC}"
    echo -e "${BOLD}UUID:${NC}    $NEW_UUID"
    echo -e "${BOLD}Comment:${NC} $COMMENT"
    echo ""
    echo -e "${BOLD}VLESS URI:${NC}"
    echo "vless://${NEW_UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SID}&type=xhttp&path=${ENCODED_PATH}&host=${SNI}&mode=${MODE}#${COMMENT}"
    echo ""
    xm apply
    ;;

del-client)
    echo -e "${BOLD}Текущие клиенты:${NC}"
    jq -r '.inbounds[0].settings.clients | to_entries[] | "  \(.key+1)) \(.value.id)  \(.value.comment // "")"' "$CONFIG"
    read -rp "Номер клиента для удаления: " NUM
    INDEX=$((NUM-1))
    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG" "$BACKUP_DIR/config_$(date +%Y%m%d_%H%M%S).json"
    jq --argjson idx "$INDEX" 'del(.inbounds[0].settings.clients[$idx])' \
      "$CONFIG" > /tmp/xray_cfg_tmp.json && mv /tmp/xray_cfg_tmp.json "$CONFIG"
    echo -e "${GREEN}Клиент удалён${NC}"
    xm apply
    ;;

# ─── Логи ────────────────────────────────────────────────────────────────────
log)      tail -50 "$LOG" ;;
log-live) tail -f "$LOG" ;;
log-clear) > "$LOG"; echo -e "${GREEN}Лог очищен${NC}" ;;

# ─── Инфо ────────────────────────────────────────────────────────────────────
info)
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}  Xray Info${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}Версия:${NC}  $(xray version | head -1)"
    echo -e "${BOLD}Сервис:${NC}  $(systemctl is-active xray)"
    echo -e "${BOLD}Конфиг:${NC}  $CONFIG"
    echo -e "${BOLD}Лог:${NC}     $LOG"
    echo -e "${BOLD}Клиенты:${NC} $(jq '.inbounds[0].settings.clients | length' "$CONFIG")"
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG")
    echo -e "${BOLD}Порт:${NC}    $PORT"
    echo -e "${BOLD}Порт открыт:${NC} $(ss -tlnp | grep -c ":$PORT" || echo 0)"
    ;;

paths)
    echo -e "${BOLD}Пути:${NC}"
    echo "  Конфиг:      $CONFIG"
    echo "  Бэкапы:      $BACKUP_DIR"
    echo "  Лог:         $LOG"
    echo "  Клиент-файл: $CLIENT_FILE"
    echo "  Бинарник:    $(which xray)"
    echo "  Сервис:      /etc/systemd/system/xray.service"
    ;;

uuid)
    NEW=$(xray uuid)
    echo "$NEW"
    ;;

# ─── Помощь ──────────────────────────────────────────────────────────────────
*)
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}  xm — Xray Manager${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Сервис:${NC}"
    echo "  xm start          Запустить Xray"
    echo "  xm stop           Остановить Xray"
    echo "  xm restart        Перезапустить Xray"
    echo "  xm status         Статус сервиса"
    echo ""
    echo -e "${BOLD}Конфиг:${NC}"
    echo "  xm edit           Открыть конфиг в nano (с автобэкапом)"
    echo "  xm test           Проверить валидность конфига"
    echo "  xm apply          Проверить + перезапустить"
    echo ""
    echo -e "${BOLD}Бэкапы:${NC}"
    echo "  xm backup         Создать бэкап конфига"
    echo "  xm restore        Восстановить конфиг из бэкапа"
    echo "  xm backups        Список всех бэкапов"
    echo ""
    echo -e "${BOLD}Клиенты:${NC}"
    echo "  xm clients                Показать всех клиентов"
    echo "  xm add-client [имя]       Добавить клиента (генерирует UUID)"
    echo "  xm del-client             Удалить клиента"
    echo ""
    echo -e "${BOLD}Логи:${NC}"
    echo "  xm log            Последние 50 строк лога"
    echo "  xm log-live       Лог в реальном времени (Ctrl+C выход)"
    echo "  xm log-clear      Очистить лог"
    echo ""
    echo -e "${BOLD}Инфо:${NC}"
    echo "  xm info           Общая информация о сервере"
    echo "  xm paths          Все важные пути"
    echo "  xm uuid           Сгенерировать новый UUID"
    ;;
esac
