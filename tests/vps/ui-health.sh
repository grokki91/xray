#!/usr/bin/env bash
# Вкладка «Здоровье» панели xm на живом VPS: установленный server.py отдаёт api/health с теми же
# цифрами за 7 дней и инцидентами, что `xm health --json`; «включён» — по юниту монитора; без
# токена — пустой 404; страница с вкладкой; панель слушает только петлю и закрывается.
# Монитор и данные не трогаются: панель запускается на свободном порту на время скрипта, порт
# панели (xm ui --port) не сохраняется. Запуск: sudo bash tests/vps/ui-health.sh
source "${BASH_SOURCE[0]%/*}/../lib.sh"
UI=/usr/local/lib/xm/ui
UNIT=/etc/systemd/system/xm-health.timer
vpr
vneed "python3 есть" bash -c 'command -v python3'
vneed "панель установлена (sudo xm self-update)" test -f "$UI/server.py"
vneed "curl есть" bash -c 'command -v curl'

PORT=""
for p in $(seq 18600 18650); do
  ss -tlnH "( sport = :$p )" | grep -q . || { PORT=$p; break; }
done
vneed "свободный порт для панели" test -n "$PORT"
python3 "$UI/server.py" --port "$PORT" --idle 2 --xm /usr/local/bin/xm >"$VTMP/ui.log" 2>&1 &
UI_PID=$!
trap 'kill "$UI_PID" 2>/dev/null' EXIT
for _ in $(seq 1 20); do grep -q 'Остановить' "$VTMP/ui.log" && break; sleep 0.5; done
TOK=$(grep -oE "127\.0\.0\.1:$PORT/[A-Za-z0-9_-]+/" "$VTMP/ui.log" | head -n 1 | cut -d/ -f2)
vneed "панель запустилась" test -n "$TOK"
export BASE="http://127.0.0.1:$PORT/$TOK" PORT

curl -s -m 30 -H 'X-Xm: 1' "$BASE/api/health" >"$VTMP/api.json"
xm health --json >"$VTMP/cli.json" 2>/dev/null

fact() { printf '  · %-30s %s\n' "$1" "$2"; }
echo "Факты:"
fact "монитор (юнит)" "$([[ -f $UNIT ]] && echo вкл || echo выкл)"
fact "таймеры" "$(systemctl is-active xm-health-sample.timer xm-health.timer 2>&1 | paste -sd' ')"
fact "api: enabled / active / stats" "$(jq -r '"\(.enabled) / \(.active) / \(.stats)"' "$VTMP/api.json" 2>&1)"
fact "api: d7" "$(jq -c '.d7' "$VTMP/api.json" 2>&1)"
fact "cli: d7" "$(jq -c '.d7' "$VTMP/cli.json" 2>&1)"
fact "api: инциденты / события" "$(jq -r '"\(.incidents | length) / \(.events | length)"' "$VTMP/api.json" 2>&1)"
fact "api: последнее окно" "$(jq -r '.last | if . then "\(.verdict); самопроверка \(.self); классов \(.classes | length)" else "нет" end' "$VTMP/api.json" 2>&1)"

vcheck  "api/health — JSON" jq -e '.band | length == 96' "$VTMP/api.json"
vexpect "enabled — по юниту монитора" "$([[ -f $UNIT ]] && echo true || echo false)" jq -r '.enabled' "$VTMP/api.json"
vexpect "active — оба таймера работают" \
  "$([[ "$(systemctl is-active xm-health-sample.timer xm-health.timer 2>/dev/null | paste -sd' ')" == "active active" ]] && echo true || echo false)" \
  jq -r '.active' "$VTMP/api.json"
if [[ -s /var/lib/xm/health/windows.jsonl ]]; then
  # Окно раз в 5 минут может попасть между двумя запросами — тогда перезапустить скрипт.
  vexpect "7 дней — как в xm health --json" "$(jq -c '.d7' "$VTMP/cli.json")" jq -c '.d7' "$VTMP/api.json"
  vexpect "инциденты — как в xm health --json" "$(jq -c '[.incidents[] | [.from, .to, .why]]' "$VTMP/cli.json")" \
    jq -c '[.incidents[] | [.from, .to, .why]]' "$VTMP/api.json"
  vcheck  "события — словами" jq -e '[.events[], .incidents[].events[]] | all(.text | type == "string")' "$VTMP/api.json"
else
  vexpect "окон нет — пустой отчёт" "0" jq -r '.d7.windows' "$VTMP/api.json"
fi
vexpect "без токена — 404" "404" bash -c 'curl -s -o /dev/null -w "%{http_code}" -H "X-Xm: 1" "http://127.0.0.1:$PORT/api/health"'
vexpect "на странице вкладка «Здоровье»" "1" bash -c 'curl -s "$BASE/" | grep -c "id=\"t-health\""'
vexpect "панель слушает только петлю" "127.0.0.1:$PORT" bash -c 'ss -tlnH "( sport = :$PORT )" | awk "{print \$4}" | sort -u | paste -sd" "'
kill "$UI_PID" 2>/dev/null; wait "$UI_PID" 2>/dev/null
vexpect "после остановки порт закрыт" "" bash -c 'ss -tlnH "( sport = :$PORT )"'
vreport
