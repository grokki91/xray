#!/usr/bin/env bash
# Вкладка «Здоровье» панели (api_health в ui/server.py): отчёт xm health с текстами для страницы —
# события рядом с инцидентом не дублируются в общем списке, последнее окно словами, монитор
# выключен — enabled false без окон. Окна — синтетические в формате health.py; systemctl и файл
# юнита — заглушки (их сверяет tests/vps/ui-health.sh), отчёт — настоящий build_report.
root=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export XM_HEALTH_DIR="$T/data" XM_HEALTH_RUN="$T/run" XM_STATS_SAMPLES="$T/samples.jsonl" PYTHONDONTWRITEBYTECODE=1
mkdir -p "$T/data"
out=$(python3 - "$root/ui" "$T" <<'PY' 2>&1
import json, sys, time
sys.path.insert(0, sys.argv[1]); T = sys.argv[2]
import server

fails = []
def want(name, got, exp):
    if got != exp:
        fails.append("%s: ожидалось %r, получено %r" % (name, exp, got))

class R:
    stdout = "active\nactive\n"
unit = {"on": True}
server.P = type("P", (), {"config": T + "/нет.json"})
server.os.path.exists = lambda p: unit["on"] if p.endswith("xm-health.timer") else False
server.subprocess.run = lambda *a, **k: R()

now = int(time.time()) // 300 * 300
with open(T + "/data/windows.jsonl", "w") as f:
    for i in range(30, 0, -1):
        w = {"t": now - i * 300, "self": {"r": "ok"}, "tr": 100000,
             "c": {"cmax": 5, "new": 1, "pmax": 2, "pnew": 1, "norm": 4, "post": 1}}
        if i == 20:
            w["self"] = {"r": "fail", "at": "handshake"}
            w["ev"] = ["xray"]
        if i == 5:
            w["ev"] = ["ver_xm"]
        f.write(json.dumps(w) + "\n")

want("маршрут", server.GET_ROUTES.get("health"), server.api_health)
r = server.api_health({}, {})
want("включён и таймеры работают", (r["enabled"], r["active"]), (True, True))
want("инциденты", [x["why"] for x in r["incidents"]], ["сбой сервера: рукопожатие"])
want("событие рядом с инцидентом — словами", [e["text"] for e in r["incidents"][0]["events"]], ["перезапуск Xray"])
want("общий список без событий инцидента", [e["text"] for e in r["events"]], ["обновлён xm"])
L = r["last"]
want("последнее окно: вердикт и самопроверка", (L["verdict"], L["self"]), ("OK", "прошла"))
want("последнее окно: классы", L["classes"], [{"text": "встало после ClientHello", "n": 1}])
want("последнее окно: соединения", L["conns"], {"cmax": 5, "new": 1, "pmax": 2, "pnew": 1})
want("полоса суток", len(r["band"]), 96)
json.dumps(r)  # ответ сериализуется

unit["on"] = False
open(T + "/data/windows.jsonl", "w").close()
r = server.api_health({}, {})
want("выключен: состояние", (r["enabled"], r["active"], r["d7"]["windows"], r["last"]), (False, False, 0, None))

print("\n".join("FAIL " + x for x in fails) or "ok")
PY
)
[[ $out == ok ]] || { echo "$out"; exit 1; }
echo "ui-health: ok"
