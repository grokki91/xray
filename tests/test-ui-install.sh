#!/usr/bin/env bash
# _ui_install (xm.sh) ставит все файлы ui/, а не список: новый файл доезжает до сервера без правки
# списка; подкаталоги не копируются; битый .py останавливает установку и оставляет прежнюю панель.
root=${BASH_SOURCE[0]%/*}/..
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
RED= YELLOW= GREEN= CYAN= BOLD= NC=
eval "$(sed -n '/^ok()/,/^sep()/p; /^_ui_install()/,/^}/p' "$root/xm.sh")"
declare -F _ui_install >/dev/null || { echo "FAIL: в xm.sh нет _ui_install"; exit 1; }
UI_DIR="$T/lib/ui"
mkdir -p "$T/repo/ui/__pycache__"
cp "$root"/ui/*.* "$T/repo/ui/"
echo 'x = 1' >"$T/repo/ui/new_module.py"
fails=0
_ui_install "$T/repo" >/dev/null || { echo "FAIL: установка не прошла"; fails=$((fails + 1)); }
for f in "$T"/repo/ui/*.*; do
  cmp -s "$f" "$UI_DIR/${f##*/}" || { echo "FAIL: не установлен ui/${f##*/}"; fails=$((fails + 1)); }
done
[[ -e $UI_DIR/__pycache__ ]] && { echo "FAIL: скопирован подкаталог __pycache__"; fails=$((fails + 1)); }
echo 'def (' >"$T/repo/ui/new_module.py"
_ui_install "$T/repo" >/dev/null && { echo "FAIL: битый .py установлен"; fails=$((fails + 1)); }
grep -q 'x = 1' "$UI_DIR/new_module.py" 2>/dev/null || { echo "FAIL: после отказа прежняя панель не осталась"; fails=$((fails + 1)); }
(( fails == 0 )) || exit 1
echo "ui-install: ok"
