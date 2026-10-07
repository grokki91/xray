#!/usr/bin/env bash
# PreToolUse(Read): xm.sh и setup.sh — большие файлы, целиком их не читать. Без limit или
# больше MAX строк за раз — отказ (exit 2, причина — в stderr, её видит Claude) с картой.
# Нет jq — хук молча пропускает: сломанный хук не должен блокировать работу.
MAX=800
command -v jq >/dev/null 2>&1 || exit 0
input=$(cat)
file=$(jq -r '.tool_input.file_path // empty' <<<"$input" 2>/dev/null)
case "${file##*/}" in
  xm.sh|setup.sh) ;;
  *) exit 0 ;;
esac
limit=$(jq -r '.tool_input.limit // empty' <<<"$input" 2>/dev/null)
[[ "$limit" =~ ^[0-9]+$ ]] && (( limit <= MAX )) && exit 0
cat >&2 <<EOF
${file##*/} — большой файл: читать по диапазону, Read с offset и limit не больше $MAX.
Карта xm.sh (разделы и команды): grep -nE '^# ─── |^[a-z][a-z|-]*\)' xm.sh | sed -E 's/ (─)+\$//'
Карта setup.sh (функции и шаги): grep -nE '^[a-z_]+\(\)|^ *header ' setup.sh
Функция: grep -n '^имя()' xm.sh
EOF
exit 2
