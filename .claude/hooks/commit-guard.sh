#!/usr/bin/env bash
# PreToolUse(Bash): git commit и git push — только при зелёном tests/check.sh (синтаксис, скиллы,
# тесты, данные установки в ветке и в тексте команды — там сообщение коммита; локальные пути
# /tmp/… и /root/… из текста вырезаются: в них UUID сессии, а не установки). Провал — отказ
# (exit 2, провалы — в stderr, их видит Claude). Нет jq — молча пропускает, как read-guard.
command -v jq >/dev/null 2>&1 || exit 0
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null)
re='(^|[^[:alnum:]_.-])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+(commit|push)([[:space:]]|$)'
[[ $cmd =~ $re ]] || exit 0
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$cmd" | sed -E "s#/(tmp|root)/[^[:space:]'\"]*##g" >"$tmp"
out=$(bash "$root/tests/check.sh" "$tmp" 2>&1) && exit 0
printf '%s\n' "git ${BASH_REMATCH[3]} остановлен: tests/check.sh не прошёл — исправь и повтори." "$out" >&2
exit 2
