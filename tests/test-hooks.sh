#!/usr/bin/env bash
# Тесты хуков .claude/hooks: на входе — JSON, как его даёт Claude Code; проверяются код выхода
# и решение (block / подсказка). commit-guard гоняет настоящий tests/check.sh (без тестов внутри).
H="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)/.claude/hooks"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
command -v jq >/dev/null || { echo "FAIL нет jq"; exit 1; }
fails=0
no() { echo "FAIL $1"; [[ -n ${2:-} ]] && sed 's/^/    /' <<<"$2"; fails=$((fails + 1)); }
ip="5.6.7.$((4 * 2))"  # не документационный адрес; собран здесь, чтобы его не нашёл check.sh

# Транскрипт из N реплик владельца (плюс служебные записи, которые не считаются)
transcript() {
  local f="$T/t$1.jsonl" i
  [[ -f $f ]] || for ((i = 1; i <= $1; i++)); do
    printf '%s\n' "{\"type\":\"user\",\"message\":{\"content\":\"реплика $i\"},\"promptId\":\"p$i\"}" \
      '{"type":"user","message":{"content":[{"type":"tool_result","content":"x"}]}}' \
      '{"type":"user","isMeta":true,"message":{"content":"Stop hook feedback"}}'
  done >"$f"
  echo "$f"
}

# verdict ИМЯ pass|block ТЕКСТ [ЧИСЛО_РЕПЛИК_ВЛАДЕЛЬЦА]
verdict() {
  local out tr; tr=$(transcript "${4:-1}")
  out=$(jq -n --arg m "$3" --arg t "$tr" '{last_assistant_message:$m,transcript_path:$t}' | bash "$H/verdict-guard.sh")
  case $2 in
    pass) [[ -z $out ]] || no "verdict: $1 — ждали пропуск" "$out" ;;
    block) [[ $(jq -r .decision <<<"$out" 2>/dev/null) == block ]] || no "verdict: $1 — ждали block" "$out" ;;
  esac
}
long=$(printf 'Изменено: строка отчёта %.0s\n' {1..12})
# rep CODE CHECKS INTEGRATION ХВОСТ — отчёт в блоке кода после длинного текста
rep() { printf '%s\n\n```\ncode_pr: %s\nchecks: %s\nintegration: %s\n%s\n```\n' "$long" "$1" "$2" "$3" "$4"; }

verdict "короткий ответ без вердикта" pass "Да: sudo xm journal."
verdict "длинный без вердикта" block "$long"
verdict "ИТОГ OK" pass "$long
ИТОГ: OK — проверено"
verdict "отчёт YES" pass "$(rep PASS PASS NOT_REQUIRED 'merge_ready: YES')"
verdict "отчёт с жирными значениями" pass "$(rep '**PASS**' PASS '**PASS**' 'merge_ready: **YES**')"
verdict "YES при integration NOT_RUN" block "$(rep PASS PASS NOT_RUN 'merge_ready: YES')"
verdict "YES при checks FAIL с причиной" block "$(rep PASS 'FAIL — bash -n xm.sh' PASS 'merge_ready: YES')"
verdict "YES при differences 3" block "$(rep PASS PASS PASS 'differences: 3
merge_ready: YES')"
verdict "YES при expected≠actual" block "$(rep PASS PASS PASS 'sent: expected=9849, actual=9848
differences: 0
merge_ready: YES')"
verdict "YES при expected=actual" pass "$(rep PASS PASS PASS 'sent: expected=9849, actual=9849
differences: 0
merge_ready: YES')"
verdict "короткий отчёт YES без полей" block 'checks: PASS
merge_ready: YES'
verdict "чужое значение" block "$(rep PASS OK PASS 'merge_ready: YES')"
verdict "UNKNOWN, ответ 1" pass "$(rep PASS PASS 'NOT_RUN — нужен VPS' 'merge_ready: UNKNOWN — прогон tests/vps')"
verdict "UNKNOWN, ответ 3 без журнала" block "$(rep PASS PASS NOT_RUN 'merge_ready: UNKNOWN')" 3
verdict "NO, ответ 3 с журналом" pass "sudo xm journal add …
$(rep FAIL PASS FAIL 'merge_ready: NO')" 3
verdict "ПРОБЛЕМА, ответ 3 без журнала" block "$long
ИТОГ: ПРОБЛЕМА — не решено" 3
out=$(jq -n --arg m "$long" '{last_assistant_message:$m,stop_hook_active:true}' | bash "$H/verdict-guard.sh")
[[ -z $out ]] || no "verdict: stop_hook_active — ждали пропуск" "$out"

# guard ИМЯ КОД КОМАНДА — commit-guard с настоящим check.sh
guard() {
  local out rc
  out=$(jq -n --arg c "$3" '{tool_input:{command:$c}}' \
    | CLAUDE_PROJECT_DIR="${H%/.claude/hooks}" bash "$H/commit-guard.sh" 2>&1); rc=$?
  [[ $rc == "$2" ]] || no "commit-guard: $1 — код $rc, ждали $2" "$out"
}
guard "не git" 0 "grep -n $ip README.md"
guard "чужое слово с git" 0 "legit-git commit $ip"
guard "коммит с адресом в сообщении" 2 "git add -A && git commit -m 'фикс для $ip'"
guard "push через -C" 2 "git -C /tmp push origin x # $ip"
guard "коммит с документационным адресом" 0 "git commit -m 'пример 192.0.2.1'"
uuid=$(printf '%s-%s-%s-%s-%s' 1b671a64 40d5 491e 99b0 da01ff1f3341)
guard "UUID в сообщении" 2 "git commit -m 'клиент $uuid'"
guard "UUID в локальном пути" 0 "cd /tmp/s/$uuid/x && git commit -m 'тест'"

# rg ИМЯ КОД ФАЙЛ [LIMIT] — read-guard
rg() {
  local rc
  jq -n --arg f "$3" --arg l "${4:-}" \
    '{tool_input:({file_path:$f} + (if $l == "" then {} else {limit:($l|tonumber)} end))}' \
    | bash "$H/read-guard.sh" 2>/dev/null; rc=$?
  [[ $rc == "$2" ]] || no "read-guard: $1 — код $rc, ждали $2"
}
rg "xm.sh целиком" 2 /r/xm.sh
rg "xm.sh 500 строк" 0 /r/xm.sh 500
rg "setup.sh 900 строк" 2 /r/setup.sh 900
rg "другой файл" 0 /r/README.md

# budget ИМЯ ПОДСТРОКА ПРОМТ ЧИСЛО_РЕПЛИК_В_ТРАНСКРИПТЕ — answer-budget
budget() {
  local out
  out=$(jq -n --arg p "$3" --arg t "$(transcript "$4")" '{prompt:$p,transcript_path:$t,prompt_id:"new"}' \
    | bash "$H/answer-budget.sh" | jq -r .hookSpecificOutput.additionalContext)
  [[ $out == *"$2"* ]] || no "answer-budget: $1 — нет «$2»" "$out"
}
budget "первая реплика" "Ответ 1/3" "сделай" 0
budget "третья реплика" "Ответ 3/3" "ещё" 2
budget "пятая реплика" "Ответ 5: бюджет исчерпан" "ещё" 4
budget "маркер новой задачи" "Ответ 1/3" "Новая задача: другое" 4

(( fails == 0 )) || exit 1
echo "hooks: ok"
