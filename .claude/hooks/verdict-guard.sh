#!/usr/bin/env bash
# Stop: ответ кончается вердиктом «ИТОГ: OK | OK С ОГОВОРКАМИ | НУЖНЫ ДАННЫЕ | ПРОБЛЕМА»
# (AGENTS.md); с третьего ответа вердикт ПРОБЛЕМА или НУЖНЫ ДАННЫЕ требует в тексте
# «sudo xm journal add» (task-completion). Нарушение — decision: block, агент дописывает.
# stop_hook_active — остановка после такого возврата: пропускаем, цикла нет.
# Нет jq или поля last_assistant_message — молча пропускает, как read-guard.
MIN_CHARS=200  # короче — простой вопрос: одна-две фразы без вердикта (AGENTS.md)
command -v jq >/dev/null 2>&1 || exit 0
source "${BASH_SOURCE[0]%/*}/answer-count.sh"
input=$(cat)
[[ $(jq -r '.stop_hook_active // false' <<<"$input" 2>/dev/null) == true ]] && exit 0
msg=$(jq -r '.last_assistant_message // empty' <<<"$input" 2>/dev/null)
(( ${#msg} >= MIN_CHARS )) || exit 0

block() {
  jq -n --arg r "$1" '{decision: "block", reason: $r}'
  exit 0
}

last=$(grep -v '^[[:space:]]*$' <<<"$msg" | tail -n 1)
verdict_re='^[*_` ]*ИТОГ: (OK С ОГОВОРКАМИ|OK|НУЖНЫ ДАННЫЕ|ПРОБЛЕМА)'
if ! [[ $last =~ $verdict_re ]]; then
  block "Ответ не кончается вердиктом. Ответь одной строкой: «ИТОГ: OK», «ИТОГ: OK С ОГОВОРКАМИ», «ИТОГ: НУЖНЫ ДАННЫЕ» или «ИТОГ: ПРОБЛЕМА» и краткое обоснование (AGENTS.md)."
fi

verdict=${BASH_REMATCH[1]}
case $verdict in
  "НУЖНЫ ДАННЫЕ" | "ПРОБЛЕМА")
    n=$(answer_count "$(jq -r '.transcript_path // empty' <<<"$input" 2>/dev/null)")
    if (( n >= 3 )) && ! grep -qE 'sudo[[:space:]]+xm[[:space:]]+journal[[:space:]]+add' <<<"$msg"; then
      block "Ответ $n с вердиктом $verdict без «sudo xm journal add». Дай готовую команду по .claude/skills/task-completion/references/journal-template.md и снова кончи ответ строкой «ИТОГ: …»."
    fi ;;
esac
exit 0
