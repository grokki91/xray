#!/usr/bin/env bash
# UserPromptSubmit: подсказка агенту, какой это ответ по бюджету task-completion — 1/3, 2/3,
# 3/3 (финальный), с 4-го бюджет исчерпан. Счёт — по транскрипту (answer-count.sh); сбросить
# его для новой задачи — начать реплику со слов «Новая задача».
# Нет jq — хук молча пропускает: сломанный хук не должен блокировать работу.
command -v jq >/dev/null 2>&1 || exit 0
source "${BASH_SOURCE[0]%/*}/answer-count.sh"
input=$(cat)
prompt=$(jq -r '.prompt // empty' <<<"$input" 2>/dev/null)
transcript=$(jq -r '.transcript_path // empty' <<<"$input" 2>/dev/null)
prompt_id=$(jq -r '.prompt_id // empty' <<<"$input" 2>/dev/null)

if is_marker "$prompt"; then
  n=1
else
  n=$(( $(answer_count "$transcript" "$prompt_id") + 1 ))
fi

verdict='последняя строка — «ИТОГ: …», при PR — отчёт с merge_ready (AGENTS.md)'
case $n in
  1) hint="Ответ 1/3 (task-completion). Если это задача, а не простой вопрос: начни с «Готово, когда:» (1–3 проверяемых условия) и «Вне задачи:», затем полное решение; данные с VPS — одним пакетом команд; $verdict." ;;
  2) hint="Ответ 2/3 (task-completion): все недочёты разом, без раундов; проверь, что исправление не задело работавшее; $verdict." ;;
  3) hint="Ответ 3/3 — финальный (task-completion): цельное решение и команды проверки. Не решено — «ИТОГ: ПРОБЛЕМА» или «ИТОГ: НУЖНЫ ДАННЫЕ» (merge_ready: NO или UNKNOWN) и готовая «sudo xm journal add» по references/journal-template.md; $verdict." ;;
  *) hint="Ответ $n: бюджет исчерпан (task-completion). Новых проверок, команд сбора данных и доработок нет — только ответ по присланному: выполнены ли «Готово, когда». Нерешённое — «sudo xm journal add», новое — во «Вне задачи»; $verdict. Несвязанная задача — реплика, начатая словами «Новая задача»." ;;
esac

jq -n --arg c "$hint" '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $c}}'
