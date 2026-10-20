#!/usr/bin/env bash
# Stop: ответ кончается вердиктом (AGENTS.md) — строкой «ИТОГ: OK | OK С ОГОВОРКАМИ | НУЖНЫ ДАННЫЕ |
# ПРОБЛЕМА» или, при PR, отчётом с последней строкой «merge_ready: YES | NO | UNKNOWN». Отчёт
# проверяется всегда: поля на месте, значения из списка, YES не противоречит полям. С третьего
# ответа ПРОБЛЕМА, НУЖНЫ ДАННЫЕ, merge_ready NO или UNKNOWN требуют в тексте «sudo xm journal add»
# (task-completion). Нарушение — decision: block, агент дописывает.
# stop_hook_active — остановка после такого возврата: пропускаем, цикла нет.
# Нет jq или поля last_assistant_message — молча пропускает, как read-guard.
MIN_CHARS=200  # короче — простой вопрос: одна-две фразы без вердикта (AGENTS.md)
command -v jq >/dev/null 2>&1 || exit 0
source "${BASH_SOURCE[0]%/*}/answer-count.sh"
input=$(cat)
[[ $(jq -r '.stop_hook_active // false' <<<"$input" 2>/dev/null) == true ]] && exit 0
msg=$(jq -r '.last_assistant_message // empty' <<<"$input" 2>/dev/null)

block() {
  jq -n --arg r "$1" '{decision: "block", reason: $r}'
  exit 0
}

# Значение поля отчёта: последнее «поле: ЗНАЧЕНИЕ» в начале строки, без причины после « — »
field() {
  grep -E "^[*_\` ]*$1:" <<<"$msg" | tail -n 1 | sed -E "s/^[*_\` ]*$1:[*_\`[:space:]]*//; s/[[:space:]]*(—|-|\().*//; s/[*_\` ]+$//"
}

last=$(grep -v -e '^[[:space:]]*$' -e '^[[:space:]]*```' <<<"$msg" | tail -n 1)
verdict_re='^[*_` ]*ИТОГ: (OK С ОГОВОРКАМИ|OK|НУЖНЫ ДАННЫЕ|ПРОБЛЕМА)'
report_re='^[*_` ]*merge_ready:[*_` ]*(YES|NO|UNKNOWN)'
fmt='code_pr: PASS|FAIL|NOT_RUN, checks: PASS|FAIL|NOT_RUN, integration: PASS|FAIL|NOT_REQUIRED|NOT_RUN|BLOCKED, merge_ready: YES|NO|UNKNOWN'

if [[ $last =~ $report_re ]]; then
  verdict=${BASH_REMATCH[1]}
  code=$(field code_pr) checks=$(field checks) integ=$(field integration)
  [[ $code =~ ^(PASS|FAIL|NOT_RUN)$ && $checks =~ ^(PASS|FAIL|NOT_RUN)$ \
     && $integ =~ ^(PASS|FAIL|NOT_REQUIRED|NOT_RUN|BLOCKED)$ ]] \
    || block "Отчёт неполон или с чужими значениями (code_pr=«$code», checks=«$checks», integration=«$integ»). Формат: $fmt — по строке, merge_ready последней (AGENTS.md)."
  if [[ $verdict == YES ]]; then
    why=""
    [[ $code == PASS ]] || why+=" code_pr=$code;"
    [[ $checks == PASS ]] || why+=" checks=$checks;"
    [[ $integ == PASS || $integ == NOT_REQUIRED ]] || why+=" integration=$integ;"
    diffs=$(field differences)
    [[ -z $diffs || $diffs == 0 ]] || why+=" differences=$diffs;"
    while read -r e a; do
      [[ $e == "$a" ]] || why+=" expected=$e ≠ actual=$a;"
    done < <(grep -oE 'expected=[0-9]+, actual=[0-9]+' <<<"$msg" | sed -E 's/expected=([0-9]+), actual=([0-9]+)/\1 \2/')
    [[ -z $why ]] || block "merge_ready: YES противоречит отчёту:$why YES — только когда code_pr и checks PASS, integration PASS или NOT_REQUIRED, расхождений нет; иначе NO или UNKNOWN с причиной (AGENTS.md)."
  fi
  case $verdict in NO) verdict="ПРОБЛЕМА" ;; UNKNOWN) verdict="НУЖНЫ ДАННЫЕ" ;; esac
else
  (( ${#msg} >= MIN_CHARS )) || exit 0
  [[ $last =~ $verdict_re ]] \
    || block "Ответ не кончается вердиктом. Ответь одной строкой: «ИТОГ: OK», «ИТОГ: OK С ОГОВОРКАМИ», «ИТОГ: НУЖНЫ ДАННЫЕ» или «ИТОГ: ПРОБЛЕМА» и краткое обоснование; при PR — отчётом с merge_ready последней строкой (AGENTS.md)."
  verdict=${BASH_REMATCH[1]}
fi

case $verdict in
  "НУЖНЫ ДАННЫЕ" | "ПРОБЛЕМА")
    n=$(answer_count "$(jq -r '.transcript_path // empty' <<<"$input" 2>/dev/null)")
    if (( n >= 3 )) && ! grep -qE 'sudo[[:space:]]+xm[[:space:]]+journal[[:space:]]+add' <<<"$msg"; then
      block "Ответ $n с вердиктом «$verdict» (или merge_ready NO / UNKNOWN) без «sudo xm journal add». Дай готовую команду по .claude/skills/task-completion/references/journal-template.md и снова кончи ответ вердиктом."
    fi ;;
esac
exit 0
