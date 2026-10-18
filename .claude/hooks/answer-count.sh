# Общее для answer-budget.sh и verdict-guard.sh (подключается через source, не запускается).
# Номер ответа считается по транскрипту сессии: он пишется целиком и сжатие контекста его не
# трогает, поэтому счёт переживает /compact. Ответ = реплика владельца; не считаются
# tool_result, служебные записи (isMeta, в т.ч. «Stop hook feedback»), сводка сжатия, локальные
# команды вроде /compact и прерывания. Реплика, начинающаяся со слов «Новая задача», открывает
# новую задачу — счёт идёт с неё заново.
MARKER_RE='^\s*новая задача\b'

JQ_DEFS='
def text: (.message.content // "") | if type == "string" then . else map(select(.type == "text") | .text) | join("\n") end;
def human: .type == "user" and (.isMeta | not) and (.isSidechain | not) and (.isCompactSummary | not)
  and ((.message.content // "") | type == "string" or all(.[]; .type != "tool_result"))
  and (text | test("^\\s*(<command-name>|<local-command-|<task-notification|\\[Request interrupted)") | not);
def marker: test($re; "i");
'

# is_marker TEXT — реплика открывает новую задачу
is_marker() {
  jq -e -R --arg re "$MARKER_RE" 'test($re; "i")' <<<"$1" >/dev/null 2>&1
}

# answer_count TRANSCRIPT [PROMPT_ID] — число реплик владельца с последнего маркера, кроме реплики
# PROMPT_ID: UserPromptSubmit срабатывает до записи текущей реплики в транскрипт, Stop — после.
answer_count() {
  [[ -r $1 ]] || { echo 0; return; }
  grep -F '"type":"user"' "$1" | jq -nR --arg skip "${2:-}" --arg re "$MARKER_RE" "$JQ_DEFS"'
    reduce (inputs | fromjson? | select(human and ($skip == "" or (.promptId // "") != $skip))) as $m
      (0; if ($m | text | marker) then 1 else . + 1 end)' 2>/dev/null || echo 0
}
