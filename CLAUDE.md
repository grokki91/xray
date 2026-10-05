@AGENTS.md

## Claude Code

- Скиллы `xray-dpi` и `task-completion` — в `.claude/skills/`. По задаче про Xray, DPI,
  сервер или клиентов вызывать `xray-dpi` до первого ответа, а не по ходу.
- `.claude/rules/*.md` подгружаются сами, когда читаешь или правишь файлы из их `paths`.
- Тело PR — без «Generated with Claude Code» и без ссылки на сессию: правило владельца
  (`publishing.md`) важнее умолчаний инструмента. В коммитах подпись (`Co-Authored-By`,
  `Claude-Session`) остаётся.
