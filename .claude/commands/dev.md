# /dev — Toolchain Status & Override

Shows the status of all three integrated tools, or forces a specific mode.

## When invoked with no args

Report current state:
- **Graphify**: check if graphify-out/graph.json exists. Show last modified time. Run `graphify query "project summary"` for a quick health check.
- **Ponytail**: report current mode (lite/full/ultra/off).
- **Agent-skills**: list available skills relevant to what's been discussed.
- **Graph freshness**: compare graph.json mtime against latest git commit — warn if stale.

## When invoked with args

- `/dev status` — same as no args
- `/dev rebuild` — run `graphify update .` to refresh the knowledge graph
- `/dev ponytail <lite|full|ultra|off>` — switch ponytail intensity
- `/dev graph <question>` — shortcut for `graphify query "<question>"`

## Notes

The auto-routing in CLAUDE.md handles tool selection for all normal tasks. This command is for checking status or manual overrides only.
