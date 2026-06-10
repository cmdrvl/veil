# Veil Agent Playbook

Use these commands in order when approaching an unfamiliar Veil checkout:

1. `veil --robot-triage`
2. `veil capabilities --json`
3. `veil robot-docs guide`
4. `veil doctor health --json`
5. `veil operator --json` only after guard hooks are healthy

Bare `veil` is hook mode. It expects a Claude/Gemini/Copilot hook payload on stdin and is not a discovery command.

Composition rule:

- `dcg` blocks destructive shell commands.
- `veil` blocks raw local sensitive reads.
- Authorized spine tools perform metadata-safe local processing.
- `airlock` attests derived artifacts that later cross a model boundary.
