# Veil Agent Ergonomics Scorecard, Pass 1

Scope: standard agent-facing discovery surfaces and hook-mode recovery behavior.

## Summary

- Surfaces inventoried: 57
- Surfaces scored: 5
- Recommendations applied: 5 of 5
- Regressions detected: 0
- Intent corpus result after changes: 0 silent failures, 0 useless errors, 97 useful hints, 3 inferred-and-acted cases

## Highest-Impact Changes

1. `veil --robot-triage` now works as the top-level read-only triage command.
2. `veil capabilities --json` exposes a full command contract, including guard preflight and mutability.
3. `veil robot-docs guide` explains hook mode and composition with dcg, authorized spine tools, and airlock.
4. Empty stdin in hook mode now explains recovery commands instead of surfacing raw JSON EOF.
5. `veil --help` and README now advertise the standard agent surfaces.

## Residual Risk

The pass did not redesign `install` or `uninstall`; those remain explicit mutating maintenance commands. Domain commands still intentionally fail closed when guard hooks are unhealthy.
