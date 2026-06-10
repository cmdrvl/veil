# Uplift Diff

This was the first recorded pass, so there is no previous scorecard baseline in the audit workspace.

Observed uplift from pre-pass runtime checks:

- `veil --robot-triage`: unrecognized argument to successful JSON triage.
- `veil capabilities --json`: unrecognized subcommand to successful JSON contract.
- `veil robot-docs guide`: unrecognized subcommand to successful operational guide.
- Empty stdin to `veil`: raw JSON EOF to actionable hook-mode diagnostic.

Median estimated uplift across the five scored surfaces: 300 points.
