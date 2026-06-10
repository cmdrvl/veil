# Ambition Bar Check

Pass 1 meets the ambition bar for this release because it converts the missing standard agent surfaces into tested, documented, release-smoked commands.

The pass deliberately avoided broader behavior changes:

- Hook-mode allow/deny logic is unchanged.
- Guard preflight still fails closed for domain commands when hooks are unhealthy.
- Mutating maintenance commands remain explicit.

The next pass should evaluate whether `veil install` needs a dry-run or plan mode, but that is outside this release scope.
