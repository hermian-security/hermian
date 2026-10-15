# False-positive log

One row per HIGH/CRITICAL that wasn't a real event, from the burn-in
([ROADMAP-BURN-IN.md](ROADMAP-BURN-IN.md#32-what-to-do-with-a-false-positive)).
Cause is one of: rule wrong, attribution failed, host-specific. Only
host-specific ones end with an allowlist entry; the others end with a fix and
a regression test.

| Date | Host | Ref | Rule | Cause | Fix | Closed |
|---|---|---|---|---|---|---|
