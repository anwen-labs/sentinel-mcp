# Contributing

Thanks for helping improve the Sentinel MCP Scorecard. This is security research
tooling, so correctness and reproducibility matter more than speed of change.

## Ways to contribute

- **Report an inaccurate finding.** A false positive or a missed issue on a scored
  server is the most valuable feedback we can get. Open an issue with the server,
  the rule, and the `file:line` in question. Because scoring is deterministic and
  pins a commit, we can reproduce and show the exact diff.
- **Request a server be scored.** Open an issue with the repository and an
  install/download signal.
- **Propose or refine a rule.** See the [methodology](docs/METHODOLOGY.md) for the
  five dimensions and the rule catalog.

## Ground rules for code changes

- **Deterministic.** Scoring is a pure function of `(repo tree @ commit,
  ruleset_version)`. No wall-clock, no network reads inside scoring. Two runs of the
  same commit must produce the same grade and the same evidence.
- **Precision over recall.** A new rule should come with a validation guard for its
  most likely false positive, and a test for both a true and a false case. We would
  rather miss a finding than ship one that flags a server for doing its declared job
  (e.g. a shell tool being a shell, a validated path, a SaaS client forwarding a URL
  to its own API).
- **Evidence-gated.** Every finding must carry a `file:line` (or artifact) pointer.
  No score is emitted for a dimension without either a finding or a coverage artifact.
- **Tests + lint.** `cargo test` and `cargo clippy` must pass. Add a regression test
  for any FP/FN you fix.

## Build and test

```
cargo test          # fetches the pinned Sentinel engine (git dep) and runs the suites
cargo clippy --all-targets
```

The Sentinel engine is a pinned git dependency, so a clean checkout reproduces
byte-for-byte.

## Style

Match the surrounding code. Rust is formatted with `cargo fmt`. Keep rule IDs in the
`MCP-<AREA>-<NAME>` form and map each to CWE / OWASP MCP Top 10 / MAESTRO where it fits.
