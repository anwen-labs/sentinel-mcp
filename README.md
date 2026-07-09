# sentinel-mcp

Open, reproducible security scoring for **Model Context Protocol (MCP) servers** — the engine
behind the Sentinel MCP Scorecard. Every score is a deterministic function of a repo at a pinned
commit, and every finding points at a specific line of code. *Provable, not promised.*

This is a **separate** tool from [`anwen-labs/sentinel`](https://github.com/anwen-labs/sentinel)
(the configuration-misconfiguration scanner). It **reuses** that engine — the fact-graph, findings,
and content-addressed report digest — and adds MCP-specific rules on top. It is source analysis of
MCP servers, a different job from config scanning, so it lives in its own repo.

## What it does
- Parses an MCP server repo into a normalized fact model (`mcp-parser`): transport, dependency
  pinning + lockfiles, tool inventory, and (via the source-flow pass) the taint facts.
- Scores it against 13+ MCP rules (`pack-mcp-core`) across five weighted dimensions — tool-description
  injection, credential handling & exfiltration, network egress / SSRF, permission scope vs declared
  function, and supply-chain provenance — mapped to CWE, OWASP MCP Top 10, MAESTRO, and ETDI.
- Applies **deterministic context modifiers** (e.g. a stdio, read-only, keyless server is not
  scored as if it were internet-exposed) and records each one, so the grade is both nuanced and
  reproducible.
- Emits a `scores.json` (0–100 → A–F, grade caps, per-finding evidence) that drives the public
  registry and its embeddable badges.

## Layout
```
crates/pack-mcp-core   # rules + context modifiers + scoring + scores.json
crates/mcp-parser      # MCP repo -> FactModel (structural pass done; source-flow AST pass in progress)
```

## Build / test
```
cargo test          # fetches the pinned Sentinel engine (git dep) and runs the rule + parser suites
```
The Sentinel engine is a **pinned git dependency** on `anwen-labs/sentinel`, so a clean checkout
reproduces byte-for-byte. Open rules + pinned commits + per-finding evidence are the point: you can
re-run any published score and get the same grade.

## Status
Scaffold. Structural scoring (provenance / transport / dependency pinning) runs end-to-end today;
the source-flow AST pass (SSRF / shell-exec / credential-exfiltration taint) is in progress.

## License
MIT.
