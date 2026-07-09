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
- Scores it against 16 MCP rules (`pack-mcp-core`) across five weighted dimensions — tool-description
  injection, credential handling & exfiltration, network egress / SSRF, permission scope vs declared
  function, and supply-chain provenance — mapped to CWE, OWASP MCP Top 10, MAESTRO, and ETDI. See
  [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full ruleset, scoring, grade caps, and coverage gate.
- Applies **deterministic context modifiers** (e.g. a stdio, read-only, keyless server is not
  scored as if it were internet-exposed) and records each one, so the grade is both nuanced and
  reproducible.
- Emits a `scores.json` (0–100 → A–F, grade caps, per-finding evidence) that drives the public
  registry and its embeddable badges.

## Layout
```
crates/pack-mcp-core   # rules + context modifiers + scoring + scores.json
crates/mcp-parser      # MCP repo -> FactModel: structural facts + same-file source-flow taint
```

## Build / test
```
cargo test          # fetches the pinned Sentinel engine (git dep) and runs the rule + parser suites
```
The Sentinel engine is a **pinned git dependency** on `anwen-labs/sentinel`, so a clean checkout
reproduces byte-for-byte. Open rules + pinned commits + per-finding evidence are the point: you can
re-run any published score and get the same grade.

## Findings
A first scorecard of the top MCP servers (ranked by install/download proxy) is published in
[`FINDINGS.md`](FINDINGS.md), with the machine-readable data under [`results/`](results/):
- [`results/registry.json`](results/registry.json) — graded servers plus the ones we **withhold**,
  each with a specific reason (we don't publish a grade we can't back with evidence).
- [`results/scores.json`](results/scores.json) — raw per-server output at pinned commits, with
  per-finding `file:line` evidence — the reproducibility anchor.

Of the top 35, 26 could be statically graded (25 A, 1 B); the rest are withheld with a reason. The
single B is `microsoft/markitdown`, whose `convert_to_markdown(uri)` fetches an arbitrary URI in
process — the SSRF that was publicly disclosed against it — flagged deterministically at a named line.

## How to read a score
Each server in [`results/scores.json`](results/scores.json) is one object. Here is the real
(trimmed, annotated) entry for `microsoft/markitdown`:

```jsonc
{
  "server": "microsoft/markitdown",
  "commit": "e144e0a...",                      // the exact commit scored — the determinism anchor
  "status": "scored",                          // "scored" | "insufficient_coverage" (withheld)
  "grade": "B",                                // A–F, the headline
  "composite": 94,                             // 0–100 weighted average across the five dimensions
  "grade_caps_applied": ["high-unresolved:cap-B"],  // why the letter can sit below the band
  "context_modifiers": [],                     // deterministic severity downgrades for reachability
  "dimensions": [
    { "id": "network-egress-ssrf", "weight": 20, "sub_score": 75, "findings": [
        { "rule": "MCP-SSRF-USER-CONTROLLED-URL", "severity": "High",
          "evidence": { "file": "packages/markitdown-mcp/src/markitdown_mcp/__main__.py", "line": 21 } } ] },
    { "id": "supply-chain-provenance", "weight": 15, "sub_score": 90, "findings": [
        { "rule": "MCP-DEPS-UNPINNED", "severity": "Medium",
          "evidence": { "file": "packages/markitdown-mcp/pyproject.toml", "line": 26 } } ] }
    // the other three dimensions scored 100 with no findings
  ]
}
```

- **Grade (A–F) is the headline;** `composite` is the 0–100 weighted average across the five
  [dimensions](docs/METHODOLOGY.md). Bands: 90–100 **A**, 80–89 **B**, 70–79 **C**, 60–69 **D**, 0–59 **F**.
- **Grade caps can pull the letter below the band.** markitdown computes to 94 (an A band) but carries
  a **High** finding, and any unresolved High caps the grade at **B** — a "Grade A" listed next to a
  High finding would be incoherent. (A Critical caps at F; an unmitigated shell-exec surface at D.)
- **Every finding cites `file:line`.** Here `convert_to_markdown(uri)` fetches an arbitrary URI in
  process (SSRF) at `__main__.py:21` — open the file at that commit and you see exactly what the
  scanner saw. *Provable, not promised.*
- **`context_modifiers`** lists each deterministic severity downgrade — e.g. a stdio (local) server's
  network findings are downgraded because there is no remote attacker — so the grade is nuanced yet
  reproducible.
- **`status: "insufficient_coverage"`** means the tool surface could not be analyzed at that commit,
  so the grade is **withheld** rather than defaulted to A. It is "not yet gradeable," not a failing
  grade — see the withheld list in [`FINDINGS.md`](FINDINGS.md) for why.
- **Reproduce it:** clone the repo at `commit`, run the scanner, and you get the same grade and the
  same evidence pointers.

## Status
v0.1. Structural scoring **and** the source-flow taint pass run end-to-end today: SSRF (including
wrapped local fetches), shell-exec, filesystem-traversal, and credential-exfiltration, with per-tool
scoping and URL/path validation guards. Taint is same-file; cross-file / inter-procedural analysis,
Go tool-level taint, and class/registry tool shapes are on the roadmap (see the withheld list in
`FINDINGS.md` for exactly what isn't yet covered).

## Contributing & security
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — how a repo becomes a grade (rules, scoring, caps, coverage).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — report an inaccurate finding, request a scan, or propose a rule.
- [`SECURITY.md`](SECURITY.md) — how to report an issue in the scanner, and our disclosure policy for
  findings about other projects (including maintainers' right of reply).

## License
MIT — see [`LICENSE`](LICENSE).

