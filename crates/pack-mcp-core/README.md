# pack-mcp-core

Deterministic MCP-server security rules — the scoring engine behind the **Sentinel MCP Scorecard**
registry (rubric v1.1, approved 2026-07-08). Pure functions of a `FactModel`, same shape as
`pack-gha-core` et al.

**Home:** `anwen-labs/sentinel-mcp` — a **separate** repo from `anwen-labs/sentinel` (the
config-misconfiguration scanner). It *reuses* the Sentinel engine (`fact-model` + `engine` crates)
but is a distinct product: source analysis of MCP servers, feeding the public registry — not part of
the `sentinel` CLI or its release binary.

## Status: scaffold (B1 start)

**Done (this crate):**
- 13 rules across the 5 rubric dimensions, each in the pack + catalog with framework mappings
  (CWE + OWASP-MCP-Top-10 + MAESTRO + ETDI) — see `catalog()` in `src/lib.rs`.
- **Context modifiers** (`src/context.rs`) — deterministic exploitability downgrades that match
  BlueRock's nuance *and* stay reproducible (stdio → no remote attacker; read-only → no write path;
  keyless → no secret to leak). Every applied modifier is recorded for the audit trail.
- **Scoring** (`src/score.rs`) — sub-scores → weighted composite → A–F, grade caps, and the
  `scores.json` shape from rubric §6 (with `context_modifiers[]`).
- Full-pipeline tests with fixtures: a stdio/read-only/keyless server (→ A/B, like the real
  `il-eli-mcp` BlueRock rated LOW), an HTTP shell+SSRF server (→ capped D), a credential-exfil
  server (→ F), a stdio-downgrade case, and a determinism check.

**TODO (the remaining B1 work): `mcp-parser`.** These rules consume a `FactModel`; the parser that
produces it is not built yet. Split:
- **Structural facts — cheap, no AST:** `transport` (`server.json`), lockfile presence + pin status
  (`package.json`/`pyproject.toml`/`go.mod`), tool count/names/annotations, GH-Actions pinning.
- **Source-flow facts — need JS/TS + Python AST (tree-sitter):** the `*_from_input` taint flags,
  `secret_source_to_egress`, `insecure_deser`. This is the hard slice (see
  `lane1/b1-build-sheet.md` §"Coverage vs BlueRock" and §"Context modifiers").

The fact contract (attribute names the parser must set) is documented at the top of `src/lib.rs`.

## Design choices
- MCP entities are modeled as `EntityKind::Resource` + an `mcp_kind` attribute, so this crate
  compiles against the **unmodified** engine/fact-model. Production nicety: add dedicated
  `EntityKind::McpServer/McpTool/McpDependency` variants (a small `fact-model` diff).
- Rules never assume a fact is safe when absent (Sentinel's `Unknown`-is-load-bearing rule).

## Verify (needs the Rust toolchain — CI or a dev box; not installed on the author's machine)
```
cargo test -p pack-mcp-core        # runs the fixture pipeline + determinism test
cargo build -p pack-mcp-core
```
If `cargo fmt`/`clippy -D warnings` gate in CI, run those too — the crate is written to pass a
warnings-clean build (all items reachable via pub API or tests).

## Entry point (next, in this repo — NOT in the `sentinel` CLI)
`sentinel-mcp` gets its own thin harness/CLI that: walks a repo (`mcp-parser::read_repo`) →
`mcp-parser::parse_repo` → `run_pack(&McpCorePack, &model)` → context modifiers → `score` →
`scores.json` per server. The batch runner over the 50 `targets.csv` servers (pinned commits)
produces the registry's `scores.json`. The `sentinel` config scanner is untouched — MCP never
ships in its binary or `RULES.md`.
