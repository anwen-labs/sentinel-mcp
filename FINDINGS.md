# Sentinel MCP Scorecard - Findings (v0.1)

An open, reproducible security scorecard for the most-installed Model Context
Protocol (MCP) servers. Every grade is a deterministic function of public code at a
pinned commit; anyone can re-run the open ruleset and get the same result.

Published by Anwen Labs as security research. Grades measure observable attack
surface and provenance hygiene - not maintainer trustworthiness. Nothing here is an
accusation of intent.

## Summary

We scanned the top 35 MCP servers by install/download proxy. Of them,
**26 could be statically graded at their pinned commit: 25 scored A and 1 scored B**
(composite 94-100). The remaining 9 are withheld, each with a specific reason (below) -
we do not publish a grade we cannot back with evidence.

The single B is instructive. `microsoft/markitdown`'s `convert_to_markdown(uri)` tool
fetches an arbitrary user-supplied URI in-process with no allowlist - the same SSRF that
was publicly disclosed against it. Our open ruleset flags it deterministically, with a
`file:line` pointer, and the High finding caps the grade at B. That is the point: an
honest scorecard reproduces real issues AND declines to inflate the rest.

The headline: contrary to alarmist framing that flags every popular MCP project as
critical, the servers people actually install are, by and large, carefully built - and
the exceptions are specific and evidenced, not hand-waved. Telling the difference,
reproducibly, is the whole value.

## Method

- **Open ruleset.** Every finding cites a named rule (`MCP-*`) mapped to CWE / OWASP
  MCP Top 10 / MAESTRO. No black-box scoring.
- **Deterministic + pinned.** Scoring is a pure function of (repo tree @ commit,
  ruleset version). Re-running the same commit reproduces the same grade and the same
  per-finding `file:line` evidence.
- **Precision over recall.** Conservative detection with per-finding evidence, tuned
  to avoid the ~78% false-positive rates documented for pattern/YARA scanners. We
  would rather miss a finding than publish a false one.
- **Coverage gate.** If a server's tool surface cannot be analyzed at the pinned
  commit, we withhold the grade rather than defaulting it to A.
- **Context-aware.** A stdio/local tool is not scored as an internet-exposed one;
  transport and reachability modify severity deterministically.

## Results

25 servers scored A; 1 scored B (a High SSRF finding caps the grade). Full list:

| Server | Grade | Composite |
|---|---|---|
| qdrant/mcp-server-qdrant | A | 100 |
| modelcontextprotocol/servers-archived | A | 100 |
| mendableai/firecrawl-mcp-server | A | 100 |
| GLips/Figma-Context-MCP | A | 100 |
| tavily-ai/tavily-mcp | A | 100 |
| stripe/agent-toolkit | A | 100 |
| e2b-dev/mcp-server | A | 100 |
| cloudflare/mcp-server-cloudflare | A | 100 |
| mongodb-js/mongodb-mcp-server | A | 99 |
| Flux159/mcp-server-kubernetes | A | 99 |
| redis/mcp-redis | A | 99 |
| upstash/context7 | A | 98 |
| modelcontextprotocol/servers | A | 98 |
| getsentry/sentry-mcp | A | 98 |
| supabase-community/supabase-mcp | A | 98 |
| block/goose | A | 98 |
| exa-labs/exa-mcp-server | A | 98 |
| pydantic/pydantic-ai | A | 98 |
| apify/actors-mcp-server | A | 98 |
| 21st-dev/magic-mcp | A | 98 |
| browserbase/mcp-server-browserbase | A | 98 |
| awslabs/mcp | A | 98 |
| ppl-ai/modelcontextprotocol | A | 97 |
| sooperset/mcp-atlassian | A | 96 |
| chroma-core/chroma-mcp | A | 94 |
| microsoft/markitdown | B | 94 |

## Ecosystem signals

Across the 26 graded servers, the observable (mostly low-severity, context-modified)
signals break down as:

| Signal | Share of graded servers |
|---|---|
| CORS allows any origin (wildcard) | 30% (8/26) |
| No committed dependency lockfile | 19% (5/26) |
| Binds all network interfaces (0.0.0.0) | 15% (4/26) |
| Binds all interfaces with no detected auth | 7% (2/26) |
| Disables TLS certificate verification | 3% (1/26) |
| Unbounded/unvalidated tool input | 3% (1/26) |
| SSRF (fetches a user-controlled URL, no allowlist) | 3% (1/26) |

No graded server had a Critical finding, and only 1 had a High (microsoft/markitdown). The rest are hygiene items (a wildcard CORS
default, a missing lockfile) rather than exploitable vulnerabilities.

## What we do not grade (and why)

Withholding is a feature, not a gap: we only grade what we can verify statically at
the pinned commit. These 7 are not scored:

| Server | Reason withheld |
|---|---|
| microsoft/playwright-mcp | tool implementation ships in the playwright-core dependency (repo index.js is a shim) - not present at the pinned commit |
| makenotion/notion-mcp-server | tools are generated at runtime from an OpenAPI spec, not defined in source |
| wonderwhy-er/DesktopCommanderMCP | high-privilege local agent (terminal command execution) - grading calibration in progress |
| github/github-mcp-server | Go tool-level source-flow analysis not yet supported (structural-only) - withheld to avoid an unearned grade |
| oraios/serena | high-privilege local coding agent (shell + filesystem tools) - grading calibration in progress |
| executeautomation/mcp-playwright | high-privilege local agent (drives a local browser to arbitrary URLs / runs page JS) - grading calibration in progress |
| googleapis/genai-toolbox | tools are defined in user-supplied YAML config, not in source |
| microsoft/mcp | no analyzable MCP tool source at the pinned commit (docs/CLI repo, no source in a supported language) |
| grafana/mcp-grafana | Go tool-level source-flow analysis not yet supported (structural-only) - withheld to avoid an unearned grade |

## Reproduce it

The scanner and ruleset are open. Each server's grade pins the exact commit it was
computed from (see `registry.json`). Clone the target at that commit, run the scanner,
and you will get the same grade and the same evidence pointers.

## Scope and limitations

- We score the **repository at a pinned commit**, not a live endpoint. Runtime
  deployment properties (e.g. whether a given instance is exposed unauthenticated) are
  out of scope here.
- Denial-of-service and SQL-injection are covered coarsely/syntactically in v0.1.
- Source-flow taint is same-file in v0.1; cross-file / inter-procedural analysis and a
  path-jail guard are planned. Go tool-level taint and servers whose tools are
  generated at runtime (OpenAPI/YAML) or shipped in a dependency are withheld until
  supported - see the withheld list above.

Ruleset: pack-mcp-core@0.1.0.
