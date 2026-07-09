# Methodology

How the Sentinel MCP Scorecard turns a repository into a grade. The whole point is
that this is **open and reproducible**: the ruleset is public, every score pins the
commit it was computed from, and every finding points at a line of code.

## Pipeline

1. Clone the target repo at a pinned commit (recorded in the output - the determinism
   anchor).
2. Parse it into a normalized fact model (`mcp-parser`): transport, dependency pinning
   and lockfiles, tool inventory, and same-file source-flow taint facts.
3. Evaluate the `pack-mcp-core` rules over the facts. Each finding carries a `file:line`
   (or artifact) evidence pointer.
4. Apply deterministic **context modifiers** (below), then score each of the five
   dimensions, combine, and apply **grade caps**.

Scoring is a pure function of `(repo tree @ commit, ruleset_version)`. No wall-clock,
no network reads inside scoring - two runs of the same commit produce the same grade
and the same evidence.

## Dimensions and weights

| Dimension | Weight | What it measures |
|---|---|---|
| D1 - Tool-description injection | 20 | Hostile/hidden instructions in tool descriptions ("tool poisoning") reaching model context |
| D2 - Credential & secret handling | 20 | How secrets are stored, forwarded, exfiltrated, or logged |
| D3 - Network egress / SSRF | 20 | Outbound reach; user-controlled URLs; TLS verification |
| D4 - Permission scope vs declared | 25 | Filesystem/shell/SQL surface, input validation, network exposure vs the server's declared job |
| D5 - Supply-chain provenance | 15 | Lockfiles, dependency pinning, release provenance |

Weights are grounded in 2025-26 prevalence data: classic AppSec bugs (arbitrary file
access, command injection, SSRF) are an order of magnitude more common in MCP servers
than tool poisoning, which is why D4 carries the most weight.

## Rules

16 rules ship in `pack-mcp-core@0.1.0`, each mapped to CWE / OWASP MCP Top 10 / MAESTRO.

**D1 - Tool-description injection**
- `MCP-TOOL-DESCRIPTION-INJECTION` (High) - instruction-like / hidden-unicode description reaching model context. CWE-74, CWE-116.
- `MCP-TOOL-SHADOWING` (Medium) - generic tool name that can shadow/spoof another server's tool. CWE-290, CWE-345.

**D2 - Credential & secret handling**
- `MCP-CREDENTIAL-EXFILTRATION` (Critical) - a secret source flows to a network egress sink to an undeclared/known-exfil host. CWE-200, CWE-522.
- `MCP-SECRET-IN-CONFIG` (High) - a real-looking key/token embedded in shipped config / README. CWE-798, CWE-312.

**D3 - Network egress / SSRF**
- `MCP-SSRF-USER-CONTROLLED-URL` (High) - an HTTP request (incl. wrapped local fetch helpers) targets a host derived from tool input with no allowlist. CWE-918.
- `MCP-TLS-VERIFICATION-DISABLED` (Medium) - code disables TLS certificate verification. CWE-295, CWE-319.

**D4 - Permission scope vs declared**
- `MCP-FILESYSTEM-UNSCOPED` (High) - tool-input paths reach a filesystem call with no jail root. CWE-22, CWE-59.
- `MCP-SHELL-EXEC-SURFACE` (High) - a process/shell is spawned with interpolated tool input. CWE-78, CWE-94.
- `MCP-SQL-INJECTION` (High) - tool input concatenated into a SQL query. CWE-89.
- `MCP-INSECURE-DESERIALIZATION` (High) - tool input deserialized unsafely (pickle / yaml.load / marshal). CWE-502.
- `MCP-INPUT-UNVALIDATED` (Medium) - unbounded numeric param or input treated as a regex (resource exhaustion / ReDoS). CWE-20, CWE-1284.
- `MCP-DOS-UNBOUNDED` (Low) - no timeout / size bound on a tool operation. CWE-400, CWE-770.
- `MCP-BIND-NO-AUTH` (High) - binds all interfaces (0.0.0.0) with no detected inbound auth. CWE-668, CWE-306.
- `MCP-BIND-ALL-INTERFACES` (Medium) - binds all interfaces. CWE-668.
- `MCP-CORS-WILDCARD` (Medium) - CORS allows any origin. CWE-942, CWE-346.

**D5 - Supply-chain provenance**
- `MCP-DEPS-UNPINNED` (Medium) - no committed lockfile, so installs are not reproducible. CWE-1104, CWE-829.

## Sub-scores, composite, grade

Each dimension starts at 100 and subtracts a penalty per unique `(rule, file, line)`:

| Severity | Penalty |
|---|---|
| Critical | -50 |
| High | -25 |
| Medium | -10 |
| Low | -4 |
| Informational | 0 |

A single rule contributes at most **2x** its per-finding penalty within a dimension
(anti-noise cap, so one chatty rule cannot dominate). The composite is the
weight-average over the dimensions that applied.

| Composite | Grade |
|---|---|
| 90-100 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 0-59 | F |

**Grade caps** (a single severe surface must not average away):

- Any **Critical** finding -> capped at **F**.
- Any unresolved **High** in D1 (injection) or D2 (credentials) -> capped at **C**.
- `MCP-SHELL-EXEC-SURFACE` present -> capped at **D**.
- Any unresolved **High** (after context modifiers) -> capped at **B**. A "Grade A"
  listed next to a High finding is incoherent, so a High always pulls a server out of
  the A band.

The letter is the lower of the band grade and any cap.

## Context modifiers

Severity is adjusted deterministically for reachability, so a local tool is not scored
as if it were internet-exposed - and each adjustment is recorded:

- **stdio transport** downgrades the network-family rules (SSRF, bind, CORS, TLS): a
  stdio server has no remote attacker.
- **read-only tools** downgrade a filesystem-traversal finding from RCE-class to
  information-disclosure.

## Validation guards (precision)

To avoid flagging a server for doing its declared job, a finding is suppressed when the
tool's own body shows it validates the input:

- A **URL allowlist / private-IP block / URL validation** suppresses SSRF.
- A **path jail** (resolve-under-root, reject `..`, `validate_relative_path`,
  `is_relative_to`) suppresses filesystem-traversal.

Taint is scoped to each tool's own function body, so a multi-tool file does not
cross-contaminate (a sink in one tool does not taint another that merely shares a
parameter name).

## Coverage gate - what we do NOT grade

If we cannot analyze a server's tool surface at the pinned commit, we **withhold** the
grade rather than defaulting it to A. A repo with zero resolvable tools is marked
`insufficient_coverage`. Reasons we withhold in practice (see [`FINDINGS.md`](../FINDINGS.md)):

- Tools generated at runtime (from an OpenAPI spec or YAML config) or shipped in a
  dependency rather than the repo.
- Languages / registration shapes the parser does not yet cover (e.g. Go tool-level
  taint, some class/registry tool shapes).
- High-privilege local agents (shell / filesystem / browser) whose grading is still
  being calibrated.

## Evidence gate

No dimension emits a score without either a finding (each carrying `file:line` or
`{artifact, locator}`) or a coverage artifact proving the checks ran. A clean dimension
therefore still has an evidence pointer, never a silent default.

## Scope and limitations (v0.1)

- We score the **repository at a commit**, not a live endpoint. Runtime deployment
  properties are out of scope.
- Source-flow taint is **same-file**; cross-file / inter-procedural analysis is planned.
- DoS and SQL injection are covered coarsely / syntactically.
