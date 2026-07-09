# Security Policy

## Reporting a vulnerability in this scanner

If you find a security issue in `sentinel-mcp` itself (the scanner, its rules, or
its published data), please report it privately rather than opening a public issue:

- Use GitHub's **private vulnerability reporting** on this repository
  (the "Report a vulnerability" button under the *Security* tab).

We aim to acknowledge a report within a few business days and to fix confirmed
issues promptly. We are happy to credit reporters who want it.

## How we handle findings about other projects

This project publishes a security scorecard of third-party MCP servers. We hold
ourselves to the same disclosure standards we would want applied to us.

- **We score public code at a pinned commit.** Every grade is a deterministic
  function of a public repository at a specific commit, recorded in the output.
  Findings cite public code and a named rule (`MCP-*`); nothing here is an
  accusation of intent or a claim about a maintainer.
- **We measure observable attack surface and provenance hygiene** - not
  trustworthiness. A grade is not a statement that a server is "safe" or "unsafe".
- **Precision over recall.** Detection is conservative and every finding carries a
  `file:line` (or artifact) evidence pointer. We would rather withhold a grade than
  publish one we cannot back with evidence (see the "withheld" list in
  [`FINDINGS.md`](FINDINGS.md)).
- **High-stakes findings on a named project** (e.g. a potential credential-exfil
  flow) are manually confirmed before any per-server page is published, and are
  described as an observed *code flow* with evidence - never with loaded language.
- **Right of reply / re-scan.** If you maintain a scored server and believe a
  finding is a false positive, is fixed at a later commit, or is missing context,
  open an issue (use the *Report an inaccurate finding* template). Because scoring
  is deterministic and pins a commit, we can re-run and show the exact diff. We
  will correct or withhold anything we cannot stand behind.

## Scope notes

- We score the **repository at a commit**, not a live endpoint. Runtime deployment
  properties (e.g. whether a given instance is exposed unauthenticated) are out of
  scope.
- Source-flow analysis is best-effort and evolving; the methodology page documents
  what is and is not yet covered.
