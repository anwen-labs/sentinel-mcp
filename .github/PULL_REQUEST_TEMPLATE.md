<!-- Thanks for contributing. See CONTRIBUTING.md. -->

## What and why

<!-- What does this change and why? Link any issue. -->

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets` is clean
- [ ] Scoring stays deterministic (no wall-clock / network reads inside scoring)
- [ ] New/changed rule has a **validation guard** for its most likely false positive
- [ ] Added a regression test for both a true case and a false case
- [ ] Every new finding carries a `file:line` (or artifact) evidence pointer
- [ ] Rule mapped to CWE / OWASP MCP Top 10 / MAESTRO where applicable
