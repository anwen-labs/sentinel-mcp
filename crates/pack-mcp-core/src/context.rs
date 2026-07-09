//! Context modifiers — match BlueRock's exploitability nuance *deterministically*.
//!
//! BlueRock rated a stdio, read-only, keyless server LOW despite HIGH findings by
//! discounting exploitability in LLM prose. We do the same, but as pure functions of
//! statically-derivable facts, and we RECORD every applied modifier so the downgrade is
//! auditable (their "mitigating factor" prose is not). See lane1/b1-build-sheet.md
//! "Context modifiers".

use engine::{Finding, Severity};
use fact_model::FactModel;

use crate::{server_entity, MCP_NETWORK_RULES};

/// One applied downgrade, surfaced in scores.json as `context_modifiers[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedModifier {
    pub modifier: String,
    pub rule_id: String,
    pub from: Severity,
    pub to: Severity,
}

fn down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

/// Deterministic exploitability context read off the server entity.
struct Ctx {
    stdio: bool,
    all_read_only: bool,
    keyless: bool,
}

fn ctx(m: &FactModel) -> Ctx {
    let s = server_entity(m);
    let transport = s
        .and_then(|e| e.attr("transport"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    Ctx {
        stdio: transport == "stdio",
        all_read_only: s
            .and_then(|e| e.attr("all_tools_read_only"))
            .and_then(|v| v.as_bool())
            == Some(true),
        keyless: s
            .and_then(|e| e.attr("keyless_public_only"))
            .and_then(|v| v.as_bool())
            == Some(true),
    }
}

/// Apply deterministic exploitability downgrades. Returns the modified findings and the
/// list of applied modifiers (for the audit trail in scores.json).
pub fn apply(mut findings: Vec<Finding>, m: &FactModel) -> (Vec<Finding>, Vec<AppliedModifier>) {
    let c = ctx(m);
    let mut applied = Vec::new();

    for f in findings.iter_mut() {
        // 1. stdio transport → no remote attacker surface: downgrade network-family rules.
        if c.stdio && MCP_NETWORK_RULES.contains(&f.rule_id.as_str()) {
            let to = down(f.severity);
            applied.push(AppliedModifier {
                modifier: "transport-stdio:no-remote-attacker".into(),
                rule_id: f.rule_id.clone(),
                from: f.severity,
                to,
            });
            f.severity = to;
        }
        // 2. all tools read-only → a filesystem-read traversal is info-disclosure, not RCE.
        if c.all_read_only && f.rule_id == "MCP-FILESYSTEM-UNSCOPED" {
            let to = down(f.severity);
            applied.push(AppliedModifier {
                modifier: "tools-read-only:no-write-path".into(),
                rule_id: f.rule_id.clone(),
                from: f.severity,
                to,
            });
            f.severity = to;
        }
        // 3. keyless (no secret sources anywhere) → credential rules can't reach a real secret.
        if c.keyless
            && matches!(
                f.rule_id.as_str(),
                "MCP-CREDENTIAL-EXFILTRATION" | "MCP-SECRET-IN-CONFIG" | "MCP-CREDENTIAL-LOGGED"
            )
        {
            let to = down(f.severity);
            applied.push(AppliedModifier {
                modifier: "keyless-public-api:no-secret-to-leak".into(),
                rule_id: f.rule_id.clone(),
                from: f.severity,
                to,
            });
            f.severity = to;
        }
    }

    (findings, applied)
}
