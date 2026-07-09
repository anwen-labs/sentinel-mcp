//! Deterministic scoring: findings → per-dimension sub-scores → composite → A–F.
//! Implements rubric v1.1 §3 (sub-scores), §5 (composite + grade caps), §6 (scores.json).
//! Weights (approved 2026-07-08): D1 20 / D2 20 / D3 20 / D4 25 / D5 15.

use std::collections::BTreeMap;

use engine::{Finding, Severity};
use fact_model::{FactModel, Json};

use crate::context::AppliedModifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dim {
    D1ToolInjection,
    D2Credential,
    D3Egress,
    D4Permission,
    D5Provenance,
}

impl Dim {
    pub fn id(self) -> &'static str {
        match self {
            Dim::D1ToolInjection => "tool-description-injection",
            Dim::D2Credential => "credential-secret-handling",
            Dim::D3Egress => "network-egress-ssrf",
            Dim::D4Permission => "permission-scope-vs-declared",
            Dim::D5Provenance => "supply-chain-provenance",
        }
    }
    pub fn weight(self) -> u32 {
        match self {
            Dim::D1ToolInjection => 20,
            Dim::D2Credential => 20,
            Dim::D3Egress => 20,
            Dim::D4Permission => 25,
            Dim::D5Provenance => 15,
        }
    }
    pub fn all() -> [Dim; 5] {
        [
            Dim::D1ToolInjection,
            Dim::D2Credential,
            Dim::D3Egress,
            Dim::D4Permission,
            Dim::D5Provenance,
        ]
    }
}

/// Which dimension a rule contributes to (rubric §2).
pub fn dimension_of(rule_id: &str) -> Dim {
    match rule_id {
        "MCP-TOOL-DESCRIPTION-INJECTION"
        | "MCP-HIDDEN-TOOL-METADATA"
        | "MCP-DYNAMIC-TOOL-DEFINITION"
        | "MCP-TOOL-SHADOWING" => Dim::D1ToolInjection,
        "MCP-CREDENTIAL-EXFILTRATION"
        | "MCP-SECRET-IN-CONFIG"
        | "MCP-CREDENTIAL-LOGGED"
        | "MCP-TOKEN-PASSTHROUGH-UNSCOPED" => Dim::D2Credential,
        "MCP-SSRF-USER-CONTROLLED-URL"
        | "MCP-UNRESTRICTED-EGRESS"
        | "MCP-TLS-VERIFICATION-DISABLED" => Dim::D3Egress,
        "MCP-FILESYSTEM-UNSCOPED"
        | "MCP-SHELL-EXEC-SURFACE"
        | "MCP-SQL-INJECTION"
        | "MCP-INSECURE-DESERIALIZATION"
        | "MCP-INPUT-UNVALIDATED"
        | "MCP-SCOPE-OVERREACH"
        | "MCP-DOS-UNBOUNDED"
        | "MCP-BIND-NO-AUTH"
        | "MCP-BIND-ALL-INTERFACES"
        | "MCP-CORS-WILDCARD" => Dim::D4Permission,
        "MCP-DEPS-UNPINNED" | "MCP-RELEASE-UNSIGNED" | "MCP-MAINTAINER-SIGNAL" => Dim::D5Provenance,
        // Unknown rule ids default to permission-scope (safest bucket) — a real engine asserts here.
        _ => Dim::D4Permission,
    }
}

fn penalty(sev: Severity) -> i32 {
    match sev {
        Severity::Critical => 50,
        Severity::High => 25,
        Severity::Medium => 10,
        Severity::Low => 4,
        Severity::Info => 0,
    }
}

pub struct DimScore {
    pub dim: Dim,
    pub status: &'static str, // "scored" | "na"
    pub sub_score: Option<u32>,
    pub findings: Vec<Finding>,
}

/// Whether the scan achieved enough coverage to publish a grade. `InsufficientCoverage` means the
/// tool surface could not be analyzed (an MCP server we couldn't resolve tools for) — the grade is
/// withheld so we never publish an unearned A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreStatus {
    Scored,
    InsufficientCoverage,
}

impl ScoreStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ScoreStatus::Scored => "scored",
            ScoreStatus::InsufficientCoverage => "insufficient_coverage",
        }
    }
}

pub struct ScoreReport {
    pub composite: u32,
    pub grade: char,
    pub status: ScoreStatus,
    pub caps: Vec<String>,
    pub dims: Vec<DimScore>,
    pub modifiers: Vec<AppliedModifier>,
}

/// Sub-score for one dimension: start 100, subtract per-finding penalty, per-rule
/// contribution capped at 2× its penalty (anti-noise), floored at 0 (rubric §3).
fn sub_score(findings: &[Finding]) -> u32 {
    let mut per_rule: BTreeMap<&str, i32> = BTreeMap::new();
    for f in findings {
        let p = penalty(f.severity);
        let cap = p * 2;
        let e = per_rule.entry(f.rule_id.as_str()).or_insert(0);
        *e = (*e + p).min(cap);
    }
    let total: i32 = per_rule.values().sum();
    (100 - total).max(0) as u32
}

fn band(composite: u32) -> char {
    match composite {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    }
}

/// Lower of two letter grades (A best … F worst).
fn worse(a: char, b: char) -> char {
    if a as u8 >= b as u8 {
        a
    } else {
        b
    } // 'F' > 'A' in ASCII, so the larger char is the worse grade
}

/// `scored_dims` marks which dimensions had a coverage pass (a dimension with no
/// applicable surface is `na` and excluded from the weighted average, rubric §4).
pub fn score(
    findings: &[Finding],
    modifiers: &[AppliedModifier],
    scored_dims: &[Dim],
    analyzable: bool,
) -> ScoreReport {
    let mut dims = Vec::new();
    let mut num = 0u32;
    let mut den = 0u32;

    for dim in Dim::all() {
        let dfindings: Vec<Finding> = findings
            .iter()
            .filter(|f| dimension_of(&f.rule_id) == dim)
            .cloned()
            .collect();
        let has_coverage = scored_dims.contains(&dim) || !dfindings.is_empty();
        if has_coverage {
            let s = sub_score(&dfindings);
            num += s * dim.weight();
            den += dim.weight();
            dims.push(DimScore {
                dim,
                status: "scored",
                sub_score: Some(s),
                findings: dfindings,
            });
        } else {
            dims.push(DimScore {
                dim,
                status: "na",
                sub_score: None,
                findings: dfindings,
            });
        }
    }

    let composite = (num + den / 2).checked_div(den).unwrap_or(100); // rounded; den==0 -> 100
    let mut grade = band(composite);
    let mut caps = Vec::new();

    // Grade caps (rubric §5).
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        grade = worse(grade, 'F');
        caps.push("critical-present:cap-F".into());
    }
    let high_in_d1_d2 = findings.iter().any(|f| {
        f.severity == Severity::High
            && matches!(dimension_of(&f.rule_id), Dim::D1ToolInjection | Dim::D2Credential)
    });
    if high_in_d1_d2 {
        grade = worse(grade, 'C');
        caps.push("d1|d2-high-unresolved:cap-C".into());
    }
    if findings.iter().any(|f| f.rule_id == "MCP-SHELL-EXEC-SURFACE") {
        grade = worse(grade, 'D');
        caps.push("shell-exec-surface:cap-D".into());
    }
    // Any unresolved High (after context modifiers) disqualifies an A: a "Grade A" listed next to a
    // High-severity finding (e.g. an SSRF surface) is incoherent to a reader. Caps at B; D1/D2
    // highs and shell-exec cap lower still (above).
    if findings.iter().any(|f| f.severity == Severity::High) {
        grade = worse(grade, 'B');
        caps.push("high-unresolved:cap-B".into());
    }

    let status = if analyzable {
        ScoreStatus::Scored
    } else {
        ScoreStatus::InsufficientCoverage
    };

    ScoreReport {
        composite,
        grade,
        status,
        caps,
        dims,
        modifiers: modifiers.to_vec(),
    }
}

impl ScoreReport {
    /// scores.json shape (rubric §6), using the engine's canonical Json. `model` supplies each
    /// evidence entity's provenance so every finding carries a concrete `file`+`line` locator
    /// (rubric §6 invariant #2) resolved from its primary evidence entity.
    pub fn to_json(&self, model: &FactModel, server: &str, repo_url: &str, commit: &str) -> Json {
        // entity id → (file, line) from provenance, for the evidence locator.
        let loc: BTreeMap<&str, (&str, Option<u32>)> = model
            .entities
            .iter()
            .map(|e| (e.id.as_str(), (e.provenance.source_path.as_str(), e.provenance.line)))
            .collect();
        let dims = self
            .dims
            .iter()
            .map(|d| {
                let findings = Json::Arr(
                    d.findings
                        .iter()
                        .map(|f| {
                            // Primary locator = first evidence entity (tools/sites are placed
                            // first). file from its provenance path; line from its provenance line,
                            // falling back to the aggregated attach_lines() value.
                            let primary = f.evidence.first().and_then(|id| loc.get(id.as_str()));
                            let file = primary.map(|(p, _)| *p).filter(|p| !p.is_empty() && *p != ".");
                            let line = primary
                                .and_then(|(_, l)| *l)
                                .or_else(|| f.lines.first().copied());
                            Json::Obj(vec![
                                ("rule".into(), Json::Str(f.rule_id.clone())),
                                ("severity".into(), Json::Str(f.severity.as_str().into())),
                                (
                                    "evidence".into(),
                                    Json::Obj(vec![
                                        (
                                            "file".into(),
                                            file.map(|p| Json::Str(p.to_string()))
                                                .unwrap_or(Json::Null),
                                        ),
                                        (
                                            "line".into(),
                                            line.map(|l| Json::Int(l as i64)).unwrap_or(Json::Null),
                                        ),
                                        (
                                            "entities".into(),
                                            Json::Arr(
                                                f.evidence.iter().cloned().map(Json::Str).collect(),
                                            ),
                                        ),
                                        (
                                            "lines".into(),
                                            Json::Arr(
                                                f.lines.iter().map(|l| Json::Int(*l as i64)).collect(),
                                            ),
                                        ),
                                    ]),
                                ),
                            ])
                        })
                        .collect(),
                );
                Json::Obj(vec![
                    ("id".into(), Json::Str(d.dim.id().into())),
                    ("weight".into(), Json::Int(d.dim.weight() as i64)),
                    ("status".into(), Json::Str(d.status.into())),
                    (
                        "sub_score".into(),
                        match d.sub_score {
                            Some(s) => Json::Int(s as i64),
                            None => Json::Null,
                        },
                    ),
                    ("findings".into(), findings),
                ])
            })
            .collect();

        let modifiers = Json::Arr(
            self.modifiers
                .iter()
                .map(|m| {
                    Json::Obj(vec![
                        ("modifier".into(), Json::Str(m.modifier.clone())),
                        ("rule".into(), Json::Str(m.rule_id.clone())),
                        ("from".into(), Json::Str(m.from.as_str().into())),
                        ("to".into(), Json::Str(m.to.as_str().into())),
                    ])
                })
                .collect(),
        );

        let scored = self.status == ScoreStatus::Scored;
        // Withhold grade/composite when coverage was insufficient — never publish an unearned grade.
        let (grade, composite) = if scored {
            (Json::Str(self.grade.to_string()), Json::Int(self.composite as i64))
        } else {
            (Json::Null, Json::Null)
        };

        Json::Obj(vec![
            ("server".into(), Json::Str(server.into())),
            ("repo_url".into(), Json::Str(repo_url.into())),
            ("commit".into(), Json::Str(commit.into())),
            ("ruleset_version".into(), Json::Str("pack-mcp-core@0.1.0".into())),
            ("status".into(), Json::Str(self.status.as_str().into())),
            ("composite".into(), composite),
            ("grade".into(), grade),
            (
                "grade_caps_applied".into(),
                Json::Arr(self.caps.iter().cloned().map(Json::Str).collect()),
            ),
            ("context_modifiers".into(), modifiers),
            ("dimensions".into(), Json::Arr(dims)),
        ])
    }
}
