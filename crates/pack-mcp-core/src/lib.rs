//! mcp-core pack — deterministic MCP-server security rules (rubric v1.1, approved
//! 2026-07-08 → `lane1/rubric.md`). Pure functions of a `FactModel` produced by a
//! future `mcp-parser`.
//!
//! ## Fact contract (what `mcp-parser` must produce)
//! MCP entities are modeled as `EntityKind::Resource` carrying an `mcp_kind` attribute
//! (`"server" | "tool" | "dependency"`) — so this pack compiles against the *unmodified*
//! engine. (Production nicety: add dedicated `EntityKind::McpServer/McpTool` variants;
//! a small `fact-model` diff. Not required to run.)
//!
//! - **server** (one) attrs: `transport` (enum `stdio|http|sse`), `commit`, `resolved_version`,
//!   `all_tools_read_only` (bool), `keyless_public_only` (bool), `has_lockfile` (bool),
//!   `secret_source_to_egress` (bool), `secret_in_config` (bool), `tls_verify_disabled` (bool).
//! - **tool** attrs: `name`, `read_only_hint`, `desc_injection`, `desc_hidden_unicode`,
//!   `name_collision`, `ssrf_url_from_input`, `fs_path_from_input`, `shell_exec_from_input`,
//!   `sql_from_input`, `insecure_deser`, `unbounded_limit`, `redos_regex`, `no_timeout_bound`.
//! - **dependency** attrs: `name`, `pinned` (bool), `range` (str).
//!
//! **Boundary — what compiles today vs the parser TODO.** The rules below are *done* and
//! tested against these facts. The STRUCTURAL facts (`transport`, lockfile/pins, tool
//! annotations, `has_lockfile`) are cheap for `mcp-parser` to extract from `server.json` /
//! `package.json` / `pyproject.toml`. The SOURCE-FLOW facts (`*_from_input`,
//! `secret_source_to_egress`, `insecure_deser`) need the JS/TS + Python AST pass — that pass
//! is the remaining B1 work (see `lane1/b1-build-sheet.md`). Rules consume the facts either way.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{Entity, FactModel};

pub mod context;
pub mod score;

pub const PACK_ID: &str = "mcp-core";

/// Network-family rules that a `stdio` transport downgrades (no remote attacker). Used by
/// [`context`].
pub const MCP_NETWORK_RULES: &[&str] = &[
    "MCP-SSRF-USER-CONTROLLED-URL",
    "MCP-UNRESTRICTED-EGRESS",
    "MCP-TLS-VERIFICATION-DISABLED",
    "MCP-BIND-NO-AUTH",
    "MCP-BIND-ALL-INTERFACES",
    "MCP-CORS-WILDCARD",
];

// --- fact accessors --------------------------------------------------------
// NB: `iter().filter(|e| ...)` yields `&&Entity`; method access (`e.attr`)
// auto-derefs, so we inline it rather than call a `fn(&Entity)` helper (which
// would not auto-deref).
/// The single server entity, if present.
pub fn server_entity(m: &FactModel) -> Option<&Entity> {
    m.entities
        .iter()
        .find(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("server"))
}
fn tools(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities
        .iter()
        .filter(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("tool"))
}
fn deps(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities
        .iter()
        .filter(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("dependency"))
}
fn flag(e: &Entity, key: &str) -> bool {
    e.attr(key).and_then(|v| v.as_bool()) == Some(true)
}

// --- rule plumbing (mirrors pack-gha-core) ---------------------------------
struct FnRule {
    id: &'static str,
    f: fn(&FactModel) -> Vec<Finding>,
}
impl Rule for FnRule {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, m: &FactModel) -> Vec<Finding> {
        (self.f)(m)
    }
}

fn finding(
    rule_id: &str,
    severity: Severity,
    evidence: Vec<String>,
    message: String,
    fix: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        controls: Vec::new(), // stamped from catalog by run_pack
        severity,
        evidence,
        message,
        remediation: fix.to_string(),
        lines: Vec::new(),
    }
}

/// Emit one finding per tool matching `pred`.
fn per_tool(
    m: &FactModel,
    rule_id: &'static str,
    sev: Severity,
    fix: &'static str,
    pred: fn(&Entity) -> bool,
    msg: fn(&str) -> String,
) -> Vec<Finding> {
    tools(m)
        .filter(|t| pred(t))
        .map(|t| {
            let name = t.attr("name").and_then(|v| v.as_str()).unwrap_or(&t.id);
            finding(rule_id, sev, vec![t.id.clone()], msg(name), fix)
        })
        .collect()
}

// =========================== D1 — tool-description injection ================
fn r_tool_desc_injection(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-TOOL-DESCRIPTION-INJECTION",
        Severity::High,
        "Treat tool descriptions as untrusted content into the model. Strip instruction-like text, HTML comments, and invisible unicode; never generate descriptions from remote/user data.",
        |t| flag(t, "desc_injection") || flag(t, "desc_hidden_unicode"),
        |n| format!("Tool '{n}' has an instruction-like or hidden-unicode description that reaches the model context (tool poisoning)"),
    )
}
fn r_tool_shadowing(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-TOOL-SHADOWING",
        Severity::Medium,
        "Namespace tool names to the server's domain so they can't shadow a common tool from another server in a multi-server client.",
        |t| flag(t, "name_collision"),
        |n| format!("Tool '{n}' uses a generic name that can shadow/spoof a tool from another MCP server"),
    )
}

// =========================== D2 — credential / secret handling =============
fn r_credential_exfiltration(m: &FactModel) -> Vec<Finding> {
    let s = match server_entity(m) {
        Some(s) if flag(s, "secret_source_to_egress") => s,
        _ => return Vec::new(),
    };
    vec![finding(
        "MCP-CREDENTIAL-EXFILTRATION",
        Severity::Critical,
        vec![s.id.clone()],
        "A secret source (env token/credential-file read) flows to a network egress sink to an undeclared/hardcoded host in the same module — a credential-exfiltration path".into(),
        "Remove the egress of the secret; if a token must be sent, restrict the destination to a declared allowlist and never forward it to a hardcoded/undeclared host.",
    )]
}
fn r_secret_in_config(m: &FactModel) -> Vec<Finding> {
    match server_entity(m) {
        Some(s) if flag(s, "secret_in_config") => vec![finding(
            "MCP-SECRET-IN-CONFIG",
            Severity::High,
            vec![s.id.clone()],
            "A real-looking key/token is embedded in the shipped config / example / README install snippet".into(),
            "Reference secrets from the environment or a secret manager; never inline a real key in mcp.json / README examples. Rotate the exposed value.",
        )],
        _ => Vec::new(),
    }
}

// =========================== D3 — network egress / SSRF ====================
fn r_ssrf(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-SSRF-USER-CONTROLLED-URL",
        Severity::High,
        "Validate the destination against a host allowlist; block RFC1918/link-local/metadata IPs and disable redirects to them.",
        |t| flag(t, "ssrf_url_from_input"),
        |n| format!("Tool '{n}' issues an HTTP request to a host derived from tool input with no allowlist (SSRF)"),
    )
}
fn r_tls_disabled(m: &FactModel) -> Vec<Finding> {
    match server_entity(m) {
        Some(s) if flag(s, "tls_verify_disabled") => vec![finding(
            "MCP-TLS-VERIFICATION-DISABLED",
            Severity::Medium,
            vec![s.id.clone()],
            "Code disables TLS verification (rejectUnauthorized:false / verify=False / NODE_TLS_REJECT_UNAUTHORIZED=0) — traffic can be MitM'd".into(),
            "Remove the insecure flag and fix CA trust; verify a checksum/signature for downloaded artifacts.",
        )],
        _ => Vec::new(),
    }
}

// =========================== D4 — permission scope vs declared =============
fn r_filesystem_unscoped(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-FILESYSTEM-UNSCOPED",
        Severity::High,
        "Resolve every path under a fixed jail root and reject traversal ('..', absolute paths, symlinks) before any filesystem call.",
        |t| flag(t, "fs_path_from_input"),
        |n| format!("Tool '{n}' passes tool-input paths to a filesystem call with no jail root (path traversal)"),
    )
}
fn r_shell_exec(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-SHELL-EXEC-SURFACE",
        Severity::High,
        "Never build a shell string from tool input; use argument-vector exec with a fixed binary, or remove the exec surface.",
        |t| flag(t, "shell_exec_from_input"),
        |n| format!("Tool '{n}' spawns a process/shell with interpolated tool input (command injection — the CVE-2025-6514 pattern)"),
    )
}
fn r_sql_injection(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-SQL-INJECTION",
        Severity::High,
        "Use parameterized queries / bound parameters; never concatenate tool input into SQL.",
        |t| flag(t, "sql_from_input"),
        |n| format!("Tool '{n}' concatenates tool input into a SQL query with no parameterization (SQL injection)"),
    )
}
fn r_insecure_deser(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-INSECURE-DESERIALIZATION",
        Severity::High,
        "Never deserialize tool input with pickle/marshal/yaml.load(Loader=FullLoader off); use a safe format (JSON) or yaml.safe_load.",
        |t| flag(t, "insecure_deser"),
        |n| format!("Tool '{n}' deserializes tool input via an unsafe deserializer (pickle/yaml.load/marshal)"),
    )
}
fn r_input_unvalidated(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-INPUT-UNVALIDATED",
        Severity::Medium,
        "Bound numeric params (e.g. MAX_LIMIT), cap string lengths, and pass regex=False to substring filters unless a regex is intended.",
        |t| flag(t, "unbounded_limit") || flag(t, "redos_regex"),
        |n| format!("Tool '{n}' accepts an unbounded numeric param or treats input as a regex (resource exhaustion / ReDoS)"),
    )
}
fn r_dos_unbounded(m: &FactModel) -> Vec<Finding> {
    per_tool(
        m,
        "MCP-DOS-UNBOUNDED",
        Severity::Low,
        "Add timeouts, size limits, and concurrency bounds to tool operations.",
        |t| flag(t, "no_timeout_bound"),
        |n| format!("Tool '{n}' has no timeout/size bound on its operation (resource exhaustion)"),
    )
}

// =========================== D5 — supply-chain provenance ==================
fn r_deps_unpinned(m: &FactModel) -> Vec<Finding> {
    let server = server_entity(m);
    let no_lock = server
        .map(|s| s.attr("has_lockfile").and_then(|v| v.as_bool()) == Some(false))
        .unwrap_or(false);
    let unpinned: Vec<String> = deps(m)
        .filter(|d| d.attr("pinned").and_then(|v| v.as_bool()) == Some(false))
        .map(|d| d.id.clone())
        .collect();
    let has_deps = deps(m).next().is_some();
    // fire on: any unpinned dep, or (no lockfile AND there is at least one dep to pin).
    if unpinned.is_empty() && (!no_lock || !has_deps) {
        return Vec::new();
    }
    let mut evidence = Vec::new();
    if let Some(s) = server {
        evidence.push(s.id.clone());
    }
    evidence.extend(unpinned.iter().cloned());
    let why = if no_lock {
        "no committed lockfile and floating dependency ranges"
    } else {
        "floating dependency ranges with no upper bound"
    };
    vec![finding(
        "MCP-DEPS-UNPINNED",
        Severity::Medium,
        evidence,
        format!("Supply-chain: {why} — installs are not reproducible and a silent major-version bump can ship unreviewed code"),
        "Commit a lockfile (uv.lock / poetry.lock / package-lock.json / go.sum) and pin ranges with upper bounds; pin GitHub Actions to commit SHAs.",
    )]
}

// --- catalog ---------------------------------------------------------------
// =========================== D4 — HTTP-transport exposure ==================
fn r_bind_no_auth(m: &FactModel) -> Vec<Finding> {
    match server_entity(m) {
        Some(s) if flag(s, "binds_all_interfaces") && !flag(s, "has_auth") => vec![finding(
            "MCP-BIND-NO-AUTH",
            Severity::High,
            vec![s.id.clone()],
            "Server binds all interfaces (0.0.0.0) with no detectable inbound authentication — an internet-reachable, unauthenticated MCP endpoint".into(),
            "Bind to 127.0.0.1 for local use, or require authentication (token/OAuth) before listening on 0.0.0.0.",
        )],
        _ => Vec::new(),
    }
}
fn r_bind_all(m: &FactModel) -> Vec<Finding> {
    match server_entity(m) {
        Some(s) if flag(s, "binds_all_interfaces") && flag(s, "has_auth") => vec![finding(
            "MCP-BIND-ALL-INTERFACES",
            Severity::Medium,
            vec![s.id.clone()],
            "Server binds all interfaces (0.0.0.0) — reachable from any network interface".into(),
            "Bind to a specific interface (127.0.0.1) unless external exposure is intended and hardened.",
        )],
        _ => Vec::new(),
    }
}
fn r_cors_wildcard(m: &FactModel) -> Vec<Finding> {
    match server_entity(m) {
        Some(s) if flag(s, "cors_wildcard") => vec![finding(
            "MCP-CORS-WILDCARD",
            Severity::Medium,
            vec![s.id.clone()],
            "CORS allows any origin (*) — a browser on any site can call this server".into(),
            "Restrict CORS to an explicit allowlist of trusted origins; never pair wildcard origin with credentials.",
        )],
        _ => Vec::new(),
    }
}

/// Static catalog: id → metadata (controls = CWE + OWASP MCP Top-10 + MAESTRO + ETDI).
pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    use engine::Severity::{Critical, High, Low, Medium};
    let t = "MCP";
    vec![
        RuleMeta { id: "MCP-TOOL-DESCRIPTION-INJECTION", title: "Tool-description injection (tool poisoning)", target: t, severity: High, controls: &["CWE-74", "CWE-116", "OWASP-MCP-A2", "MAESTRO-L3", "ETDI-tool-descriptions"], summary: "A tool description/annotation carries instruction-like or hidden (zero-width/HTML-comment) content that reaches the model context.", fix: "Sanitize descriptions; never generate them from remote/user data.", strict: false },
        RuleMeta { id: "MCP-TOOL-SHADOWING", title: "Tool name collision / shadowing", target: t, severity: Medium, controls: &["CWE-290", "CWE-345", "OWASP-MCP-A1", "ETDI-versioning", "MAESTRO-L3"], summary: "A generic tool name can shadow/spoof a tool from another server in a multi-server client.", fix: "Namespace tool names to the server's domain.", strict: false },
        RuleMeta { id: "MCP-CREDENTIAL-EXFILTRATION", title: "Credential exfiltration (secret → egress)", target: t, severity: Critical, controls: &["CWE-200", "CWE-522", "CWE-312", "OWASP-MCP-A7", "MAESTRO-L4"], summary: "A secret source reaches a network egress sink to an undeclared/hardcoded host — a credential-theft path.", fix: "Remove the egress; allowlist any legitimate destination.", strict: false },
        RuleMeta { id: "MCP-SECRET-IN-CONFIG", title: "Secret in shipped config/README", target: t, severity: High, controls: &["CWE-798", "CWE-312", "OWASP-MCP-A7", "MAESTRO-L4"], summary: "A real-looking key/token is embedded in the shipped config / example / README snippet.", fix: "Reference from env/secret manager; rotate the exposed value.", strict: false },
        RuleMeta { id: "MCP-SSRF-USER-CONTROLLED-URL", title: "SSRF via user-controlled URL", target: t, severity: High, controls: &["CWE-918", "OWASP-MCP-A3", "MAESTRO-L6"], summary: "An HTTP request targets a host derived from tool input with no allowlist.", fix: "Allowlist destinations; block RFC1918/metadata IPs.", strict: false },
        RuleMeta { id: "MCP-TLS-VERIFICATION-DISABLED", title: "TLS verification disabled", target: t, severity: Medium, controls: &["CWE-295", "CWE-319", "OWASP-MCP-A5", "MAESTRO-L6"], summary: "Code disables TLS certificate verification (rejectUnauthorized:false / verify=False).", fix: "Remove the insecure flag; fix CA trust.", strict: false },
        RuleMeta { id: "MCP-FILESYSTEM-UNSCOPED", title: "Unscoped filesystem path (traversal)", target: t, severity: High, controls: &["CWE-22", "CWE-59", "OWASP-MCP-A3", "MAESTRO-L3"], summary: "Tool-input paths reach a filesystem call with no jail root.", fix: "Resolve under a fixed root; reject traversal/symlinks.", strict: false },
        RuleMeta { id: "MCP-SHELL-EXEC-SURFACE", title: "Command injection / shell-exec surface", target: t, severity: High, controls: &["CWE-78", "CWE-77", "CWE-94", "OWASP-MCP-A1", "MAESTRO-L3"], summary: "A process/shell is spawned with interpolated tool input (the CVE-2025-6514 pattern).", fix: "Use argument-vector exec with a fixed binary; never build a shell string from input.", strict: false },
        RuleMeta { id: "MCP-SQL-INJECTION", title: "SQL injection via tool input", target: t, severity: High, controls: &["CWE-89", "OWASP-MCP-A1", "MAESTRO-L3"], summary: "Tool input is concatenated into a SQL query with no parameterization.", fix: "Use parameterized queries.", strict: false },
        RuleMeta { id: "MCP-INSECURE-DESERIALIZATION", title: "Insecure deserialization", target: t, severity: High, controls: &["CWE-502", "OWASP-MCP-A1", "MAESTRO-L3"], summary: "Tool input is deserialized with an unsafe deserializer (pickle/yaml.load/marshal).", fix: "Use JSON / yaml.safe_load; never unpickle untrusted input.", strict: false },
        RuleMeta { id: "MCP-INPUT-UNVALIDATED", title: "Missing input validation", target: t, severity: Medium, controls: &["CWE-20", "CWE-1284", "OWASP-MCP-A5", "MAESTRO-L3"], summary: "An unbounded numeric param or input-as-regex enables resource exhaustion / ReDoS.", fix: "Bound params; cap lengths; regex=False unless intended.", strict: false },
        RuleMeta { id: "MCP-DOS-UNBOUNDED", title: "No timeout/size bound (DoS)", target: t, severity: Low, controls: &["CWE-400", "CWE-770", "OWASP-MCP-A5", "MAESTRO-L6"], summary: "A tool operation has no timeout/size/concurrency bound.", fix: "Add timeouts and size/concurrency limits.", strict: false },
        RuleMeta { id: "MCP-DEPS-UNPINNED", title: "Unpinned dependencies / supply chain", target: t, severity: Medium, controls: &["CWE-1104", "CWE-829", "OWASP-MCP-A6", "MAESTRO-L3", "MCP-Spec-supply-chain"], summary: "No committed lockfile and/or floating ranges — installs are not reproducible.", fix: "Commit a lockfile; pin ranges and GitHub Actions to SHAs.", strict: false },
        RuleMeta { id: "MCP-BIND-NO-AUTH", title: "Binds 0.0.0.0 without auth", target: t, severity: High, controls: &["CWE-668", "CWE-306", "OWASP-MCP-A6", "MAESTRO-L4"], summary: "Server binds all interfaces (0.0.0.0) with no detectable inbound authentication — internet-reachable and unauthenticated.", fix: "Bind to 127.0.0.1, or require authentication before listening on 0.0.0.0.", strict: false },
        RuleMeta { id: "MCP-BIND-ALL-INTERFACES", title: "Binds all interfaces (0.0.0.0)", target: t, severity: Medium, controls: &["CWE-668", "OWASP-MCP-A6", "MAESTRO-L4"], summary: "Server binds all interfaces — reachable from any network interface.", fix: "Bind to a specific interface unless external exposure is intended and hardened.", strict: false },
        RuleMeta { id: "MCP-CORS-WILDCARD", title: "CORS wildcard origin", target: t, severity: Medium, controls: &["CWE-942", "CWE-346", "OWASP-MCP-A4", "MAESTRO-L6"], summary: "CORS allows any origin (*) — any website can call the server.", fix: "Restrict CORS to a trusted-origin allowlist; never pair wildcard with credentials.", strict: false },
    ]
}

pub struct McpCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl McpCorePack {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "MCP-TOOL-DESCRIPTION-INJECTION", f: r_tool_desc_injection }),
            Box::new(FnRule { id: "MCP-TOOL-SHADOWING", f: r_tool_shadowing }),
            Box::new(FnRule { id: "MCP-CREDENTIAL-EXFILTRATION", f: r_credential_exfiltration }),
            Box::new(FnRule { id: "MCP-SECRET-IN-CONFIG", f: r_secret_in_config }),
            Box::new(FnRule { id: "MCP-SSRF-USER-CONTROLLED-URL", f: r_ssrf }),
            Box::new(FnRule { id: "MCP-TLS-VERIFICATION-DISABLED", f: r_tls_disabled }),
            Box::new(FnRule { id: "MCP-FILESYSTEM-UNSCOPED", f: r_filesystem_unscoped }),
            Box::new(FnRule { id: "MCP-SHELL-EXEC-SURFACE", f: r_shell_exec }),
            Box::new(FnRule { id: "MCP-SQL-INJECTION", f: r_sql_injection }),
            Box::new(FnRule { id: "MCP-INSECURE-DESERIALIZATION", f: r_insecure_deser }),
            Box::new(FnRule { id: "MCP-INPUT-UNVALIDATED", f: r_input_unvalidated }),
            Box::new(FnRule { id: "MCP-DOS-UNBOUNDED", f: r_dos_unbounded }),
            Box::new(FnRule { id: "MCP-DEPS-UNPINNED", f: r_deps_unpinned }),
            Box::new(FnRule { id: "MCP-BIND-NO-AUTH", f: r_bind_no_auth }),
            Box::new(FnRule { id: "MCP-BIND-ALL-INTERFACES", f: r_bind_all }),
            Box::new(FnRule { id: "MCP-CORS-WILDCARD", f: r_cors_wildcard }),
        ];
        Self { rules }
    }
}

impl Default for McpCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for McpCorePack {
    fn catalog(&self) -> Vec<engine::RuleMeta> {
        catalog()
    }
    fn id(&self) -> &str {
        PACK_ID
    }
    fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
    fn verdict(&self, findings: &[Finding]) -> Verdict {
        let counts = count_severities(findings);
        let status = if counts.critical > 0 || counts.high > 0 {
            Status::FlaggedGap
        } else {
            Status::Cleared
        };
        Verdict {
            counts,
            status,
            pack_policy: "any Critical or High => Flagged-Gap".to_string(),
        }
    }
}

// ===========================================================================
// Tests — fixtures exercise the full pipeline: rules → context modifiers → score.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use fact_model::{AttrValue, EntityKind, Provenance, SourceDescriptor};
    use score::Dim;

    fn ent(id: &str, attrs: Vec<(&str, AttrValue)>) -> Entity {
        Entity {
            id: id.into(),
            kind: EntityKind::Resource,
            attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            provenance: Provenance::explicit(id).with_line(Some(1)),
        }
    }
    fn model(entities: Vec<Entity>) -> FactModel {
        FactModel {
            schema_version: "0".into(),
            source: SourceDescriptor {
                kind: "mcp_server".into(),
                input_hash: "sha256:test".into(),
                parser_version: "0".into(),
            },
            entities,
            relations: vec![],
        }
    }
    fn b(v: bool) -> AttrValue {
        AttrValue::Bool(v)
    }
    fn run(m: &FactModel) -> score::ScoreReport {
        let pack = McpCorePack::new();
        let mut f = engine::run_pack(&pack, m);
        engine::attach_lines(&mut f, m);
        let (f, mods) = context::apply(f, m);
        score::score(&f, &mods, &Dim::all(), true)
    }

    // il-eli-mcp-shaped: stdio, read-only, keyless, unpinned deps + unbounded limit.
    // BlueRock rated this LOW; we should land high (A/B) with no Critical.
    fn fx_good_stdio() -> FactModel {
        model(vec![
            ent("mcp_server:il", vec![
                ("mcp_kind", AttrValue::Str("server".into())),
                ("transport", AttrValue::Enum("stdio".into())),
                ("all_tools_read_only", b(true)),
                ("keyless_public_only", b(true)),
                ("has_lockfile", b(false)),
            ]),
            ent("tool:search", vec![
                ("mcp_kind", AttrValue::Str("tool".into())),
                ("name", AttrValue::Str("il_search".into())),
                ("unbounded_limit", b(true)),
                ("redos_regex", b(true)),
            ]),
            ent("dep:fastmcp", vec![
                ("mcp_kind", AttrValue::Str("dependency".into())),
                ("name", AttrValue::Str("fastmcp".into())),
                ("pinned", b(false)),
            ]),
        ])
    }

    // networked server with a shell-exec + SSRF tool → capped low, no stdio downgrade.
    fn fx_http_shell_ssrf() -> FactModel {
        model(vec![
            ent("mcp_server:x", vec![
                ("mcp_kind", AttrValue::Str("server".into())),
                ("transport", AttrValue::Enum("http".into())),
                ("has_lockfile", b(true)),
            ]),
            ent("tool:run", vec![
                ("mcp_kind", AttrValue::Str("tool".into())),
                ("name", AttrValue::Str("run".into())),
                ("shell_exec_from_input", b(true)),
                ("ssrf_url_from_input", b(true)),
            ]),
        ])
    }

    // credential exfiltration → Critical → F.
    fn fx_exfil() -> FactModel {
        model(vec![
            ent("mcp_server:e", vec![
                ("mcp_kind", AttrValue::Str("server".into())),
                ("transport", AttrValue::Enum("stdio".into())),
                ("secret_source_to_egress", b(true)),
            ]),
        ])
    }

    #[test]
    fn good_stdio_scores_high_no_critical() {
        let r = run(&fx_good_stdio());
        assert!(r.grade == 'A' || r.grade == 'B', "expected A/B, got {}", r.grade);
        assert!(!r.caps.iter().any(|c| c.contains("critical")));
    }

    #[test]
    fn http_shell_ssrf_is_capped_low() {
        let r = run(&fx_http_shell_ssrf());
        assert!(r.grade == 'D' || r.grade == 'F', "expected D/F, got {}", r.grade);
        assert!(r.caps.iter().any(|c| c.contains("shell-exec")));
        // http transport → SSRF stays High (no stdio downgrade).
        assert!(r.modifiers.is_empty(), "no context downgrade on http");
    }

    #[test]
    fn stdio_downgrades_ssrf_severity() {
        // Same SSRF tool but stdio transport → the High SSRF is downgraded to Medium.
        let m = model(vec![
            ent("mcp_server:s", vec![
                ("mcp_kind", AttrValue::Str("server".into())),
                ("transport", AttrValue::Enum("stdio".into())),
                ("has_lockfile", b(true)),
            ]),
            ent("tool:fetch", vec![
                ("mcp_kind", AttrValue::Str("tool".into())),
                ("name", AttrValue::Str("fetch".into())),
                ("ssrf_url_from_input", b(true)),
            ]),
        ]);
        let r = run(&m);
        let m0 = &r.modifiers[0];
        assert_eq!(m0.modifier, "transport-stdio:no-remote-attacker");
        assert_eq!(m0.from, Severity::High);
        assert_eq!(m0.to, Severity::Medium);
    }

    #[test]
    fn exfil_caps_at_f() {
        let r = run(&fx_exfil());
        assert_eq!(r.grade, 'F');
        assert!(r.caps.iter().any(|c| c.contains("critical")));
    }

    #[test]
    fn scoring_is_deterministic() {
        let m = fx_http_shell_ssrf();
        let a = run(&m).to_json("x/x", "https://x", "abc").to_canonical_string();
        let b = run(&m).to_json("x/x", "https://x", "abc").to_canonical_string();
        assert_eq!(a, b, "same model + ruleset must reproduce identical scores.json");
    }

    #[test]
    fn every_rule_maps_to_a_dimension_and_catalog() {
        let cat = catalog();
        for r in McpCorePack::new().rules() {
            assert!(cat.iter().any(|m| m.id == r.id()), "rule {} missing from catalog", r.id());
            let _ = score::dimension_of(r.id()); // never panics
        }
    }
}
