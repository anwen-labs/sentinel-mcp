//! MCP server repo → `FactModel` (deterministic, no LLM). Consumed by `pack-mcp-core`.
//!
//! ## Scope (scaffold)
//! **Structural facts (done here, robust):** `transport` (server.json), lockfile presence,
//! dependency names + pin status (package.json / pyproject.toml / requirements.txt),
//! languages, `tls_verify_disabled` (presence scan). **Heuristic:** tool inventory
//! (count/names) + `read_only_hint` from a light source scan — labeled, best-effort.
//! **Source-flow (Python + JS/TS — done, see `python.rs` / `js.rs`, shared `taint.rs`):** taint-lite
//! links sink calls to a tool's parameter names → `ssrf_url_from_input`, `fs_path_from_input`,
//! `shell_exec_from_input`, `sql_from_input`, `insecure_deser`, `unbounded_limit`, `redos_regex`,
//! `desc_hidden_unicode`, plus module-level `secret_source_to_egress` (secret → known exfil host).
//! **TODO:** cross-file / inter-procedural taint (v1.2) — today's pass is file-scoped.
//!
//! Core (`parse_repo`) is a **pure function** of the input files (determinism). `read_repo`
//! is a thin filesystem walk for the CLI/harness.

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, SourceDescriptor,
};

mod js;
mod python;
mod taint;

pub const PARSER_VERSION: &str = "0.1.0";

const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pdm.lock",
    "go.sum",
    "Cargo.lock",
];

const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "vendor", ".next", "out",
];

/// Directory segments whose contents are NOT the shipped server — bundled examples, tutorials,
/// tests, docs, fixtures. Analyzing them attributes demo/sample code to the product's grade (e.g.
/// a `read_wikipedia_article` SSRF demo under `examples/mcp-wiki/` graded the whole `block/goose`
/// repo down to a B). Excluded from ALL fact extraction so the grade reflects the shipped surface.
const NON_SHIPPED_DIRS: &[&str] = &[
    "examples", "example", "samples", "sample", "demo", "demos", "test", "tests", "__tests__",
    "testing", "testdata", "fixtures", "e2e", "docs", "doc",
];

/// True if any path segment marks the file as non-shipped (see [`NON_SHIPPED_DIRS`]).
fn is_non_shipped(path: &str) -> bool {
    path.split(['/', '\\']).any(|seg| NON_SHIPPED_DIRS.contains(&seg))
}

/// One file's relative path + text content.
#[derive(Debug, Clone)]
pub struct RepoFile {
    pub path: String,
    pub content: String,
}

// --- small helpers ---------------------------------------------------------
fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}
fn is_source(p: &str) -> bool {
    let b = basename(p);
    [".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".go", ".java", ".kt", ".rs"]
        .iter()
        .any(|e| b.ends_with(e))
}
fn lang_of(p: &str) -> Option<&'static str> {
    let b = basename(p);
    for (ext, lang) in [
        (".py", "Python"),
        (".ts", "TypeScript"),
        (".tsx", "TypeScript"),
        (".js", "JavaScript"),
        (".mjs", "JavaScript"),
        (".cjs", "JavaScript"),
        (".go", "Go"),
        (".java", "Java"),
        (".kt", "Kotlin"),
        (".rs", "Rust"),
    ] {
        if b.ends_with(ext) {
            return Some(lang);
        }
    }
    None
}
fn s(v: &str) -> AttrValue {
    AttrValue::Str(v.to_string())
}

fn ent(id: String, path: &str, attrs: Vec<(&str, AttrValue)>) -> Entity {
    ent_at(id, path, None, attrs)
}

/// Like [`ent`] but records a 1-based source `line` on the provenance so `engine::attach_lines`
/// can surface `file:line` evidence for findings that cite this entity (rubric §6 locator).
fn ent_at(id: String, path: &str, line: Option<u32>, attrs: Vec<(&str, AttrValue)>) -> Entity {
    Entity {
        id,
        kind: EntityKind::Resource,
        attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        provenance: Provenance::explicit(path.to_string()).with_line(line),
    }
}

// --- dependency parsing ----------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub spec: String,
    pub pinned: bool,
    pub source_path: String,
}

/// npm: exact semver (digits + dots only) is pinned; carets/tilde/ranges/tags/urls are not.
fn npm_pinned(spec: &str) -> bool {
    let s = spec.trim();
    !s.is_empty()
        && s.as_bytes()[0].is_ascii_digit()
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn parse_npm(content: &str, path: &str) -> Vec<Dep> {
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(obj) = v.get("dependencies").and_then(|d| d.as_object()) {
        for (name, spec) in obj {
            let spec = spec.as_str().unwrap_or("");
            out.push(Dep {
                name: name.clone(),
                spec: spec.to_string(),
                pinned: npm_pinned(spec),
                source_path: path.to_string(),
            });
        }
    }
    out
}

/// PEP 508: name is the leading identifier; pinned iff the specifier contains `==`.
fn py_dep(spec: &str) -> (String, bool) {
    let name: String = spec
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    (name, spec.contains("=="))
}

fn extract_quoted(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            if let Some(sub) = s.get(start..i) {
                out.push(sub.to_string());
            }
        }
        i += 1;
    }
    out
}

/// PEP 621 `[project].dependencies = [ "pkg>=1", ... ]` (the array form). Poetry's
/// `[tool.poetry.dependencies]` table form is not handled (documented gap).
fn parse_pyproject(content: &str, path: &str) -> Vec<Dep> {
    let mut buf = String::new();
    let mut collecting = false;
    for line in content.lines() {
        let t = line.trim();
        if !collecting {
            if t.starts_with("dependencies") && t.contains('=') && t.contains('[') {
                collecting = true;
                if let Some(idx) = t.find('[') {
                    buf.push_str(&t[idx + 1..]);
                }
                if t.contains(']') {
                    collecting = false;
                }
            }
        } else {
            buf.push('\n');
            buf.push_str(t);
            if t.contains(']') {
                collecting = false;
            }
        }
        if !collecting && !buf.is_empty() {
            break;
        }
    }
    extract_quoted(&buf)
        .into_iter()
        .filter_map(|item| {
            let (name, pinned) = py_dep(&item);
            (!name.is_empty()).then(|| Dep {
                name,
                spec: item.clone(),
                pinned,
                source_path: path.to_string(),
            })
        })
        .collect()
}

fn parse_requirements(content: &str, path: &str) -> Vec<Dep> {
    content
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('-') {
                return None;
            }
            let (name, pinned) = py_dep(t);
            (!name.is_empty()).then(|| Dep {
                name,
                spec: t.to_string(),
                pinned,
                source_path: path.to_string(),
            })
        })
        .collect()
}

// --- server.json / transport ----------------------------------------------
fn transport_of(content: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
        if v.get("remotes").and_then(|r| r.as_array()).map(|a| !a.is_empty()) == Some(true) {
            return Some("http".into());
        }
    }
    if content.contains("streamable-http") || content.contains("\"sse\"") {
        return Some("http".into());
    }
    if content.contains("\"stdio\"") {
        return Some("stdio".into());
    }
    None
}

fn server_name(files: &[RepoFile]) -> Option<String> {
    let json_name = |c: &str| -> Option<String> {
        serde_json::from_str::<serde_json::Value>(c)
            .ok()?
            .get("name")?
            .as_str()
            .map(|n| n.to_string())
    };
    for f in files {
        if basename(&f.path) == "package.json" {
            if let Some(n) = json_name(&f.content) {
                return Some(n);
            }
        }
    }
    for f in files {
        if basename(&f.path) == "server.json" {
            if let Some(n) = json_name(&f.content) {
                return Some(n);
            }
        }
    }
    None
}

// --- source-file heuristics (labeled best-effort) --------------------------
const TLS_DISABLE_PATTERNS: &[&str] = &[
    "rejectUnauthorized: false",
    "rejectUnauthorized:false",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "verify=False",
    "verify = False",
    "InsecureSkipVerify: true",
    "InsecureSkipVerify:true",
];

/// `(file, 1-based line)` of the first TLS-verification-disable in source, or `None`.
fn tls_disabled_loc(files: &[RepoFile]) -> Option<(String, u32)> {
    for f in files.iter().filter(|f| is_source(&f.path)) {
        for (i, line) in f.content.lines().enumerate() {
            if TLS_DISABLE_PATTERNS.iter().any(|p| line.contains(p)) {
                return Some((f.path.clone(), i as u32 + 1));
            }
        }
    }
    None
}

/// Coarse: Some(false) if any destructive/write annotation is seen; else Some(true) if a
/// read-only annotation is seen; else None (unknown — no context downgrade).
fn all_read_only(files: &[RepoFile]) -> Option<bool> {
    let mut saw_ro = false;
    let mut saw_write = false;
    for f in files.iter().filter(|f| is_source(&f.path)) {
        let c = &f.content;
        if c.contains("readOnlyHint=True") || c.contains("readOnlyHint: true") || c.contains("readOnlyHint:true") {
            saw_ro = true;
        }
        if c.contains("destructiveHint=True")
            || c.contains("destructiveHint: true")
            || c.contains("readOnlyHint=False")
            || c.contains("readOnlyHint: false")
        {
            saw_write = true;
        }
    }
    if saw_write {
        Some(false)
    } else if saw_ro {
        Some(true)
    } else {
        None
    }
}

struct ToolRec {
    name: String,
    path: String,
    line: u32,
    taint: Option<taint::ToolTaint>,
}

fn is_js_ts(p: &str) -> bool {
    let b = basename(p);
    [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"].iter().any(|e| b.ends_with(e))
}

/// Is this repo actually an MCP server? (an `mcp` SDK dependency, a `server.json`, or an SDK
/// import in source). Used by the coverage gate: an MCP repo where we resolved zero tools was
/// not really analyzed, so its grade must be withheld rather than defaulting to A.
fn detect_mcp(files: &[RepoFile], deps: &[Dep]) -> bool {
    if files.iter().any(|f| basename(&f.path) == "server.json") {
        return true;
    }
    let mcp_dep = deps.iter().any(|d| {
        let n = d.name.to_ascii_lowercase();
        n == "mcp" || n == "fastmcp" || n.contains("modelcontextprotocol") || n.contains("mcp-sdk")
    });
    if mcp_dep {
        return true;
    }
    files.iter().filter(|f| is_source(&f.path)).any(|f| {
        let c = &f.content;
        c.contains("modelcontextprotocol")
            || c.contains("fastmcp")
            || c.contains("FastMCP")
            || c.contains("from mcp")
            || c.contains("import mcp")
    })
}

/// Tool inventory + source-flow taint. Python → `python::analyze`, JS/TS → `js::analyze`; other
/// source languages contribute no tools yet. Returns the tool records and whether any module has a
/// secret→exfil flow.
fn collect_tools(files: &[RepoFile]) -> (Vec<ToolRec>, Option<(String, u32)>) {
    let mut out: Vec<ToolRec> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut secret_egress: Option<(String, u32)> = None;

    // Python: analyze the whole repo together so tools registered across files are all discovered;
    // sink→param taint itself is same-file (v1). See `python::analyze_repo`.
    let py: Vec<(&str, &str)> = files
        .iter()
        .filter(|f| f.path.ends_with(".py"))
        .map(|f| (f.path.as_str(), f.content.as_str()))
        .collect();
    if !py.is_empty() {
        let a = python::analyze_repo(&py);
        if secret_egress.is_none() {
            secret_egress = a.secret_egress.clone();
        }
        for t in a.tools {
            if !t.name.is_empty() && seen.insert(t.name.clone()) {
                let path = if t.file.is_empty() { ".".to_string() } else { t.file.clone() };
                let line = t.line;
                out.push(ToolRec { name: t.name.clone(), path, line, taint: Some(t) });
            }
        }
    }

    // JS/TS: per-file for now (repo-wide JS is a later slice).
    for f in files.iter().filter(|f| is_js_ts(&f.path)) {
        let a = js::analyze(&f.content);
        if secret_egress.is_none() {
            // js analyzer leaves the path empty (per-file) — fill it with this file's path.
            secret_egress = a.secret_egress.as_ref().map(|(_, l)| (f.path.clone(), *l));
        }
        for t in a.tools {
            if !t.name.is_empty() && seen.insert(t.name.clone()) {
                let line = t.line;
                out.push(ToolRec {
                    name: t.name.clone(),
                    path: f.path.clone(),
                    line,
                    taint: Some(t),
                });
            }
        }
    }
    (out, secret_egress)
}

// --- core: pure function of the input files --------------------------------
pub fn parse_repo(all_files: &[RepoFile]) -> FactModel {
    // Restrict every downstream fact to the shipped server surface — drop bundled
    // examples/tests/docs so demo code can't be attributed to the product's grade. The pure
    // function owns this so the exclusion is deterministic and testable (not just a walk detail).
    let shipped: Vec<RepoFile> =
        all_files.iter().filter(|f| !is_non_shipped(&f.path)).cloned().collect();
    let files = &shipped[..];

    let has_lockfile = files.iter().any(|f| LOCKFILES.contains(&basename(&f.path)));

    // dependencies (dedup by name, first wins)
    let mut dep_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut deps: Vec<Dep> = Vec::new();
    for f in files {
        let found = match basename(&f.path) {
            "package.json" => parse_npm(&f.content, &f.path),
            "pyproject.toml" => parse_pyproject(&f.content, &f.path),
            "requirements.txt" => parse_requirements(&f.content, &f.path),
            _ => Vec::new(),
        };
        for d in found {
            if dep_names.insert(d.name.clone()) {
                deps.push(d);
            }
        }
    }

    let transport = files
        .iter()
        .find(|f| basename(&f.path) == "server.json")
        .and_then(|f| transport_of(&f.content))
        .unwrap_or_else(|| "unknown".to_string());

    let name = server_name(files).unwrap_or_else(|| "server".to_string());
    let server_path = files
        .iter()
        .find(|f| basename(&f.path) == "server.json")
        .or_else(|| files.iter().find(|f| basename(&f.path) == "package.json"))
        .map(|f| f.path.clone())
        .unwrap_or_else(|| ".".to_string());

    let (tools, secret_egress) = collect_tools(files);
    let tls_loc = tls_disabled_loc(files);
    let exposure = http_exposure(files);

    let mut langs: Vec<&'static str> = Vec::new();
    for f in files {
        if let Some(l) = lang_of(&f.path) {
            if !langs.contains(&l) {
                langs.push(l);
            }
        }
    }
    langs.sort_unstable();

    let mut entities: Vec<Entity> = Vec::new();

    // server entity
    let mut sattrs: Vec<(&str, AttrValue)> = vec![
        ("mcp_kind", s("server")),
        ("transport", AttrValue::Enum(transport)),
        ("has_lockfile", AttrValue::Bool(has_lockfile)),
        ("tool_count", AttrValue::Int(tools.len() as i64)),
        ("is_mcp", AttrValue::Bool(detect_mcp(files, &deps))),
    ];
    sattrs.push(("binds_all_interfaces", AttrValue::Bool(exposure.bind.is_some())));
    sattrs.push(("has_auth", AttrValue::Bool(exposure.has_auth)));
    sattrs.push(("cors_wildcard", AttrValue::Bool(exposure.cors.is_some())));
    if !langs.is_empty() {
        sattrs.push(("languages", AttrValue::List(langs.iter().map(|l| s(l)).collect())));
    }
    if tls_loc.is_some() {
        sattrs.push(("tls_verify_disabled", AttrValue::Bool(true)));
    }
    if let Some(ro) = all_read_only(files) {
        sattrs.push(("all_tools_read_only", AttrValue::Bool(ro)));
    }
    if secret_egress.is_some() {
        sattrs.push(("secret_source_to_egress", AttrValue::Bool(true)));
    }
    entities.push(ent(format!("mcp_server:{name}"), &server_path, sattrs));

    // Server-level finding "sites" — each carries the exact (file, line) of its signal so the
    // corresponding rule can cite a precise evidence locator (rubric §6). One entity per signal
    // (the single server entity can't hold distinct lines for bind vs. tls vs. cors).
    let site = |id: &str, loc: &Option<(String, u32)>, ents: &mut Vec<Entity>| {
        if let Some((f, l)) = loc {
            ents.push(ent_at(id.to_string(), f, Some(*l), vec![("mcp_kind", s("site"))]));
        }
    };
    site("site:bind-all-interfaces", &exposure.bind, &mut entities);
    site("site:cors-wildcard", &exposure.cors, &mut entities);
    site("site:tls-verify-disabled", &tls_loc, &mut entities);
    site("site:secret-egress", &secret_egress, &mut entities);

    // tool entities (inventory + Python source-flow taint facts)
    for t in &tools {
        let mut a: Vec<(&str, AttrValue)> = vec![("mcp_kind", s("tool")), ("name", s(&t.name))];
        if let Some(tt) = &t.taint {
            for (flag, key) in [
                (tt.ssrf, "ssrf_url_from_input"),
                (tt.fs, "fs_path_from_input"),
                (tt.shell, "shell_exec_from_input"),
                (tt.sql, "sql_from_input"),
                (tt.deser, "insecure_deser"),
                (tt.unbounded_limit, "unbounded_limit"),
                (tt.redos, "redos_regex"),
                (tt.desc_hidden_unicode, "desc_hidden_unicode"),
            ] {
                if flag {
                    a.push((key, AttrValue::Bool(true)));
                }
            }
        }
        let line = (t.line > 0).then_some(t.line);
        entities.push(ent_at(format!("tool:{}", t.name), &t.path, line, a));
    }

    // dependency entities
    for d in &deps {
        entities.push(ent(
            format!("dep:{}", d.name),
            &d.source_path,
            vec![
                ("mcp_kind", s("dependency")),
                ("name", s(&d.name)),
                ("pinned", AttrValue::Bool(d.pinned)),
                ("range", s(&d.spec)),
            ],
        ));
    }

    // DEPS-UNPINNED locator: the dependency manifest that ships without a committed lockfile.
    if !has_lockfile {
        if let Some(d) = deps.first() {
            let line = files
                .iter()
                .find(|f| f.path == d.source_path)
                .and_then(|f| f.content.lines().position(|l| l.contains("dependencies")))
                .map(|i| i as u32 + 1);
            entities.push(ent_at(
                "site:no-lockfile".to_string(),
                &d.source_path,
                line,
                vec![("mcp_kind", s("site"))],
            ));
        }
    }

    // input hash over the sorted (path, content) set — deterministic.
    let mut parts: Vec<String> = files.iter().map(|f| format!("{}\u{0}{}", f.path, f.content)).collect();
    parts.sort();
    let input_hash = sha256_prefixed(parts.join("\u{1}").as_bytes());

    FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "mcp_server".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities,
        relations: Vec::new(),
    }
}

// --- thin filesystem walk for the CLI/harness (not compiled for wasm) ------
#[cfg(not(target_arch = "wasm32"))]
pub fn read_repo(root: &std::path::Path) -> std::io::Result<Vec<RepoFile>> {
    fn interesting(name: &str) -> bool {
        matches!(
            name,
            "package.json" | "pyproject.toml" | "requirements.txt" | "go.mod" | "server.json"
        ) || LOCKFILES.contains(&name)
            || is_source(name)
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            if !interesting(&name) {
                continue;
            }
            if entry.metadata().map(|m| m.len() > 512 * 1024).unwrap_or(true) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(RepoFile { path: rel, content });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Convenience: number of entities of a given `mcp_kind` (test/debug aid).
pub fn kind_count(m: &FactModel, kind: &str) -> usize {
    m.entities
        .iter()
        .filter(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

/// Inbound-auth indicators (specific to *checking* auth, not just sending an Authorization header
/// on outbound calls — biased to avoid false "no-auth" flags).
const AUTH_INDICATORS: &[&str] = &[
    "requireAuth", "verifyToken", "ensureAuth", "auth_required", "authenticate(", "OAuth", "oauth",
    "passport", "express-jwt", "verifyJwt", "verifyJWT", "checkAuth", "bearerAuth",
    "WWW-Authenticate", "AuthMiddleware", "auth_middleware", "verify_token", "get_current_user",
    "HTTPBearer", "OAuth2", "login_required", "requireAuthentication",
];

/// Deployment-exposure signals scanned across source, each with the `(file, line)` of its first
/// match (evidence locator): binds all interfaces (0.0.0.0), CORS wildcard, plus whether any
/// inbound auth check is present. Feed the HTTP-transport rules.
#[derive(Default)]
struct Exposure {
    bind: Option<(String, u32)>,
    cors: Option<(String, u32)>,
    has_auth: bool,
}

/// A line binds all interfaces only if it mentions `0.0.0.0` **in a bind context** (host/bind/
/// listen/addr/serve) and does not merely *compare* against the literal. Presence alone is too
/// coarse — it matched a `bare_host == "0.0.0.0"` localhost check and a `0.0.0.0:3000` unit-test
/// string in goose. Precision-first: we'd rather miss a context-less bind than flag a test string.
/// (Surfacing `file:line` evidence is exactly what made those false locators visible.)
fn binds_all_line(line: &str) -> bool {
    if !line.contains("0.0.0.0") {
        return false;
    }
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("==\"0.0.0.0\"")
        || compact.contains("=='0.0.0.0'")
        || compact.contains("!=\"0.0.0.0\"")
        || compact.contains("!='0.0.0.0'")
    {
        return false; // a comparison against the literal is a host check, not a bind
    }
    let l = line.to_ascii_lowercase();
    ["host", "bind", "listen", "addr", "serve", "default"].iter().any(|k| l.contains(k))
}

fn cors_wildcard_line(line: &str) -> bool {
    line.contains("allow_origins=[\"*\"]")
        || line.contains("origin: \"*\"")
        || line.contains("origin: '*'")
        || (line.contains("Access-Control-Allow-Origin") && line.contains('*'))
}

fn http_exposure(files: &[RepoFile]) -> Exposure {
    let mut e = Exposure::default();
    for f in files.iter().filter(|f| is_source(&f.path)) {
        for (i, line) in f.content.lines().enumerate() {
            if e.bind.is_none() && binds_all_line(line) {
                e.bind = Some((f.path.clone(), i as u32 + 1));
            }
            if !e.has_auth && AUTH_INDICATORS.iter().any(|k| line.contains(k)) {
                e.has_auth = true;
            }
            if e.cors.is_none() && cors_wildcard_line(line) {
                e.cors = Some((f.path.clone(), i as u32 + 1));
            }
        }
    }
    e
}

/// Coverage gate: false when this is an MCP server but we resolved zero tools (so the tool-driven
/// dimensions were never really analyzed — the grade must be withheld, not defaulted to A).
pub fn analyzable(m: &FactModel) -> bool {
    let is_mcp = m
        .entities
        .iter()
        .find(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("server"))
        .map(|e| e.attr("is_mcp").and_then(|v| v.as_bool()) == Some(true))
        .unwrap_or(false);
    !(is_mcp && kind_count(m, "tool") == 0)
}

/// One-line human summary of the parsed model (transport, tool/dep counts, languages) for CLI/debug.
pub fn model_summary(m: &FactModel) -> String {
    let server = m
        .entities
        .iter()
        .find(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("server"));
    let transport = server
        .and_then(|e| e.attr("transport"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let langs = server
        .and_then(|e| e.attr("languages"))
        .map(|v| match v {
            AttrValue::List(xs) => xs.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","),
            _ => String::new(),
        })
        .unwrap_or_default();
    format!(
        "transport={} · tools={} · deps={} · langs=[{}]",
        transport,
        kind_count(m, "tool"),
        kind_count(m, "dependency"),
        langs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, content: &str) -> RepoFile {
        RepoFile { path: path.into(), content: content.into() }
    }
    fn server(m: &FactModel) -> &Entity {
        m.entities
            .iter()
            .find(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("server"))
            .unwrap()
    }

    #[test]
    fn npm_pins_classified() {
        assert!(npm_pinned("1.2.3"));
        assert!(!npm_pinned("^1.2.3"));
        assert!(!npm_pinned(">=0.27"));
        assert!(!npm_pinned("*"));
        assert!(!npm_pinned("latest"));
    }

    #[test]
    fn pyproject_ranges_are_unpinned() {
        let content = r#"
[project]
name = "il-eli-mcp"
dependencies = [
  "fastmcp>=0.2.0",
  "httpx>=0.27",
  "pandas==2.2.0",
]
"#;
        let deps = parse_pyproject(content, "pyproject.toml");
        assert_eq!(deps.len(), 3);
        let fast = deps.iter().find(|d| d.name == "fastmcp").unwrap();
        assert!(!fast.pinned);
        let pandas = deps.iter().find(|d| d.name == "pandas").unwrap();
        assert!(pandas.pinned);
    }

    #[test]
    fn transport_and_lockfile_detected() {
        let files = vec![
            f("server.json", r#"{ "name": "x", "packages": [ { "transport": { "type": "stdio" } } ] }"#),
            f("pyproject.toml", "[project]\nname=\"x\"\ndependencies = [\"httpx>=0.27\"]\n"),
        ];
        let m = parse_repo(&files);
        let sv = server(&m);
        assert_eq!(sv.attr("transport").and_then(|v| v.as_str()), Some("stdio"));
        assert_eq!(sv.attr("has_lockfile").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(kind_count(&m, "dependency"), 1);
    }

    #[test]
    fn lockfile_presence_flips_flag() {
        let files = vec![
            f("package.json", r#"{ "name": "x", "dependencies": { "zod": "^3.0.0" } }"#),
            f("package-lock.json", "{}"),
        ];
        let m = parse_repo(&files);
        assert_eq!(server(&m).attr("has_lockfile").and_then(|v| v.as_bool()), Some(true));
        // caret range → not pinned
        let dep = m.entities.iter().find(|e| e.id == "dep:zod").unwrap();
        assert_eq!(dep.attr("pinned").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn bind_detection_ignores_host_comparisons() {
        // real binds (0.0.0.0 in a host/bind/listen context)
        assert!(binds_all_line("DEFAULT_HOST = \"0.0.0.0\""));
        assert!(binds_all_line("app.run(host='0.0.0.0', port=8000)"));
        assert!(binds_all_line("srv.listen(3000, \"0.0.0.0\")"));
        assert!(binds_all_line("    default=\"0.0.0.0\","));
        // NOT binds: comparisons, unit-test / URL strings, no bind context
        assert!(!binds_all_line("        || bare_host == \"0.0.0.0\""));
        assert!(!binds_all_line("assert_eq!(ensure_url_scheme(\"0.0.0.0:3000\"), x)"));
        assert!(!binds_all_line("a line with no address"));
    }

    #[test]
    fn non_shipped_dirs_excluded_from_tools() {
        // block/goose regression: a tool that exists only under examples/ must NOT be attributed
        // to the shipped server. Result: zero tools → coverage gate withholds (not a wrong grade).
        let files = vec![
            f("package.json", r#"{ "name": "prod", "dependencies": { "@modelcontextprotocol/sdk": "^1.0.0" } }"#),
            f(
                "examples/mcp-wiki/server.py",
                "@mcp.tool()\ndef read_wikipedia_article(url: str):\n    return requests.get(url)\n",
            ),
        ];
        let m = parse_repo(&files);
        assert_eq!(kind_count(&m, "tool"), 0, "examples/ tools must be excluded from the grade");
        assert!(!analyzable(&m), "an MCP repo with only example tools must be withheld, not graded");
    }

    #[test]
    fn parse_is_deterministic() {
        let files = vec![f("pyproject.toml", "[project]\nname=\"x\"\ndependencies=[\"a>=1\",\"b==2\"]\n")];
        assert_eq!(parse_repo(&files).model_hash(), parse_repo(&files).model_hash());
    }
}
