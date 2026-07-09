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
    Entity {
        id,
        kind: EntityKind::Resource,
        attributes: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        provenance: Provenance::explicit(path.to_string()),
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
fn tls_disabled(c: &str) -> bool {
    [
        "rejectUnauthorized: false",
        "rejectUnauthorized:false",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "verify=False",
        "verify = False",
        "InsecureSkipVerify: true",
        "InsecureSkipVerify:true",
    ]
    .iter()
    .any(|p| c.contains(p))
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
    taint: Option<taint::ToolTaint>,
}

fn is_js_ts(p: &str) -> bool {
    let b = basename(p);
    [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"].iter().any(|e| b.ends_with(e))
}

/// Tool inventory + source-flow taint. Python → `python::analyze`, JS/TS → `js::analyze`; other
/// source languages contribute no tools yet. Returns the tool records and whether any module has a
/// secret→exfil flow.
fn collect_tools(files: &[RepoFile]) -> (Vec<ToolRec>, bool) {
    let mut out: Vec<ToolRec> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut secret_exfil = false;
    for f in files.iter().filter(|f| is_source(&f.path)) {
        let analysis = if f.path.ends_with(".py") {
            python::analyze(&f.content)
        } else if is_js_ts(&f.path) {
            js::analyze(&f.content)
        } else {
            continue;
        };
        if analysis.secret_source_to_egress {
            secret_exfil = true;
        }
        for t in analysis.tools {
            if !t.name.is_empty() && seen.insert(t.name.clone()) {
                out.push(ToolRec { name: t.name.clone(), path: f.path.clone(), taint: Some(t) });
            }
        }
    }
    (out, secret_exfil)
}

// --- core: pure function of the input files --------------------------------
pub fn parse_repo(files: &[RepoFile]) -> FactModel {
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

    let (tools, secret_exfil) = collect_tools(files);
    let tls = files.iter().filter(|f| is_source(&f.path)).any(|f| tls_disabled(&f.content));

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
    ];
    if !langs.is_empty() {
        sattrs.push(("languages", AttrValue::List(langs.iter().map(|l| s(l)).collect())));
    }
    if tls {
        sattrs.push(("tls_verify_disabled", AttrValue::Bool(true)));
    }
    if let Some(ro) = all_read_only(files) {
        sattrs.push(("all_tools_read_only", AttrValue::Bool(ro)));
    }
    if secret_exfil {
        sattrs.push(("secret_source_to_egress", AttrValue::Bool(true)));
    }
    entities.push(ent(format!("mcp_server:{name}"), &server_path, sattrs));

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
        entities.push(ent(format!("tool:{}", t.name), &t.path, a));
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
    fn parse_is_deterministic() {
        let files = vec![f("pyproject.toml", "[project]\nname=\"x\"\ndependencies=[\"a>=1\",\"b==2\"]\n")];
        assert_eq!(parse_repo(&files).model_hash(), parse_repo(&files).model_hash());
    }
}
