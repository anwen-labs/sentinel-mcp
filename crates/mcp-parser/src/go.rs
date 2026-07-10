//! Go source-flow taint-lite. Two MCP-SDK idioms in the wild:
//!
//!   A. `mcp.Tool{ Name: "x", InputSchema: {Properties: {"owner": ...}} }` with an inline
//!      `func(ctx, deps, req, args map[string]any)` handler that reads params via
//!      `owner, err := RequiredParam[string](args, "owner")` (github/github-mcp-server).
//!   B. `var X = MustTool("name", "desc", handlerFn, ...)` where `handlerFn(ctx, args T)` uses a
//!      typed struct — params are read as `args.Field` (grafana/mcp-grafana).
//!
//! Taint sources are therefore the LOCALS assigned from a request getter (idiom A) or the
//! `args.<Field>` accesses (idiom B) — "request-arg-var taint". Same precision-tuned, same-file v1
//! model as `python.rs`/`js.rs`: a sink line must reference a tainted token, and a validation guard
//! in the body suppresses the finding. API-client calls (`client.Do`, `c.baseURL + path`) and
//! non-arg URLs (a GitHub-returned `logURL`) are deliberately NOT flagged — these servers are
//! clean API wrappers and must grade as such.

use crate::taint::{any_marker, is_ident, is_zero_width, word_present, Analysis, ToolTaint};

const TOOL_STRUCT: &str = "mcp.Tool{";
const MUST_TOOL: &str = "MustTool(";

// Getters that read a tool argument into a local (idiom A). Matched as `<local>, ... := <getter>`.
const ARG_GETTERS: &[&str] = &[
    "RequiredParam", "OptionalParam", "RequiredInt", "OptionalInt", "RequiredBigInt",
    "OptionalBigInt", "OptionalStringArrayParam", "OptionalNumberParam", "RequiredStringArrayParam",
    "OptionalBooleanParam", "OptionalPaginationParams",
];

// Raw outbound-HTTP sinks. NARROW on purpose: an API client's own `client.Do(req)` /
// `client.Issues.Get(...)` is not here — only a raw fetch whose URL could be the tainted value.
const SSRF: &[&str] = &["http.Get(", "http.Post(", "http.Head(", "http.NewRequest("];
const SHELL: &[&str] = &["exec.Command(", "exec.CommandContext("];
const FS: &[&str] = &[
    "os.ReadFile(", "os.Open(", "os.OpenFile(", "os.WriteFile(", "os.Create(", "ioutil.ReadFile(",
];
const SQL: &[&str] = &[".Query(", ".QueryContext(", ".Exec(", ".ExecContext(", ".QueryRow("];

// A URL/host validation or fixed-base join in the body suppresses SSRF (grafana validates every
// outbound URL against its own base host).
const URL_GUARD: &[&str] = &[
    "ValidateGrafanaURL", "validateURL", "validate_url", "allowlist", "allow_list", "IsPrivate",
    "ParseIP", "isAllowedHost", "checkURL", "url.Parse", "net.ParseIP",
];
// Building the URL by concatenating a trusted base host => fixed destination, not SSRF.
const BASE_JOIN: &[&str] = &["baseURL", "baseUrl", "base_url", ".base", "BaseURL", "c.url"];
const PATH_GUARD: &[&str] = &[
    "filepath.Clean", "filepath.Rel(", "filepath.IsLocal", "SecureJoin", "strings.Contains", "\"..\"",
];

/// Byte positions of each tool-registration marker, in order.
fn marker_positions(content: &str) -> Vec<usize> {
    let mut pos = Vec::new();
    for m in [TOOL_STRUCT, MUST_TOOL] {
        let mut start = 0;
        while let Some(p) = content[start..].find(m) {
            pos.push(start + p);
            start += p + m.len();
        }
    }
    pos.sort_unstable();
    pos.dedup();
    pos
}

/// The first `Name: "..."` string after `from` (idiom A tool name).
fn struct_name(region: &str) -> Option<String> {
    let n = region.find("Name:")?;
    quoted_after(&region[n + 5..])
}

/// The first quoted string literal in `s` (skipping leading whitespace/newlines).
fn quoted_after(s: &str) -> Option<String> {
    let q = s.find(['"', '`'])?;
    let qc = s.as_bytes()[q] as char;
    let rest = &s[q + 1..];
    let end = rest.find(qc)?;
    let v = &rest[..end];
    if v.is_empty() || v.len() > 80 {
        None
    } else {
        Some(v.to_string())
    }
}

/// Property keys of an `InputSchema{ Properties: map[string]*jsonschema.Schema{ "k": {...} } }`
/// block — the declared parameter names (idiom A).
fn schema_props(region: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(p) = region.find("Properties:") {
        // scan the map literal for top-level `"key":` entries
        let after = &region[p..];
        let bytes = after.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                if let Some(end) = after[i + 1..].find('"') {
                    let key = &after[i + 1..i + 1 + end];
                    let next = after[i + 1 + end + 1..].trim_start();
                    if next.starts_with(':') && !key.is_empty() && key.len() <= 64 {
                        out.push(key.to_string());
                    }
                    i = i + 1 + end + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
    out
}

/// Locals assigned from a request getter in this region: `local, err := RequiredParam[..](args,...)`.
fn tainted_locals(region: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in region.lines() {
        let l = line.trim();
        if !l.contains(":=") || !ARG_GETTERS.iter().any(|g| l.contains(g)) {
            continue;
        }
        // require the getter to read from `args` / the request bag
        if !l.contains("(args") && !l.contains("(request") && !l.contains("(req,") && !l.contains(", args")
            && !l.contains("Arguments")
        {
            // still accept the common `RequiredParam[T](args, "x")` even if spacing differs
            if !l.contains("args") {
                continue;
            }
        }
        let lhs = &l[..l.find(":=").unwrap()];
        // first identifier on the LHS is the value local (the `err` is second)
        let id: String = lhs.trim_start().chars().take_while(|c| is_ident(*c)).collect();
        if !id.is_empty() && id != "_" && id != "err" {
            out.push(id);
        }
    }
    out
}

/// The handler symbol passed to `MustTool("name", "desc", handlerSym, ...)` — 3rd argument (idiom B).
fn must_tool_handler(region: &str) -> Option<String> {
    // region begins at `MustTool(`. Split the call's top-level args.
    let open = region.find('(')?;
    let inner = &region[open + 1..];
    let mut depth = 0i32;
    let mut args = Vec::new();
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' if depth > 0 => {
                depth -= 1;
                cur.push(ch);
            }
            ')' if depth == 0 => break,
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur));
                if args.len() >= 3 {
                    break;
                }
            }
            _ => cur.push(ch),
        }
    }
    let h = args.get(2)?.trim();
    let sym: String = h.chars().take_while(|c| is_ident(*c)).collect();
    if sym.is_empty() {
        None
    } else {
        Some(sym)
    }
}

/// Body region of `func <name>(...) {...}` in `content`, matched by brace balance.
fn func_body<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("func {name}(");
    let start = content.find(&pat)?;
    let open = start + content[start..].find('{')?;
    let bytes = content.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&content[open..=i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Some(&content[open..])
}

/// Run the sink scan over `body`, given the set of tainted tokens (locals or `args.Field` markers).
/// `tainted_marker` = a token that itself signals request-derived data (idiom B uses `args.`).
fn scan_sinks(t: &mut ToolTaint, body: &str, locals: &[String], args_field_taint: bool) {
    let url_guard = body.lines().any(|l| any_marker(l, URL_GUARD));
    let path_guard = body.lines().any(|l| any_marker(l, PATH_GUARD));
    for line in body.lines() {
        let tainted = (args_field_taint && line.contains("args."))
            || locals.iter().any(|v| word_present(line, v));
        if !tainted {
            continue;
        }
        if any_marker(line, SSRF) && !any_marker(line, BASE_JOIN) && !url_guard {
            t.ssrf = true;
        }
        if any_marker(line, SHELL) {
            t.shell = true;
        }
        if any_marker(line, FS) && !path_guard {
            t.fs = true;
        }
        if any_marker(line, SQL) && (line.contains(" + ") || line.contains("fmt.Sprintf")) {
            t.sql = true;
        }
    }
}

pub fn analyze(content: &str) -> Analysis {
    let positions = marker_positions(content);
    let mut tools: Vec<ToolTaint> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (i, &start) in positions.iter().enumerate() {
        let end = positions.get(i + 1).copied().unwrap_or(content.len());
        let region = &content[start..end];
        let is_must = content[start..].starts_with(MUST_TOOL);

        let name = if is_must {
            quoted_after(&region[MUST_TOOL.len()..])
        } else {
            struct_name(region)
        };
        let name = match name {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        if !seen.insert(name.clone()) {
            continue;
        }

        let mut t = ToolTaint::new(name.clone(), Vec::new());
        t.line = content[..start].matches('\n').count() as u32 + 1;
        t.desc_hidden_unicode = region.chars().any(is_zero_width);

        if is_must {
            // idiom B: params + taint come from the referenced handler's own body.
            if let Some(sym) = must_tool_handler(region) {
                if let Some(body) = func_body(content, &sym) {
                    scan_sinks(&mut t, body, &[], true);
                }
            }
        } else {
            // idiom A: params from the schema; taint from request-getter locals in the same region.
            t.params = schema_props(region);
            let locals = tainted_locals(region);
            scan_sinks(&mut t, region, &locals, false);
        }
        tools.push(t);
    }

    Analysis { tools, secret_egress: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_struct_tool_name_and_params() {
        let src = r#"
mcp.Tool{
    Name: "actions_list",
    InputSchema: &jsonschema.Schema{
        Properties: map[string]*jsonschema.Schema{
            "owner": {Type: "string"},
            "repo": {Type: "string"},
        },
    },
},
func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest, args map[string]any) {
    owner, err := RequiredParam[string](args, "owner")
    _ = owner
}
"#;
        let a = analyze(src);
        assert_eq!(a.tools.len(), 1);
        assert_eq!(a.tools[0].name, "actions_list");
        assert!(a.tools[0].params.contains(&"owner".to_string()));
        assert!(a.tools[0].params.contains(&"repo".to_string()));
        assert!(!a.tools[0].ssrf, "an API-wrapper with no raw fetch is clean");
    }

    #[test]
    fn github_logurl_get_is_not_flagged() {
        // http.Get on a GitHub-returned URL (not a tool arg) must NOT be SSRF.
        let src = r#"
mcp.Tool{ Name: "get_job_logs" },
func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest, args map[string]any) {
    owner, err := RequiredParam[string](args, "owner")
    _ = owner
    logURL := resp.GetURL()
    httpResp, err := http.Get(logURL)
    _ = httpResp
}
"#;
        let a = analyze(src);
        assert!(!a.tools[0].ssrf, "logURL is not a request-arg var — no SSRF");
    }

    #[test]
    fn github_real_ssrf_from_arg_is_flagged() {
        // if a tool DID fetch a user-supplied URL raw, we catch it.
        let src = r#"
mcp.Tool{ Name: "fetch" },
func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest, args map[string]any) {
    target, err := RequiredParam[string](args, "url")
    resp, err := http.Get(target)
    _ = resp
}
"#;
        let a = analyze(src);
        assert!(a.tools[0].ssrf, "raw http.Get(target) where target is a request arg is SSRF");
    }

    #[test]
    fn grafana_musttool_name_and_clean_body() {
        let src = r#"
func getDashboardByUID(ctx context.Context, args GetDashboardByUIDParams) (*DashboardResponse, error) {
    res, err := fetchDashboard(ctx, args.UID)
    return res, err
}

var GetDashboardByUID = mcpgrafana.MustTool(
    "get_dashboard_by_uid",
    "Retrieves the complete dashboard for a UID.",
    getDashboardByUID,
    mcp.WithReadOnlyHintAnnotation(true),
)
"#;
        let a = analyze(src);
        assert_eq!(a.tools.len(), 1);
        assert_eq!(a.tools[0].name, "get_dashboard_by_uid");
        assert!(!a.tools[0].ssrf, "args.UID -> client call is not raw SSRF");
    }

    #[test]
    fn grafana_base_join_is_not_ssrf() {
        // url built as baseURL + path from args is a fixed-host call, not SSRF.
        let src = r#"
func doIt(ctx context.Context, args P) error {
    req, err := http.NewRequest(http.MethodGet, c.baseURL+args.Path, nil)
    _ = req
    return err
}
var DoIt = MustTool("do_it", "desc", doIt)
"#;
        let a = analyze(src);
        assert!(!a.tools[0].ssrf, "baseURL + args.Path is a fixed destination — not SSRF");
    }
}
