//! Shared source-flow taint types + language-agnostic helpers. The per-language analyzers
//! (`python`, `js`) both produce an [`Analysis`]. Taint model: link a sink call to a tool's
//! parameter names ("tainted" sources). NOT full dataflow — precision-tuned v1 (see `python.rs`).

/// Per-tool taint facts. Bools default false; set true when a sink references a tool param.
pub struct ToolTaint {
    pub name: String,
    pub params: Vec<String>,
    pub ssrf: bool,
    pub fs: bool,
    pub shell: bool,
    pub sql: bool,
    pub deser: bool,
    pub unbounded_limit: bool,
    pub redos: bool,
    pub desc_hidden_unicode: bool,
    /// Source file the tool is defined in (for provenance + same-file taint scoping).
    pub file: String,
}

impl ToolTaint {
    pub fn new(name: String, params: Vec<String>) -> Self {
        Self {
            name,
            params,
            ssrf: false,
            fs: false,
            shell: false,
            sql: false,
            deser: false,
            unbounded_limit: false,
            redos: false,
            desc_hidden_unicode: false,
            file: String::new(),
        }
    }
}

pub struct Analysis {
    pub tools: Vec<ToolTaint>,
    pub secret_source_to_egress: bool,
}

/// Known credential-exfiltration destinations. The Critical `secret_source_to_egress` rule fires
/// ONLY on these (not a generic external host) — a token sent to its own declared API is not exfil.
pub const EXFIL_HOSTS: &[&str] = &[
    "discord.com/api/webhooks", "api.telegram.org", "pastebin.com", "requestbin", "ngrok",
    "oast.", "interact.sh", "hookbin", "webhook.site", "burpcollaborator",
];
pub const SECRET_WORDS: &[&str] = &[
    "TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY",
];

/// Identifier char for both Python and JS/TS (JS allows `$`).
pub fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// `word` appears in `line` bounded by non-identifier chars (whole identifier, not substring).
pub fn word_present(line: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(pos) = line[start..].find(word) {
        let idx = start + pos;
        let before_ok = idx == 0 || !is_ident(bytes[idx - 1] as char);
        let after = idx + word.len();
        let after_ok = after >= bytes.len() || !is_ident(bytes[after] as char);
        if before_ok && after_ok {
            return true;
        }
        start = idx + word.len();
        if start >= line.len() {
            break;
        }
    }
    false
}

pub fn is_zero_width(c: char) -> bool {
    matches!(c as u32,
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

pub fn any_marker(line: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| line.contains(m))
}

/// Split a parameter list on top-level commas (ignoring commas inside `()[]{}`).
pub fn split_top_level(inner: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut d = 0i32;
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' | '{' => {
                d += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                d -= 1;
                cur.push(ch);
            }
            ',' if d == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_present_is_whole_word() {
        assert!(word_present("df.str.contains(court, na=False)", "court"));
        assert!(!word_present("courthouse = 1", "court"));
        assert!(word_present("body: JSON.stringify({ key })", "key"));
    }
}
