//! sentinel-mcp — scan an MCP server repo and emit `scores.json` (rubric v1.1).
//!
//! usage: sentinel-mcp <repo-path> [--server owner/name] [--repo-url URL] [--commit SHA]
//!
//! Prints the canonical `scores.json` to stdout and a one-line summary to stderr. Commit and
//! repo-url default to the repo's own git metadata when not passed (so a score pins to a commit).

use std::path::Path;

use mcp_parser::{parse_repo, read_repo};
use pack_mcp_core::{context, score, McpCorePack};
use score::Dim;

fn git_out(path: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    let mut path: Option<String> = None;
    let mut repo_url: Option<String> = None;
    let mut commit: Option<String> = None;
    let mut server: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--repo-url" => repo_url = it.next(),
            "--commit" => commit = it.next(),
            "--server" => server = it.next(),
            "-h" | "--help" => {
                eprintln!("usage: sentinel-mcp <repo-path> [--server owner/name] [--repo-url URL] [--commit SHA]");
                return;
            }
            _ if path.is_none() => path = Some(a),
            _ => {}
        }
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("error: missing <repo-path>\nusage: sentinel-mcp <repo-path> [--server owner/name] [--repo-url URL] [--commit SHA]");
            std::process::exit(2);
        }
    };

    let files = match read_repo(Path::new(&path)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: reading {path}: {e}");
            std::process::exit(1);
        }
    };
    if files.is_empty() {
        eprintln!("warning: no scannable files under {path}");
    }

    let model = parse_repo(&files);
    let pack = McpCorePack::new();
    let mut findings = engine::run_pack(&pack, &model);
    engine::attach_lines(&mut findings, &model);
    let (findings, mods) = context::apply(findings, &model);
    let report = score::score(&findings, &mods, &Dim::all());

    let server = server.unwrap_or_else(|| {
        Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "server".to_string())
    });
    let commit = commit
        .or_else(|| git_out(&path, &["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let repo_url = repo_url
        .or_else(|| git_out(&path, &["remote", "get-url", "origin"]))
        .unwrap_or_default();

    let json = report.to_json(&server, &repo_url, &commit);
    println!("{}", json.to_canonical_string());

    let caps = if report.caps.is_empty() {
        String::new()
    } else {
        format!("  ·  caps: {}", report.caps.join(", "))
    };
    eprintln!(
        "\n{}  grade {} (composite {})  ·  {} finding(s)  ·  {} context modifier(s){}",
        server,
        report.grade,
        report.composite,
        findings.len(),
        report.modifiers.len(),
        caps
    );
}
