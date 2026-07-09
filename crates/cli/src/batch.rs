//! sentinel-mcp-batch — scan every server in a targets.csv and write one aggregated `scores.json`.
//!
//! usage: sentinel-mcp-batch --targets targets.csv --out scores.json
//!        [--workdir DIR] [--limit N] [--keep]
//!
//! Designed for unattended (overnight) runs: it shallow-clones each repo at current HEAD, records
//! the resolved commit (so a score pins to a commit), scans in-process, and aggregates. Clone
//! failures are logged and skipped, never fatal. Re-running refreshes grades as servers change —
//! the output feeds the registry/website generator.

use std::path::PathBuf;
use std::process::Command;

use fact_model::Json;
use mcp_parser::{model_summary, parse_repo, read_repo};
use pack_mcp_core::{context, score, McpCorePack};
use score::Dim;

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_q {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_q = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_q = true,
                ',' => out.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
    }
    out.push(cur);
    out
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let mut targets = "targets.csv".to_string();
    let mut out_path = "scores.json".to_string();
    let mut workdir: Option<String> = None;
    let mut limit: Option<usize> = None;
    let mut keep = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--targets" => targets = it.next().unwrap_or(targets),
            "--out" => out_path = it.next().unwrap_or(out_path),
            "--workdir" => workdir = it.next(),
            "--limit" => limit = it.next().and_then(|v| v.parse().ok()),
            "--keep" => keep = true,
            "-h" | "--help" => {
                eprintln!("usage: sentinel-mcp-batch --targets targets.csv --out scores.json [--workdir DIR] [--limit N] [--keep]");
                return;
            }
            _ => {}
        }
    }

    let csv = match std::fs::read_to_string(&targets) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: reading {targets}: {e}");
            std::process::exit(1);
        }
    };
    let mut lines = csv.lines();
    let header = parse_csv_line(lines.next().unwrap_or(""));
    let idx = |name: &str| header.iter().position(|h| h == name);
    let (ci_repo, ci_url) = match (idx("repo"), idx("repo_url")) {
        (Some(r), Some(u)) => (r, u),
        _ => {
            eprintln!("error: targets.csv must have 'repo' and 'repo_url' columns");
            std::process::exit(1);
        }
    };

    // Collect unique repos (dedup by url; monorepo per-package rows collapse to one repo scan).
    let mut seen = std::collections::BTreeSet::new();
    let mut repos: Vec<(String, String)> = Vec::new();
    for line in lines {
        let row = parse_csv_line(line);
        let url = row.get(ci_url).cloned().unwrap_or_default();
        let repo = row.get(ci_repo).cloned().unwrap_or_default();
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        repos.push((repo, url));
    }
    if let Some(n) = limit {
        repos.truncate(n);
    }

    let work = workdir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sentinel-mcp-batch"));
    let _ = std::fs::create_dir_all(&work);

    let total = repos.len();
    eprintln!("scanning {total} unique repos → {out_path}\n");

    let mut servers: Vec<Json> = Vec::new();
    let mut summary: Vec<(String, char, u32, usize)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for (i, (repo, url)) in repos.iter().enumerate() {
        let safe = repo.replace(['/', '\\', ':'], "__");
        let dir = work.join(&safe);
        let _ = std::fs::remove_dir_all(&dir);
        eprint!("[{}/{}] {repo} … ", i + 1, total);

        if git(&["clone", "--depth", "1", "--quiet", url, &dir.to_string_lossy()]).is_none()
            && !dir.exists()
        {
            eprintln!("CLONE FAILED");
            failures.push(repo.clone());
            continue;
        }
        let dir_s = dir.to_string_lossy().to_string();
        let commit = git(&["-C", &dir_s, "rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());

        let files = read_repo(&dir).unwrap_or_default();
        let model = parse_repo(&files);
        let pack = McpCorePack::new();
        let mut findings = engine::run_pack(&pack, &model);
        engine::attach_lines(&mut findings, &model);
        let (findings, mods) = context::apply(findings, &model);
        let report = score::score(&findings, &mods, &Dim::all(), mcp_parser::analyzable(&model));

        let gchar = if report.status == score::ScoreStatus::Scored {
            eprintln!(
                "grade {} ({})  ·  {}  ·  {} finding(s)",
                report.grade,
                report.composite,
                model_summary(&model),
                findings.len()
            );
            report.grade
        } else {
            eprintln!("NOT GRADED (no tools resolved)  ·  {}", model_summary(&model));
            '?'
        };
        summary.push((repo.clone(), gchar, report.composite, findings.len()));
        servers.push(report.to_json(repo, url, &commit));

        if !keep {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let doc = Json::Obj(vec![
        ("generated_at_unix".into(), Json::Int(generated_at)),
        ("ruleset_version".into(), Json::Str("pack-mcp-core@0.1.0".into())),
        ("count".into(), Json::Int(servers.len() as i64)),
        ("servers".into(), Json::Arr(servers)),
    ]);
    if let Err(e) = std::fs::write(&out_path, doc.to_canonical_string()) {
        eprintln!("error: writing {out_path}: {e}");
        std::process::exit(1);
    }

    // Grade distribution + summary table.
    eprintln!("\n=== summary ({} scored, {} failed) ===", summary.len(), failures.len());
    for g in ['A', 'B', 'C', 'D', 'F', '?'] {
        let n = summary.iter().filter(|s| s.1 == g).count();
        if n > 0 {
            let label = if g == '?' { "not-graded".to_string() } else { g.to_string() };
            eprint!("{label}:{n}  ");
        }
    }
    eprintln!("\n");
    let mut sorted = summary.clone();
    sorted.sort_by(|a, b| (b.1 as u8).cmp(&(a.1 as u8)).then(a.0.cmp(&b.0))); // worst grade first
    for (repo, grade, composite, n) in &sorted {
        if *grade == '?' {
            eprintln!("  ?    —                {repo}  (insufficient coverage)");
        } else {
            eprintln!("  {grade}  {composite:>3}  {n:>2} finding(s)  {repo}");
        }
    }
    if !failures.is_empty() {
        eprintln!("\nfailed to clone: {}", failures.join(", "));
    }
    eprintln!("\nwrote {out_path}");
}
