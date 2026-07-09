//! End-to-end: a synthetic repo → mcp-parser → pack-mcp-core → grade.
//! This is the "structural pass runs on a real repo" proof.

use mcp_parser::{parse_repo, RepoFile};
use pack_mcp_core::{context, score, McpCorePack};
use score::Dim;

fn f(path: &str, content: &str) -> RepoFile {
    RepoFile { path: path.into(), content: content.into() }
}

// il-eli-mcp-shaped: stdio transport, no lockfile, >= python deps, read-only tool.
// BlueRock rated the real one LOW; our structural pass should flag unpinned deps but land high.
#[test]
fn il_eli_like_repo_flags_unpinned_deps_and_scores_high() {
    let files = vec![
        f(
            "server.json",
            r#"{ "name": "il-eli-mcp", "packages": [ { "registry_type": "pypi", "transport": { "type": "stdio" } } ] }"#,
        ),
        f(
            "pyproject.toml",
            "[project]\nname = \"il-eli-mcp\"\ndependencies = [\n  \"fastmcp>=0.2.0\",\n  \"httpx>=0.27\",\n]\n",
        ),
        f(
            "src/il_eli_mcp/server.py",
            "READ_ONLY = ToolAnnotations(readOnlyHint=True)\n\n@mcp.tool(annotations=READ_ONLY)\ndef il_search_laws(query: str, limit: int = 20):\n    pass\n",
        ),
    ];

    let m = parse_repo(&files);

    // parser facts
    let server = m
        .entities
        .iter()
        .find(|e| e.attr("mcp_kind").and_then(|v| v.as_str()) == Some("server"))
        .unwrap();
    assert_eq!(server.attr("transport").and_then(|v| v.as_str()), Some("stdio"));
    assert_eq!(server.attr("has_lockfile").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(mcp_parser::kind_count(&m, "dependency"), 2);
    assert_eq!(mcp_parser::kind_count(&m, "tool"), 1);

    // run the pack pipeline
    let pack = McpCorePack::new();
    let mut findings = engine::run_pack(&pack, &m);
    engine::attach_lines(&mut findings, &m);
    let (findings, mods) = context::apply(findings, &m);
    let report = score::score(&findings, &mods, &Dim::all());

    assert!(
        findings.iter().any(|x| x.rule_id == "MCP-DEPS-UNPINNED"),
        "unpinned python deps + no lockfile should fire MCP-DEPS-UNPINNED"
    );
    assert!(report.grade == 'A' || report.grade == 'B', "expected A/B, got {}", report.grade);
    assert!(!report.caps.iter().any(|c| c.contains("critical")));

    // scores.json serializes deterministically
    let a = report.to_json("matematicsolutions/il-eli-mcp", "https://github.com/matematicsolutions/il-eli-mcp", "a2b3437").to_canonical_string();
    let report2 = score::score(&findings, &mods, &Dim::all());
    let b = report2.to_json("matematicsolutions/il-eli-mcp", "https://github.com/matematicsolutions/il-eli-mcp", "a2b3437").to_canonical_string();
    assert_eq!(a, b);
}
