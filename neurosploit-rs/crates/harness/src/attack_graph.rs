//! Attack graph & kill-chain mapping.
//!
//! Enriches findings with OWASP Top 10 / MITRE ATT&CK / kill-chain stage /
//! exploitability (derived from CWE + severity when the model didn't supply
//! them), then renders an attack-path graph (Mermaid) and a kill-chain table for
//! the report, plus a compact ASCII summary for the REPL.

use crate::types::Finding;

/// CWE → (OWASP Top 10 2021, MITRE ATT&CK technique, kill-chain stage).
fn map_cwe(cwe: &str) -> (&'static str, &'static str, &'static str) {
    let n: u32 = cwe.trim_start_matches("CWE-").parse().unwrap_or(0);
    match n {
        89 | 943 => ("A03:2021-Injection", "T1190", "initial-access"),
        77 | 78 | 94 | 95 | 917 | 1336 => ("A03:2021-Injection", "T1059", "execution"),
        79 | 80 => ("A03:2021-Injection", "T1059.007", "execution"),
        90 => ("A03:2021-Injection", "T1190", "initial-access"),
        611 | 776 => ("A05:2021-Security-Misconfiguration", "T1190", "initial-access"),
        918 => ("A10:2021-SSRF", "T1090", "lateral"),
        22 | 23 | 98 | 73 => ("A01:2021-Broken-Access-Control", "T1083", "execution"),
        639 | 862 | 863 | 284 | 285 => ("A01:2021-Broken-Access-Control", "T1078", "privesc"),
        287 | 384 | 613 | 620 => ("A07:2021-Auth-Failures", "T1078", "initial-access"),
        798 | 522 | 321 | 256 | 257 | 312 | 319 => ("A07:2021-Auth-Failures", "T1552", "credential-access"),
        502 => ("A08:2021-Software-Data-Integrity", "T1059", "execution"),
        327 | 328 | 916 | 326 | 330 => ("A02:2021-Cryptographic-Failures", "T1600", "credential-access"),
        200 | 209 | 538 | 540 | 532 => ("A05:2021-Security-Misconfiguration", "T1592", "recon"),
        601 => ("A01:2021-Broken-Access-Control", "T1566", "initial-access"),
        352 => ("A01:2021-Broken-Access-Control", "T1189", "execution"),
        434 => ("A04:2021-Insecure-Design", "T1505.003", "execution"),
        1321 | 915 => ("A08:2021-Software-Data-Integrity", "T1059", "execution"),
        400 | 770 | 1333 | 799 => ("A04:2021-Insecure-Design", "T1499", "impact"),
        _ => ("A04:2021-Insecure-Design", "T1190", "initial-access"),
    }
}

fn exploitability(sev: &str, conf: f64) -> &'static str {
    match (sev, conf) {
        (_, c) if c >= 0.85 => "trivial",
        ("Critical" | "High", _) => "moderate",
        _ => "hard",
    }
}

/// Fill in any empty mapping fields on each finding (does not overwrite model-set values).
pub fn enrich(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let (owasp, mitre, stage) = map_cwe(&f.cwe);
        if f.owasp.is_empty() { f.owasp = owasp.into(); }
        if f.mitre.is_empty() { f.mitre = mitre.into(); }
        if f.stage.is_empty() { f.stage = stage.into(); }
        if f.exploitability.is_empty() { f.exploitability = exploitability(&f.severity, f.confidence).into(); }
        if f.business_impact.is_empty() { f.business_impact = f.impact.clone(); }
    }
}

const STAGE_ORDER: &[&str] = &[
    "recon", "initial-access", "execution", "credential-access", "privesc", "lateral", "exfil", "impact",
];

fn stage_rank(s: &str) -> usize {
    STAGE_ORDER.iter().position(|x| *x == s).unwrap_or(STAGE_ORDER.len())
}

/// Mermaid flowchart of the attack path: findings grouped by kill-chain stage,
/// with explicit chains_from edges plus implicit stage→stage progression.
pub fn mermaid(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut out = String::from("flowchart LR\n");
    // stage subgraphs
    let mut by_stage: std::collections::BTreeMap<usize, Vec<&Finding>> = Default::default();
    for f in findings {
        by_stage.entry(stage_rank(&f.stage)).or_default().push(f);
    }
    let node_id = |f: &Finding| -> String {
        format!("n{}", sanitize_id(&f.id))
    };
    for (rank, group) in &by_stage {
        let stage = STAGE_ORDER.get(*rank).copied().unwrap_or("other");
        out.push_str(&format!("  subgraph S{rank}[\"{}\"]\n", stage));
        for f in group {
            out.push_str(&format!("    {}[\"{}<br/>{} · {}\"]\n",
                node_id(f), esc(&f.title), esc(&f.severity), esc(&f.owasp)));
        }
        out.push_str("  end\n");
    }
    // explicit chain edges
    let ids: std::collections::HashMap<&str, &Finding> = findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let mut had_edge = false;
    for f in findings {
        for src in &f.chains_from {
            if let Some(sf) = ids.get(src.as_str()) {
                out.push_str(&format!("  {} --> {}\n", node_id(sf), node_id(f)));
                had_edge = true;
            }
        }
    }
    // implicit progression between consecutive populated stages if no explicit edges
    if !had_edge && by_stage.len() > 1 {
        let ranks: Vec<usize> = by_stage.keys().copied().collect();
        for w in ranks.windows(2) {
            if let (Some(a), Some(b)) = (by_stage[&w[0]].first(), by_stage[&w[1]].first()) {
                out.push_str(&format!("  {} -.-> {}\n", node_id(a), node_id(b)));
            }
        }
    }
    out
}

/// Compact ASCII kill-chain for the REPL: one line per stage with its findings.
pub fn ascii_killchain(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "  (no findings to map)".into();
    }
    let mut by_stage: std::collections::BTreeMap<usize, Vec<&Finding>> = Default::default();
    for f in findings {
        by_stage.entry(stage_rank(&f.stage)).or_default().push(f);
    }
    let mut out = String::new();
    for (rank, group) in &by_stage {
        let stage = STAGE_ORDER.get(*rank).copied().unwrap_or("other");
        out.push_str(&format!("  ▸ {:<16} ", stage));
        let items: Vec<String> = group.iter()
            .map(|f| format!("[{}] {} ({})", f.severity, f.title, f.mitre))
            .collect();
        out.push_str(&items.join("\n                     "));
        out.push('\n');
    }
    out
}

fn sanitize_id(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).take(24).collect()
}
fn esc(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ").chars().take(60).collect()
}
