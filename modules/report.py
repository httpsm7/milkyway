"""
report.py — HTML report generator (dark theme, M7Hunter style)
"""
import json
import os
from datetime import datetime
from typing import Dict, List


def generate_report(db, config: dict, output_dir: str) -> str:
    """Generate full HTML report. Returns path to report file."""

    findings = db.get_findings(status="verified")
    all_findings = db.get_findings()
    chains = db.get_all_chains() if hasattr(db, 'get_all_chains') else _get_chains(db)
    stats = db.get_stats()
    actions = db.get_recent_actions(limit=50)

    # Calculate risk score
    risk_score = _calculate_risk(stats)

    target = config.get("target", "Unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {target}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0a0a0f; color:#e0e0e0; font-family:'Courier New',monospace; }}
  .header {{ background:linear-gradient(135deg,#1a0a2e,#0d1b2a); padding:40px; text-align:center; border-bottom:2px solid #7b2d8b; }}
  .eye {{ font-size:60px; }}
  h1 {{ color:#9b59b6; font-size:2em; margin:10px 0; }}
  .subtitle {{ color:#3498db; font-size:0.9em; }}
  .warning {{ background:#2d1a00; border:1px solid #e67e22; color:#e67e22; padding:10px 20px; margin:10px auto; max-width:800px; border-radius:4px; font-size:0.8em; }}
  .container {{ max-width:1200px; margin:0 auto; padding:20px; }}
  .risk-box {{ background:#1a1a2e; border:2px solid #e74c3c; border-radius:8px; padding:20px; margin:20px 0; text-align:center; }}
  .risk-score {{ font-size:4em; font-weight:bold; }}
  .risk-critical {{ color:#e74c3c; }} .risk-high {{ color:#e67e22; }}
  .risk-medium {{ color:#f39c12; }} .risk-low {{ color:#27ae60; }}
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:15px; margin:20px 0; }}
  .stat-card {{ background:#1a1a2e; border:1px solid #2c2c4e; border-radius:8px; padding:15px; text-align:center; }}
  .stat-num {{ font-size:2.5em; font-weight:bold; color:#9b59b6; }}
  .stat-label {{ color:#aaa; font-size:0.8em; margin-top:5px; }}
  .section {{ margin:30px 0; }}
  .section-title {{ color:#9b59b6; font-size:1.3em; border-bottom:1px solid #333; padding-bottom:10px; margin-bottom:20px; }}
  .finding-card {{ background:#1a1a2e; border-left:4px solid #333; border-radius:4px; padding:20px; margin:15px 0; }}
  .finding-card.critical {{ border-left-color:#e74c3c; }}
  .finding-card.high {{ border-left-color:#e67e22; }}
  .finding-card.medium {{ border-left-color:#f39c12; }}
  .finding-card.low {{ border-left-color:#27ae60; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:3px; font-size:0.75em; font-weight:bold; }}
  .badge-critical {{ background:#e74c3c; color:#fff; }}
  .badge-high {{ background:#e67e22; color:#fff; }}
  .badge-medium {{ background:#f39c12; color:#000; }}
  .badge-low {{ background:#27ae60; color:#fff; }}
  .badge-info {{ background:#3498db; color:#fff; }}
  .finding-title {{ font-size:1.1em; font-weight:bold; margin:10px 0 5px; color:#e0e0e0; }}
  .finding-endpoint {{ color:#3498db; font-size:0.85em; margin:5px 0; }}
  .finding-desc {{ color:#aaa; font-size:0.9em; margin:8px 0; line-height:1.5; }}
  .proof-block {{ background:#0d0d1a; border:1px solid #333; padding:10px; border-radius:4px; font-size:0.8em; color:#2ecc71; margin:10px 0; overflow-x:auto; }}
  .remediation {{ background:#0d2a1a; border:1px solid #27ae60; padding:10px; border-radius:4px; font-size:0.85em; color:#2ecc71; margin:10px 0; }}
  .chain-card {{ background:#1a1a2e; border:1px solid #9b59b6; border-radius:8px; padding:20px; margin:15px 0; }}
  .chain-title {{ color:#9b59b6; font-size:1.1em; font-weight:bold; margin-bottom:10px; }}
  .chain-step {{ padding:5px 0; color:#aaa; font-size:0.9em; }}
  .chain-step::before {{ content:"→ "; color:#9b59b6; }}
  .ai-log {{ background:#0a0a0f; border:1px solid #222; border-radius:4px; padding:10px; margin:5px 0; font-size:0.75em; }}
  .ai-action {{ color:#3498db; }} .ai-reason {{ color:#aaa; }} .ai-model {{ color:#9b59b6; }}
  .confidence-bar {{ height:6px; background:#333; border-radius:3px; margin:5px 0; }}
  .confidence-fill {{ height:6px; border-radius:3px; background:linear-gradient(90deg,#e74c3c,#f39c12,#27ae60); }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:#1a1a2e; color:#9b59b6; padding:10px; text-align:left; }}
  td {{ padding:10px; border-bottom:1px solid #222; font-size:0.85em; }}
  tr:hover {{ background:#111; }}
  .footer {{ text-align:center; padding:30px; color:#444; font-size:0.8em; border-top:1px solid #222; margin-top:50px; }}
  .toc a {{ color:#3498db; text-decoration:none; display:block; padding:3px 0; }}
  .toc a:hover {{ color:#9b59b6; }}
</style>
</head>
<body>

<div class="header">
  <div class="eye">👁</div>
  <h1>AUTONOMOUS PENTEST AGENT</h1>
  <div class="subtitle">Security Assessment Report</div>
  <div style="margin-top:15px;color:#aaa;font-size:0.85em;">
    Target: <span style="color:#3498db">{target}</span> &nbsp;|&nbsp;
    Date: {timestamp} &nbsp;|&nbsp;
    Mode: {config.get('mode','standard')}
  </div>
</div>

<div style="text-align:center;">
  <div class="warning">
    ⚠ This report contains sensitive security information. Handle with care. For authorized security testing only.
  </div>
</div>

<div class="container">

<!-- RISK SCORE -->
<div class="risk-box">
  <div style="color:#aaa;font-size:0.9em;">OVERALL RISK SCORE</div>
  <div class="risk-score risk-{'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'}">{risk_score}/100</div>
  <div style="color:#aaa;font-size:0.85em;margin-top:10px;">
    {'🔴 CRITICAL — Immediate action required' if risk_score >= 70 else '🟠 HIGH — Address within 7 days' if risk_score >= 40 else '🟡 MEDIUM — Address within 30 days' if risk_score >= 20 else '🟢 LOW — Monitor and patch next cycle'}
  </div>
</div>

<!-- STATS -->
<div class="stats-grid">
  <div class="stat-card"><div class="stat-num">{stats['total_nodes']}</div><div class="stat-label">Endpoints Found</div></div>
  <div class="stat-card"><div class="stat-num">{stats['tested_nodes']}</div><div class="stat-label">Endpoints Tested</div></div>
  <div class="stat-card"><div class="stat-num" style="color:#e74c3c">{stats['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card"><div class="stat-num" style="color:#e67e22">{stats['high']}</div><div class="stat-label">High</div></div>
  <div class="stat-card"><div class="stat-num" style="color:#f39c12">{stats['medium']}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card"><div class="stat-num" style="color:#9b59b6">{stats['chains']}</div><div class="stat-label">Attack Chains</div></div>
  <div class="stat-card"><div class="stat-num">{stats['verified_findings']}</div><div class="stat-label">Verified Findings</div></div>
  <div class="stat-card"><div class="stat-num">{stats['ai_actions']}</div><div class="stat-label">AI Decisions</div></div>
</div>

<!-- FINDINGS TABLE -->
<div class="section" id="findings">
  <div class="section-title">📋 SECURITY FINDINGS</div>
  
  <table>
  <tr><th>#</th><th>Type</th><th>Severity</th><th>Endpoint</th><th>Confidence</th><th>Status</th></tr>
"""

    for i, f in enumerate(all_findings):
        sev = f.get("severity", "INFO").lower()
        status_color = "#27ae60" if f.get("status") == "verified" else "#e67e22"
        html += f"""
  <tr>
    <td>{i+1}</td>
    <td>{f.get('vuln_type','?')}</td>
    <td><span class="badge badge-{sev}">{f.get('severity','INFO')}</span></td>
    <td style="color:#3498db;font-size:0.8em">{f.get('endpoint','')[:60]}</td>
    <td>
      <div class="confidence-bar"><div class="confidence-fill" style="width:{f.get('confidence',0)}%"></div></div>
      {f.get('confidence',0)}%
    </td>
    <td><span style="color:{status_color}">{f.get('status','?')}</span></td>
  </tr>"""

    html += """
  </table>
</div>

<!-- DETAILED FINDINGS -->
<div class="section" id="details">
  <div class="section-title">🔴 DETAILED FINDINGS</div>
"""

    for f in findings:  # Only verified findings in detail
        sev = f.get("severity", "INFO").lower()
        html += f"""
  <div class="finding-card {sev}">
    <span class="badge badge-{sev}">{f.get('severity','INFO')}</span>
    <span class="badge badge-info" style="margin-left:5px">{f.get('vuln_type','UNKNOWN')}</span>
    <div class="finding-title">{f.get('vuln_type','Unknown Vulnerability')}</div>
    <div class="finding-endpoint">📍 {f.get('method','GET')} {f.get('endpoint','')}</div>
    {f'<div style="color:#aaa;font-size:0.75em">Parameter: {f["param"]}</div>' if f.get('param') else ''}
    <div class="finding-desc">{f.get('description','No description')}</div>
    
    {'<div class="proof-block">📤 Request:<br>' + (f.get("proof_request","") or "").replace("<","&lt;")[:300] + '</div>' if f.get('proof_request') else ''}
    {'<div class="proof-block">📥 Response (snippet):<br>' + (f.get("proof_response","") or "").replace("<","&lt;")[:300] + '</div>' if f.get('proof_response') else ''}
    {'<div class="remediation">✅ Remediation: ' + f.get("remediation","No remediation provided") + '</div>' if f.get('remediation') else ''}
    
    <div style="color:#555;font-size:0.75em;margin-top:10px">
      Found: {f.get('found_at','')} | 
      Confidence: {f.get('confidence',0)}% |
      Status: {f.get('status','')}
    </div>
  </div>"""

    html += """
</div>

<!-- ATTACK CHAINS -->
<div class="section" id="chains">
  <div class="section-title">⛓ ATTACK CHAINS</div>
"""

    if chains:
        for chain in chains:
            try:
                steps = json.loads(chain.get("steps", "[]")) if isinstance(chain.get("steps"), str) else chain.get("steps", [])
            except:
                steps = []
            sev = chain.get("severity", "HIGH").lower()
            html += f"""
  <div class="chain-card">
    <span class="badge badge-{sev}">{chain.get('severity','HIGH')}</span>
    <div class="chain-title">⛓ {chain.get('name','Attack Chain')}</div>
    {''.join(f'<div class="chain-step">{step}</div>' for step in steps)}
    <div style="color:#555;font-size:0.75em;margin-top:10px">
      Chain ID: {chain.get('chain_id','?')} | Confidence: {chain.get('confidence',0)}%
    </div>
  </div>"""
    else:
        html += '<p style="color:#555">No attack chains detected.</p>'

    html += """
</div>

<!-- AI AUDIT LOG -->
<div class="section" id="ailog">
  <div class="section-title">🤖 AI DECISION LOG (Last 50)</div>
"""

    for a in actions[:50]:
        try:
            params_str = json.loads(a.get("params", "{}") or "{}")
            endpoint = params_str.get("endpoint", "")
        except:
            endpoint = ""
        html += f"""
  <div class="ai-log">
    <span class="ai-action">[{a.get('action','')}]</span>
    <span style="color:#3498db"> {a.get('engine','')}</span>
    {f'<span style="color:#555"> {endpoint[:50]}</span>' if endpoint else ''}
    <span class="ai-model"> [{a.get('ai_model','?')}]</span>
    <span class="ai-reason"> — {a.get('reason','')[:100]}</span>
    <span style="color:#555"> ({a.get('timestamp','')})</span>
  </div>"""

    html += f"""
</div>

</div><!-- /container -->

<div class="footer">
  <div>👁 AUTONOMOUS PENTEST AGENT</div>
  <div style="margin-top:5px">Generated: {timestamp} | Target: {target}</div>
  <div style="margin-top:5px;color:#e67e22">⚠ For authorized security testing only. Unauthorized use is illegal.</div>
</div>

</body>
</html>"""

    # Write report
    report_path = os.path.join(output_dir, f"report_{datetime.now().strftime('%H%M%S')}.html")
    os.makedirs(output_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path


def _calculate_risk(stats: dict) -> int:
    """Calculate overall risk score 0-100"""
    score = 0
    score += min(stats.get("critical", 0) * 25, 50)
    score += min(stats.get("high", 0) * 10, 30)
    score += min(stats.get("medium", 0) * 3, 15)
    score += min(stats.get("chains", 0) * 5, 5)
    return min(score, 100)


def _get_chains(db) -> List[Dict]:
    try:
        c = db.conn.cursor()
        c.execute("SELECT * FROM chains ORDER BY id DESC")
        return [dict(r) for r in c.fetchall()]
    except:
        return []
