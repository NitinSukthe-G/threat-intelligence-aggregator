"""Self-contained HTML threat report. Every feed-supplied value is escaped."""

from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path

CSS = """
:root{--bg:#0b1020;--panel:#141b2f;--line:#26304d;--text:#e6ebf7;--muted:#8d99b8;
--high:#ff5d6c;--med:#ffb347;--low:#4ecb8d;--accent:#6aa8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 60px}
h1{margin:0;font-size:30px;letter-spacing:-.5px}h2{margin:34px 0 12px;font-size:18px;
border-left:4px solid var(--accent);padding-left:10px}
.sub{color:var(--muted);margin:6px 0 24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card b{display:block;font-size:28px}.card span{color:var(--muted);font-size:13px}
.high b{color:var(--high)}.med b{color:var(--med)}.low b{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:12px;overflow:hidden;font-size:13.5px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;background:#101830}tr:last-child td{border:0}
code{font-family:Consolas,monospace;overflow-wrap:anywhere;color:#cfe0ff}
td:first-child{min-width:190px}
.pill{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600}
.pill.HIGH{background:#ff5d6c22;color:var(--high)}.pill.MEDIUM{background:#ffb34722;color:var(--med)}
.pill.LOW{background:#4ecb8d22;color:var(--low)}.pill.ok{background:#4ecb8d22;color:var(--low)}
.pill.bad{background:#ff5d6c22;color:var(--high)}.pill.warn{background:#ffb34722;color:var(--med)}
.bar{height:10px;border-radius:6px;background:#1d2744;overflow:hidden;display:flex}
.bar i{display:block;height:100%}.muted{color:var(--muted)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.two{grid-template-columns:1fr}}
footer{margin-top:40px;color:var(--muted);font-size:12px}
"""


def _e(value):
    return escape(str(value if value is not None else ""), quote=True)


def _card(label, value, cls=""):
    return f'<div class="card {cls}"><b>{_e(value)}</b><span>{_e(label)}</span></div>'


def _bar(parts):
    total = sum(v for _, v, _ in parts) or 1
    cells = "".join(
        f'<i style="width:{v / total * 100:.2f}%;background:{color}" title="{_e(n)}: {v:,}"></i>'
        for n, v, color in parts if v)
    return f'<div class="bar">{cells}</div>'


def _ioc_rows(items, limit):
    rows = []
    for item in items[:limit]:
        rows.append(
            "<tr>"
            f"<td><code>{_e(item.get('indicator'))}</code></td>"
            f"<td>{_e(item.get('type'))}</td>"
            f"<td>{_e(', '.join(item.get('sources', [])))}</td>"
            f"<td>{_e(item.get('independent_count', item.get('source_count', 0)))}</td>"
            f"<td>{_e(item.get('risk_score', 0))}</td>"
            f"<td><span class='pill {_e(item.get('risk_level', 'LOW'))}'>{_e(item.get('risk_level', 'LOW'))}</span></td>"
            f"<td class='muted'>{_e('; '.join(item.get('risk_reasons', [])[:3]))}</td>"
            "</tr>")
    return "".join(rows) or '<tr><td colspan="7" class="muted">No indicators in this category.</td></tr>'


def build_report_html(iocs, summary=None, feeds=None):
    summary = summary or {}
    feeds = feeds or []
    by_risk = summary.get("by_risk") or Counter(i.get("risk_level", "LOW") for i in iocs)
    by_type = summary.get("by_type") or Counter(i.get("type", "") for i in iocs)
    generated = summary.get("generated_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")

    correlated = sorted(
        (i for i in iocs if i.get("independent_count", i.get("source_count", 0)) >= 2),
        key=lambda i: (-i.get("independent_count", 0), -i.get("risk_score", 0)))
    top_high = [i for i in iocs if i.get("risk_level") == "HIGH"][:25]
    malware = Counter(i["malware"] for i in iocs if i.get("malware")).most_common(10)
    categories = Counter(i["category"] for i in iocs if i.get("category")).most_common(8)

    feed_rows = "".join(
        "<tr>"
        f"<td>{_e(f['name'])}<div class='muted'>{_e(f.get('description', ''))}</div></td>"
        f"<td><span class='pill {'ok' if f['status'] in ('fresh', 'cached') else 'warn' if f['status'] in ('stale', 'skipped') else 'bad'}'>{_e(f['status'])}</span></td>"
        f"<td>{f.get('records', 0):,}</td>"
        f"<td class='muted'>{_e(', '.join(f'{k}: {v:,}' for k, v in sorted((f.get('types') or {}).items())))}</td>"
        f"<td class='muted'>{_e(f.get('error', ''))}</td></tr>"
        for f in feeds) or '<tr><td colspan="5" class="muted">No feed information recorded.</td></tr>'

    bl = (summary.get("blocklists") or {}).get("counts", {})
    cards = "".join([
        _card("Feeds processed", f"{summary.get('feeds_ok', 0)}/{summary.get('feeds_configured', len(feeds))}"),
        _card("Raw indicators", f"{summary.get('raw_iocs', 0):,}"),
        _card("Unique indicators", f"{summary.get('unique_iocs', len(iocs)):,}"),
        _card("Cross-feed correlated", f"{summary.get('correlated_iocs', len(correlated)):,}"),
        _card("HIGH risk", f"{by_risk.get('HIGH', 0):,}", "high"),
        _card("MEDIUM risk", f"{by_risk.get('MEDIUM', 0):,}", "med"),
        _card("LOW risk", f"{by_risk.get('LOW', 0):,}", "low"),
        _card("Max independent sources", summary.get("max_independent_sources", 0)),
    ])
    bl_cards = "".join(_card(k.title(), f"{v:,}") for k, v in bl.items())
    type_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v:,}</td></tr>" for k, v in sorted(by_type.items()))
    mal_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in malware) or \
        '<tr><td class="muted" colspan="2">No malware family data.</td></tr>'
    cat_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in categories) or \
        '<tr><td class="muted" colspan="2">No category data.</td></tr>'
    dropped = summary.get("allowlist_dropped") or {}
    dropped_text = ", ".join(f"{k}: {v:,}" for k, v in dropped.items()) or "none"

    head = "<th>Indicator</th><th>Type</th><th>Sources</th><th>Indep.</th><th>Score</th><th>Risk</th><th>Why</th>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Intelligence Report</title><style>{CSS}</style></head>
<body><div class="wrap">
<h1>Threat Intelligence Report</h1>
<p class="sub">Generated {_e(generated)} &middot; rule-based (non-AI) aggregation, correlation and scoring</p>
<div class="grid">{cards}</div>
<h2>Risk distribution</h2>
{_bar([("HIGH", by_risk.get("HIGH", 0), "var(--high)"), ("MEDIUM", by_risk.get("MEDIUM", 0), "var(--med)"), ("LOW", by_risk.get("LOW", 0), "var(--low)")])}
<h2>Feed health</h2>
<table><tr><th>Feed</th><th>Status</th><th>Records</th><th>Types</th><th>Notes</th></tr>{feed_rows}</table>
<h2>Cross-feed correlated indicators</h2>
<p class="muted">Indicators confirmed by two or more <em>independent</em> feeds (aggregators are not double-counted).</p>
<table><tr>{head}</tr>{_ioc_rows(correlated, 25)}</table>
<h2>Highest-priority indicators</h2>
<table><tr>{head}</tr>{_ioc_rows(top_high, 25)}</table>
<div class="two"><div><h2>Indicator types</h2><table><tr><th>Type</th><th>Count</th></tr>{type_rows}</table></div>
<div><h2>Malware families</h2><table><tr><th>Family</th><th>Indicators</th></tr>{mal_rows}</table>
<h2>Threat categories</h2><table><tr><th>Category</th><th>Indicators</th></tr>{cat_rows}</table></div></div>
<h2>Generated blocklists</h2><div class="grid">{bl_cards}</div>
<footer>False-positive controls: allowlist/private-IP filter removed {_e(dropped_text)}.
Scores combine independent corroboration, source reputation, indicator type, confidence, threat category and recency.</footer>
</div></body></html>"""


def generate_threat_report(iocs, output_path, summary=None, feeds=None):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_report_html(iocs, summary, feeds), encoding="utf-8")
    print(f"[+] Threat report: {output_path}")
    return output_path
