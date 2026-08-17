from datetime import datetime
from pathlib import Path


def generate_threat_report(iocs, output_path):
    """
    Generate an HTML Threat Intelligence report
    from processed IOC records.
    """

    output_path = Path(output_path)

    total_iocs = len(iocs)

    high_count = sum(
        1
        for item in iocs
        if item.get("risk_level") == "HIGH"
    )

    medium_count = sum(
        1
        for item in iocs
        if item.get("risk_level") == "MEDIUM"
    )

    low_count = sum(
        1
        for item in iocs
        if item.get("risk_level") == "LOW"
    )

    ip_count = sum(
        1
        for item in iocs
        if item.get("type") == "IP"
    )

    domain_count = sum(
        1
        for item in iocs
        if item.get("type") == "DOMAIN"
    )

    url_count = sum(
        1
        for item in iocs
        if item.get("type") == "URL"
    )

    hash_count = sum(
        1
        for item in iocs
        if item.get("type") in {
            "MD5",
            "SHA1",
            "SHA256"
        }
    )

    email_count = sum(
        1
        for item in iocs
        if item.get("type") == "EMAIL"
    )

    correlated = [
        item
        for item in iocs
        if item.get("source_count", 0) >= 2
    ]

    sources = set()

    for item in iocs:
        for source in item.get(
            "sources",
            []
        ):
            sources.add(source)

    feed_count = len(sources)

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    risk_rows = ""

    for item in sorted(
        iocs,
        key=lambda x: x.get(
            "risk_score",
            0
        ),
        reverse=True
    )[:50]:

        indicator = item.get(
            "indicator",
            ""
        )

        ioc_type = item.get(
            "type",
            ""
        )

        source_text = ", ".join(
            item.get(
                "sources",
                []
            )
        )

        source_count = item.get(
            "source_count",
            0
        )

        risk_score = item.get(
            "risk_score",
            0
        )

        risk_level = item.get(
            "risk_level",
            ""
        )

        malware = item.get(
            "malware",
            ""
        )

        reasons = "; ".join(
            item.get(
                "risk_reasons",
                []
            )
        )

        risk_rows += f"""
        <tr>
            <td class="indicator">{indicator}</td>
            <td>{ioc_type}</td>
            <td>{source_text}</td>
            <td>{source_count}</td>
            <td>{risk_score}</td>
            <td>
                <span class="risk {risk_level.lower()}">
                    {risk_level}
                </span>
            </td>
            <td>{malware or "-"}</td>
            <td>{reasons or "-"}</td>
        </tr>
        """

    correlation_rows = ""

    for item in sorted(
        correlated,
        key=lambda x: x.get(
            "source_count",
            0
        ),
        reverse=True
    )[:25]:

        correlation_rows += f"""
        <tr>
            <td class="indicator">
                {item.get("indicator", "")}
            </td>

            <td>
                {item.get("type", "")}
            </td>

            <td>
                {", ".join(
                    item.get("sources", [])
                )}
            </td>

            <td>
                {item.get("source_count", 0)}
            </td>

            <td>
                {item.get(
                    "correlation_level",
                    "-"
                )}
            </td>

            <td>
                {item.get(
                    "risk_level",
                    "-"
                )}
            </td>
        </tr>
        """

    if not correlation_rows:
        correlation_rows = """
        <tr>
            <td colspan="6" class="empty">
                No cross-feed correlated indicators
                were found in the current real-feed run.
            </td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
Threat Intelligence Aggregator Report
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    color: #172033;
}}

.container {{
    width: 92%;
    max-width: 1400px;
    margin: 35px auto;
}}

.header {{
    background: #172033;
    color: white;
    padding: 35px;
    border-radius: 12px;
    margin-bottom: 25px;
}}

.header h1 {{
    margin: 0 0 10px;
    font-size: 32px;
}}

.header p {{
    margin: 4px 0;
    color: #d0d5dd;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}

.card {{
    background: white;
    padding: 22px;
    border-radius: 10px;
    border: 1px solid #eaecf0;
}}

.card .label {{
    color: #667085;
    font-size: 13px;
    margin-bottom: 8px;
}}

.card .number {{
    font-size: 30px;
    font-weight: bold;
}}

.section {{
    background: white;
    padding: 25px;
    border-radius: 10px;
    border: 1px solid #eaecf0;
    margin-bottom: 25px;
}}

.section h2 {{
    margin-top: 0;
    font-size: 21px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #eaecf0;
    font-size: 12px;
    vertical-align: top;
}}

th {{
    background: #f8fafc;
}}

.indicator {{
    font-family: Consolas, monospace;
    font-weight: 600;
}}

.risk {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 11px;
}}

.risk.high {{
    background: #fee4e2;
    color: #b42318;
}}

.risk.medium {{
    background: #fef0c7;
    color: #b54708;
}}

.risk.low {{
    background: #dcfae6;
    color: #027a48;
}}

.summary {{
    line-height: 1.7;
    color: #475467;
}}

.empty {{
    text-align: center;
    color: #667085;
    padding: 25px;
}}

.footer {{
    text-align: center;
    color: #667085;
    font-size: 12px;
    margin-top: 35px;
}}

@media (max-width: 900px) {{

    .grid {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

}}

@media (max-width: 600px) {{

    .grid {{
        grid-template-columns: 1fr;
    }}

}}

</style>

</head>


<body>

<div class="container">


<div class="header">

    <h1>
        Threat Intelligence Aggregator Report
    </h1>

    <p>
        Non-AI Threat Intelligence Collection,
        Normalization, Correlation and Risk Analysis
    </p>

    <p>
        Generated: {generated_time}
    </p>

</div>


<div class="section">

    <h2>
        1. Executive Summary
    </h2>

    <div class="summary">

        The Threat Intelligence Aggregator collected,
        parsed, validated, normalized and analyzed
        indicators from {feed_count} threat intelligence
        source(s).

        The current dataset contains
        <strong>{total_iocs}</strong>
        unique indicators.

        The system classified the indicators by IOC type,
        calculated explainable risk scores and generated
        blocklists for actionable defensive use.

    </div>

</div>


<div class="section">

    <h2>
        2. Feed Statistics
    </h2>

    <div class="grid">

        <div class="card">
            <div class="label">
                Feeds Processed
            </div>

            <div class="number">
                {feed_count}
            </div>
        </div>


        <div class="card">
            <div class="label">
                Unique IOCs
            </div>

            <div class="number">
                {total_iocs}
            </div>
        </div>


        <div class="card">
            <div class="label">
                Correlated IOCs
            </div>

            <div class="number">
                {len(correlated)}
            </div>
        </div>


        <div class="card">
            <div class="label">
                Generated
            </div>

            <div class="number">
                Report
            </div>
        </div>

    </div>

</div>


<div class="section">

    <h2>
        3. Risk Distribution
    </h2>

    <div class="grid">

        <div class="card">
            <div class="label">
                HIGH
            </div>

            <div class="number">
                {high_count}
            </div>
        </div>


        <div class="card">
            <div class="label">
                MEDIUM
            </div>

            <div class="number">
                {medium_count}
            </div>
        </div>


        <div class="card">
            <div class="label">
                LOW
            </div>

            <div class="number">
                {low_count}
            </div>
        </div>

    </div>

</div>


<div class="section">

    <h2>
        4. IOC Type Distribution
    </h2>

    <table>

        <thead>

            <tr>
                <th>IOC Type</th>
                <th>Count</th>
            </tr>

        </thead>

        <tbody>

            <tr>
                <td>IP Address</td>
                <td>{ip_count}</td>
            </tr>

            <tr>
                <td>Domain</td>
                <td>{domain_count}</td>
            </tr>

            <tr>
                <td>URL</td>
                <td>{url_count}</td>
            </tr>

            <tr>
                <td>Hash</td>
                <td>{hash_count}</td>
            </tr>

            <tr>
                <td>Email</td>
                <td>{email_count}</td>
            </tr>

        </tbody>

    </table>

</div>


<div class="section">

    <h2>
        5. Correlation Results
    </h2>

    <table>

        <thead>

            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Sources</th>
                <th>Source Count</th>
                <th>Correlation</th>
                <th>Risk</th>
            </tr>

        </thead>

        <tbody>

            {correlation_rows}

        </tbody>

    </table>

</div>


<div class="section">

    <h2>
        6. Highest-Risk Indicators
    </h2>

    <table>

        <thead>

            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Source</th>
                <th>Sources</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Malware</th>
                <th>Reason</th>
            </tr>

        </thead>

        <tbody>

            {risk_rows}

        </tbody>

    </table>

</div>


<div class="section">

    <h2>
        7. Blocklist Generation
    </h2>

    <div class="summary">

        The system generated category-based blocklists
        from medium- and high-risk indicators.

        These outputs include IP, domain, URL and
        hash blocklists together with CSV and JSON
        machine-readable datasets.

    </div>

</div>


<div class="section">

    <h2>
        8. Processing Methodology
    </h2>

    <div class="summary">

        <strong>Feed Collection</strong> →
        Download threat intelligence data.

        <br>

        <strong>IOC Parsing</strong> →
        Extract IP addresses, domains, URLs,
        hashes and email indicators.

        <br>

        <strong>Validation</strong> →
        Remove malformed indicators.

        <br>

        <strong>Normalization</strong> →
        Standardize indicators and remove duplicates.

        <br>

        <strong>Correlation</strong> →
        Identify indicators reported by multiple sources.

        <br>

        <strong>Risk Scoring</strong> →
        Assign explainable risk levels based on
        source count, indicator type, confidence
        and threat category.

        <br>

        <strong>Blocklist Generation</strong> →
        Export actionable defensive lists.

    </div>

</div>


<div class="section">

    <h2>
        9. Conclusion
    </h2>

    <div class="summary">

        The Threat Intelligence Aggregator provides a
        non-AI defensive workflow for collecting and
        standardizing threat intelligence from multiple
        feeds.

        It reduces manual feed processing by automating
        IOC parsing, validation, normalization,
        correlation, risk prioritization and blocklist
        generation.

    </div>

</div>


<div class="footer">

    Threat Intelligence Aggregator |
    Non-AI |
    Internship Project

</div>


</div>

</body>

</html>
"""

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print()
    print(
        f"[+] Threat intelligence report generated:"
    )

    print(
        f"[+] {output_path}"
    )

    return output_path