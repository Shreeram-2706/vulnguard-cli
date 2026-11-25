
package com.vulnguard.vulnguard_cli.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class HtmlReportFormatter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public void generateReport(String responseJson, Path outputFile)
            throws IOException {

        JsonNode root = objectMapper.readTree(responseJson);

        int totalDependencies = root.isArray() ? root.size() : 0;
        int vulnerableDependencies = 0;
        int totalVulnerabilities = 0;
        int uncheckedDependencies = 0;

        int critical = 0, high = 0, medium = 0, low = 0, unknown = 0;

        StringBuilder rows = new StringBuilder();
        StringBuilder uncheckedRows = new StringBuilder();

        if (root.isArray()) {
            for (JsonNode dependency : root) {

                String name = dependency.path("name").asText("Unknown");
                String version = dependency.path("version").asText("Unknown");
                String status = dependency.path("status").asText("");

                JsonNode vulnerabilities = dependency.path("vulnerabilities");

                if (status.equalsIgnoreCase("ERROR")
                        || status.equalsIgnoreCase("UNCHECKED")) {

                    uncheckedDependencies++;

                    uncheckedRows.append("<tr>")
                            .append("<td>").append(escapeHtml(name)).append("</td>")
                            .append("<td>").append(escapeHtml(version)).append("</td>")
                            .append("<td>").append(escapeHtml(status)).append("</td>")
                            .append("</tr>");

                    continue;
                }

                if (vulnerabilities.isArray() && !vulnerabilities.isEmpty()) {

                    vulnerableDependencies++;
                    totalVulnerabilities += vulnerabilities.size();

                    for (JsonNode vulnerability : vulnerabilities) {

                        String id = vulnerability.path("id").asText("Unknown");
                        String severity = vulnerability.path("severity").asText("UNKNOWN").toUpperCase();
                        String summary = vulnerability.path("summary").asText("No description available.");
                        String fixedVersion = vulnerability.path("fixedVersion").asText("Not available");

                        switch (severity) {
                            case "CRITICAL" -> critical++;
                            case "HIGH" -> high++;
                            case "MEDIUM" -> medium++;
                            case "LOW" -> low++;
                            default -> unknown++;
                        }

                        rows.append("<tr data-severity=\"")
                                .append(escapeHtml(severity))
                                .append("\">")
                                .append("<td><strong>").append(escapeHtml(name))
                                .append("</strong></td>")
                                .append("<td>").append(escapeHtml(version)).append("</td>")
                                .append("<td class=\"id\">").append(escapeHtml(id)).append("</td>")
                                .append("<td><span class=\"badge ")
                                .append(severityClass(severity)).append("\">")
                                .append(escapeHtml(severity)).append("</span></td>")
                                .append("<td class=\"description\">").append(escapeHtml(summary)).append("</td>")
                                .append("<td class=\"fix\">").append(escapeHtml(fixedVersion)).append("</td>")
                                .append("</tr>");
                    }
                }
            }
        }

        int checkedDependencies = totalDependencies - uncheckedDependencies;
        int safeDependencies = checkedDependencies - vulnerableDependencies;

        if (safeDependencies < 0) safeDependencies = 0;

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>VulnGuard | Security Report</title>

                <style>
                    :root {
                        --bg: #f6f8fa;
                        --surface: #ffffff;
                        --border: #d8dee4;
                        --text: #1f2328;
                        --muted: #656d76;
                        --accent: #0969da;
                    }

                    * { box-sizing: border-box; }

                    body {
                        margin: 0;
                        background: var(--bg);
                        color: var(--text);
                        font-family: -apple-system, BlinkMacSystemFont,
                                     "Segoe UI", Helvetica, Arial, sans-serif;
                        font-size: 14px;
                    }

                    .topbar {
                        background: #161b22;
                        color: #fff;
                        padding: 16px 32px;
                    }

                    .topbar-inner {
                        max-width: 1440px;
                        margin: auto;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }

                    .brand {
                        font-size: 17px;
                        font-weight: 700;
                        letter-spacing: -.3px;
                    }

                    .brand span {
                        color: #58a6ff;
                    }

                    .product-label {
                        color: #8b949e;
                        font-size: 12px;
                    }

                    .container {
                        max-width: 1440px;
                        margin: auto;
                        padding: 32px;
                    }

                    .heading {
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-start;
                        flex-wrap: wrap;
                        gap: 16px;
                        margin-bottom: 24px;
                    }

                    h1 {
                        font-size: 25px;
                        letter-spacing: -.5px;
                        margin: 0 0 6px;
                    }

                    .subtitle {
                        color: var(--muted);
                    }

                    .overview {
                        display: grid;
                        grid-template-columns: repeat(4, 1fr);
                        background: var(--surface);
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        margin-bottom: 24px;
                    }

                    .metric {
                        padding: 22px;
                        border-right: 1px solid var(--border);
                    }

                    .metric:last-child {
                        border-right: none;
                    }

                    .metric-label {
                        color: var(--muted);
                        font-size: 13px;
                    }

                    .metric-value {
                        font-size: 28px;
                        font-weight: 700;
                        margin-top: 8px;
                        letter-spacing: -.5px;
                    }

                    .severity-panel, .panel {
                        background: var(--surface);
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        margin-bottom: 24px;
                    }

                    .panel-heading {
                        padding: 18px 20px;
                        border-bottom: 1px solid var(--border);
                    }

                    h2 {
                        font-size: 16px;
                        margin: 0;
                    }

                    .panel-subtitle {
                        color: var(--muted);
                        margin-top: 5px;
                        font-size: 13px;
                    }

                    .severity-list {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 0;
                        padding: 16px 20px;
                    }

                    .severity-stat {
                        min-width: 130px;
                        padding: 8px 20px 8px 0;
                        margin-right: 20px;
                    }

                    .severity-stat strong {
                        display: block;
                        font-size: 22px;
                        margin-top: 8px;
                    }

                    .severity-name {
                        font-size: 12px;
                        font-weight: 700;
                    }

                    .critical { color: #cf222e; }
                    .high { color: #e16f24; }
                    .medium { color: #9a6700; }
                    .low { color: #1a7f37; }
                    .unknown { color: #656d76; }

                    .toolbar {
                        padding: 16px 20px;
                        display: flex;
                        gap: 12px;
                        flex-wrap: wrap;
                    }

                    input, select {
                        background: #fff;
                        border: 1px solid var(--border);
                        border-radius: 6px;
                        padding: 9px 12px;
                        font: inherit;
                        color: var(--text);
                    }

                    input {
                        flex: 1;
                        min-width: 250px;
                    }

                    input:focus, select:focus {
                        outline: 2px solid #80bfff;
                        outline-offset: 1px;
                    }

                    .table-wrap {
                        overflow-x: auto;
                    }

                    table {
                        width: 100%;
                        border-collapse: collapse;
                    }

                    th {
                        background: #f6f8fa;
                        color: #656d76;
                        text-transform: uppercase;
                        letter-spacing: .4px;
                        font-size: 11px;
                        font-weight: 700;
                        text-align: left;
                        padding: 12px 16px;
                        border-top: 1px solid var(--border);
                        border-bottom: 1px solid var(--border);
                    }

                    td {
                        padding: 15px 16px;
                        border-bottom: 1px solid var(--border);
                        vertical-align: top;
                        line-height: 1.55;
                    }

                    tbody tr:last-child td {
                        border-bottom: none;
                    }

                    tbody tr:hover {
                        background: #f6f8fa;
                    }

                    .id {
                        color: var(--accent);
                        font-family: Consolas, monospace;
                        white-space: nowrap;
                    }

                    .description {
                        min-width: 280px;
                        max-width: 600px;
                        color: #444d56;
                    }

                    .fix {
                        color: #1a7f37;
                        font-weight: 600;
                        white-space: nowrap;
                    }

                    .badge {
                        display: inline-block;
                        border-radius: 4px;
                        padding: 3px 8px;
                        font-size: 11px;
                        font-weight: 700;
                        white-space: nowrap;
                    }

                    .badge-critical {
                        background: #ffebe9;
                        color: #cf222e;
                    }

                    .badge-high {
                        background: #fff1e5;
                        color: #bc4c00;
                    }

                    .badge-medium {
                        background: #fff8c5;
                        color: #9a6700;
                    }

                    .badge-low {
                        background: #dafbe1;
                        color: #1a7f37;
                    }

                    .badge-unknown {
                        background: #eaeef2;
                        color: #656d76;
                    }

                    .empty {
                        padding: 48px 20px;
                        text-align: center;
                        color: var(--muted);
                    }

                    .empty strong {
                        display: block;
                        color: #1a7f37;
                        font-size: 17px;
                        margin-bottom: 8px;
                    }

                    .footer {
                        text-align: center;
                        color: var(--muted);
                        padding: 20px;
                        font-size: 12px;
                    }

                    .hidden {
                        display: none !important;
                    }

                    @media(max-width: 900px) {
                        .overview {
                            grid-template-columns: repeat(2, 1fr);
                        }

                        .metric:nth-child(2) {
                            border-right: none;
                        }

                        .metric:nth-child(-n+2) {
                            border-bottom: 1px solid var(--border);
                        }
                    }

                    @media(max-width: 600px) {
                        .container {
                            padding: 20px 14px;
                        }

                        .topbar {
                            padding: 14px;
                        }

                        .overview {
                            grid-template-columns: 1fr 1fr;
                        }

                        .metric {
                            padding: 16px;
                        }

                        .metric-value {
                            font-size: 24px;
                        }

                        input {
                            min-width: 100%;
                        }
                    }
                </style>
                </head>

                <body>

                <header class="topbar">
                    <div class="topbar-inner">
                        <div class="brand">Vuln<span>Guard</span></div>
                        <div class="product-label">DEPENDENCY SECURITY</div>
                    </div>
                </header>

                <main class="container">

                    <div class="heading">
                        <div>
                            <h1>Security Report</h1>
                            <div class="subtitle">Dependency vulnerability analysis</div>
                        </div>
                    </div>

                    <section class="overview">

                        <div class="metric">
                            <div class="metric-label">Total dependencies</div>
                            <div class="metric-value">@@TOTAL@@</div>
                        </div>

                        <div class="metric">
                            <div class="metric-label">Checked dependencies</div>
                            <div class="metric-value">@@CHECKED@@</div>
                        </div>

                        <div class="metric">
                            <div class="metric-label">Vulnerable dependencies</div>
                            <div class="metric-value @@VULN_COLOR@@">@@VULN_DEP@@</div>
                        </div>

                        <div class="metric">
                            <div class="metric-label">Total findings</div>
                            <div class="metric-value @@VULN_COLOR@@">@@VULN_COUNT@@</div>
                        </div>

                    </section>

                    <section class="severity-panel">
                        <div class="panel-heading">
                            <h2>Severity breakdown</h2>
                            <div class="panel-subtitle">Findings grouped by severity level</div>
                        </div>

                        <div class="severity-list">

                            <div class="severity-stat">
                                <span class="severity-name critical">CRITICAL</span>
                                <strong>@@CRITICAL@@</strong>
                            </div>

                            <div class="severity-stat">
                                <span class="severity-name high">HIGH</span>
                                <strong>@@HIGH@@</strong>
                            </div>

                            <div class="severity-stat">
                                <span class="severity-name medium">MEDIUM</span>
                                <strong>@@MEDIUM@@</strong>
                            </div>

                            <div class="severity-stat">
                                <span class="severity-name low">LOW</span>
                                <strong>@@LOW@@</strong>
                            </div>

                            <div class="severity-stat">
                                <span class="severity-name unknown">UNKNOWN</span>
                                <strong>@@UNKNOWN@@</strong>
                            </div>

                        </div>
                    </section>

                    <section class="panel">
                        <div class="panel-heading">
                            <h2>Vulnerability findings</h2>
                            <div class="panel-subtitle">
                                Review affected packages and remediation information.
                            </div>
                        </div>

                        <div class="toolbar">
                            <input type="search" id="search"
                                   placeholder="Search package, ID or description">

                            <select id="filter">
                                <option value="ALL">All severities</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                                <option value="UNKNOWN">Unknown</option>
                            </select>
                        </div>

                        <div class="table-wrap" id="findingsWrap">
                            <table id="findings">
                                <thead>
                                    <tr>
                                        <th>Dependency</th>
                                        <th>Version</th>
                                        <th>Vulnerability</th>
                                        <th>Severity</th>
                                        <th>Description</th>
                                        <th>Fixed version</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @@ROWS@@
                                </tbody>
                            </table>
                        </div>

                        <div class="empty hidden" id="emptySearch">
                            No findings match the current search or filter.
                        </div>

                        <div class="empty hidden" id="emptyAll">
                            <strong>No vulnerabilities detected</strong>
                            No known vulnerability findings were returned for the checked dependencies.
                        </div>
                    </section>

                    <section class="panel @@UNCHECKED_CLASS@@">
                        <div class="panel-heading">
                            <h2>Unchecked dependencies (@@UNCHECKED@@)</h2>
                            <div class="panel-subtitle">
                                Dependencies that could not be successfully checked.
                            </div>
                        </div>

                        <div class="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Dependency</th>
                                        <th>Version</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @@UNCHECKED_ROWS@@
                                </tbody>
                            </table>
                        </div>
                    </section>

                </main>

                <footer class="footer">
                    VulnGuard · Dependency Security Analysis
                </footer>

                <script>
                    const search = document.getElementById('search');
                    const filter = document.getElementById('filter');
                    const table = document.getElementById('findings');
                    const rows = Array.from(table.querySelectorAll('tbody tr'));
                    const emptySearch = document.getElementById('emptySearch');
                    const emptyAll = document.getElementById('emptyAll');
                    const findingsWrap = document.getElementById('findingsWrap');

                    function update() {
                        const term = search.value.toLowerCase().trim();
                        const severity = filter.value;
                        let visible = 0;

                        rows.forEach(row => {
                            const matchesText = row.innerText.toLowerCase().includes(term);
                            const matchesSeverity = severity === 'ALL'
                                || row.dataset.severity === severity;

                            const show = matchesText && matchesSeverity;

                            row.classList.toggle('hidden', !show);

                            if (show) visible++;
                        });

                        emptySearch.classList.toggle('hidden', visible !== 0);
                        emptyAll.classList.add('hidden');
                    }

                    search.addEventListener('input', update);
                    filter.addEventListener('change', update);

                    if (rows.length === 0) {
                        findingsWrap.classList.add('hidden');
                        emptySearch.classList.add('hidden');
                        emptyAll.classList.remove('hidden');
                    }
                </script>

                </body>
                </html>
                """;

        html = html.replace("@@TOTAL@@", String.valueOf(totalDependencies));
        html = html.replace("@@CHECKED@@", String.valueOf(checkedDependencies));
        html = html.replace("@@VULN_DEP@@", String.valueOf(vulnerableDependencies));
        html = html.replace("@@VULN_COUNT@@", String.valueOf(totalVulnerabilities));
        html = html.replace("@@VULN_COLOR@@", totalVulnerabilities > 0 ? "high" : "low");

        html = html.replace("@@CRITICAL@@", String.valueOf(critical));
        html = html.replace("@@HIGH@@", String.valueOf(high));
        html = html.replace("@@MEDIUM@@", String.valueOf(medium));
        html = html.replace("@@LOW@@", String.valueOf(low));
        html = html.replace("@@UNKNOWN@@", String.valueOf(unknown));

        html = html.replace("@@ROWS@@", rows.toString());
        html = html.replace("@@UNCHECKED_ROWS@@", uncheckedRows.toString());
        html = html.replace("@@UNCHECKED@@", String.valueOf(uncheckedDependencies));
        html = html.replace("@@UNCHECKED_CLASS@@",
                uncheckedDependencies == 0 ? "hidden" : "");

        Files.createDirectories(outputFile.toAbsolutePath().getParent());
        Files.writeString(outputFile, html);
    }

    private String severityClass(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "badge-critical";
            case "HIGH" -> "badge-high";
            case "MEDIUM" -> "badge-medium";
            case "LOW" -> "badge-low";
            default -> "badge-unknown";
        };
    }

    private String escapeHtml(String value) {
        if (value == null) return "";

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
