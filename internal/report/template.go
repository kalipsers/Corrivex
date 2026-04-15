package report

// reportTemplate is the single Go html/template used for every report kind.
// Swiss-modernist layout: 12-column grid, mathematical spacing, monochrome +
// one accent colour. WCAG AAA contrast. Prints cleanly to A4 or Letter via
// browser print-to-PDF; no server-side PDF renderer is needed.
//
// Kept in a Go constant (not a separate .html file) so the binary stays a
// single artifact — important for the Windows-native install path where the
// server is shipped as a lone .exe.
const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>{{.Title}} — Corrivex</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lexend:wght@400;500;600;700&family=Source+Sans+3:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ---- Brand tokens ---- */
:root {
  --ink:     #0F172A;
  --ink-2:   #334155;
  --muted:   #64748B;
  --rule:    #CBD5E1;
  --rule-2:  #E2E8F0;
  --bg:      #FFFFFF;
  --panel:   #F8FAFC;
  --accent:  #0369A1;
  --accent-ink: #0B4A78;
  --danger:  #991B1B;
  --warn:    #92400E;
  --ok:      #166534;
  --mono:    ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --page-pad: 42px;
}

* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--ink);
  font-family: "Source Sans 3", system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  font-size: 14px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  font-variant-numeric: tabular-nums;
}
body { forced-color-adjust: none; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ---- Page frame ---- */
.page {
  max-width: 1120px;
  margin: 0 auto;
  padding: var(--page-pad);
}
.cover {
  border-top: 4px solid var(--ink);
  padding-top: 28px;
  margin-bottom: 32px;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 24px;
  align-items: start;
}
.brand {
  font-family: "Lexend", system-ui, sans-serif;
  font-weight: 700;
  font-size: 11px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 14px;
}
.title {
  font-family: "Lexend", system-ui, sans-serif;
  font-weight: 700;
  font-size: 32px;
  letter-spacing: -0.015em;
  line-height: 1.12;
  margin: 0 0 6px 0;
  color: var(--ink);
}
.subtitle {
  font-size: 15px;
  color: var(--ink-2);
  margin: 0 0 2px 0;
}
.meta {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--muted);
  white-space: nowrap;
  text-align: right;
}
.meta strong { color: var(--ink); font-weight: 600; }
.meta div { margin-top: 4px; }

/* ---- Summary strip ---- */
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0;
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
  background: var(--panel);
  margin-bottom: 28px;
}
.summary-cell {
  padding: 14px 18px;
  border-right: 1px solid var(--rule-2);
}
.summary-cell:last-child { border-right: none; }
.summary-label {
  font-family: "Lexend", system-ui, sans-serif;
  font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--muted); font-weight: 600; margin-bottom: 4px;
}
.summary-value {
  font-family: "Lexend", system-ui, sans-serif;
  font-size: 22px; font-weight: 700; line-height: 1; color: var(--ink);
}

/* ---- Toolbar (hidden in print) ---- */
.toolbar {
  display: flex; gap: 10px; align-items: center; justify-content: flex-end;
  margin-bottom: 18px;
  font-family: "Lexend", system-ui, sans-serif;
}
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 14px; border-radius: 6px;
  font-family: "Lexend", system-ui, sans-serif;
  font-size: 13px; font-weight: 500;
  border: 1px solid var(--rule); background: #fff; color: var(--ink);
  cursor: pointer; text-decoration: none;
}
.btn:hover { border-color: var(--ink); }
.btn-primary { background: var(--ink); color: #fff; border-color: var(--ink); }
.btn-primary:hover { background: var(--accent-ink); border-color: var(--accent-ink); }

/* ---- Data table ---- */
.tbl-wrap { border: 1px solid var(--rule); border-radius: 6px; overflow: hidden; }
table.tbl {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
  font-variant-numeric: tabular-nums;
}
table.tbl thead th {
  text-align: left;
  font-family: "Lexend", system-ui, sans-serif;
  font-weight: 600;
  font-size: 10.5px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--muted);
  padding: 10px 14px;
  background: var(--panel);
  border-bottom: 1px solid var(--rule);
  white-space: nowrap;
}
table.tbl tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--rule-2);
  vertical-align: top;
  word-break: break-word;
}
table.tbl tbody tr:last-child td { border-bottom: none; }
table.tbl tbody tr:nth-child(even) { background: #fcfcfd; }
.mono { font-family: var(--mono); font-size: 12px; color: var(--ink-2); }
.muted { color: var(--muted); }
.strong { font-weight: 600; }

/* ---- Chips ---- */
.chip {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 10.5px; font-weight: 600;
  font-family: "Lexend", system-ui, sans-serif;
  letter-spacing: 0.04em; text-transform: uppercase;
  border: 1px solid currentColor; line-height: 1.4;
}
.chip-crit { color: var(--danger); background: #FEF2F2; }
.chip-high { color: var(--danger); background: #FEF2F2; }
.chip-med  { color: var(--warn);   background: #FFFBEB; }
.chip-low  { color: var(--ink-2);  background: #F1F5F9; }
.chip-unk  { color: var(--muted);  background: #F8FAFC; }
.chip-kev  { color: var(--danger); background: #FEF2F2; margin-left: 6px; }
.chip-ok   { color: var(--ok);     background: #F0FDF4; }

/* ---- Footer ---- */
.footer {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--rule);
  font-size: 11px;
  color: var(--muted);
  display: flex; justify-content: space-between; align-items: center;
}

/* ---- Print rules ---- */
@page {
  size: A4;
  margin: 18mm 14mm 20mm 14mm;
  @bottom-right { content: "Corrivex · page " counter(page) " / " counter(pages); font-family: "Lexend", sans-serif; font-size: 9pt; color: #64748B; }
  @bottom-left  { content: "{{.Title}}"; font-family: "Lexend", sans-serif; font-size: 9pt; color: #64748B; }
}
@media print {
  :root { --page-pad: 0; }
  html, body { background: #fff !important; color: #000 !important; font-size: 11pt; }
  .toolbar { display: none !important; }
  .page { max-width: 100% !important; padding: 0 !important; }
  .cover { break-after: avoid; }
  .summary { break-inside: avoid; background: #fff !important; }
  .summary-cell { border-right: 1px solid #CBD5E1 !important; }
  table.tbl thead { display: table-header-group; }
  table.tbl tbody tr { break-inside: avoid; }
  table.tbl tbody tr:nth-child(even) { background: #fafafa !important; }
  .chip { border: 1px solid #334155 !important; background: transparent !important; color: #0F172A !important; }
  .chip-kev, .chip-crit, .chip-high { border-color: #991B1B !important; color: #991B1B !important; }
  a { color: #0F172A !important; text-decoration: underline; }
  .footer { display: none; }
}

/* ---- Kind-specific colour cues ---- */
.kind-installed_software .cover { border-top-color: var(--ink); }
.kind-local_admins       .cover { border-top-color: var(--accent); }
.kind-cve_findings       .cover { border-top-color: var(--danger); }
</style>
</head>
<body class="kind-{{.Kind}}">
<div class="page">

<header class="cover">
  <div>
    <div class="brand">Corrivex · Endpoint Patch Management</div>
    <h1 class="title">{{.Title}}</h1>
    <p class="subtitle">{{.Subtitle}}</p>
  </div>
  <div class="meta">
    <div>SCOPE <strong>{{defaultStr .Scope "fleet"}}</strong></div>
    <div>GENERATED <strong>{{fmtTime .GeneratedAt}}</strong></div>
    {{if .GeneratedBy}}<div>BY <strong>{{.GeneratedBy}}</strong></div>{{end}}
    <div>BUILD <strong>v{{.AppVersion}}</strong></div>
  </div>
</header>

{{if .SummaryItems}}
<section class="summary">
  {{range .SummaryItems}}
  <div class="summary-cell">
    <div class="summary-label">{{.Label}}</div>
    <div class="summary-value">{{.Value}}</div>
  </div>
  {{end}}
</section>
{{end}}

<div class="toolbar">
  <button class="btn" onclick="window.close()">Close</button>
  <button class="btn btn-primary" onclick="window.print()">Print / Save as PDF</button>
</div>

{{if eq .Kind "installed_software"}}
{{- template "installedSoftware" . -}}
{{else if eq .Kind "local_admins"}}
{{- template "localAdmins" . -}}
{{else if eq .Kind "cve_findings"}}
{{- template "cveFindings" . -}}
{{end}}

<footer class="footer">
  <div>{{.Title}} · scope: {{defaultStr .Scope "fleet"}} · generated {{fmtTime .GeneratedAt}}</div>
  <div>Corrivex v{{.AppVersion}}</div>
</footer>

</div>
<script>
// Auto-print if the URL carries ?print=1 — used by the Reports tab's
// "Print / PDF" button to open a print-ready window.
if (new URLSearchParams(location.search).get('print') === '1') {
  window.addEventListener('load', () => setTimeout(() => window.print(), 150));
}
</script>
</body>
</html>

{{define "installedSoftware"}}
<div class="tbl-wrap">
<table class="tbl">
  <thead>
    <tr>
      <th>Host</th>
      <th>Package ID</th>
      <th>Name</th>
      <th>Version</th>
      <th>Source</th>
      <th>First seen</th>
      <th>Last seen</th>
    </tr>
  </thead>
  <tbody>
    {{range .Rows}}
    <tr>
      <td class="strong">{{.Hostname}}</td>
      <td class="mono">{{.PackageID}}</td>
      <td>{{defaultStr .PackageName "—"}}</td>
      <td class="mono">{{defaultStr .Version "—"}}</td>
      <td class="muted">{{defaultStr .Source "—"}}</td>
      <td class="mono muted">{{fmtDate .FirstSeen}}</td>
      <td class="mono muted">{{fmtDate .LastSeen}}</td>
    </tr>
    {{else}}
    <tr><td colspan="7" class="muted" style="text-align:center;padding:40px">No installed-software rows available.</td></tr>
    {{end}}
  </tbody>
</table>
</div>
{{end}}

{{define "localAdmins"}}
<div class="tbl-wrap">
<table class="tbl">
  <thead>
    <tr>
      <th>Host</th>
      <th>Domain</th>
      <th>Account</th>
      <th>Type</th>
      <th>Enabled</th>
    </tr>
  </thead>
  <tbody>
    {{range .Rows}}
    <tr>
      <td class="strong">{{.Hostname}}</td>
      <td class="muted">{{defaultStr .Domain "—"}}</td>
      <td class="mono">{{.AccountName}}</td>
      <td class="muted">{{defaultStr .AccountType "—"}}</td>
      <td>
        {{if .Enabled}}<span class="chip chip-ok">enabled</span>
        {{else}}<span class="chip chip-low">disabled / unknown</span>{{end}}
      </td>
    </tr>
    {{else}}
    <tr><td colspan="5" class="muted" style="text-align:center;padding:40px">No local-administrator entries captured yet.</td></tr>
    {{end}}
  </tbody>
</table>
</div>
{{end}}

{{define "cveFindings"}}
<div class="tbl-wrap">
<table class="tbl">
  <thead>
    <tr>
      <th>Host</th>
      <th>CVE</th>
      <th>Severity</th>
      <th>Package</th>
      <th>Installed</th>
      <th>Fixed in</th>
      <th>Summary</th>
    </tr>
  </thead>
  <tbody>
    {{range .Rows}}
    <tr>
      <td class="strong">{{.Hostname}}</td>
      <td class="mono">
        {{with cveLink .CVEID}}<a href="{{.}}" target="_blank" rel="noopener">{{end}}{{.CVEID}}{{if cveLink .CVEID}}</a>{{end}}
        {{if .KEV}}<span class="chip chip-kev">KEV</span>{{end}}
      </td>
      <td>
        {{if eq .Severity "CRITICAL"}}<span class="chip chip-crit">critical</span>
        {{else if eq .Severity "HIGH"}}<span class="chip chip-high">high</span>
        {{else if eq .Severity "MEDIUM"}}<span class="chip chip-med">medium</span>
        {{else if eq .Severity "LOW"}}<span class="chip chip-low">low</span>
        {{else}}<span class="chip chip-unk">unknown</span>{{end}}
        {{if .CVSS}}<div class="mono muted" style="margin-top:4px">CVSS {{printf "%.1f" .CVSS}}</div>{{end}}
      </td>
      <td>
        <div class="strong">{{defaultStr .PackageName .PackageID}}</div>
        <div class="mono muted" style="font-size:11px">{{.PackageID}}</div>
      </td>
      <td class="mono">{{defaultStr .Version "—"}}</td>
      <td class="mono">{{defaultStr .FixedIn "—"}}</td>
      <td style="max-width:380px">{{.Summary}}</td>
    </tr>
    {{else}}
    <tr><td colspan="7" class="muted" style="text-align:center;padding:40px">No CVE findings. Either the scanner has not run yet, or all installed packages are at up-to-date, non-vulnerable versions.</td></tr>
    {{end}}
  </tbody>
</table>
</div>
{{end}}
`
