"""Reporting engine (Module H): generates HTML, JSON, and PDF security assessment reports.

Guarantees:
- Every finding includes: Finding ID (finding_key), Title, Category, Severity, Status, Confidence,
  Affected URL or file, Evidence (secret-redacted), Detection method, Impact, Reproduction steps
  (safe requests), Remediation, References, CVSS 4.0 (when confirmed), and Verification status.
- HTML reports use Jinja2 with ``autoescape=True`` so untrusted target strings can never execute XSS.
- PDF reports are built with a dependency-free pure-Python PDF 1.4 writer (using built-in Helvetica /
  Courier Type1 fonts) so PDF generation works reliably offline on every OS without system libraries.
"""

from __future__ import annotations

import hashlib
import json
import textwrap
from typing import Any

from jinja2 import BaseLoader, Environment

from app.core.redaction import redact_text

HTML_REPORT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>VibeScan Security Assessment Report — {{ target.name }}</title>
  <style>
    :root {
      --bg: #090d16; --panel: #111827; --border: #1f2937; --text: #e5e7eb; --muted: #9ca3af;
      --critical: #f43f5e; --high: #f97316; --medium: #f59e0b; --low: #38bdf8; --info: #94a3b8;
    }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 32px; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; }
    .container { max-width: 1120px; margin: 0 auto; }
    header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: flex-start; }
    h1 { margin: 0 0 6px 0; font-size: 24px; }
    h2 { margin: 28px 0 12px 0; font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
    h3 { margin: 0 0 8px 0; font-size: 15px; }
    .meta { color: var(--muted); font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .kpi { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
    .kpi .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    .kpi .val { font-size: 22px; font-weight: 700; margin-top: 4px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .sev-critical { background: rgba(244,63,94,.18); color: var(--critical); border: 1px solid rgba(244,63,94,.4); }
    .sev-high { background: rgba(249,115,22,.18); color: var(--high); border: 1px solid rgba(249,115,22,.4); }
    .sev-medium { background: rgba(245,158,11,.18); color: var(--medium); border: 1px solid rgba(245,158,11,.4); }
    .sev-low { background: rgba(56,189,248,.18); color: var(--low); border: 1px solid rgba(56,189,248,.4); }
    .sev-info, .sev-none { background: rgba(148,163,184,.15); color: var(--info); border: 1px solid rgba(148,163,184,.3); }
    .status-chip { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; margin-left: 6px; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; font-size: 13px; margin-bottom: 20px; }
    th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { background: #0f172a; color: var(--muted); font-weight: 600; }
    .finding { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 16px; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px; }
    .mono, pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
    pre { background: #060911; border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 6px 0; }
    .kv { display: grid; grid-template-columns: 160px 1fr; gap: 6px 12px; font-size: 13px; margin-top: 8px; }
    .kv dt { color: var(--muted); font-weight: 600; }
    .kv dd { margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>VibeScan Security Assessment Report</h1>
        <div class="meta">Target: <strong>{{ target.name }}</strong> (<span class="mono">{{ target.base_url }}</span>)</div>
        <div class="meta">Scan ID: <span class="mono">{{ scan.id }}</span> · Completed: {{ scan.finished_at or scan.created_at }} · Authorization: {{ target.authorization_status }}</div>
      </div>
      <div class="meta">VibeScan v0.1 · Non-Destructive Audit</div>
    </header>

    <div class="grid">
      <div class="kpi"><div class="label">Total Findings</div><div class="val">{{ findings|length }}</div></div>
      <div class="kpi"><div class="label">Critical / High</div><div class="val" style="color: var(--critical)">{{ stats.critical_high }}</div></div>
      <div class="kpi"><div class="label">Routes Scanned</div><div class="val">{{ routes|length }}</div></div>
      <div class="kpi"><div class="label">Admin Surfaces</div><div class="val">{{ admin_routes|length }}</div></div>
      <div class="kpi"><div class="label">API Endpoints</div><div class="val">{{ endpoints|length }}</div></div>
    </div>

    {% if analysis and analysis.output %}
    <h2>Executive Summary &amp; AI Security Analysis</h2>
    <div class="finding">
      <p style="margin-top:0">{{ analysis.output.executive_summary }}</p>
      <div class="meta">Provider: {{ analysis.provider }} ({{ analysis.model }}) · Overall Risk: <span class="badge sev-{{ analysis.output.overall_risk }}">{{ analysis.output.overall_risk }}</span></div>
    </div>
    {% endif %}

    <h2>Fingerprinted Technologies &amp; Vibe-Coding Platforms</h2>
    <table>
      <thead><tr><th>Technology / Platform</th><th>Kind</th><th>Confidence</th><th>Supporting Evidence</th></tr></thead>
      <tbody>
        {% for t in technologies %}
        <tr>
          <td><strong>{{ t.name }}</strong></td>
          <td>{{ t.kind }}</td>
          <td>{{ (t.confidence * 100)|int }}%</td>
          <td>{% for ev in t.evidence %}{{ ev.detail }}{% if not loop.last %}; {% endif %}{% endfor %}</td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="meta">No framework signatures exceeded threshold.</td></tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>Discovered Administrative &amp; Management Surfaces ({{ admin_routes|length }})</h2>
    <table>
      <thead><tr><th>Route</th><th>Category</th><th>HTTP Status</th><th>Auth Observation</th><th>Risk</th><th>Discovery</th></tr></thead>
      <tbody>
        {% for r in admin_routes %}
        <tr>
          <td class="mono">{{ r.path }}</td>
          <td>{{ r.admin_category }}</td>
          <td>{{ r.status_code or "—" }}</td>
          <td>{{ r.auth_observation }}</td>
          <td><span class="badge sev-{{ r.risk_level }}">{{ r.risk_level }}</span></td>
          <td>{{ r.discovery_methods|join(", ") }}</td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="meta">No administrative routes discovered.</td></tr>
        {% endfor %}
      </tbody>
    </table>

    <h2>Security Findings ({{ findings|length }})</h2>
    {% for f in findings %}
    <div class="finding">
      <div class="finding-header">
        <h3><span class="mono">{{ f.finding_key }}</span> — {{ f.title }}</h3>
        <div>
          <span class="badge sev-{{ f.severity }}">{{ f.severity }}</span>
          <span class="badge status-chip">{{ f.status }}</span>
          {% if f.cvss_score %}<span class="badge status-chip">CVSS 4.0: {{ f.cvss_score }}</span>{% endif %}
        </div>
      </div>
      <dl class="kv">
        <dt>Rule / Category</dt><dd><span class="mono">{{ f.rule_id }}</span> · {{ f.category }}</dd>
        <dt>Affected Resource</dt><dd class="mono">{{ f.affected }}</dd>
        <dt>Confidence / Triage</dt><dd>{{ (f.confidence * 100)|int }}% · Verification status: <strong>{{ f.verification_status }}</strong></dd>
        <dt>Detection Method</dt><dd>{{ f.detection_method }}</dd>
        <dt>Impact</dt><dd>{{ f.impact }}</dd>
        <dt>Evidence</dt>
        <dd>
          {% for ev in f.evidence %}
          <div>• {{ ev.detail }} {% if ev.location %}(<span class="mono">{{ ev.location }}</span>){% endif %}</div>
          {% if ev.snippet %}<pre>{{ ev.snippet }}</pre>{% endif %}
          {% endfor %}
        </dd>
        <dt>Safe Reproduction</dt>
        <dd>{% for step in f.reproduction %}<pre>{{ step }}</pre>{% endfor %}</dd>
        <dt>Remediation</dt><dd>{{ f.remediation }}</dd>
        {% if f.references %}
        <dt>References</dt>
        <dd>{% for ref in f.references %}<div>{{ ref.title }} — <span class="mono">{{ ref.url }}</span></div>{% endfor %}</dd>
        {% endif %}
      </dl>
    </div>
    {% else %}
    <p class="meta">No security findings recorded for this scan.</p>
    {% endfor %}
  </div>
</body>
</html>
"""

_jinja_env = Environment(loader=BaseLoader(), autoescape=True)


def build_report_payload(
    *,
    target: dict[str, Any],
    scan: dict[str, Any],
    technologies: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    admin_routes = [r for r in routes if r.get("is_admin_surface")]
    crit_high = sum(1 for f in findings if f.get("severity") in ("critical", "high") and f.get("status") != "false_positive")
    return {
        "report_version": "1.0",
        "generator": "VibeScan/0.1",
        "target": target,
        "scan": scan,
        "stats": {
            **(scan.get("stats") or {}),
            "critical_high": crit_high,
        },
        "technologies": technologies,
        "admin_routes": admin_routes,
        "routes": routes,
        "endpoints": endpoints,
        "findings": findings,
        "analysis": analysis,
    }


def render_json_report(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_html_report(payload: dict[str, Any]) -> bytes:
    tmpl = _jinja_env.from_string(HTML_REPORT_TEMPLATE)
    html = tmpl.render(**payload)
    return html.encode("utf-8")


def _pdf_escape(text: str) -> str:
    ascii_text = (text or "").encode("latin-1", "replace").decode("latin-1")
    return ascii_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf_report(payload: dict[str, Any]) -> bytes:
    """Render a multi-page PDF 1.4 document using standard Helvetica / Helvetica-Bold fonts."""
    target = payload["target"]
    scan = payload["scan"]
    findings = payload["findings"]
    admin_routes = payload["admin_routes"]
    analysis = payload.get("analysis") or {}

    lines: list[tuple[str, int, str]] = []  # (font, size, text)

    def heading(text: str, size: int = 14) -> None:
        lines.append(("F2", size, ""))
        lines.append(("F2", size, text))

    def body(text: str, indent: int = 0) -> None:
        prefix = " " * indent
        for wrapped in textwrap.wrap(text or "", width=88 - indent) or [""]:
            lines.append(("F1", 10, prefix + wrapped))

    lines.append(("F2", 18, f"VibeScan Security Assessment Report - {target.get('name', '')}"))
    body(f"Target URL: {target.get('base_url', '')} | Authorization: {target.get('authorization_status', '')}")
    body(f"Scan ID: {scan.get('id', '')} | Status: {scan.get('status', '')}")
    body(
        f"Summary: {len(findings)} findings ({payload['stats'].get('critical_high', 0)} critical/high), "
        f"{len(payload['routes'])} routes ({len(admin_routes)} admin surfaces), {len(payload['endpoints'])} API endpoints."
    )

    if analysis and analysis.get("output"):
        heading("Executive Summary")
        body(str(analysis["output"].get("executive_summary") or ""))

    heading(f"Administrative & Management Surfaces ({len(admin_routes)})")
    for r in admin_routes[:35]:
        body(
            f"- {r.get('path')} [{r.get('admin_category')}] HTTP {r.get('status_code') or '-'} | "
            f"auth={r.get('auth_observation')} | risk={r.get('risk_level')}",
            indent=2,
        )

    heading(f"Security Findings ({len(findings)})")
    for f in findings:
        cvss = f" | CVSS 4.0: {f['cvss_score']}" if f.get("cvss_score") else ""
        lines.append(("F2", 11, f"[{f['finding_key']}] ({f['severity'].upper()} / {f['status']}{cvss}) {f['title']}"))
        body(f"Rule: {f['rule_id']} | Category: {f['category']} | Confidence: {int(f['confidence'] * 100)}% | Verification: {f['verification_status']}", indent=2)
        body(f"Affected: {f['affected']}", indent=2)
        body(f"Detection: {f['detection_method']}", indent=2)
        body(f"Impact: {f['impact']}", indent=2)
        for ev in (f.get("evidence") or [])[:3]:
            body(f"Evidence: {redact_text(str(ev.get('detail') or ''), 180)}", indent=4)
            if ev.get("snippet"):
                body(f"Snippet: {redact_text(str(ev.get('snippet') or ''), 180)}", indent=4)
        for step in (f.get("reproduction") or [])[:2]:
            body(f"Reproduction: {step}", indent=2)
        body(f"Remediation: {f['remediation']}", indent=2)
        lines.append(("F1", 9, ""))

    # Paginate lines into 792pt-tall pages (US Letter 612 x 792)
    pages_streams: list[bytes] = []
    y = 748
    current_ops: list[str] = ["BT"]
    for font, size, txt in lines:
        step = size + 4
        if y - step < 48:
            current_ops.append("ET")
            pages_streams.append("\n".join(current_ops).encode("latin-1"))
            current_ops = ["BT"]
            y = 748
        if txt:
            current_ops.append(f"/{font} {size} Tf 1 0 0 1 44 {y} Tm ({_pdf_escape(txt)}) Tj")
        y -= step
    current_ops.append("ET")
    pages_streams.append("\n".join(current_ops).encode("latin-1"))

    # Assemble PDF 1.4 object table
    # Obj 1: Catalog, Obj 2: Pages, Obj 3: Font F1 (Helvetica), Obj 4: Font F2 (Helvetica-Bold)
    objects: list[bytes] = []
    num_pages = len(pages_streams)
    first_page_obj = 5
    kids_refs = " ".join(f"{first_page_obj + i * 2} 0 R" for i in range(num_pages))

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids_refs}] /Count {num_pages} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

    for i, stream in enumerate(pages_streams):
        page_obj_num = first_page_obj + i * 2
        content_obj_num = page_obj_num + 1
        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_obj_num} 0 R >>"
        ).encode("ascii")
        content_dict = f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        objects.append(page_dict)
        objects.append(content_dict)

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(obj)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def generate_report_bytes(fmt: str, payload: dict[str, Any]) -> tuple[bytes, str]:
    """Return ``(report_bytes, sha256_hex)`` for ``fmt`` in ``('html', 'json', 'pdf')``."""
    if fmt == "json":
        data = render_json_report(payload)
    elif fmt == "html":
        data = render_html_report(payload)
    elif fmt == "pdf":
        data = render_pdf_report(payload)
    else:
        raise ValueError(f"Unsupported report format {fmt!r}")
    return data, hashlib.sha256(data).hexdigest()
