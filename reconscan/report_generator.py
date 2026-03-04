import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

from jinja2 import Environment, select_autoescape


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 12:
        return value[:2] + "…" + value[-2:]
    return value[:6] + "…" + value[-4:]


def _risk_counts(risks: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in risks or []:
        sev = (r.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _render_markdown(data: dict) -> str:
    env = Environment(autoescape=False)
    env.filters["tojson"] = lambda x: json.dumps(x, ensure_ascii=False)
    tmpl = env.from_string(
        """
Recon Report
============

Target: {{ data.target }}

## Technologies
{% for t in data.technologies %}
- {{ t }}
{% endfor %}

## Endpoints
{% for ep in data.endpoints %}
- {{ ep.path if ep.path is defined else ep["path"] }} ({{ ep.get("category", "unknown") }})
{% endfor %}

## Business Logic Flows
{% for flow in data.business_flows %}
### {{ flow.name if flow.name is defined else flow["name"] }}
{% for p in flow.endpoints %}
- {{ p }}
{% endfor %}
{% endfor %}

## Risks
{% for r in data.risks %}
- **{{ r.severity }}** - {{ r.title }}
{% endfor %}
"""
    )
    return tmpl.render(data=data)


def _render_html(data: dict) -> str:
    env = Environment(autoescape=select_autoescape(enabled_extensions=("html", "xml")))
    env.filters["tojson"] = lambda x: json.dumps(x, ensure_ascii=False)

    # Precompute UI helpers
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    risks = data.get("risks", []) or []
    counts = _risk_counts(risks)
    data["__generated_at"] = now
    data["__risk_counts"] = counts

    # Mask secrets in-place for display (keep raw in JSON exports)
    secrets = data.get("secrets", []) or []
    data["__secrets_masked"] = [
        {**s, "masked": _mask_secret(s.get("value", ""))}
        for s in secrets
    ]

    tmpl = env.from_string(
        """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Recon Report - {{ data.target }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      :root{
        --bg: #0b1220;
        --panel: rgba(255,255,255,0.04);
        --panel2: rgba(255,255,255,0.06);
        --text: #e5e7eb;
        --muted: #9ca3af;
        --border: rgba(255,255,255,0.10);
        --shadow: 0 10px 30px rgba(0,0,0,0.35);

        --crit: #ef4444;
        --high: #f97316;
        --med: #f59e0b;
        --low: #22c55e;
        --info: #60a5fa;
      }

      * { box-sizing: border-box; }
      body {
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        margin: 0;
        background: radial-gradient(1200px 800px at 20% 0%, rgba(96,165,250,0.18), transparent),
                    radial-gradient(900px 600px at 80% 20%, rgba(245,158,11,0.12), transparent),
                    var(--bg);
        color: var(--text);
      }

      a { color: #93c5fd; text-decoration: none; }
      a:hover { text-decoration: underline; }

      .container { max-width: 1200px; margin: 0 auto; padding: 28px 18px 40px; }
      .header {
        display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;
        margin-bottom: 18px;
      }
      .title { margin: 0; font-size: 28px; letter-spacing: 0.2px; }
      .subtitle { margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.35; }

      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.03);
        padding: 8px 10px; border-radius: 999px;
        color: var(--muted); font-size: 12px;
      }

      .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px; }
      .card {
        grid-column: span 3;
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 14px 14px 12px;
        box-shadow: var(--shadow);
      }
      .card .k { color: var(--muted); font-size: 12px; }
      .card .v { font-size: 22px; margin-top: 6px; }

      .panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 14px;
        box-shadow: var(--shadow);
      }

      h2 { margin: 0 0 10px; font-size: 16px; }
      h3 { margin: 14px 0 8px; font-size: 14px; color: #fde68a; }

      code { background: rgba(0,0,0,0.28); padding: 0.12rem 0.35rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.08); }
      .muted { color: var(--muted); }

      .badge {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 4px 8px;
        border-radius: 999px;
        font-size: 11px;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(255,255,255,0.04);
        white-space: nowrap;
      }
      .sev-CRITICAL { border-color: rgba(239,68,68,0.55); color: #fecaca; }
      .sev-HIGH { border-color: rgba(249,115,22,0.55); color: #fed7aa; }
      .sev-MEDIUM { border-color: rgba(245,158,11,0.55); color: #fde68a; }
      .sev-LOW { border-color: rgba(34,197,94,0.55); color: #bbf7d0; }
      .sev-INFO { border-color: rgba(96,165,250,0.55); color: #bfdbfe; }

      table { width: 100%; border-collapse: separate; border-spacing: 0; overflow: hidden; border-radius: 12px; border: 1px solid var(--border); }
      thead th {
        background: rgba(255,255,255,0.04);
        color: var(--muted);
        font-size: 12px;
        text-align: left;
        padding: 10px 10px;
        border-bottom: 1px solid var(--border);
      }
      tbody td {
        padding: 10px 10px;
        border-bottom: 1px solid rgba(255,255,255,0.06);
        vertical-align: top;
        font-size: 13px;
      }
      tbody tr:hover td { background: rgba(255,255,255,0.03); }
      tbody tr:last-child td { border-bottom: 0; }

      details { border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 10px 12px; background: rgba(255,255,255,0.03); }
      details summary { cursor: pointer; color: #eab308; font-weight: 600; }
      details .content { margin-top: 10px; }

      .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      @media (max-width: 980px) { .card { grid-column: span 6; } .two-col { grid-template-columns: 1fr; } }
      @media (max-width: 560px) { .card { grid-column: span 12; } }

      .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
      .chip { cursor: pointer; user-select: none; }
      .chip input { margin-right: 6px; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div>
          <h1 class="title">Recon Report</h1>
          <div class="subtitle">
            <div><strong>Target:</strong> <code>{{ data.target }}</code></div>
            <div>Generated: {{ data.__generated_at }}</div>
          </div>
        </div>
        <div class="pill">
          <span>Endpoints:</span> <strong>{{ (data.endpoints|length) }}</strong>
          <span style="margin-left:10px;">JS Secrets:</span> <strong>{{ (data.secrets|length) }}</strong>
          <span style="margin-left:10px;">Vuln matches:</span> <strong>{{ (data.vulns|length) }}</strong>
        </div>
      </div>

      <div class="grid" style="margin-bottom: 12px;">
        <div class="card">
          <div class="k">CRITICAL</div>
          <div class="v" style="color: var(--crit)">{{ data.__risk_counts.CRITICAL }}</div>
        </div>
        <div class="card">
          <div class="k">HIGH</div>
          <div class="v" style="color: var(--high)">{{ data.__risk_counts.HIGH }}</div>
        </div>
        <div class="card">
          <div class="k">MEDIUM</div>
          <div class="v" style="color: var(--med)">{{ data.__risk_counts.MEDIUM }}</div>
        </div>
        <div class="card">
          <div class="k">LOW / INFO</div>
          <div class="v" style="color: var(--info)">{{ data.__risk_counts.LOW + data.__risk_counts.INFO }}</div>
        </div>
      </div>

      <div class="panel" style="margin-bottom: 12px;">
        <div class="toolbar">
          <strong>Findings</strong>
          <span class="muted">(click filters)</span>
          <label class="badge chip sev-CRITICAL"><input type="checkbox" checked data-sev="CRITICAL" />CRITICAL</label>
          <label class="badge chip sev-HIGH"><input type="checkbox" checked data-sev="HIGH" />HIGH</label>
          <label class="badge chip sev-MEDIUM"><input type="checkbox" checked data-sev="MEDIUM" />MEDIUM</label>
          <label class="badge chip sev-LOW"><input type="checkbox" checked data-sev="LOW" />LOW</label>
          <label class="badge chip sev-INFO"><input type="checkbox" checked data-sev="INFO" />INFO</label>
        </div>
        <div class="muted" style="margin-top:8px;">Includes secrets, known vulnerable libraries, exposed admin/debug endpoints (when probing enabled), and header issues.</div>

        <table style="margin-top: 10px;">
          <thead>
            <tr>
              <th style="width: 110px;">Severity</th>
              <th>Title</th>
              <th style="width: 42%;">Details</th>
            </tr>
          </thead>
          <tbody id="findingsBody">
            {% for r in data.risks %}
            <tr data-sev="{{ r.severity }}">
              <td><span class="badge sev-{{ r.severity }}">{{ r.severity }}</span></td>
              <td>{{ r.title }}</td>
              <td class="muted"><code>{{ (r.details | tojson)[:180] }}</code></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="two-col">
        <div class="panel">
          <h2>JavaScript Secrets</h2>
          {% if data.__secrets_masked|length == 0 %}
            <div class="muted">No secret patterns matched.</div>
          {% else %}
          <table>
            <thead>
              <tr><th>Type</th><th>Value (masked)</th></tr>
            </thead>
            <tbody>
              {% for s in data.__secrets_masked %}
              <tr>
                <td>{{ s.type }}</td>
                <td><code>{{ s.masked }}</code></td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
          {% endif %}
        </div>

        <div class="panel">
          <h2>Vulnerability Matches (JS Tech)</h2>
          {% if data.vulns|length == 0 %}
            <div class="muted">No library matches found in the built-in vulnerability matcher.</div>
          {% else %}
          <table>
            <thead>
              <tr>
                <th>Technology</th>
                <th>CVE</th>
                <th>Severity</th>
                <th>CISA KEV</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {% for v in data.vulns %}
              <tr>
                <td>{{ v.technology_instance }}</td>
                <td><code>{{ v.cve }}</code></td>
                <td><span class="badge sev-{{ v.severity }}">{{ v.severity }}</span></td>
                <td>{{ "Yes" if v.cisa_kev else "No" }}</td>
                <td class="muted">
                  {% if v.sources %}
                    {{ v.sources|join(", ") }}
                  {% else %}
                    <span class="muted">unknown source</span>
                  {% endif %}
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
          {% endif %}
        </div>
      </div>

      <div class="panel" style="margin-top: 12px;">
        <h2>Technologies (with Evidence)</h2>
        {% if data.technology_hits is defined and data.technology_hits|length > 0 %}
        <table>
          <thead>
            <tr>
              <th>Technology</th>
              <th>Source</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {% for th in data.technology_hits %}
            <tr>
              <td>{{ th.technology }}</td>
              <td class="muted">{{ th.source }}</td>
              <td class="muted"><code>{{ th.evidence }}</code></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% else %}
          <div class="muted">No technology signatures detected from JavaScript.</div>
        {% endif %}
      </div>

      <div class="panel" style="margin-top: 12px;">
        <h2>Endpoints</h2>
        {% if data.endpoints|length == 0 %}
          <div class="muted">No endpoints extracted from JavaScript.</div>
        {% else %}
        <table>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Category</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {% for ep in data.endpoints %}
            <tr>
              <td><code>{{ ep.path }}</code></td>
              <td><span class="badge sev-INFO">{{ ep.category }}</span></td>
              <td class="muted">{{ ep.source }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% endif %}
      </div>

      <div class="two-col" style="margin-top: 12px;">
        <div class="panel">
          <h2>Business Logic Flows</h2>
          {% if data.business_flows|length == 0 %}
            <div class="muted">No flows detected from endpoint naming patterns.</div>
          {% else %}
            {% for flow in data.business_flows %}
            <details style="margin-bottom: 10px;" {% if loop.index0 < 2 %}open{% endif %}>
              <summary>{{ flow.name }} <span class="muted">({{ flow.endpoints|length }})</span></summary>
              <div class="content">
                <ul>
                  {% for p in flow.endpoints %}
                  <li><code>{{ p }}</code></li>
                  {% endfor %}
                </ul>
              </div>
            </details>
            {% endfor %}
          {% endif %}
        </div>

        <div class="panel">
          <h2>Endpoint Behavior Probing</h2>
          {% if data.behavior|length == 0 %}
            <div class="muted">No probing results (run with <code>--probe</code>).</div>
          {% else %}
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>HEAD</th>
                <th>GET</th>
                <th>Auth?</th>
                <th>Redirects</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {% for b in data.behavior %}
              <tr>
                <td><code>{{ b.path }}</code></td>
                <td>{{ b.head_status }}</td>
                <td>{{ b.get_status }}</td>
                <td>{{ "Yes" if b.auth_required else "No" }}</td>
                <td class="muted">{{ b.redirects|length }}</td>
                <td class="muted">{{ b.risk if b.risk else "" }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
          {% endif %}
        </div>
      </div>

      <div class="two-col" style="margin-top: 12px;">
        <div class="panel">
          <h2>HTTP Header Issues</h2>
          {% if not data.headers or (data.headers.header_issues|length == 0) %}
            <div class="muted">No header issues captured (or scan was JS-only).</div>
          {% else %}
          <table>
            <thead>
              <tr><th>URL</th><th>Issue</th></tr>
            </thead>
            <tbody>
              {% for hi in data.headers.header_issues %}
              <tr>
                <td class="muted">{{ hi.url }}</td>
                <td class="muted"><code>{{ hi | tojson }}</code></td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
          {% endif %}
        </div>

        <div class="panel">
          <h2>API Surface Graph</h2>
          {% if data.api_graph.relationships is defined and data.api_graph.relationships|length > 0 %}
            <ul>
              {% for rel in data.api_graph.relationships %}
              <li><code>{{ rel.from }}</code> &rarr; <code>{{ rel.to }}</code> <span class="muted">({{ rel.type }})</span></li>
              {% endfor %}
            </ul>
          {% else %}
            <div class="muted">No relationships inferred (graph still includes node lists in JSON format).</div>
          {% endif %}
        </div>
      </div>

      <div class="muted" style="margin-top: 14px;">
        Report is rule-based and deterministic. Always validate findings manually before exploitation.
      </div>
    </div>

    <script>
      (function(){
        const checks = Array.from(document.querySelectorAll('input[data-sev]'));
        const body = document.getElementById('findingsBody');
        function apply(){
          const enabled = new Set(checks.filter(c => c.checked).map(c => c.getAttribute('data-sev')));
          Array.from(body.querySelectorAll('tr')).forEach(tr => {
            const sev = tr.getAttribute('data-sev');
            tr.style.display = enabled.has(sev) ? '' : 'none';
          });
        }
        checks.forEach(c => c.addEventListener('change', apply));
        apply();
      })();
    </script>
  </body>
</html>
"""
    )
    return tmpl.render(data=data)


def generate_report(result: Any, report_format: str = "json") -> str:
    data = _to_dict(result)

    if report_format == "json":
        return json.dumps(data, indent=2)
    if report_format == "md":
        return _render_markdown(data)
    if report_format == "html":
        return _render_html(data)

    return json.dumps(data, indent=2)

