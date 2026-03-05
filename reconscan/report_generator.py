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
    <!-- Tabler CSS -->
    <link href="https://cdn.jsdelivr.net/npm/tabler@1.0.0/dist/css/tabler.min.css" rel="stylesheet" />
    <style>
      :root{
        --bg: #0a0e27;
        --panel: rgba(255,255,255,0.04);
        --panel2: rgba(255,255,255,0.06);
        --text: #e5e7eb;
        --muted: #9ca3af;
        --border: rgba(16,124,16,0.25);
        --shadow: 0 10px 30px rgba(0,0,0,0.35);
        --glass-shadow: 0 8px 32px rgba(0,0,0,0.2);

        --xbox-green: #107C10;
        --xbox-green-light: #10B981;
        --xbox-dark-grey: #1a1a1a;
        --xbox-mid-grey: #2d2d2d;
        --xbox-wave-grey: #3d3d3d;
        --xbox-light-grey: #666666;

        --crit: #ef4444;
        --high: #f97316;
        --med: #f59e0b;
        --low: #22c55e;
        --info: #60a5fa;
      }

      * { box-sizing: border-box; }
      html { 
        scroll-behavior: smooth;
      }
      
      /* Xbox wave pattern background */
      @keyframes wave {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-8px); }
      }
      
      body {
        font-family: 'Segoe UI', ui-sans-serif, system-ui, -apple-system, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, var(--xbox-dark-grey) 0%, var(--xbox-mid-grey) 20%, var(--xbox-dark-grey) 40%, var(--xbox-mid-grey) 60%, var(--xbox-dark-grey) 80%, var(--xbox-mid-grey) 100%);
        background-size: 100% 400px;
        animation: wave 8s ease-in-out infinite;
        color: var(--text);
        position: relative;
      }
      
      body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: 
          radial-gradient(600px 300px at 10% 20%, rgba(16,124,16,0.15), transparent),
          radial-gradient(800px 400px at 90% 30%, rgba(16,124,16,0.10), transparent),
          radial-gradient(600px 300px at 50% 100%, rgba(16,124,16,0.08), transparent);
        pointer-events: none;
        z-index: 0;
      }

      .container { 
        position: relative;
        z-index: 1;
        max-width: 1200px; 
        margin: 0 auto; 
        padding: 28px 18px 40px; 
      }
      
      .header {
        display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;
        margin-bottom: 18px;
     padding: 20px;
        background: linear-gradient(135deg, rgba(16,124,16,0.12) 0%, rgba(16,124,16,0.05) 100%);
        border-left: 4px solid var(--xbox-green);
        border-radius: 12px;
      }
      .title { 
        margin: 0; 
        font-size: 32px; 
        letter-spacing: 0.5px;
        color: var(--xbox-green-light);
        font-weight: 700;
      }
      .subtitle { margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.35; }

      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        border: 2px solid var(--xbox-green);
        background: rgba(16,124,16,0.10);
        backdrop-filter: blur(12px);
        padding: 10px 14px; border-radius: 8px;
        color: var(--xbox-green-light); 
        font-size: 12px;
        font-weight: 600;
        box-shadow: var(--glass-shadow);
      }

      .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px; }
      .card {
        grid-column: span 3;
        background: linear-gradient(135deg, rgba(16,124,16,0.08) 0%, rgba(61,61,61,0.05) 100%);
        border: 1px solid var(--xbox-wave-grey);
        border-top: 3px solid var(--xbox-green);
        border-radius: 12px;
        padding: 18px 14px 12px;
        box-shadow: var(--glass-shadow);
        backdrop-filter: blur(20px);
        transition: all 0.3s ease;
      }
      .card:hover {
        background: linear-gradient(135deg, rgba(16,124,16,0.15) 0%, rgba(61,61,61,0.10) 100%);
        border-color: var(--xbox-green);
        transform: translateY(-4px);
        box-shadow: 0 12px 40px rgba(16,124,16,0.2);
      }
      .card .k { 
        color: var(--xbox-light-grey); 
        font-size: 11px; 
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
      }
      .card .v { 
        font-size: 28px; 
        margin-top: 8px; 
        font-weight: 700;
        color: var(--xbox-green-light);
      }

      .panel {
        background: linear-gradient(135deg, rgba(45,45,45,0.6) 0%, rgba(61,61,61,0.4) 100%);
        border: 1px solid var(--xbox-wave-grey);
        border-left: 4px solid var(--xbox-green);
        border-radius: 12px;
        padding: 16px;
        box-shadow: var(--glass-shadow);
        backdrop-filter: blur(20px);
        margin-bottom: 12px;
      }

      h2 { 
        margin: 0 0 12px; 
        font-size: 18px; 
        font-weight: 700;
        color: var(--xbox-green-light);
        display: flex;
        align-items: center;
        gap: 8px;
      }
      h2::before {
        content: '';
        width: 4px;
        height: 20px;
        background: var(--xbox-green);
        border-radius: 2px;
      }
      h3 { margin: 14px 0 8px; font-size: 14px; color: var(--xbox-green-light); }

      code { 
        background: rgba(0,0,0,0.45); 
        padding: 0.12rem 0.35rem; 
        border-radius: 4px; 
        border: 1px solid var(--xbox-wave-grey);
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        color: var(--xbox-green-light);
      }
      .muted { color: var(--muted); }

      .badge {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 5px 10px;
        border-radius: 6px;
        font-size: 11px;
        border: 1px solid var(--xbox-wave-grey);
        background: rgba(16,124,16,0.08);
        backdrop-filter: blur(10px);
        white-space: nowrap;
        transition: all 0.2s ease;
        font-weight: 600;
      }
      .badge:hover {
        background: rgba(16,124,16,0.15);
        border-color: var(--xbox-green);
      }
      
      .sev-CRITICAL { 
        border-color: rgba(239,68,68,0.6); 
        color: #fecaca; 
        background: rgba(239,68,68,0.12);
      }
      .sev-HIGH { 
        border-color: rgba(249,115,22,0.6); 
        color: #fed7aa; 
        background: rgba(249,115,22,0.12);
      }
      .sev-MEDIUM { 
        border-color: rgba(245,158,11,0.6); 
        color: #fde68a; 
        background: rgba(245,158,11,0.12);
      }
      .sev-LOW { 
        border-color: rgba(34,197,94,0.6); 
        color: #bbf7d0; 
        background: rgba(34,197,94,0.12);
      }
      .sev-INFO { 
        border-color: rgba(96,165,250,0.6); 
        color: #bfdbfe; 
        background: rgba(96,165,250,0.12);
      }

      table { 
        width: 100%; 
        border-collapse: separate; 
        border-spacing: 0; 
        overflow: hidden; 
        border-radius: 10px; 
        border: 1px solid var(--xbox-wave-grey);
      }
      thead th {
        background: linear-gradient(90deg, rgba(16,124,16,0.10) 0%, rgba(61,61,61,0.08) 100%);
        backdrop-filter: blur(10px);
        color: var(--xbox-green-light);
        font-size: 11px;
        text-align: left;
        padding: 12px 10px;
        border-bottom: 2px solid var(--xbox-wave-grey);
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      tbody td {
        padding: 11px 10px;
        border-bottom: 1px solid var(--xbox-wave-grey);
        vertical-align: top;
        font-size: 13px;
        background: rgba(16,124,16,0.02);
      }
      tbody tr:hover td { 
        background: rgba(16,124,16,0.08); 
      }
      tbody tr:last-child td { border-bottom: 0; }

      details { 
        border: 1px solid var(--xbox-wave-grey); 
        border-left: 3px solid var(--xbox-green);
        border-radius: 10px; 
        padding: 12px; 
        background: rgba(61,61,61,0.4);
        backdrop-filter: blur(10px);
        margin-bottom: 10px;
      }
      details summary { 
        cursor: pointer; 
        color: var(--xbox-green-light); 
        font-weight: 700;
        outline: none;
        user-select: none;
        padding: 4px 0;
      }
      details summary:hover {
        color: #10B981;
      }
      details .content { margin-top: 12px; }

      /* Credentials specific styling */
      .credentials-container {
        background: linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(61,61,61,0.04) 100%);
        border: 2px solid var(--xbox-wave-grey);
        border-left: 4px solid #ef4444;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 12px;
      }

      .credential-item {
        background: rgba(61,61,61,0.6);
        border: 1px solid var(--xbox-wave-grey);
        border-left: 3px solid var(--xbox-green);
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 10px;
        display: grid;
        grid-template-columns: 1fr 2fr 1fr;
        gap: 12px;
        align-items: start;
      }

      .credential-type {
        font-weight: 700;
        color: var(--xbox-green-light);
        word-break: break-word;
      }

      .credential-details {
        font-size: 12px;
        color: var(--muted);
        line-height: 1.6;
      }

      .credential-severity {
        text-align: right;
      }

      /* credential probe result styles */
      .credential-test-valid {
        color: #ef4444;
        font-weight: 700;
        margin-top: 6px;
      }
      .credential-test-info {
        font-size: 11px;
        color: var(--muted);
        margin-top: 4px;
      }

      .jwt-details {
        background: rgba(16,124,16,0.04);
        border: 1px solid var(--xbox-wave-grey);
        border-radius: 6px;
        padding: 8px;
        margin-top: 8px;
        font-size: 11px;
        font-family: 'Courier New', monospace;
      }

      .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      @media (max-width: 980px) { .card { grid-column: span 6; } .two-col { grid-template-columns: 1fr; } }
      @media (max-width: 560px) { .card { grid-column: span 12; } }

      .toolbar { 
        display: flex; 
        align-items: center; 
        gap: 10px; 
        flex-wrap: wrap;
        padding: 14px;
        background: rgba(61,61,61,0.5);
        backdrop-filter: blur(10px);
        border-radius: 10px;
        margin-bottom: 14px;
        border-left: 3px solid var(--xbox-green);
      }
      .toolbar strong {
        color: var(--xbox-green-light);
        font-size: 14px;
      }
      .chip { 
        cursor: pointer; 
        user-select: none;
        transition: all 0.2s ease;
      }
      .chip:hover {
        transform: translateY(-1px);
      }
      .chip input { 
        margin-right: 6px;
        cursor: pointer;
      }

      ul {
        margin: 8px 0;
        padding-left: 20px;
      }
      li {
        margin: 6px 0;
        line-height: 1.6;
      }

      /* Scrollable secrets container */
      .secrets-scroll-container {
        max-height: 600px;
        overflow-y: auto;
        border: 2px solid var(--xbox-wave-grey);
        border-radius: 10px;
        padding: 12px;
        background: rgba(61,61,61,0.4);
        backdrop-filter: blur(10px);
      }
      
      .secrets-scroll-container::-webkit-scrollbar {
        width: 8px;
      }
      
      .secrets-scroll-container::-webkit-scrollbar-track {
        background: rgba(16,124,16,0.1);
        border-radius: 8px;
      }
      
      .secrets-scroll-container::-webkit-scrollbar-thumb {
        background: var(--xbox-green);
        border-radius: 8px;
      }
      
      .secrets-scroll-container::-webkit-scrollbar-thumb:hover {
        background: var(--xbox-green-light);
      }

      .copy-button {
        background: linear-gradient(135deg, rgba(16,124,16,0.15) 0%, rgba(16,124,16,0.08) 100%);
        border: 1px solid var(--xbox-green);
        color: var(--xbox-green-light);
        padding: 6px 12px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: all 0.2s ease;
        margin-left: 8px;
      }
      
      .copy-button:hover {
        background: linear-gradient(135deg, rgba(16,124,16,0.25) 0%, rgba(16,124,16,0.15) 100%);
        transform: translateY(-1px);
      }
      
      .copy-button.copied {
        background: rgba(34,197,94,0.2);
        border-color: var(--low);
        color: var(--low);
      }

      .full-value-display {
        background: rgba(0,0,0,0.6);
        border: 1px solid var(--xbox-wave-grey);
        border-radius: 6px;
        padding: 10px;
        margin-top: 8px;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        color: var(--xbox-green-light);
        word-break: break-all;
        white-space: pre-wrap;
        line-height: 1.4;
      }
    </style>
  </head>
  <body class="antialiased">
    <div class="page">
      <div class="page-main">
        <div class="container-xl">
      <div class="header">
        <div>
          <h1 class="title">🛡️ RECON REPORT</h1>
          <div class="subtitle">
            <div><strong>Target:</strong> <code>{{ data.target }}</code></div>
            <div>Generated: {{ data.__generated_at }}</div>
          </div>
        </div>
        <div class="pill">
          <span>Endpoints:</span> <strong>{{ (data.endpoints|length) }}</strong>
          <span style="margin-left:10px;">Exposed Creds:</span> <strong>{{ (data.secrets|length) }}</strong>
          <span style="margin-left:10px;">Vulns:</span> <strong>{{ (data.vulns|length) }}</strong>
        </div>
      </div>

      <div class="row row-deck" style="margin-bottom: 12px;">
        <div class="col-sm-6 col-lg-3">
          <div class="card card-bordered">
            <div class="k">🔴 CRITICAL</div>
            <div class="v" style="color: var(--crit)">{{ data.__risk_counts.CRITICAL }}</div>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <div class="card card-bordered">
            <div class="k">🟠 HIGH</div>
            <div class="v" style="color: var(--high)">{{ data.__risk_counts.HIGH }}</div>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <div class="card card-bordered">
            <div class="k">🟡 MEDIUM</div>
            <div class="v" style="color: var(--med)">{{ data.__risk_counts.MEDIUM }}</div>
          </div>
        </div>
        <div class="col-sm-6 col-lg-3">
          <div class="card card-bordered">
            <div class="k">🟢 LOW / INFO</div>
            <div class="v" style="color: var(--info)">{{ data.__risk_counts.LOW + data.__risk_counts.INFO }}</div>
          </div>
        </div>
      </div>

      <div class="panel" style="margin-bottom: 12px;">
        <div class="toolbar">
          <strong>🎯 Risk Findings</strong>
          <span class="muted">(click to filter)</span>
          <label class="badge chip sev-CRITICAL"><input type="checkbox" checked data-sev="CRITICAL" />CRITICAL</label>
          <label class="badge chip sev-HIGH"><input type="checkbox" checked data-sev="HIGH" />HIGH</label>
          <label class="badge chip sev-MEDIUM"><input type="checkbox" checked data-sev="MEDIUM" />MEDIUM</label>
          <label class="badge chip sev-LOW"><input type="checkbox" checked data-sev="LOW" />LOW</label>
          <label class="badge chip sev-INFO"><input type="checkbox" checked data-sev="INFO" />INFO</label>
        </div>

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

      <!-- EXPOSED CREDENTIALS SECTION -->
      {% if data.__secrets_masked|length > 0 %}
      <div class="credentials-container">
        <h2 style="color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 10px;">⚠️  EXPOSED CREDENTIALS DETECTED</h2>
        <div class="muted" style="margin-bottom: 14px; font-size: 12px;">
          <strong>{{ data.__secrets_masked|length }}</strong> credential(s) found across JavaScript, configuration, and response data. Review and rotate immediately.
        </div>
        
        <div class="secrets-scroll-container">
          {% for s in data.__secrets_masked %}
          <div class="credential-item">
            <div class="credential-type">{{ s.type }}</div>
            <div class="credential-details">
              <strong>Value:</strong> <code>{{ s.masked }}</code>
              <button class="copy-button" data-secret="{{ s.value }}">📋 Copy</button>
              <br>
              <strong>Confidence:</strong> {{ "%.0f" | format(s.get('confidence', 0.8) * 100) }}%<br>
              <strong>Category:</strong> <span class="badge">{{ s.get('category', 'unknown') }}</span><br>
              {% if s.get('jwt_claims') %}
              <details style="margin-top: 8px;">
                <summary style="color: var(--xbox-green-light); font-weight: 600; cursor: pointer;">JWT Claims</summary>
                <div class="jwt-details">
                  {{ (s.jwt_claims | tojson) }}
                </div>
              </details>
              {% endif %}
              <strong>Description:</strong> {{ s.get('description', 'Exposed credential') }}
              
              <!-- Full Value Display -->
              <div class="full-value-display">
                <strong>Full Secret Value:</strong><br>
                {{ s.value }}
              </div>
              
              {% if s.valid %}
              <div class="credential-test-valid">⚠️ Probe succeeded (status {{ s.test_status }}{% if s.test_method %} via {{ s.test_method }}{% endif %})</div>
              {% if s.test_message %}
              <div class="credential-test-info">{{ s.test_message }}</div>
              {% endif %}
              {% if s.test_excerpt %}
              <div class="credential-test-info"><strong>Response Excerpt:</strong><br><code style="display: block; padding: 8px; background: rgba(0,0,0,0.8); border-radius: 4px; margin-top: 4px;">{{ s.test_excerpt }}</code></div>
              {% endif %}
              {% elif s.tested %}
              <div class="credential-test-info">Tested; status {{ s.test_status }}{% if s.test_method %} via {{ s.test_method }}{% endif %}</div>
              {% elif s.test_message %}
              <div class="credential-test-info">Probe note: {{ s.test_message }}</div>
              {% endif %}
            </div>
            <div class="credential-severity">
              <span class="badge sev-{{ s.get('severity', 'HIGH') }}">{{ s.get('severity', 'HIGH') }}</span>
              <div style="font-size: 11px; color: var(--muted); margin-top: 6px;">{{ s.get('source', 'unknown') }}</div>
            </div>
          </div>
          {% endfor %}
        </div>
      </div>
      {% else %}
      <div class="panel">
        <h2>🔐 Exposed Credentials</h2>
        <div class="muted">✅ No exposed credentials detected.</div>
      </div>
      {% endif %}

      <div class="two-col">
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
    </div> <!-- container-xl -->
  </div> <!-- page-main -->
</div> <!-- page -->

    <script src="https://cdn.jsdelivr.net/npm/tabler@1.0.0/dist/js/tabler.min.js"></script>
    <script>
      /**
       * Copy secret value to clipboard with visual feedback
       * Shows a temporary "Copied" indicator on the button
       */
      function copySecret(button) {
        const secretValue = button.getAttribute('data-secret');
        navigator.clipboard.writeText(secretValue).then(() => {
          const originalText = button.textContent;
          button.textContent = '✓ Copied!';
          button.classList.add('copied');
          setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
          }, 2000);
        }).catch(err => {
          console.error('Failed to copy:', err);
          alert('Failed to copy. Check browser console.');
        });
      }
      
      // Attach click handlers to all copy buttons
      document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.copy-button').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            copySecret(btn);
          });
        });
      });
      
      // Risk findings filter functionality
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

