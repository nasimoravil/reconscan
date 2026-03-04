#!/usr/bin/env python3
"""Test report generation with sample data."""

from reconscan.core import ReconResult, ReconConfig, ReconEngine

# Create a test result with sample data
test_result = ReconResult(
    target="https://test.example.com",
    technologies=["React", "Express.js"],
    endpoints=[
        {"path": "/api/users", "category": "api", "source": "js"},
        {"path": "/api/admin", "category": "admin", "source": "js"},
        {"path": "/debug", "category": "debug", "source": "js"}
    ],
    secrets=[
        {"type": "AWS_KEY", "value": "AKIA1234567890ABCDEF", "confidence": 0.95}
    ],
    vulns=[
        {
            "technology_instance": "lodash@3.10.1",
            "technology": "lodash",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "cisa_kev": True,
            "sources": ["package.json"]
        }
    ],
    risks=[
        {
            "severity": "CRITICAL",
            "title": "Exposed AWS_KEY",
            "details": {"value": "AKIA1234567890ABCDEF"}
        },
        {
            "severity": "HIGH",
            "title": "Vulnerable dependency match: lodash@3.10.1",
            "details": {"cve": "CVE-2021-23337", "cisa_kev": True}
        }
    ]
)

# Generate HTML report
config = ReconConfig(report_format="html")
engine = ReconEngine(config=config)
html_report = engine.render_report(test_result)

# Check if report contains expected data
tests = [
    ("https://test.example.com", "Target URL"),
    ("AKIA1234567890ABCD", "Secret (masked)"),
    ("lodash@3.10.1", "Vulnerability"),
    ("/api/users", "Endpoints"),
    ("CRITICAL", "Risk severities"),
]

print("Report Generation Tests:")
print("-" * 50)
all_passed = True
for test_str, label in tests:
    if test_str in html_report:
        print(f"✓ {label} found in report")
    else:
        print(f"✗ {label} NOT found in report")
        all_passed = False

# Save to file
with open("test_report.html", "w", encoding="utf-8") as f:
    f.write(html_report)
print("\n✓ Test report saved to test_report.html")

if all_passed:
    print("\n✓ All tests passed!")
else:
    print("\n✗ Some tests failed!")

# additional CLI error check for missing JS file
import subprocess, sys
print("\nChecking CLI behavior for non-existent JS file...")
proc = subprocess.run([sys.executable, "-m", "reconscan", "--js", "does_not_exist.js"], capture_output=True, text=True)
print(f"exit code: {proc.returncode}")
print(proc.stderr or proc.stdout)
if proc.returncode != 0 and "not found" in (proc.stderr + proc.stdout).lower():
    print("✓ CLI produced helpful missing-file message")
else:
    print("✗ CLI message for missing file not as expected")
