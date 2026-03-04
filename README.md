# reconscan

`reconscan` is a modular command-line reconnaissance and vulnerability analysis tool for web applications and JavaScript-heavy frontends.

It analyzes websites, JavaScript files, or pasted JavaScript code to discover:

- API endpoints and internal surfaces
- Authentication and business logic flows
- Secrets and internal infrastructure references
- HTTP security posture and technology stack

The engine is rule-based and deterministic; it does **not** use AI during scans.

## Installation

```bash
python -m venv venv
venv\Scripts\activate  # on Windows
pip install -r requirements.txt
```

## Basic Usage

- **Scan a domain** (crawl, collect JS, analyze):

```bash
python -m reconscan https://example.com
```

- **Scan a local JS file**:

```bash
python -m reconscan --js path\to\main.js
```

- **Scan a list of JS URLs**:

```bash
python -m reconscan --js-list jsfiles.txt
```

- **Paste JS via stdin**:

```bash
python -m reconscan --paste
```

Reports can be generated as JSON, Markdown, or HTML.

