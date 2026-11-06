# AppScan API Unique Issue Reporter

A dependency-free command line tool that talks directly to the **HCL AppScan on Cloud Data API**
(<https://cloud.appscan.com/swagger/index.html>) and produces a remediation-focused report of the
**unique issue types** affecting an application.

Instead of wading through hundreds of individual findings, you get one entry per distinct weakness —
with AppScan's own description and fix guidance, and a clickable link to the authoritative **CWE
definition** for that weakness.

![Output formats](https://img.shields.io/badge/output-HTML%20%7C%20XML%20%7C%20JSON-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)

## What it does

| Step | Action | Endpoint |
| --- | --- | --- |
| 1 | Establish the connection (API key → bearer token) | `POST /api/v4/Account/ApiKeyLogin` |
| 2 | Resolve the application ID from its name (or validate a supplied ID) | `GET /api/v4/Apps` |
| 3 | Retrieve the full issue list, transparently paged | `GET /api/v4/Issues/Application/{appId}` |
| 4 | Collapse the issues into a list of unique issue types | *(local aggregation)* |
| 5 | Enrich each type with AppScan's advisory and render the report | `GET /api/v4/Issues/{issueId}/Details` |

For every unique issue type the report contains:

* **Summary** — occurrences, maximum severity, severity/status breakdown, CWE, the scanners that
  found it, and example locations (URLs, or source files with line numbers).
* **AppScan's own definition**, cause / security risk, **fix recommendation**, affected products and
  threat classification, taken from the AppScan advisory for that issue type.
* **Technical detail** for IAST/SAST findings — sink information, exploit example, vulnerable
  characters and source URL — where AppScan returns issue instance data rather than advisory prose.
* A clickable **CWE definition link** (e.g. <https://cwe.mitre.org/data/definitions/89.html>) plus
  the exact **OData filter** for querying just that issue type through the Data API.

> **Why CWE links rather than AppScan deep links?**
> The AppScan console does not honour an externally supplied issue-type filter on its issue list — a
> per-type deep link silently shows *every* issue in the application, which is misleading. The report
> therefore links to the authoritative CWE definition at MITRE, and prints the OData filter so the
> same selection can be reproduced against the Data API, where filtering does work.

## Requirements

* Python **3.8 or newer**.
* **No third-party packages.** The tool uses only the Python standard library — see
  [SECURITY-DEPENDENCY-REVIEW.md](./SECURITY-DEPENDENCY-REVIEW.md) for the NVD vulnerability review
  that drove that decision.
* An AppScan on Cloud **API Key ID** and **Key Secret**
  (AppScan → *user menu* → **API Key Management**).

## Install

```powershell
git clone https://github.com/aaron-appscan/appscan-api-unique-issue-reporter.git
cd appscan-api-unique-issue-reporter
py -m pip install .
```

This registers the `appscan-unique-issues` command. For development use `py -m pip install -e .`.
Without installing at all, run it as a module: `py -m appscan_unique_issues --help`.

## Credentials

The Key ID and Key Secret are resolved **independently**, each taking the first source available:

1. the command line argument — `--key-id` / `--key-secret`
2. the environment variable — `APPSCAN_KEY_ID` / `APPSCAN_KEY_SECRET`
3. for the secret only, a non-echoing interactive prompt

Arguments override the environment, the environment is the fallback when arguments are absent, and
the two can be mixed freely. The secret is never logged, never shown in `--help` output, never
written into a report, and is dropped from memory as soon as the bearer token is obtained.

```powershell
# Environment variables (recommended for CI)
$env:APPSCAN_KEY_ID     = "<key id>"
$env:APPSCAN_KEY_SECRET = "<key secret>"
appscan-unique-issues --app-name "AltoroJ" -o report.html

# Arguments (used when the environment variables are not set)
appscan-unique-issues --key-id "<key id>" --key-secret "<key secret>" --app-name "AltoroJ"

# Mixed: ID from the environment, secret supplied explicitly
appscan-unique-issues --key-secret "<key secret>" --app-name "AltoroJ"

# Interactive: prompts for the secret without echoing it
appscan-unique-issues --key-id "<key id>" --app-name "AltoroJ"
```

> On a shared machine prefer the environment variables or the prompt — command line arguments are
> visible in shell history and in the process list.

## Usage

```powershell
# HTML report for an application resolved by name
appscan-unique-issues --app-name "AltoroJ" --output altoroj-unique-issues.html

# JSON, scoped to open issues only, using an application ID
appscan-unique-issues --app-id 0a1b2c3d-... --open-only --format json -o report.json

# XML, filtered to high and critical findings
appscan-unique-issues --app-name "AltoroJ" --format xml `
  --filter "Severity eq 'High' or Severity eq 'Critical'" -o report.xml
```

Logs go to stderr and the report to stdout, so the tool pipes cleanly:

```powershell
appscan-unique-issues --app-name "AltoroJ" --format json --quiet | py -m json.tool
```

### Options

| Option | Description |
| --- | --- |
| `--key-id`, `--key-secret` | AppScan API key pair. Override `APPSCAN_KEY_ID` / `APPSCAN_KEY_SECRET`. |
| `--base-url` | API base URL for your region (env `APPSCAN_BASE_URL`, default `https://cloud.appscan.com`). |
| `--ui-base-url` | Web UI base URL used for the application link; defaults to `--base-url`. |
| `--app-name` / `--app-id` | Target application, by name or ID (mutually exclusive). |
| `--filter` | Extra OData `$filter`, e.g. `"Severity eq 'High'"`. |
| `--open-only` | Shortcut for `Status eq 'Open'`. |
| `--format` | `html` (default), `xml`, or `json`. |
| `--output` / `-o` | Output file. Prints to stdout when omitted. |
| `--no-advisories` | Skip advisory lookups — much faster, but no definitions or fix guidance. |
| `--locale` | Advisory locale (default `en-US`). |
| `--page-size`, `--max-issues` | Paging controls (1–500 per page; `--max-issues 0` = unlimited). |
| `--timeout`, `--retries` | Per-request timeout and retry budget for throttling / transient errors. |
| `--cwe-link-template` | Override the CWE URL, e.g. an internal mirror. Use `{0}` or `{cwe}` for the id. |
| `--insecure` | Disable TLS verification — private gateways only, not recommended. |
| `--verbose` / `--quiet` | Logging verbosity. |

Application name resolution is case-insensitive and exact. If no exact match exists the tool
suggests near matches; if a name is ambiguous it lists the candidate IDs and asks you to use
`--app-id`.

Issue types are grouped by AppScan's `IssueTypeId`, so the same weakness reported by different
analysers (for example SQL Injection found by both the Dynamic and the IAST/Static analyser) appears
as separate entries — each with its own occurrence count, evidence and scanner attribution.

## Output formats

**HTML** — a self-contained, styled report: application header, severity metrics, an index table of
every unique issue type, then one detailed card per type with CWE definition buttons.

**JSON** — the full report model, suitable for piping into other tooling:

```jsonc
{
  "application": { "id": "...", "name": "AltoroJ" },
  "summary": {
    "issuesAnalysed": 454,
    "uniqueIssueTypes": 72,
    "severityBreakdown": { "Critical": 24, "High": 112, "Medium": 157, "Low": 106 }
  },
  "issueTypes": [
    {
      "issueTypeName": "SQL Injection",
      "occurrences": 19,
      "maxSeverity": "Critical",
      "cwe": ["89"],
      "howToFix": ["..."],
      "links": {
        "cweDefinitions": [
          { "id": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html" }
        ],
        "odataFilter": "IssueTypeId eq 'Injection.SQL'"
      }
    }
  ]
}
```

**XML** — the same model as a well-formed `<AppScanUniqueIssueReport>` document, with control
characters that are illegal in XML 1.0 stripped.

## Error handling and exit codes

Every failure path is caught and reported as a single actionable message on stderr — never a raw
traceback. Advisory lookups are individually guarded, so one missing advisory never aborts the
report. Rate limiting (HTTP 429), HTTP 5xx and transient network failures are retried with
exponential backoff that honours `Retry-After`.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Unexpected error |
| 2 | Configuration / argument error |
| 3 | Could not connect to AppScan |
| 4 | Authentication failed (bad or expired API key) |
| 5 | Authorization failed (key lacks access to the application) |
| 6 | Application, issue, or endpoint not found |
| 7 | Unexpected API response |
| 8 | Rate limited, retries exhausted |
| 9 | Report could not be rendered or written |
| 130 | Interrupted by the user |

## Security

* No third-party runtime dependencies — candidates were reviewed against the NVD, see
  [SECURITY-DEPENDENCY-REVIEW.md](./SECURITY-DEPENDENCY-REVIEW.md).
* Advisory XML is scanned for DTD/entity declarations before parsing and capped at 8 MB, blocking
  entity-expansion denial of service.
* All values written into HTML are escaped, so API-sourced text cannot inject markup.
* Application names and issue type IDs are emitted as properly escaped OData string literals.
* TLS verification is on by default; disabling it requires an explicit flag and logs a warning.

## Tests

Offline tests — no credentials or network access required:

```powershell
py -m unittest discover -s tests -v
```

## Layout

```
appscan_unique_issues/
├── api.py        # Data API client (urllib, retries, error mapping)
├── analysis.py   # Unique issue type aggregation, advisory parsing, CWE links
├── report.py     # Report model + HTML / XML / JSON renderers
├── cli.py        # Argument parsing, credential resolution, pipeline
└── errors.py     # Exception hierarchy mapped to exit codes
tests/test_reporter.py
```

## Attribution

Advisory text and fix recommendations are retrieved from the HCL AppScan Data API at run time and
remain the property of HCL; none of it is bundled with this tool. CWE is a trademark of
The MITRE Corporation.
