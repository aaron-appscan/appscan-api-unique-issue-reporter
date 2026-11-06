# Open source component review (NVD)

Before any open source component was adopted, each candidate was checked against the
**National Vulnerability Database** using the NVD CVE API 2.0
(`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...`).

Review date: **2026-11-06**.

## Outcome

**No third-party runtime dependencies are used.** The tool is built entirely on the Python standard
library (`urllib.request`, `json`, `xml.etree.ElementTree`, `argparse`, `html`, `ssl`), which removes
third-party supply-chain exposure from the deployed artefact. `pyproject.toml` therefore declares
`dependencies = []`.

## Candidates evaluated

| Component | Version queried | NVD result | Decision |
| --- | --- | --- | --- |
| `requests` | 2.32.5 | **CVE-2026-25645** (MEDIUM) — `requests.utils.extract_zipped_paths()` uses a predictable temp filename; fixed in 2.33.0 | **Not adopted.** `urllib.request` covers our needs. Had it been adopted, the floor would have been `requests>=2.33.0`. |
| `requests` | 2.33.0 / 2.34.0 | 0 CVEs | Confirms 2.33.0 as the safe floor if ever needed. |
| `lxml` | 5.3.0 | **CVE-2026-41066** (HIGH) — default parser config (`resolve_entities=True`) allows untrusted XML to read local files; fixed in 6.1.0 | **Not adopted.** Advisory XML is parsed with `xml.etree.ElementTree`, which does not resolve external entities. See hardening below. |
| `click` | 8.1.8 | **CVE-2026-7246** (HIGH, disputed — NVD records that it was assigned outside CNA rules and is rejected by the Pallets project) | **Not adopted.** `argparse` from the standard library is sufficient. |
| `jinja2` | 3.1.6 | 0 CVEs | **Not adopted** anyway — HTML is rendered from a small, fully escaped builder, avoiding a template dependency. |

## Build-time tooling

`setuptools` (PEP 517 backend declared in `pyproject.toml`) is used only to build/install the
package; it is not imported at run time and ships no code into the artefact. Keep it current via
`py -m pip install --upgrade pip setuptools`.

## Runtime platform

CPython itself carries CVEs that are patched by the interpreter vendor rather than by this project
(the NVD query for CPython 3.13.9 returned 18 records, mostly historical or OS-packaging related).
Run the tool on a currently patched Python 3.8+ interpreter supplied by your platform.

## Hardening applied as a result of this review

* **XML entity expansion** — advisory documents returned by AppScan are scanned for `<!DOCTYPE` /
  `<!ENTITY` declarations before parsing. Any such document is parsed as inert text instead of XML,
  which blocks entity-expansion denial of service (`xml.etree.ElementTree` is already immune to the
  external-entity file disclosure described in CVE-2026-41066). Advisory payloads are also capped at
  8 MB. Covered by `tests/test_reporter.py::TestAdvisory::test_entity_declarations_are_not_expanded`.
* **Secret disclosure via `--help`** — the API key and secret are resolved at run time rather than
  being used as `argparse` defaults. Had they remained defaults, `ArgumentDefaultsHelpFormatter`
  would have printed the live secret into `--help` output whenever the environment variable was set.
  Covered by `TestCredentials::test_help_output_never_leaks_the_secret`.
* **HTML injection** — every value written into the HTML report is passed through `html.escape`,
  so issue names, locations, and advisory text coming from the API cannot inject markup. Covered by
  `TestRenderers::test_html_escapes_injected_markup`.
* **OData injection** — application names and issue type identifiers are emitted as properly escaped
  OData string literals (`'` doubled). Covered by `TestAggregation::test_odata_literal_escapes_quotes`.
* **XML output safety** — control characters that are illegal in XML 1.0 are stripped and element
  names are sanitised before serialisation.
* **Credential handling** — the API secret is never logged, is read from the environment or a
  non-echoing prompt by preference, and is dropped from memory once the bearer token is held.
* **Transport** — TLS certificate verification is on by default; disabling it requires the explicit
  `--insecure` flag and emits a warning.

## Re-running the check

```powershell
Invoke-RestMethod "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:python:requests:2.33.0:*:*:*:*:*:*:*"
```

Repeat for any component considered in future, and record the result in the table above.
