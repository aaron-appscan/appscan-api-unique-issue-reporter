"""Report model and HTML / XML / JSON renderers."""

import datetime
import json
import logging
import os
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ElementTree
from collections import Counter, OrderedDict
from html import escape

from . import __version__
from .analysis import SEVERITY_ORDER, build_links
from .errors import ConfigurationError, ReportGenerationError

LOGGER = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("html", "xml", "json")

_SEVERITY_COLOURS = {
    "Critical": "#7d0a0a",
    "High": "#c0392b",
    "Medium": "#e67e22",
    "Low": "#2980b9",
    "Informational": "#7f8c8d",
}


def build_report_model(application, issue_types, total_issues, ui_base_url, api_base_url,
                       cwe_template=None, odata_filter=None):
    """Assemble the format-agnostic report document."""
    app_id = application.get("Id")
    severity_totals = Counter()
    for issue_type in issue_types:
        severity_totals.update(issue_type.severities)

    serialised = []
    for issue_type in issue_types:
        links = build_links(ui_base_url, api_base_url, app_id, issue_type, cwe_template)
        serialised.append(issue_type.to_dict(links))

    return OrderedDict([
        ("tool", "AppScan Unique Issue Reporter"),
        ("toolVersion", __version__),
        ("generatedAt", datetime.datetime.now().astimezone().isoformat()),
        ("application", OrderedDict([
            ("id", app_id),
            ("name", application.get("Name")),
            ("businessUnit", application.get("BusinessUnit")),
            ("riskRating", application.get("RiskRating")),
            ("lastUpdated", application.get("LastUpdated")),
            ("appscanUrl", "{0}/AsoCUI/serviceui/main/myapps/{1}/issues".format(
                ui_base_url.rstrip("/"), app_id)),
        ])),
        ("summary", OrderedDict([
            ("issuesAnalysed", total_issues),
            ("uniqueIssueTypes", len(issue_types)),
            ("issueFilterApplied", odata_filter or "(none)"),
            ("severityBreakdown", OrderedDict(
                (s, severity_totals.get(s, 0)) for s in SEVERITY_ORDER if severity_totals.get(s)
            )),
        ])),
        ("issueTypes", serialised),
    ])


def render(model, fmt):
    """Render the report model into the requested output format."""
    fmt = (fmt or "html").lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ConfigurationError(
            "Unsupported export format {0!r}. Choose one of: {1}".format(
                fmt, ", ".join(SUPPORTED_FORMATS))
        )
    try:
        if fmt == "json":
            return json.dumps(model, indent=2, ensure_ascii=False)
        if fmt == "xml":
            return _render_xml(model)
        return _render_html(model)
    except ReportGenerationError:
        raise
    except Exception as exc:
        raise ReportGenerationError("Failed to render the {0} report: {1}".format(fmt, exc))


def write_report(content, path):
    """Write a rendered report to disk, creating parent folders as needed."""
    try:
        folder = os.path.dirname(os.path.abspath(path))
        if folder and not os.path.isdir(folder):
            os.makedirs(folder)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        raise ReportGenerationError("Could not write the report to {0}: {1}".format(path, exc))
    LOGGER.info("Report written to %s", os.path.abspath(path))
    return os.path.abspath(path)


# ----------------------------------------------------------------------
# XML
# ----------------------------------------------------------------------
def _render_xml(model):
    root = ElementTree.Element("AppScanUniqueIssueReport", {
        "tool": str(model["tool"]),
        "version": str(model["toolVersion"]),
        "generatedAt": str(model["generatedAt"]),
    })
    _dict_to_xml(ElementTree.SubElement(root, "Application"), model["application"])
    _dict_to_xml(ElementTree.SubElement(root, "Summary"), model["summary"])

    types_el = ElementTree.SubElement(root, "IssueTypes", {"count": str(len(model["issueTypes"]))})
    for item in model["issueTypes"]:
        _dict_to_xml(ElementTree.SubElement(types_el, "IssueType"), item)

    raw = ElementTree.tostring(root, encoding="utf-8")
    return minidom.parseString(raw).toprettyxml(indent="  ")


def _dict_to_xml(parent, data):
    for key, value in data.items():
        tag = _xml_tag(key)
        if isinstance(value, dict):
            _dict_to_xml(ElementTree.SubElement(parent, tag), value)
        elif isinstance(value, (list, tuple)):
            container = ElementTree.SubElement(parent, tag)
            for entry in value:
                child = ElementTree.SubElement(container, "Item")
                if isinstance(entry, dict):
                    _dict_to_xml(child, entry)
                else:
                    child.text = _xml_text(entry)
        else:
            ElementTree.SubElement(parent, tag).text = _xml_text(value)


def _xml_tag(key):
    tag = "".join(ch if (ch.isalnum() or ch in "_-.") else "_" for ch in str(key))
    if not tag or not (tag[0].isalpha() or tag[0] == "_"):
        tag = "_" + tag
    return tag[0].upper() + tag[1:]


def _xml_text(value):
    if value is None:
        return ""
    text = str(value)
    # Strip control characters that are illegal in XML 1.0.
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------
def _render_html(model):
    app = model["application"]
    summary = model["summary"]
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>{0} - Unique AppScan Issue Types</title>".format(escape(str(app.get("name")))),
        "<style>{0}</style>".format(_CSS),
        "</head><body>",
        "<header><h1>Unique AppScan Issue Types</h1>",
        "<p class='sub'>{0} &middot; generated {1} by {2} v{3}</p></header>".format(
            escape(str(app.get("name"))), escape(str(model["generatedAt"])),
            escape(str(model["tool"])), escape(str(model["toolVersion"]))),
        "<section class='card'><h2>Application</h2><dl>",
    ]

    for label, key in (("Name", "name"), ("Application ID", "id"),
                       ("Business unit", "businessUnit"), ("Risk rating", "riskRating"),
                       ("Last updated", "lastUpdated")):
        parts.append("<dt>{0}</dt><dd>{1}</dd>".format(label, escape(str(app.get(key) or "-"))))
    parts.append(
        "<dt>AppScan</dt><dd><a href='{0}' target='_blank' rel='noopener'>"
        "Open all issues in AppScan</a></dd>".format(escape(str(app.get("appscanUrl"))))
    )
    parts.append("</dl></section>")

    parts.append("<section class='card'><h2>Summary</h2><div class='metrics'>")
    parts.append(_metric("Issues analysed", summary["issuesAnalysed"]))
    parts.append(_metric("Unique issue types", summary["uniqueIssueTypes"]))
    for severity, count in summary["severityBreakdown"].items():
        parts.append(_metric(severity, count, _SEVERITY_COLOURS.get(severity)))
    parts.append("</div>")
    parts.append("<p class='sub'>Issue filter: <code>{0}</code></p></section>".format(
        escape(str(summary["issueFilterApplied"]))))

    parts.append("<section class='card'><h2>Unique issue types</h2><table><thead><tr>"
                 "<th>#</th><th>Issue type</th><th>Max severity</th><th>Occurrences</th>"
                 "<th>CWE definition</th></tr></thead><tbody>")
    for index, item in enumerate(model["issueTypes"], 1):
        parts.append(
            "<tr><td>{0}</td><td><a href='#type-{0}'>{1}</a></td><td>{2}</td>"
            "<td>{3}</td><td>{4}</td></tr>".format(
                index,
                escape(str(item["issueTypeName"])),
                _badge(item["maxSeverity"]),
                item["occurrences"],
                _cwe_link_list(item["links"]["cweDefinitions"]),
            )
        )
    parts.append("</tbody></table></section>")

    for index, item in enumerate(model["issueTypes"], 1):
        parts.append(_html_issue_type(index, item))

    parts.append("<footer><p class='sub'>Advisory text and fix recommendations are retrieved "
                 "from the HCL AppScan Data API and remain the property of HCL.</p></footer>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _html_issue_type(index, item):
    links = item["links"]
    cwe_defs = links["cweDefinitions"]
    out = ["<section class='card issue' id='type-{0}'>".format(index)]
    out.append("<h3>{0}. {1} {2}</h3>".format(
        index, escape(str(item["issueTypeName"])), _badge(item["maxSeverity"])))

    out.append("<p class='sub'>{0} occurrence(s) &middot; type id <code>{1}</code>"
               "{2}</p>".format(
                   item["occurrences"],
                   escape(str(item["issueTypeId"] or "n/a")),
                   " &middot; CWE " + escape(", ".join(item["cwe"])) if item["cwe"] else ""))

    if cwe_defs:
        buttons = " ".join(
            "<a class='button' href='{0}' target='_blank' rel='noopener'>"
            "{1} definition</a>".format(escape(str(c["url"])), escape(str(c["id"])))
            for c in cwe_defs
        )
        out.append("<p class='links'>{0}</p>".format(buttons))
    else:
        out.append("<p class='sub'>AppScan did not map this issue type to a CWE identifier.</p>")

    out.append(_html_section("What AppScan reports (definition)", item["appscanDefinition"]))
    out.append(_html_section("Cause / security risk", item["cause"]))
    out.append(_html_section("How to fix it", item["howToFix"]))
    out.append(_html_section("Affected products", item["affectedProducts"]))
    out.append(_html_section("Threat classification", item["threatClassification"]))
    out.append(_html_section("Technical detail reported by AppScan",
                             item.get("technicalDetail") or []))

    if not item["advisoryAvailable"]:
        out.append("<p class='warn'>AppScan returned no advisory text for this issue type. "
                   "Use the CWE definition above for remediation guidance.</p>")

    if item["sampleLocations"]:
        out.append("<h4>Example locations</h4><ul class='locations'>")
        for location in item["sampleLocations"]:
            out.append("<li><code>{0}</code></li>".format(escape(str(location))))
        out.append("</ul>")

    if item["references"]:
        out.append("<h4>References</h4><ul>")
        for ref in item["references"]:
            out.append("<li><a href='{0}' target='_blank' rel='noopener'>{0}</a></li>".format(
                escape(str(ref))))
        out.append("</ul>")

    out.append("<h4>AppScan query for this issue type</h4>"
               "<p class='sub'>Use this OData filter against the Data API to list just these "
               "issues: <code>{0}</code></p>".format(escape(str(links["odataFilter"]))))

    out.append("</section>")
    return "\n".join(out)


def _cwe_link_list(cwe_defs):
    if not cwe_defs:
        return "-"
    return ", ".join(
        "<a href='{0}' target='_blank' rel='noopener'>{1}</a>".format(
            escape(str(c["url"])), escape(str(c["id"])))
        for c in cwe_defs
    )


def _html_section(title, paragraphs):
    if not paragraphs:
        return ""
    body = "".join("<p>{0}</p>".format(escape(str(p))) for p in paragraphs)
    return "<h4>{0}</h4>{1}".format(escape(title), body)


def _metric(label, value, colour=None):
    style = " style='border-color:{0}'".format(colour) if colour else ""
    return "<div class='metric'{0}><span class='value'>{1}</span>" \
           "<span class='label'>{2}</span></div>".format(style, escape(str(value)), escape(label))


def _badge(severity):
    colour = _SEVERITY_COLOURS.get(severity, "#555")
    return "<span class='badge' style='background:{0}'>{1}</span>".format(
        colour, escape(str(severity)))


_CSS = """
:root{--bg:#f4f6f8;--card:#fff;--ink:#1f2933;--muted:#62707d;--line:#dfe4ea}
*{box-sizing:border-box}
body{margin:0;padding:0 0 48px;background:var(--bg);color:var(--ink);
 font:15px/1.55 "Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{background:#0f2b46;color:#fff;padding:28px 32px}
header h1{margin:0;font-size:24px}
header .sub{color:#b9c9d8}
.card{background:var(--card);margin:20px 32px;padding:20px 24px;border:1px solid var(--line);
 border-radius:10px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
h2{margin-top:0;font-size:18px}h3{margin-top:0;font-size:17px}
h4{margin:18px 0 6px;font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.sub{color:var(--muted);font-size:13px}
dl{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}
tbody tr:hover{background:#f8fafc}
.badge{display:inline-block;color:#fff;border-radius:11px;padding:1px 10px;font-size:12px}
.metrics{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0 4px}
.metric{border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:10px 16px;
 min-width:132px}
.metric .value{display:block;font-size:22px;font-weight:600}
.metric .label{color:var(--muted);font-size:12px}
.button{display:inline-block;background:#0b5fff;color:#fff;text-decoration:none;border-radius:6px;
 padding:7px 14px;font-size:13px}
.button:hover{background:#0848c4}
.button.ghost{background:#fff;color:#0b5fff;border:1px solid #0b5fff}
.links{margin:14px 0}
code{background:#eef1f5;border-radius:4px;padding:1px 5px;font-size:12.5px;word-break:break-all}
.locations{margin:4px 0;padding-left:20px}
.warn{background:#fff6e5;border-left:4px solid #e67e22;padding:10px 14px;border-radius:6px;
 font-size:13.5px}
a{color:#0b5fff}
footer{margin:24px 32px 0}
"""
