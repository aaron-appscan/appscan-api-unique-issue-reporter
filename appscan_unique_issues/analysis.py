"""Collapse a raw AppScan issue list into unique issue types and advisories."""

import logging
import re
import urllib.parse
import xml.etree.ElementTree as ElementTree
from collections import Counter, OrderedDict

from .api import quote_odata_literal
from .errors import AppScanReporterError

LOGGER = logging.getLogger(__name__)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

#: Advisory XML/HTML section names, in the order we want them reported.
_SECTION_ALIASES = OrderedDict([
    ("description", ("testtechnicaldescription", "description", "advisory", "summary",
                     "issuetypedescription")),
    ("cause", ("causes", "cause", "securityrisks", "securityrisk", "risk")),
    ("fix_recommendation", ("fixrecommendation", "fix", "recommendations", "recommendation",
                            "remediation", "general", "fixrecommendationtext")),
    ("affected_products", ("affectedproducts", "affectedproduct", "applicability")),
    ("threat_classification", ("threatclassification", "threatclass", "classification")),
    ("technical_detail", ()),
])

#: AppScan returns issue *instance* data (not advisory prose) for IAST/SAST
#: findings. These are the fields worth surfacing from such documents.
_INSTANCE_DETAIL_FIELDS = OrderedDict([
    ("sink_info", "Sink information"),
    ("sinkinfo", "Sink information"),
    ("exploit_example", "Exploit example"),
    ("exploitexample", "Exploit example"),
    ("vulnerable_characters", "Vulnerable characters"),
    ("vulnerablecharacters", "Vulnerable characters"),
    ("source_url", "Source URL"),
    ("sourceurl", "Source URL"),
])

_TAG_SPLIT = re.compile(r"\s*\n\s*")
_WHITESPACE = re.compile(r"[ \t\r\f\v]+")
_HTML_BLOCK_END = re.compile(r"</(p|div|li|h[1-6]|tr|br)\s*>|<br\s*/?>", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"https?://[^\s<>\"')]+")
#: DTD / entity declarations are rejected before parsing: ElementTree is immune to
#: external entity expansion but remains exposed to entity-expansion ("billion
#: laughs") denial of service. See SECURITY-DEPENDENCY-REVIEW.md.
_DOCTYPE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
MAX_ADVISORY_BYTES = 8 * 1024 * 1024


class UniqueIssueType(object):
    """An aggregated view of every issue sharing one AppScan issue type."""

    def __init__(self, type_id, name):
        self.type_id = type_id
        self.name = name
        self.count = 0
        self.severities = Counter()
        self.statuses = Counter()
        self.scanners = Counter()
        self.discovery_methods = Counter()
        self.cwes = set()
        self.locations = []
        self.sample_issue_id = None
        self.advisory = {}

    # -- aggregation ---------------------------------------------------
    def add(self, issue):
        self.count += 1
        _bump(self.severities, issue.get("Severity"))
        _bump(self.statuses, issue.get("Status"))
        _bump(self.scanners, issue.get("Scanner"))
        _bump(self.discovery_methods, issue.get("DiscoveryMethod"))

        cwe = issue.get("Cwe")
        if cwe not in (None, "", 0):
            self.cwes.add(str(cwe))

        location = issue.get("Location") or issue.get("SourceFile") or issue.get("Api")
        if location and len(self.locations) < 10 and location not in self.locations:
            self.locations.append(location)

        if self.sample_issue_id is None and issue.get("Id"):
            self.sample_issue_id = str(issue["Id"])

    # -- derived -------------------------------------------------------
    @property
    def max_severity(self):
        for severity in SEVERITY_ORDER:
            if self.severities.get(severity):
                return severity
        return next(iter(self.severities), "Unspecified")

    @property
    def severity_rank(self):
        try:
            return SEVERITY_ORDER.index(self.max_severity)
        except ValueError:
            return len(SEVERITY_ORDER)

    def odata_filter(self):
        """OData filter that isolates this issue type within the application."""
        if self.type_id:
            return "IssueTypeId eq {0}".format(quote_odata_literal(self.type_id))
        return "IssueType eq {0}".format(quote_odata_literal(self.name))

    def to_dict(self, links):
        return OrderedDict([
            ("issueTypeId", self.type_id),
            ("issueTypeName", self.name),
            ("occurrences", self.count),
            ("maxSeverity", self.max_severity),
            ("severityBreakdown", OrderedDict(self.severities.most_common())),
            ("statusBreakdown", OrderedDict(self.statuses.most_common())),
            ("scanners", sorted(self.scanners)),
            ("discoveryMethods", sorted(self.discovery_methods)),
            ("cwe", sorted(self.cwes)),
            ("sampleLocations", list(self.locations)),
            ("sampleIssueId", self.sample_issue_id),
            ("appscanDefinition", self.advisory.get("description", [])),
            ("cause", self.advisory.get("cause", [])),
            ("howToFix", self.advisory.get("fix_recommendation", [])),
            ("affectedProducts", self.advisory.get("affected_products", [])),
            ("threatClassification", self.advisory.get("threat_classification", [])),
            ("technicalDetail", self.advisory.get("technical_detail", [])),
            ("references", self.advisory.get("references", [])),
            ("advisoryAvailable", bool(self.advisory.get("_resolved"))),
            ("links", links),
        ])


def _bump(counter, value):
    if value not in (None, ""):
        counter[str(value)] += 1


# ----------------------------------------------------------------------
# 4. Build the unique issue type list
# ----------------------------------------------------------------------
def build_unique_issue_types(issues):
    """Group raw issues by issue type, preserving first-seen order."""
    grouped = OrderedDict()
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        name = issue.get("IssueType") or issue.get("ApiVulnName") or "Unclassified issue"
        type_id = issue.get("IssueTypeId") or issue.get("IssueTypeGuid") or ""
        key = type_id or name.lower()
        if key not in grouped:
            grouped[key] = UniqueIssueType(type_id, name)
        grouped[key].add(issue)

    ordered = sorted(
        grouped.values(), key=lambda t: (t.severity_rank, -t.count, t.name.lower())
    )
    LOGGER.info("Collapsed %s issue(s) into %s unique issue type(s)",
                sum(t.count for t in ordered), len(ordered))
    return ordered


# ----------------------------------------------------------------------
# Advisory enrichment (AppScan definition + how to fix)
# ----------------------------------------------------------------------
def enrich_with_advisories(client, issue_types, locale="en-US"):
    """Attach AppScan's own definition and fix recommendation to each type.

    Advisory retrieval is best-effort: a failure for one issue type must never
    abort the whole report, so each lookup is individually guarded.
    """
    for issue_type in issue_types:
        if not issue_type.sample_issue_id:
            issue_type.advisory = {"_resolved": False,
                                   "_error": "No representative issue id available."}
            continue
        try:
            raw = client.get_issue_details(issue_type.sample_issue_id, fmt="xml", locale=locale)
            advisory = parse_advisory_xml(raw)
            # Only retry as HTML when the XML was genuinely empty. Instance-data
            # documents return the same payload for both formats, and parsing
            # them as prose fills the report with hashes and identifiers.
            if not _has_content(advisory) and not advisory.get("_instance_data"):
                raw = client.get_issue_details(
                    issue_type.sample_issue_id, fmt="html", locale=locale)
                advisory = parse_advisory_html(raw)
            advisory["_resolved"] = _has_content(advisory)
            issue_type.advisory = advisory
        except AppScanReporterError as exc:
            LOGGER.warning("Advisory lookup failed for %r: %s", issue_type.name, exc)
            issue_type.advisory = {"_resolved": False, "_error": str(exc)}
        except Exception as exc:  # defensive: malformed advisory must not be fatal
            LOGGER.warning("Could not parse advisory for %r: %s", issue_type.name, exc)
            issue_type.advisory = {"_resolved": False, "_error": str(exc)}
    return issue_types


def _has_content(advisory):
    return any(advisory.get(key) for key in _SECTION_ALIASES)


def _has_prose(advisory):
    """True when the document contained real advisory text (not instance data)."""
    return any(advisory.get(key) for key in _SECTION_ALIASES if key != "technical_detail")


def parse_advisory_xml(xml_text):
    """Map an AppScan advisory XML document onto our canonical sections."""
    advisory = OrderedDict((key, []) for key in _SECTION_ALIASES)
    advisory["references"] = []
    if not xml_text or not xml_text.strip():
        return advisory

    if len(xml_text) > MAX_ADVISORY_BYTES:
        LOGGER.warning("Advisory document exceeded %s bytes and was truncated.",
                       MAX_ADVISORY_BYTES)
        xml_text = xml_text[:MAX_ADVISORY_BYTES]

    if _DOCTYPE.search(xml_text):
        LOGGER.warning("Advisory document declares a DTD/entity; parsing it as inert text "
                       "instead of XML.")
        return parse_advisory_html(xml_text)

    try:
        root = ElementTree.fromstring(xml_text.lstrip("\ufeff"))
    except ElementTree.ParseError as exc:
        LOGGER.debug("Advisory XML did not parse (%s); falling back to HTML parsing", exc)
        return parse_advisory_html(xml_text)

    # IAST/SAST documents carry issue instance data rather than advisory prose.
    # Parsing them as text produces meaningless hashes and identifiers, so pull
    # out the genuinely useful technical fields instead.
    for element in root.iter():
        label = _INSTANCE_DETAIL_FIELDS.get(_normalise_tag(element.tag))
        if not label:
            continue
        text = _clean_text("".join(element.itertext()))
        if text:
            _extend(advisory["technical_detail"], ["{0}: {1}".format(label, text)])
        _collect_references(advisory, text)
    advisory["technical_detail"] = advisory["technical_detail"][:12]

    for element in root.iter():
        section = _match_section(_normalise_tag(element.tag))
        if not section:
            continue
        # Skip container elements (e.g. <advisory>) that wrap more specific
        # sections, otherwise every child's text leaks into the parent section.
        if any(_match_section(_normalise_tag(child.tag)) for child in element.iter()
               if child is not element):
            continue
        text = _clean_text("".join(element.itertext()))
        if text:
            _extend(advisory[section], _paragraphs(text))
        _collect_references(advisory, text)

    for key in advisory:
        if isinstance(advisory[key], list) and key != "references":
            advisory[key] = advisory[key][:12]

    # Instance-data documents yield no advisory prose. Flag them so the caller
    # does not retry as HTML, which returns the same payload and would fill the
    # report with hashes and identifiers.
    if not _has_prose(advisory):
        advisory["_instance_data"] = True
    return advisory


def parse_advisory_html(html_text):
    """Best-effort extraction of advisory sections from the HTML rendering."""
    advisory = OrderedDict((key, []) for key in _SECTION_ALIASES)
    advisory["references"] = []
    if not html_text or not html_text.strip():
        return advisory

    text = _HTML_BLOCK_END.sub("\n", html_text)
    text = _HTML_TAG.sub(" ", text)
    text = _clean_text(_unescape(text))

    current = "description"
    for block in _paragraphs(text):
        section = _match_section(block.lower().strip(": ").replace(" ", "")[:40])
        if section and len(block) < 60:
            current = section
            continue
        advisory[current].append(block)
        _collect_references(advisory, block)

    for key in _SECTION_ALIASES:
        advisory[key] = advisory[key][:12]
    return advisory


def _match_section(tag):
    for section, aliases in _SECTION_ALIASES.items():
        for alias in aliases:
            if tag == alias or tag.startswith(alias):
                return section
    return None


def _collect_references(advisory, text):
    for url in _URL.findall(text or ""):
        url = url.rstrip(".,);")
        if url not in advisory["references"] and len(advisory["references"]) < 25:
            advisory["references"].append(url)


def _local_tag(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def _normalise_tag(tag):
    return _local_tag(tag).lower().replace("_", "").replace("-", "").replace(" ", "")


def _clean_text(text):
    text = (text or "").replace("\ufeff", "")
    text = _WHITESPACE.sub(" ", text)
    return "\n".join(line.strip() for line in text.splitlines()).strip()


def _paragraphs(text):
    return [p.strip() for p in _TAG_SPLIT.split(text) if p and p.strip()]


def _extend(target, values):
    for value in values:
        if value not in target:
            target.append(value)


def _unescape(text):
    try:
        import html
        return html.unescape(text)
    except Exception:  # pragma: no cover
        return text


# ----------------------------------------------------------------------
# Clickable reference links
# ----------------------------------------------------------------------
CWE_DEFINITION_URL = "https://cwe.mitre.org/data/definitions/{0}.html"


def build_links(ui_base_url, api_base_url, app_id, issue_type, cwe_template=None):
    """Build the clickable reference links for one issue type.

    The primary link is the authoritative CWE definition for the weakness. The
    AppScan console is linked at application scope only: its issue list does not
    honour an externally supplied issue-type filter, so a per-type deep link
    would silently show every issue and mislead the reader.
    """
    template = cwe_template or CWE_DEFINITION_URL
    cwe_links = []
    for cwe in sorted(issue_type.cwes, key=_cwe_sort_key):
        number = str(cwe).strip().upper().replace("CWE-", "").strip()
        if not number.isdigit():
            continue
        cwe_links.append(OrderedDict([
            ("id", "CWE-{0}".format(number)),
            ("url", template.format(number, cwe=number, id=number)),
        ]))

    app_link = "{api}/api/v4/Issues/Application/{appId}?$filter={filter}".format(
        api=api_base_url.rstrip("/"),
        appId=urllib.parse.quote(str(app_id)),
        filter=urllib.parse.quote(issue_type.odata_filter(), safe=""),
    )
    return OrderedDict([
        ("cweDefinitions", cwe_links),
        ("appscanApiQuery", app_link),
        ("odataFilter", issue_type.odata_filter()),
    ])


def _cwe_sort_key(cwe):
    digits = str(cwe).strip().upper().replace("CWE-", "").strip()
    return (0, int(digits)) if digits.isdigit() else (1, 0)
