"""Offline smoke tests: aggregation, advisory parsing, and all three renderers.

Run with:  py -m unittest discover -s tests  (from the project folder)
"""

import json
import os
import sys
import unittest
import xml.etree.ElementTree as ElementTree

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from appscan_unique_issues.analysis import (  # noqa: E402
    build_links,
    build_unique_issue_types,
    enrich_with_advisories,
    parse_advisory_xml,
)
from appscan_unique_issues.api import AppScanClient, quote_odata_literal  # noqa: E402
from appscan_unique_issues.cli import (  # noqa: E402
    build_parser,
    compose_filter,
    resolve_base_url,
    resolve_credentials,
)
from appscan_unique_issues.errors import AppScanReporterError, ConfigurationError  # noqa: E402
from appscan_unique_issues.report import build_report_model, render  # noqa: E402

ADVISORY_XML = """<?xml version="1.0" encoding="utf-8"?>
<issue-type>
  <advisory>
    <name>Cross-Site Scripting</name>
    <testTechnicalDescription>Untrusted input is echoed into the response.</testTechnicalDescription>
    <causes>Sanitation of hazardous characters was not performed correctly.</causes>
    <fixRecommendation>Encode all user input before writing it to the response.
See https://example.org/xss for details.</fixRecommendation>
    <affectedProducts>All web servers</affectedProducts>
  </advisory>
</issue-type>"""

ISSUES = [
    {"Id": "1", "IssueType": "Cross-Site Scripting", "IssueTypeId": "AttXSS",
     "Severity": "High", "Status": "Open", "Location": "/login.jsp", "Cwe": 79,
     "Scanner": "DAST", "DiscoveryMethod": "Dynamic Analysis"},
    {"Id": "2", "IssueType": "Cross-Site Scripting", "IssueTypeId": "AttXSS",
     "Severity": "Critical", "Status": "Open", "Location": "/search.jsp", "Cwe": 79},
    {"Id": "3", "IssueType": "Missing Secure Attribute", "IssueTypeId": "MissingSecure",
     "Severity": "Low", "Status": "Open", "Location": "/"},
]

APPLICATION = {"Id": "app-123", "Name": "AltoroJ", "RiskRating": "High"}


class StubClient(object):
    def __init__(self, fail_for=()):
        self.fail_for = set(fail_for)

    def get_issue_details(self, issue_id, fmt="xml", locale="en-US"):
        if issue_id in self.fail_for:
            raise ConfigurationError("simulated advisory failure")
        return ADVISORY_XML


def make_model(fail_for=()):
    issue_types = build_unique_issue_types(ISSUES)
    enrich_with_advisories(StubClient(fail_for), issue_types)
    return build_report_model(
        application=APPLICATION,
        issue_types=issue_types,
        total_issues=len(ISSUES),
        ui_base_url="https://cloud.appscan.com",
        api_base_url="https://cloud.appscan.com",
    )


class TestAggregation(unittest.TestCase):
    def test_unique_types_are_collapsed_and_ranked(self):
        types = build_unique_issue_types(ISSUES)
        self.assertEqual(len(types), 2)
        self.assertEqual(types[0].name, "Cross-Site Scripting")
        self.assertEqual(types[0].count, 2)
        self.assertEqual(types[0].max_severity, "Critical")
        self.assertEqual(types[1].max_severity, "Low")
        self.assertEqual(types[0].cwes, {"79"})

    def test_empty_issue_list_is_safe(self):
        self.assertEqual(build_unique_issue_types([]), [])

    def test_odata_literal_escapes_quotes(self):
        self.assertEqual(quote_odata_literal("O'Brien App"), "'O''Brien App'")


class TestAdvisory(unittest.TestCase):
    def test_xml_sections_are_extracted(self):
        advisory = parse_advisory_xml(ADVISORY_XML)
        self.assertTrue(any("Untrusted input" in p for p in advisory["description"]))
        self.assertTrue(any("Encode all user input" in p for p in advisory["fix_recommendation"]))
        self.assertIn("https://example.org/xss", advisory["references"])

    def test_container_elements_do_not_duplicate_sections(self):
        advisory = parse_advisory_xml(ADVISORY_XML)
        self.assertFalse(any("Encode all user input" in p for p in advisory["description"]))
        self.assertEqual(advisory["description"],
                         ["Untrusted input is echoed into the response."])

    def test_malformed_xml_does_not_raise(self):
        self.assertIsInstance(parse_advisory_xml("<not-xml"), dict)

    def test_entity_declarations_are_not_expanded(self):
        hostile = (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<advisory><fixRecommendation>&xxe;</fixRecommendation></advisory>'
        )
        advisory = parse_advisory_xml(hostile)
        joined = " ".join(advisory["fix_recommendation"] + advisory["description"])
        self.assertNotIn("root:", joined)
        self.assertNotIn("file:///etc/passwd", joined)

    def test_instance_data_is_not_parsed_as_prose(self):
        instance = (
            '\ufeff<?xml version="1.0" encoding="utf-8"?><root><issue-group><item>'
            '<id>667d0efd52d6e93bdd83d60565837c4a98bd42a0d5a2eb2571856d1456c66eb4</id>'
            '<agent-type>Java</agent-type>'
            '<additionalInfo><Source_url>/doLogin</Source_url>'
            '<Sink_info>Tracked unsanitized input into an sql-injection sink.</Sink_info>'
            '</additionalInfo></item></issue-group></root>'
        )
        advisory = parse_advisory_xml(instance)
        self.assertTrue(advisory.get("_instance_data"))
        self.assertEqual(advisory["description"], [])
        joined = " ".join(advisory["technical_detail"])
        self.assertIn("Sink information: Tracked unsanitized input", joined)
        self.assertIn("Source URL: /doLogin", joined)
        self.assertNotIn("667d0efd", joined)

    def test_bom_is_stripped(self):
        advisory = parse_advisory_xml(
            '\ufeff<advisory><fixRecommendation>\ufeffEncode output.</fixRecommendation></advisory>')
        self.assertEqual(advisory["fix_recommendation"], ["Encode output."])

    def test_advisory_failure_is_contained(self):
        types = build_unique_issue_types(ISSUES)
        enrich_with_advisories(StubClient(fail_for={"1"}), types)
        self.assertFalse(types[0].advisory.get("_resolved"))
        self.assertTrue(types[1].advisory.get("_resolved"))


class TestLinks(unittest.TestCase):
    def test_cwe_definition_link_is_built(self):
        issue_type = build_unique_issue_types(ISSUES)[0]
        links = build_links("https://cloud.appscan.com", "https://cloud.appscan.com",
                            "app-123", issue_type)
        self.assertEqual(links["cweDefinitions"],
                         [{"id": "CWE-79",
                           "url": "https://cwe.mitre.org/data/definitions/79.html"}])

    def test_no_cwe_yields_no_link(self):
        issue_type = build_unique_issue_types(ISSUES)[1]
        links = build_links("https://x", "https://x", "a1", issue_type)
        self.assertEqual(links["cweDefinitions"], [])

    def test_filtered_platform_link_is_gone(self):
        issue_type = build_unique_issue_types(ISSUES)[0]
        links = build_links("https://x", "https://x", "a1", issue_type)
        self.assertNotIn("appscanIssuesFiltered", links)

    def test_api_query_still_carries_the_filter(self):
        issue_type = build_unique_issue_types(ISSUES)[0]
        links = build_links("https://cloud.appscan.com", "https://cloud.appscan.com",
                            "app-123", issue_type)
        self.assertIn("$filter=IssueTypeId%20eq%20%27AttXSS%27", links["appscanApiQuery"])
        self.assertEqual(links["odataFilter"], "IssueTypeId eq 'AttXSS'")

    def test_custom_cwe_template(self):
        issue_type = build_unique_issue_types(ISSUES)[0]
        links = build_links("https://x", "https://x", "a1", issue_type,
                            cwe_template="https://example.org/cwe/{0}")
        self.assertEqual(links["cweDefinitions"][0]["url"], "https://example.org/cwe/79")

    def test_non_numeric_cwe_is_skipped(self):
        types = build_unique_issue_types([
            dict(ISSUES[0], Cwe="n/a"), dict(ISSUES[1], Cwe="CWE-89")])
        links = build_links("https://x", "https://x", "a1", types[0])
        self.assertEqual([c["id"] for c in links["cweDefinitions"]], ["CWE-89"])


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.model = make_model()

    def test_json(self):
        data = json.loads(render(self.model, "json"))
        self.assertEqual(data["summary"]["uniqueIssueTypes"], 2)
        self.assertEqual(data["issueTypes"][0]["issueTypeName"], "Cross-Site Scripting")
        self.assertTrue(data["issueTypes"][0]["howToFix"])
        self.assertEqual(data["issueTypes"][0]["links"]["cweDefinitions"][0]["id"], "CWE-79")

    def test_xml_is_well_formed(self):
        root = ElementTree.fromstring(render(self.model, "xml"))
        self.assertEqual(root.tag, "AppScanUniqueIssueReport")
        self.assertEqual(len(root.find("IssueTypes").findall("IssueType")), 2)

    def test_html_contains_links_and_sections(self):
        html = render(self.model, "html")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("https://cwe.mitre.org/data/definitions/79.html", html)
        self.assertIn("CWE-79 definition", html)
        self.assertIn("How to fix it", html)
        self.assertIn("Cross-Site Scripting", html)
        self.assertNotIn("View these issues in AppScan", html)

    def test_html_notes_missing_cwe(self):
        html = render(self.model, "html")
        self.assertIn("did not map this issue type to a CWE identifier", html)

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            render(self.model, "pdf")

    def test_html_escapes_injected_markup(self):
        hostile = dict(APPLICATION, Name="<script>alert(1)</script>")
        model = build_report_model(hostile, build_unique_issue_types(ISSUES), 3,
                                   "https://cloud.appscan.com", "https://cloud.appscan.com")
        self.assertNotIn("<script>alert(1)</script>", render(model, "html"))


class TestCredentials(unittest.TestCase):
    """Argument values must win over the environment, and vice versa as fallback."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("APPSCAN_KEY_ID", "APPSCAN_KEY_SECRET", "APPSCAN_BASE_URL")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _args(self, argv):
        return build_parser().parse_args(argv + ["--app-id", "x"])

    def test_arguments_are_used(self):
        self.assertEqual(
            resolve_credentials(self._args(["--key-id", "aid", "--key-secret", "asec"])),
            ("aid", "asec"))

    def test_environment_is_the_fallback(self):
        os.environ["APPSCAN_KEY_ID"] = "eid"
        os.environ["APPSCAN_KEY_SECRET"] = "esec"
        self.assertEqual(resolve_credentials(self._args([])), ("eid", "esec"))

    def test_arguments_override_environment(self):
        os.environ["APPSCAN_KEY_ID"] = "eid"
        os.environ["APPSCAN_KEY_SECRET"] = "esec"
        self.assertEqual(
            resolve_credentials(self._args(["--key-id", "aid", "--key-secret", "asec"])),
            ("aid", "asec"))

    def test_values_can_be_mixed(self):
        os.environ["APPSCAN_KEY_SECRET"] = "esec"
        self.assertEqual(resolve_credentials(self._args(["--key-id", "aid"])), ("aid", "esec"))

    def test_missing_key_id_is_reported(self):
        os.environ["APPSCAN_KEY_SECRET"] = "esec"
        with self.assertRaises(ConfigurationError):
            resolve_credentials(self._args([]))

    def test_empty_secret_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            resolve_credentials(self._args(["--key-id", "aid", "--key-secret", "   "]))

    def test_base_url_precedence(self):
        self.assertEqual(resolve_base_url(self._args([])), "https://cloud.appscan.com")
        os.environ["APPSCAN_BASE_URL"] = "https://env.example.com"
        self.assertEqual(resolve_base_url(self._args([])), "https://env.example.com")
        self.assertEqual(
            resolve_base_url(self._args(["--base-url", "https://arg.example.com"])),
            "https://arg.example.com")

    def test_help_output_never_leaks_the_secret(self):
        os.environ["APPSCAN_KEY_SECRET"] = "SUPER-SECRET-VALUE"
        os.environ["APPSCAN_KEY_ID"] = "SECRET-KEY-ID"
        help_text = build_parser().format_help()
        self.assertNotIn("SUPER-SECRET-VALUE", help_text)
        self.assertNotIn("SECRET-KEY-ID", help_text)


class TestCli(unittest.TestCase):
    def test_filter_composition(self):
        args = build_parser().parse_args(["--app-name", "AltoroJ", "--open-only",
                                          "--filter", "Severity eq 'High'"])
        self.assertEqual(compose_filter(args), "Status eq 'Open' and (Severity eq 'High')")

    def test_defaults(self):
        args = build_parser().parse_args(["--app-id", "x"])
        self.assertEqual(args.export_format, "html")
        self.assertIsNone(args.base_url)
        self.assertEqual(resolve_base_url(args), "https://cloud.appscan.com")

    def test_bad_base_url_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            AppScanClient(base_url="cloud.appscan.com")

    def test_unauthenticated_call_is_rejected(self):
        client = AppScanClient()
        self.assertFalse(client.is_authenticated)
        with self.assertRaises(AppScanReporterError):
            client.get_application_by_id("x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
