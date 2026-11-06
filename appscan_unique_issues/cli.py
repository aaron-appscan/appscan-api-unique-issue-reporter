"""Command line entry point for the AppScan Unique Issue Reporter."""

import argparse
import getpass
import logging
import os
import sys

from . import __version__
from .analysis import build_unique_issue_types, enrich_with_advisories
from .api import DEFAULT_BASE_URL, AppScanClient
from .errors import AppScanReporterError, ConfigurationError
from .report import SUPPORTED_FORMATS, build_report_model, render, write_report

LOGGER = logging.getLogger("appscan_unique_issues")

ENV_KEY_ID = "APPSCAN_KEY_ID"
ENV_KEY_SECRET = "APPSCAN_KEY_SECRET"
ENV_BASE_URL = "APPSCAN_BASE_URL"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="appscan-unique-issues",
        description=(
            "Connect to the HCL AppScan on Cloud Data API, resolve an application, collapse "
            "its issues into unique issue types, and export a remediation report containing "
            "AppScan's own definitions, fix guidance, and clickable pre-filtered links."
        ),
        epilog=(
            "Credentials may also be supplied via the {0} and {1} environment variables. "
            "If the secret is omitted entirely you will be prompted for it securely.".format(
                ENV_KEY_ID, ENV_KEY_SECRET)
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    auth = parser.add_argument_group("authentication")
    auth.add_argument("--key-id", default=None,
                      help="AppScan API Key ID. Overrides the {0} environment variable.".format(
                          ENV_KEY_ID))
    auth.add_argument("--key-secret", default=None,
                      help=("AppScan API Key Secret. Overrides the {0} environment variable. "
                            "If neither is supplied you are prompted securely.".format(
                                ENV_KEY_SECRET)))
    auth.add_argument("--base-url", default=None,
                      help="AppScan API base URL for your region (env: {0}, default: {1}).".format(
                          ENV_BASE_URL, DEFAULT_BASE_URL))
    auth.add_argument("--ui-base-url", default=None,
                      help="AppScan web UI base URL. Defaults to --base-url.")
    auth.add_argument("--insecure", action="store_true",
                      help="Disable TLS certificate verification (not recommended).")

    target = parser.add_argument_group("application")
    group = target.add_mutually_exclusive_group()
    group.add_argument("--app-name", help="Application name to resolve into an application ID.")
    group.add_argument("--app-id", help="Application ID, used directly when known.")

    scope = parser.add_argument_group("issue scope")
    scope.add_argument("--filter", dest="odata_filter", default=None,
                       help="Extra OData $filter, e.g. \"Severity eq 'High'\".")
    scope.add_argument("--open-only", action="store_true",
                       help="Shortcut for restricting the report to Open issues.")
    scope.add_argument("--page-size", type=int, default=200,
                       help="Issues requested per API page (1-500).")
    scope.add_argument("--max-issues", type=int, default=0,
                       help="Stop after this many issues (0 = no limit).")
    scope.add_argument("--no-advisories", action="store_true",
                       help="Skip advisory lookups (faster, but no definitions or fix guidance).")
    scope.add_argument("--locale", default="en-US", help="Advisory locale.")

    output = parser.add_argument_group("output")
    output.add_argument("--format", dest="export_format", default="html",
                        choices=list(SUPPORTED_FORMATS), help="Export format.")
    output.add_argument("--output", "-o", default=None,
                        help="Output file path. Defaults to stdout when omitted.")
    output.add_argument("--cwe-link-template", default=None,
                        help=("Override the CWE definition URL template. Use {0} or {cwe} as the "
                              "placeholder for the numeric CWE id."))

    runtime = parser.add_argument_group("runtime")
    runtime.add_argument("--timeout", type=int, default=60, help="Per-request timeout in seconds.")
    runtime.add_argument("--retries", type=int, default=3,
                         help="Retries for throttling / transient network errors.")
    runtime.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging.")
    runtime.add_argument("--quiet", "-q", action="store_true", help="Only log errors.")
    runtime.add_argument("--version", action="version",
                         version="appscan-unique-issues {0}".format(__version__))
    return parser


def configure_logging(verbose, quiet):
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(levelname)-8s %(message)s")


def resolve_credentials(args):
    """Resolve the API key pair, preferring explicit arguments over the environment.

    Precedence for each value independently:
      1. the command line argument (``--key-id`` / ``--key-secret``)
      2. the environment variable (``APPSCAN_KEY_ID`` / ``APPSCAN_KEY_SECRET``)
      3. for the secret only, a non-echoing interactive prompt

    The secret is never logged, never echoed, and never written to the report.
    """
    key_id = (args.key_id or os.environ.get(ENV_KEY_ID) or "").strip()
    source = "--key-id" if args.key_id else ENV_KEY_ID
    if not key_id:
        raise ConfigurationError(
            "An AppScan API Key ID is required. Pass --key-id or set the {0} "
            "environment variable.".format(ENV_KEY_ID))
    LOGGER.debug("Using API Key ID supplied via %s", source)

    key_secret = args.key_secret or os.environ.get(ENV_KEY_SECRET)
    if not key_secret:
        if not sys.stdin.isatty():
            raise ConfigurationError(
                "An AppScan API Key Secret is required. Pass --key-secret, set the {0} "
                "environment variable, or run interactively to be prompted.".format(
                    ENV_KEY_SECRET))
        try:
            key_secret = getpass.getpass("AppScan API Key Secret: ")
        except (EOFError, KeyboardInterrupt):
            raise ConfigurationError("No API Key Secret supplied.")
    if not key_secret.strip():
        raise ConfigurationError("The supplied AppScan API Key Secret is empty.")
    return key_id, key_secret.strip()


def resolve_base_url(args):
    """Resolve the API base URL: argument, then environment, then the default."""
    return (args.base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).strip()


def compose_filter(args):
    clauses = []
    if args.open_only:
        clauses.append("Status eq 'Open'")
    if args.odata_filter:
        clauses.append("({0})".format(args.odata_filter.strip()))
    return " and ".join(clauses) if clauses else None


def run(args):
    """Execute the full pipeline. Raises AppScanReporterError on failure."""
    if not args.app_name and not args.app_id:
        raise ConfigurationError("Specify the target application with --app-name or --app-id.")
    if args.page_size < 1:
        raise ConfigurationError("--page-size must be 1 or greater.")
    if args.max_issues < 0:
        raise ConfigurationError("--max-issues cannot be negative.")

    key_id, key_secret = resolve_credentials(args)
    base_url = resolve_base_url(args)
    ui_base_url = args.ui_base_url or base_url

    # 1. Establish the connection.
    client = AppScanClient(
        base_url=base_url,
        timeout=args.timeout,
        max_retries=args.retries,
        verify_tls=not args.insecure,
    )
    client.login(key_id, key_secret)
    key_secret = None  # drop the secret as soon as the token is held

    # 2. Resolve the application.
    if args.app_id:
        application = client.get_application_by_id(args.app_id)
    else:
        application = client.find_application_by_name(args.app_name)
    LOGGER.info("Target application: %s (%s)", application.get("Name"), application.get("Id"))

    # 3. Retrieve the issue list.
    odata_filter = compose_filter(args)
    issues = list(client.iter_issues(
        application["Id"],
        odata_filter=odata_filter,
        page_size=args.page_size,
        max_issues=args.max_issues or None,
    ))
    if not issues:
        LOGGER.warning("No issues matched for application %r - the report will be empty.",
                       application.get("Name"))

    # 4. Collapse into unique issue types.
    issue_types = build_unique_issue_types(issues)

    # 5. Enrich with AppScan definitions and fix recommendations, then report.
    if issue_types and not args.no_advisories:
        LOGGER.info("Retrieving AppScan advisories for %s issue type(s)...", len(issue_types))
        enrich_with_advisories(client, issue_types, locale=args.locale)

    model = build_report_model(
        application=application,
        issue_types=issue_types,
        total_issues=len(issues),
        ui_base_url=ui_base_url,
        api_base_url=base_url,
        cwe_template=args.cwe_link_template,
        odata_filter=odata_filter,
    )
    content = render(model, args.export_format)

    if args.output:
        path = write_report(content, args.output)
        print(path)
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        return run(args)
    except AppScanReporterError as exc:
        LOGGER.error("%s", exc)
        return exc.exit_code
    except KeyboardInterrupt:
        LOGGER.error("Interrupted by user.")
        return 130
    except Exception as exc:  # last-resort guard: never dump a raw traceback at users
        LOGGER.error("Unexpected failure: %s", exc)
        LOGGER.debug("Traceback:", exc_info=True)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
