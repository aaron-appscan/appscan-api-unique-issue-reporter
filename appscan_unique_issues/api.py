"""Thin, resilient HTTP client for the HCL AppScan on Cloud Data API (v4).

Implemented with ``urllib`` from the standard library so the tool carries no
third-party supply-chain risk. See SECURITY-DEPENDENCY-REVIEW.md.

Endpoints used (from https://cloud.appscan.com/swagger/index.html):
  POST /api/v4/Account/ApiKeyLogin   -> bearer token
  GET  /api/v4/Apps                  -> application lookup by name (OData)
  GET  /api/v4/Apps/{id}             -> application lookup by id
  GET  /api/v4/Issues/{scope}/{id}   -> paged issue list
  GET  /api/v4/Issues/{id}/Details   -> advisory / fix recommendation
"""

import json
import logging
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .errors import (
    ApiResponseError,
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConnectionFailedError,
    RateLimitError,
    ResourceNotFoundError,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://cloud.appscan.com"
RETRYABLE_STATUS = frozenset((408, 429, 500, 502, 503, 504))
MAX_PAGE_SIZE = 500


def _odata_quote(string, safe="", encoding=None, errors=None):
    """Percent-encode a query component while leaving OData syntax readable."""
    return urllib.parse.quote(str(string), safe="$,()'", encoding=encoding, errors=errors)


def quote_odata_literal(value):
    """Return ``value`` as a safely escaped OData string literal."""
    return "'{0}'".format(str(value).replace("'", "''"))


class AppScanClient(object):
    """Authenticated client for the AppScan on Cloud Data API."""

    def __init__(
        self,
        base_url=DEFAULT_BASE_URL,
        timeout=60,
        max_retries=3,
        verify_tls=True,
        user_agent=None,
    ):
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        if not self.base_url.lower().startswith(("http://", "https://")):
            raise ConfigurationError(
                "Base URL must start with http:// or https:// (got: {0!r})".format(base_url)
            )
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.user_agent = user_agent or "appscan-unique-issue-reporter/1.0"
        self._token = None

        if verify_tls:
            self._ssl_context = ssl.create_default_context()
        else:
            # Opt-in only; used for on-premise gateways with private CAs.
            LOGGER.warning("TLS certificate verification is DISABLED for %s", self.base_url)
            self._ssl_context = ssl._create_unverified_context()

    # ------------------------------------------------------------------
    # 1. Establish connection
    # ------------------------------------------------------------------
    def login(self, key_id, key_secret):
        """Exchange an API key/secret pair for a bearer token."""
        if not key_id or not key_secret:
            raise ConfigurationError(
                "Both an AppScan API Key ID and Key Secret are required to authenticate."
            )

        LOGGER.info("Authenticating against %s", self.base_url)
        payload = self._request(
            "POST",
            "/api/v4/Account/ApiKeyLogin",
            body={"KeyId": key_id, "KeySecret": key_secret},
            authenticated=False,
        )

        if not isinstance(payload, dict) or not payload.get("Token"):
            raise AuthenticationError(
                "AppScan accepted the login call but returned no token. "
                "Verify the key belongs to this AppScan region/tenant."
            )

        self._token = payload["Token"]
        LOGGER.info("Authenticated successfully (token expires: %s)", payload.get("Expire", "n/a"))
        return payload

    @property
    def is_authenticated(self):
        return self._token is not None

    # ------------------------------------------------------------------
    # 2. Resolve the application
    # ------------------------------------------------------------------
    def get_application_by_id(self, app_id):
        """Fetch a single application by its AppScan identifier."""
        app = self._request("GET", "/api/v4/Apps/{0}".format(urllib.parse.quote(str(app_id))))
        if isinstance(app, dict) and app.get("Items"):
            app = app["Items"][0]
        if not isinstance(app, dict) or not app.get("Id"):
            raise ResourceNotFoundError("No application found with id {0!r}.".format(app_id))
        return app

    def find_application_by_name(self, app_name):
        """Resolve an application id from its (case-insensitive) name."""
        if not app_name:
            raise ConfigurationError("An application name is required.")

        literal = quote_odata_literal(app_name)
        payload = self._request(
            "GET",
            "/api/v4/Apps",
            params={"$filter": "Name eq {0}".format(literal), "$top": 100},
        )
        matches = self._items(payload)

        if not matches:
            # Fall back to a contains() search so near-misses produce a helpful hint.
            payload = self._request(
                "GET",
                "/api/v4/Apps",
                params={"$filter": "contains(Name,{0})".format(literal), "$top": 25},
            )
            near = self._items(payload)
            if not near:
                raise ResourceNotFoundError(
                    "No application named {0!r} is visible to this API key.".format(app_name)
                )
            names = ", ".join(sorted(repr(a.get("Name")) for a in near))
            raise ResourceNotFoundError(
                "No exact match for application {0!r}. Did you mean: {1}?".format(app_name, names)
            )

        exact = [a for a in matches if str(a.get("Name", "")).lower() == str(app_name).lower()]
        candidates = exact or matches
        if len(candidates) > 1:
            ids = ", ".join(sorted(str(a.get("Id")) for a in candidates))
            raise ConfigurationError(
                "Application name {0!r} is ambiguous ({1} matches). "
                "Re-run with --app-id using one of: {2}".format(app_name, len(candidates), ids)
            )
        return candidates[0]

    # ------------------------------------------------------------------
    # 3. Issue list
    # ------------------------------------------------------------------
    def iter_issues(self, app_id, odata_filter=None, page_size=200, max_issues=None):
        """Yield every issue for an application, transparently paging the API."""
        page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))
        path = "/api/v4/Issues/Application/{0}".format(urllib.parse.quote(str(app_id)))
        skip = 0
        yielded = 0

        while True:
            params = {"$top": page_size, "$skip": skip}
            if odata_filter:
                params["$filter"] = odata_filter

            payload = self._request("GET", path, params=params)
            items = self._items(payload)
            LOGGER.debug("Fetched %s issue(s) at offset %s", len(items), skip)

            for item in items:
                yield item
                yielded += 1
                if max_issues and yielded >= max_issues:
                    return

            if len(items) < page_size:
                return
            skip += page_size

    # ------------------------------------------------------------------
    # 5. Issue type advisory / fix recommendation
    # ------------------------------------------------------------------
    def get_issue_details(self, issue_id, fmt="xml", locale="en-US"):
        """Return the raw advisory document (XML or HTML) for one issue."""
        accept = "application/xml" if fmt == "xml" else "text/html"
        return self._request(
            "GET",
            "/api/v4/Issues/{0}/Details".format(urllib.parse.quote(str(issue_id))),
            params={"format": fmt, "locale": locale},
            accept=accept,
            parse_json=False,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _items(payload):
        """Normalise the API's two list shapes (bare array vs. paged object)."""
        if payload is None:
            return []
        if isinstance(payload, list):
            return [i for i in payload if isinstance(i, dict)]
        if isinstance(payload, dict):
            items = payload.get("Items")
            if isinstance(items, list):
                return [i for i in items if isinstance(i, dict)]
            if payload.get("Id"):
                return [payload]
        return []

    def _build_url(self, path, params):
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean, quote_via=_odata_quote)
        return url

    def _request(self, method, path, params=None, body=None, accept="application/json",
                 authenticated=True, parse_json=True):
        """Perform one API call with bounded retries and precise error mapping."""
        if authenticated and not self._token:
            raise AuthenticationError("Not authenticated. Call login() before making API calls.")

        url = self._build_url(path, params)
        data = None
        headers = {"Accept": accept, "User-Agent": self.user_agent}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["Authorization"] = "Bearer " + self._token

        last_error = None
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout, context=self._ssl_context
                ) as response:
                    raw = response.read()
                    return self._decode(raw, response.headers, parse_json, url)

            except urllib.error.HTTPError as exc:
                detail = self._error_detail(exc)
                if exc.code in RETRYABLE_STATUS and attempt < self.max_retries:
                    delay = self._backoff(attempt, exc.headers.get("Retry-After"))
                    LOGGER.warning(
                        "HTTP %s from %s - retrying in %.1fs (attempt %s/%s)",
                        exc.code, path, delay, attempt + 1, self.max_retries,
                    )
                    time.sleep(delay)
                    last_error = exc
                    continue
                raise self._map_http_error(exc, detail, path)

            except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                if attempt < self.max_retries:
                    delay = self._backoff(attempt, None)
                    LOGGER.warning(
                        "Network error talking to %s (%s) - retrying in %.1fs (attempt %s/%s)",
                        self.base_url, reason, delay, attempt + 1, self.max_retries,
                    )
                    time.sleep(delay)
                    last_error = exc
                    continue
                raise ConnectionFailedError(
                    "Could not reach AppScan at {0}: {1}. "
                    "Check the --base-url value, network access, and any proxy settings.".format(
                        self.base_url, reason
                    )
                )

        raise ConnectionFailedError(
            "Request to {0} failed after {1} retries: {2}".format(path, self.max_retries, last_error)
        )

    @staticmethod
    def _decode(raw, headers, parse_json, url):
        charset = "utf-8"
        try:
            charset = headers.get_content_charset() or "utf-8"
        except AttributeError:
            pass
        text = raw.decode(charset, errors="replace")
        if not parse_json:
            return text
        if not text.strip():
            return None
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ApiResponseError(
                "AppScan returned a non-JSON response from {0}: {1}".format(url, exc)
            )

    @staticmethod
    def _error_detail(exc):
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - body already consumed/closed
            return ""
        try:
            parsed = json.loads(raw)
        except ValueError:
            return raw.strip()[:500]
        if isinstance(parsed, dict):
            return str(parsed.get("Message") or parsed.get("Key") or parsed)[:500]
        return str(parsed)[:500]

    @staticmethod
    def _map_http_error(exc, detail, path):
        suffix = " Details: {0}".format(detail) if detail else ""
        if "ApiKeyLogin" in path and exc.code in (400, 401, 403):
            return AuthenticationError(
                "AppScan rejected the API key (HTTP {0}). Check that the Key ID and Key Secret "
                "are correct, still active, and belong to the AppScan region named by "
                "--base-url.{1}".format(exc.code, suffix)
            )
        if exc.code == 401:
            return AuthenticationError(
                "AppScan rejected the credentials (HTTP 401) for {0}. "
                "Verify the Key ID/Secret and that they belong to this region.{1}".format(path, suffix)
            )
        if exc.code == 403:
            return AuthorizationError(
                "This API key is not permitted to access {0} (HTTP 403).{1}".format(path, suffix)
            )
        if exc.code == 404:
            return ResourceNotFoundError(
                "AppScan reported {0} as not found (HTTP 404).{1}".format(path, suffix)
            )
        if exc.code == 429:
            return RateLimitError(
                "AppScan rate limit hit for {0} and retries were exhausted. "
                "Lower --page-size or retry later.{1}".format(path, suffix)
            )
        return ApiResponseError(
            "Unexpected HTTP {0} from {1}.{2}".format(exc.code, path, suffix)
        )

    @staticmethod
    def _backoff(attempt, retry_after):
        if retry_after:
            try:
                return min(60.0, float(retry_after))
            except (TypeError, ValueError):
                pass
        return min(30.0, (2 ** attempt)) + random.uniform(0, 0.5)
