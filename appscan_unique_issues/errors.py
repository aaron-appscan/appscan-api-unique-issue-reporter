"""Exception hierarchy for the AppScan Unique Issue Reporter.

Every error raised by this package derives from :class:`AppScanReporterError`
so the CLI can map failures onto stable, scriptable exit codes.
"""


class AppScanReporterError(Exception):
    """Base class for all errors raised by this package."""

    exit_code = 1


class ConfigurationError(AppScanReporterError):
    """Invalid or missing user supplied configuration (keys, names, paths)."""

    exit_code = 2


class ConnectionFailedError(AppScanReporterError):
    """The AppScan service could not be reached (DNS, TLS, timeout, proxy)."""

    exit_code = 3


class AuthenticationError(AppScanReporterError):
    """The API key/secret pair was rejected, or the token expired."""

    exit_code = 4


class AuthorizationError(AppScanReporterError):
    """Authenticated, but the key lacks permission for the requested asset."""

    exit_code = 5


class ResourceNotFoundError(AppScanReporterError):
    """The requested application, issue, or endpoint does not exist."""

    exit_code = 6


class ApiResponseError(AppScanReporterError):
    """The API returned an unexpected status code or an unparsable payload."""

    exit_code = 7


class RateLimitError(AppScanReporterError):
    """The API throttled the client and retries have been exhausted."""

    exit_code = 8


class ReportGenerationError(AppScanReporterError):
    """The report could not be rendered or written to disk."""

    exit_code = 9
