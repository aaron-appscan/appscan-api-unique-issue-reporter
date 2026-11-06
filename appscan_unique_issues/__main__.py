"""Allow ``python -m appscan_unique_issues``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
