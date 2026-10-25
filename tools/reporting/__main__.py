"""Run the report command line with ``python -m tools.reporting``."""

import sys

from tools.reporting.cli import main

sys.exit(main(sys.argv[1:]))
