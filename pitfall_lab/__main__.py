"""
Python -m entry point for pitfall_lab.

Usage:
    python -m pitfall_lab run --challenge emailsystem --attack tool_poisoning --submission <path>
    python -m pitfall_lab analyze --run-id <id>
"""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
