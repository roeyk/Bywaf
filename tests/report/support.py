# ruff: noqa: F401
"""Shared helpers for report command tests.

Coverage focus: shared fixtures and test doubles for report tests.
"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.app import dispatch_repl_line, make_runner, process_framework_requests
from bywaf.repl import ShellState
