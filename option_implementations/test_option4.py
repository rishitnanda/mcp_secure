import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
sys.path.insert(0, HERE)

from benchmark.test_synthetic_benchmark import *  # noqa: F401,F403  (re-uses all 150 cases)
from sequence_options import PolicyEngineOption4


@pytest.fixture(scope="module")
def engine():
    eng = PolicyEngineOption4()
    if os.environ.get("MCP_SHIELD_DISABLE_SEQUENCE") == "1":
        eng._check_sequence = lambda request, session_state: None
    return eng