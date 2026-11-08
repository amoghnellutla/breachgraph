"""Every tool status has a way to be shown, so a new status can't crash a scan."""

from breachgraph.cli import TOOL_STYLE
from breachgraph.models import ToolStatus
from breachgraph.reporters.markdown import _TOOL_STATUS


def test_every_status_can_be_printed_and_reported() -> None:
    assert set(TOOL_STYLE) == set(ToolStatus)
    assert set(_TOOL_STATUS) == set(ToolStatus)
