from __future__ import annotations

import socket

from scanner.config import PortScanResult, ResolvedTarget
from scanner.output import render_markdown


def test_render_markdown_includes_table() -> None:
    target = ResolvedTarget(user_input="example", address="127.0.0.1", family=socket.AF_INET)
    result = [
        PortScanResult(
            port=22, protocol="TCP", state="open", service="ssh", reason="connect() succeeded"
        )
    ]
    table = render_markdown(result, target)
    assert "| Port |" in table
    assert "Target: example (127.0.0.1)" in table
    assert "connect() succeeded" in table


def test_render_markdown_escapes_markdown_cells() -> None:
    target = ResolvedTarget(user_input="example", address="127.0.0.1", family=socket.AF_INET)
    result = [
        PortScanResult(
            port=53,
            protocol="UDP",
            state="open|filtered",
            service="dns\\resolver",
            reason="no reply | best-effort `probe`",
        )
    ]
    table = render_markdown(result, target)
    assert "open\\|filtered" in table
    assert "dns\\\\resolver" in table
    assert "no reply \\| best-effort \\`probe\\`" in table
