from __future__ import annotations

from scanner.config import normalize_ports


def test_normalize_ports_sorts_and_filters() -> None:
    result = normalize_ports([80, -1, 443, 80, 65536])
    assert result == [80, 443]
