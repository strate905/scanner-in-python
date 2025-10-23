from __future__ import annotations

from scanner.ports import parse_port_expression


def test_parse_port_expression_range_and_duplicates() -> None:
    result = parse_port_expression("22,80-82,82,443, 0,70000,abc")
    assert result == [22, 80, 81, 82, 443]
