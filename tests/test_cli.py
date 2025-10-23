from __future__ import annotations

from scanner.cli import build_parser, build_settings
from scanner.constants import DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS


def test_build_settings_uses_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args([])
    settings = build_settings(args)
    assert settings.tcp_ports == DEFAULT_TCP_PORTS
    assert settings.udp_ports == DEFAULT_UDP_PORTS
    assert settings.target == "127.0.0.1"
    assert settings.resolve_dns is True


def test_build_settings_custom_ports() -> None:
    parser = build_parser()
    args = parser.parse_args(["--tcp", "80-81", "--udp", "53", "--no-dns", "::1"])
    settings = build_settings(args)
    assert settings.tcp_ports == [80, 81]
    assert settings.udp_ports == [53]
    assert settings.target == "::1"
    assert settings.resolve_dns is False
