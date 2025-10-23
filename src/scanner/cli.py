# Copyright (C) 2025 Strategos Network Scanner Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Command-line interface for the educational scanner."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from collections.abc import Sequence

from .config import ScanSettings, normalize_ports
from .constants import DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS
from .messages import UDP_SCANNING_PRIMER
from .output import render_json, render_markdown
from .ports import parse_port_expression
from .resolution import ResolutionError, resolve_target
from .scanning import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Educational TCP/UDP port scanner.\n\n"
            "This scanner demonstrates port scanning using standard socket APIs "
            "without requiring raw socket privileges. It's designed to help students "
            "understand:\n"
            "- TCP connection-based scanning (via connect() handshake)\n"
            "- UDP scanning by sending probes and interpreting responses\n"
            "- Network concepts like DNS resolution, timeouts, and concurrency\n\n"
            "Note: This is for educational purposes. Always ensure you have "
            "proper authorization before scanning networks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="target hostname or IP (defaults to localhost)",
    )
    parser.add_argument(
        "--tcp",
        metavar="PORTS",
        help="comma separated list or ranges for TCP (e.g. 22,80-82)",
    )
    parser.add_argument(
        "--udp",
        metavar="PORTS",
        help="comma separated list or ranges for UDP",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="seconds to wait for each probe before retrying",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="number of times to retry timeouts",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=64,
        help="maximum simultaneous probes",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=128.0,
        help="limit packets per second (set 0 for unlimited)",
    )
    parser.add_argument("--no-dns", action="store_true", help="skip DNS lookups")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument(
        "--about-udp",
        action="store_true",
        help="print a quick primer on UDP scanning behavior and exit",
    )
    return parser


def parse_ports(argument: str | None, defaults: Sequence[int]) -> Sequence[int]:
    """Parse port argument or return defaults.

    Educational note: Good CLI design provides sensible defaults. If the user
    doesn't specify ports, we use a curated list of common services. If they
    provide an invalid expression that produces no valid ports, we fall back
    to defaults rather than scanning nothing.

    Args:
        argument: User-provided port expression (e.g., "22,80-443") or None
        defaults: Default port list to use if argument is None or invalid

    Returns:
        List of ports to scan
    """
    if not argument:
        return defaults
    # Parse the user's port expression
    parsed = normalize_ports(parse_port_expression(argument))
    # Fall back to defaults if the expression produced no valid ports
    # This handles cases like "--tcp invalid" gracefully
    return parsed or defaults


def build_settings(args: argparse.Namespace) -> ScanSettings:
    """Convert parsed CLI arguments into a ScanSettings configuration object.

    This function validates and normalizes user inputs to ensure safe values:
    - Port lists are parsed and validated
    - Timeout is clamped to a minimum of 0.1 seconds
    - Retries and concurrency are clamped to minimum of 1
    - Rate of 0 is converted to None (unlimited)

    Educational note: Input validation is crucial for robustness. Even though
    argparse handles type checking, we still apply business logic constraints
    like minimum values to prevent degenerate cases (zero timeout, etc.).

    Args:
        args: Parsed command-line arguments from argparse

    Returns:
        Validated and normalized ScanSettings configuration
    """
    # Parse port expressions, falling back to defaults if needed
    tcp_ports = parse_ports(args.tcp, DEFAULT_TCP_PORTS)
    udp_ports = parse_ports(args.udp, DEFAULT_UDP_PORTS)

    # Convert rate=0 (user's way to say "no limit") to None (internal representation)
    rate = args.rate if args.rate > 0 else None

    return ScanSettings(
        target=args.target,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        # Enforce minimum timeout to prevent connection attempts from failing too fast
        timeout=max(args.timeout, 0.1),
        # Require at least 1 retry (the initial attempt counts as retry 1)
        retries=max(args.retries, 1),
        # Require at least 1 concurrent task, otherwise nothing would run
        concurrency=max(args.concurrency, 1),
        rate=rate,
        resolve_dns=not args.no_dns,
        output_json=args.json,
    )


def _is_private_network(address: str) -> bool:
    """Check if the target address is in a private network range.

    Educational note: Private IP ranges are defined in RFC 1918 and are not
    routable on the public internet. They're used for internal networks:
    - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)

    Scanning private networks without authorization is a serious ethical issue.
    This check warns users before scanning private ranges.

    Args:
        address: IP address or hostname to check

    Returns:
        True if the address is in a private network range (excluding localhost)
    """
    try:
        ip = ipaddress.ip_address(address)
        # Check if private but not loopback (127.0.0.0/8 or ::1)
        # Localhost scanning is safe for learning, but private networks need permission
        return ip.is_private and not ip.is_loopback
    except ValueError:
        # If it's not a valid IP address, it might be a hostname
        # We can't determine if it's private without resolving, so assume it's not
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.about_udp:
        parser.exit(0, UDP_SCANNING_PRIMER + "\n")

    settings = build_settings(args)

    # Warn about scanning private networks
    if _is_private_network(settings.target):
        print(
            "⚠️  WARNING: You are scanning a private network. "
            "Ensure you have proper authorization before scanning networks.",
            file=sys.stderr,
        )

    try:
        target = resolve_target(settings.target, settings.resolve_dns)
    except ResolutionError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse.error already exits

    results = asyncio.run(run_scan(settings, target))

    if settings.output_json:
        output = render_json(results, target)
    else:
        output = render_markdown(results, target)
    print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
