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

"""Configuration models shared across CLI and scanning logic.

This module defines immutable dataclasses that flow through the scanning pipeline.
Using dataclasses provides several benefits for educational code:
- Type safety: Clear documentation of expected types
- Immutability: frozen=True prevents accidental modification
- Readability: Named fields are clearer than positional tuples
- IDE support: Better autocomplete and type checking

Educational Concepts:
- Dataclasses: Python's modern way to define data structures
- Immutability: frozen=True makes objects thread-safe and predictable
- Type hints: Document expected types for better code quality
- Separation of concerns: Configuration separated from behavior
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanSettings:
    """Runtime configuration chosen by the learner via CLI flags.

    This immutable dataclass holds all scan parameters, making it easy to pass
    configuration throughout the scanning pipeline without global variables.

    Educational note: Immutable configuration objects (frozen=True) prevent bugs
    where settings are accidentally modified mid-scan. This is especially important
    in async code where multiple tasks might access the same configuration.

    Attributes:
        target: Hostname or IP address to scan (user input, may need resolution)
        tcp_ports: List of TCP ports to scan (after parsing and deduplication)
        udp_ports: List of UDP ports to scan (after parsing and deduplication)
        timeout: Seconds to wait for responses before considering them lost
        retries: Number of times to retry failed probes (minimum 1)
        concurrency: Maximum number of simultaneous scanning tasks
        rate: Maximum packets per second (None = unlimited)
        resolve_dns: Whether to perform DNS resolution on the target
        output_json: Whether to output JSON (True) or Markdown (False)
    """

    target: str
    tcp_ports: Sequence[int]
    udp_ports: Sequence[int]
    timeout: float
    retries: int
    concurrency: int
    rate: float | None
    resolve_dns: bool
    output_json: bool


@dataclass(frozen=True)
class ResolvedTarget:
    """Outcome of DNS resolution step.

    After resolving a target (hostname or IP), this dataclass holds both the
    original user input and the resolved IP address for display and connection.

    Educational note: Keeping both user_input and resolved address is important
    for user experience - people want to see what they typed, but the scanner
    needs the actual IP address to connect.

    Attributes:
        user_input: Original target string from the user (e.g., "example.com")
        address: Resolved IP address as a string (e.g., "93.184.216.34")
        family: Socket address family (AF_INET for IPv4, AF_INET6 for IPv6)
    """

    user_input: str
    address: str
    family: socket.AddressFamily

    @property
    def display_name(self) -> str:
        """Format the target for display in output messages.

        Returns just the IP if the user provided an IP, or "hostname (ip)"
        if DNS resolution occurred. This helps users understand what was scanned.

        Examples:
            - Input "127.0.0.1" → "127.0.0.1"
            - Input "example.com" → "example.com (93.184.216.34)"
        """

        if self.user_input == self.address:
            return self.address
        return f"{self.user_input} ({self.address})"


@dataclass(frozen=True)
class PortScanResult:
    """Container for reporting the outcome of a single port scan.

    Each instance represents one scanned port's status, including metadata
    to help learners understand what the scanner discovered and why.

    Educational note: Structured results make it easy to sort, filter, and
    format scan data. The immutability ensures scan results can't be
    accidentally corrupted after they're created.

    Attributes:
        port: Port number that was scanned (1-65535)
        protocol: "TCP" or "UDP"
        state: Port state - "open", "closed", "filtered", or "open|filtered"
        service: Guessed service name (e.g., "http", "ssh") or empty string
        reason: Human-readable explanation of how the state was determined
                (e.g., "connect() succeeded", "ICMP 3/3 Port Unreachable")
    """

    port: int
    protocol: str
    state: str
    service: str
    reason: str


def normalize_ports(ports: Iterable[int]) -> list[int]:
    """Return a unique, sorted list of valid ports.

    This function ensures:
    - Duplicates are removed (using a set)
    - Ports are sorted for predictable output
    - Only valid port numbers (1-65535) are included

    Educational note: The scanner accepts any order from the CLI, but normalizing
    once makes scheduling deterministic and produces predictable tables for
    teaching purposes. Set comprehensions {x for x in ...} are an efficient way
    to deduplicate collections.

    Args:
        ports: Any iterable of port numbers (may contain duplicates or invalid values)

    Returns:
        Sorted list of unique valid ports

    Example:
        normalize_ports([80, 22, 80, 443, 0, 70000])
        # Returns: [22, 80, 443]  (duplicates removed, invalid filtered)
    """

    # Set comprehension: creates a set while filtering in one pass
    # Sets automatically handle deduplication (O(1) membership test)
    unique = sorted({p for p in ports if 0 < p < 65536})
    return unique
