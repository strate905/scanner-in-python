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

"""Port parsing and validation helpers.

This module handles parsing of user port expressions from the command line,
demonstrating input validation and string parsing techniques.

Educational Concepts:
- Regular expressions for pattern matching
- Input validation and sanitization
- Handling edge cases gracefully (invalid inputs, reversed ranges)
- Using sets for deduplication
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Regular expression to match port expressions: single port or range
# Pattern breakdown:
#   ^         - Start of string
#   (\d+)     - First capture group: one or more digits (start port or single port)
#   (?:       - Non-capturing group (optional)
#     -       - Literal hyphen (range separator)
#     (\d+)   - Second capture group: one or more digits (end port)
#   )?        - Make the range part optional (allows single ports like "80")
#   $         - End of string
# Examples: "80" matches with group(1)="80", group(2)=None
#           "80-82" matches with group(1)="80", group(2)="82"
PORT_EXPR_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_port_expression(expr: str) -> list[int]:
    """Expand a comma-separated expression like ``"22,80-82"`` to integers.

    This function demonstrates robust input parsing that handles various edge cases:
    - Single ports: "80"
    - Port ranges: "80-82" (inclusive on both ends)
    - Mixed expressions: "22,80-82,443"
    - Whitespace tolerance: "22, 80-82 , 443"
    - Reversed ranges: "82-80" is automatically corrected to "80-82"
    - Invalid chunks: Silently skipped rather than causing errors

    Design decision: We use graceful degradation instead of strict validation.
    Invalid port expressions are ignored, allowing users to scan whatever valid
    ports they specified rather than failing the entire command.

    Port number validity:
    - Valid TCP/UDP ports: 1-65535 (16-bit unsigned integer)
    - Port 0 is reserved and not scannable
    - Ports outside this range are silently filtered out

    Examples:
        "22" -> [22]
        "80-82" -> [80, 81, 82]
        "22,80-82" -> [22, 80, 81, 82]
        "82-80" -> [80, 81, 82] (automatically swaps bounds)
        "22,invalid,80" -> [22, 80] (invalid chunk ignored)
        "0,22,70000" -> [22] (out-of-range ports filtered)

    Args:
        expr: Comma-separated port expression string from user input

    Returns:
        Sorted list of unique valid port numbers
    """

    # Use a set to automatically handle duplicate ports
    ports: set[int] = set()

    # Split on commas to handle multiple port specifications
    for chunk in expr.split(","):
        # Strip whitespace to be user-friendly ("80 - 82" becomes "80-82")
        chunk = chunk.strip()
        if not chunk:  # Skip empty strings from consecutive commas
            continue

        # Try to match against our port expression pattern
        match = PORT_EXPR_RE.match(chunk)
        if not match:  # Invalid format, skip this chunk
            continue

        # Extract start port (always present if we matched)
        start = int(match.group(1))

        # Extract end port if this is a range, otherwise it's a single port
        end = int(match.group(2)) if match.group(2) else start

        # Handle reversed ranges gracefully by swapping the bounds
        # This allows users to write "443-80" and we interpret it sensibly
        if end < start:
            start, end = end, start

        # Generate all ports in the range (inclusive)
        for port in range(start, end + 1):
            # Only include ports in the valid TCP/UDP range
            # Port 0 is reserved, ports > 65535 don't fit in 16 bits
            if 0 < port < 65536:
                ports.add(port)

    # Sort for deterministic output and easier reading
    return sorted(ports)


def merge_port_sources(*port_lists: Iterable[int]) -> list[int]:
    """Combine multiple port iterables into a sorted, de-duplicated list.

    This utility function is useful when combining default ports with user-specified
    ports, or when merging results from multiple configuration sources.

    Educational note: Using sets for deduplication is more efficient than using
    lists, because set membership testing is O(1) average case vs O(n) for lists.

    Args:
        *port_lists: Variable number of iterables containing port numbers

    Returns:
        Sorted list of unique ports, filtered to valid range (1-65535)

    Example:
        merge_port_sources([22, 80], [80, 443], [22, 8080])
        # Returns: [22, 80, 443, 8080]
    """

    result: set[int] = set()
    for collection in port_lists:
        # Filter to valid port range while building the set
        result.update(port for port in collection if 0 < port < 65536)
    return sorted(result)
