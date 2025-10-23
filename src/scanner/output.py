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

"""Formatting helpers for Markdown or JSON output.

This module handles rendering scan results in human-readable (Markdown tables)
and machine-readable (JSON) formats.

Educational Concepts:
- Markdown: Lightweight markup language for formatted text
- JSON: JavaScript Object Notation for structured data
- String escaping: Preventing special characters from breaking output format
- Data presentation: Different formats for different audiences
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from .config import PortScanResult, ResolvedTarget


def _escape_markdown_cell(value: str) -> str:
    """Escape characters that would break Markdown table formatting.

    Markdown tables use certain characters as syntax:
    - Pipe "|" separates columns
    - Backslash "\\" is the escape character
    - Backtick "`" denotes code spans

    Without escaping, these characters in scan results could corrupt the table
    structure, making the output unreadable or incorrectly rendered.

    Educational note: Output escaping is a critical security practice. While
    this example is benign (preventing formatting issues), similar escaping is
    essential for preventing injection attacks in SQL, HTML, shell commands, etc.

    Args:
        value: Raw string that might contain special characters

    Returns:
        Escaped string safe for Markdown table cells

    Example:
        "RST|timeout" → "RST\\|timeout"
        "c:\\windows" → "c:\\\\windows"
    """

    # Order matters! Escape backslashes first to avoid double-escaping
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace("|", r"\|")
    escaped = escaped.replace("`", r"\`")
    return escaped


def render_markdown(results: Iterable[PortScanResult], target: ResolvedTarget) -> str:
    """Render scan results as a formatted Markdown table for human readers.

    This function creates a multi-section report with:
    1. Scan summary (target, statistics)
    2. Detailed results table (port-by-port)
    3. Educational notes explaining port states

    Markdown tables use ASCII art alignment:
    - Right-aligned: Port numbers (easier to scan vertically)
    - Centered: Protocol (TCP/UDP)
    - Left-aligned: State, service, reason (text reads left-to-right)

    Educational note: Good output design considers the audience and use case.
    Humans benefit from summary statistics, aligned columns, and explanatory notes.
    Machines (see render_json) need structured, parseable data without decoration.

    Args:
        results: Iterable of PortScanResult objects to format
        target: ResolvedTarget containing the scanned address

    Returns:
        Multi-line string containing the formatted Markdown report
    """

    # Convert to list to avoid consuming the iterator multiple times
    # Iterables can only be consumed once, but we need to iterate twice:
    # once for statistics, once for the table
    results_list = list(results)

    # Compute statistics for the summary section
    # Using dict.get() with default 0 provides a clean counting pattern
    state_counts = {}
    protocol_counts = {}
    for row in results_list:
        state_counts[row.state] = state_counts.get(row.state, 0) + 1
        protocol_counts[row.protocol] = protocol_counts.get(row.protocol, 0) + 1

    # Build summary section showing high-level scan results
    # This helps users quickly understand what was scanned and what was found
    summary_lines = [
        f"Target: {target.display_name}",
        "",
        "## Scan Summary",
        f"Total ports scanned: {len(results_list)}",
        f"Protocols: {', '.join(f'{proto}: {count}' for proto, count in protocol_counts.items())}",
        f"States: {', '.join(f'{state}: {count}' for state, count in state_counts.items())}",
        "",
        "## Detailed Results",
    ]

    # Markdown table header with column names
    header = "| Port | Proto | State | Service | Reason |"

    # Divider row controls column alignment in Markdown:
    #   -----: right-aligned (port numbers)
    #   :----: centered (protocol)
    #   :----- left-aligned (state, service, reason)
    divider = "|-----:|:-----:|:-------------|:--------|:---------------------------|"
    lines: list[str] = summary_lines + [header, divider]

    # Build table rows, one per scanned port
    for row in results_list:
        # Escape any special characters that could break table formatting
        service = _escape_markdown_cell(row.service or "")
        state = _escape_markdown_cell(row.state)
        reason = _escape_markdown_cell(row.reason)

        # Format each cell with precise width control:
        #   {row.port:>4}  - Right-align in 4 characters
        #   {row.protocol:^5} - Center in 5 characters
        #   {state:<13}    - Left-align in 13 characters
        lines.append(
            f"| {row.port:>4} | {row.protocol:^5} | {state:<13} | {service:<6} | {reason} |"
        )

    # Add educational notes explaining what each state means
    # This is especially important for UDP's ambiguous states
    lines.extend(
        [
            "",
            "## Notes",
            "- **TCP closed**: Connection refused (RST packet received)",
            "- **TCP filtered**: No response (may be firewall blocking)",
            "- **UDP closed**: ICMP Port Unreachable received",
            "- **UDP open|filtered**: No response (port may be open or filtered)",
            "- **UDP open**: Application responded with data",
        ]
    )

    # Join all lines with newlines to create the final output
    return "\n".join(lines)


def render_json(results: Iterable[PortScanResult], target: ResolvedTarget) -> str:
    """Render scan results as structured JSON for machine consumption.

    This format is designed for:
    - Piping output to other tools (jq, automation scripts)
    - Storing results in databases or log aggregation systems
    - Programmatic parsing without text extraction

    Design decisions for JSON structure:
    - Protocol names are lowercased for consistency
    - Empty service names become null (not empty strings) for clarity
    - Two-space indentation makes the output human-readable when needed
    - Results are in a list to preserve order and allow multiple entries

    Educational note: JSON has become the standard for data interchange because:
    - Language-agnostic (every language has JSON libraries)
    - Self-describing (keys explain the data)
    - Typed (numbers, strings, booleans, null)
    - Widely supported by APIs, databases, and tools

    Args:
        results: Iterable of PortScanResult objects to serialize
        target: ResolvedTarget containing the scanned address

    Returns:
        JSON string with 2-space indentation

    Example output:
        {
          "target": "example.com (93.184.216.34)",
          "results": [
            {
              "port": 22,
              "protocol": "tcp",
              "state": "open",
              "service": "ssh",
              "reason": "connect() succeeded"
            }
          ]
        }
    """

    # Build a Python dict representing our data structure
    payload = {
        "target": target.display_name,
        "results": [
            {
                "port": row.port,  # Integer type preserved
                "protocol": row.protocol.lower(),  # Normalize to lowercase
                "state": row.state,  # Keep as-is (includes "open|filtered")
                "service": row.service or None,  # Convert empty string to null
                "reason": row.reason,  # Human-readable explanation
            }
            for row in results
        ],
    }

    # Serialize to JSON with indentation for readability
    # indent=2 balances human readability with file size
    return json.dumps(payload, indent=2)
