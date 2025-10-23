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

"""Target resolution helpers.

This module handles DNS resolution and IP address validation, demonstrating how
network applications translate human-readable hostnames into machine-routable
IP addresses.

Educational Concepts:
- DNS (Domain Name System): The internet's "phone book" for looking up addresses
- IPv4 vs IPv6: Two versions of the Internet Protocol (32-bit vs 128-bit addresses)
- getaddrinfo(): Modern, protocol-agnostic way to resolve hostnames
- Address families: AF_INET (IPv4) and AF_INET6 (IPv6)
"""

from __future__ import annotations

import ipaddress
import socket

from .config import ResolvedTarget


class ResolutionError(RuntimeError):
    """Raised when the scanner cannot map a target to a usable address.

    This custom exception type allows callers to distinguish resolution failures
    from other types of errors, enabling appropriate user-facing error messages.
    """


def resolve_target(target: str, enable_dns: bool) -> ResolvedTarget:
    """Return a concrete IP address for the given target.

    This function demonstrates the crucial first step in network communication:
    converting a target specification into a routable IP address.

    Two modes of operation:
    1. DNS disabled (--no-dns): Validates that target is a literal IP address
       - Useful for testing or when DNS is unavailable
       - Prevents information leakage through DNS queries
       - Requires user to know the IP address beforehand

    2. DNS enabled (default): Resolves hostnames using the system resolver
       - Translates "example.com" → "93.184.216.34"
       - Uses the operating system's DNS configuration
       - May involve multiple DNS servers and caching layers

    Educational notes:
    - DNS resolution can fail due to network issues, typos, or non-existent domains
    - IPv4 addresses look like "192.168.1.1" (32 bits = 4 octets)
    - IPv6 addresses look like "2001:db8::1" (128 bits = 8 groups of hex)
    - The address family (AF_INET vs AF_INET6) must match the address type

    Args:
        target: Hostname or IP address to resolve
        enable_dns: Whether to perform DNS lookups

    Returns:
        ResolvedTarget containing the IP address and socket family

    Raises:
        ResolutionError: If resolution fails or target is invalid
    """

    # Default to localhost if no target specified
    if not target:
        target = "127.0.0.1"

    if not enable_dns:
        # DNS-free mode: Validate that the input is a literal IP address
        try:
            # The ipaddress module handles both IPv4 and IPv6 parsing
            ip = ipaddress.ip_address(target)
        except ValueError as exc:  # pragma: no cover - defensive branch
            raise ResolutionError("--no-dns requires a literal IPv4 or IPv6 address") from exc

        # Determine socket address family based on IP version
        # This is essential - using the wrong family will cause connection failures
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        return ResolvedTarget(user_input=target, address=str(ip), family=family)

    # DNS-enabled mode: Perform hostname resolution
    try:
        # getaddrinfo() is the modern, protocol-agnostic resolution function
        # It returns a list of (family, type, proto, canonname, sockaddr) tuples
        #
        # Parameters:
        #   target: Hostname or IP address to resolve
        #   None: Port number (we pass None since we're only resolving the host)
        #
        # The function queries DNS servers configured in /etc/resolv.conf (Unix)
        # or Windows network settings, following the OS's resolution rules.
        results = socket.getaddrinfo(target, None)
    except socket.gaierror as exc:  # pragma: no cover - depends on network
        # gaierror is raised for DNS resolution failures:
        # - NXDOMAIN: Domain doesn't exist
        # - Timeout: DNS server didn't respond
        # - SERVFAIL: DNS server encountered an error
        raise ResolutionError(f"unable to resolve {target!r}: {exc}") from exc

    if not results:  # pragma: no cover - defensive
        # Extremely rare - getaddrinfo() typically raises gaierror instead
        raise ResolutionError(f"unable to resolve {target!r}")

    # getaddrinfo() may return multiple results (IPv4 and IPv6 addresses)
    # We take the first result for deterministic behavior in teaching scenarios
    # Production scanners might try all addresses or prefer IPv6/IPv4
    family, _, _, _, sockaddr = results[0]

    # Extract the IP address from the sockaddr tuple
    # sockaddr format depends on family:
    #   AF_INET: (address, port)
    #   AF_INET6: (address, port, flow_info, scope_id)
    # Index 0 is always the address string
    address = sockaddr[0]

    return ResolvedTarget(user_input=target, address=address, family=family)
