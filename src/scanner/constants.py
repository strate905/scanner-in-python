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

"""Shared constants for the educational network scanner.

This module defines default port lists and service name mappings that help students
understand common network services and their standard port assignments.

Educational Concepts:
- Port numbers: 16-bit integers (0-65535) that identify specific services
- Well-known ports (0-1023): Reserved for standard services like HTTP, SSH
- Registered ports (1024-49151): Used by applications and services
- IANA: Internet Assigned Numbers Authority maintains the official registry
"""

from __future__ import annotations

# Default TCP port selection: 25 most common services in enterprise networks
# These ports were chosen based on real-world scanning frequency and educational value.
# Each port represents a distinct protocol or service concept that students should know.
DEFAULT_TCP_PORTS: list[int] = [
    80,  # HTTP - Web traffic (unencrypted)
    443,  # HTTPS - Secure web traffic (TLS/SSL)
    22,  # SSH - Secure shell for remote administration
    21,  # FTP - File Transfer Protocol (control channel)
    25,  # SMTP - Email transmission
    23,  # Telnet - Legacy remote access (insecure, rarely used today)
    53,  # DNS - Domain Name System (usually UDP, but TCP for zone transfers)
    110,  # POP3 - Email retrieval protocol
    135,  # MS-RPC - Microsoft Remote Procedure Call
    139,  # NetBIOS Session Service - Windows file/printer sharing (legacy)
    143,  # IMAP - Email retrieval protocol (more features than POP3)
    445,  # SMB - Server Message Block (modern Windows file sharing)
    3389,  # RDP - Remote Desktop Protocol
    3306,  # MySQL - Database server
    8080,  # HTTP-Alternate - Often used for web proxies or dev servers
    5900,  # VNC - Virtual Network Computing (remote desktop)
    993,  # IMAPS - IMAP over TLS/SSL
    995,  # POP3S - POP3 over TLS/SSL
    465,  # SMTPS - SMTP over TLS/SSL (legacy, now uses STARTTLS on 587)
    587,  # Submission - Email submission with STARTTLS
    111,  # RPCBind - Sun RPC port mapper
    2049,  # NFS - Network File System
    1025,  # Microsoft RPC (dynamic high port)
    1723,  # PPTP - Point-to-Point Tunneling Protocol (VPN)
    554,  # RTSP - Real Time Streaming Protocol
]

# Default UDP port selection: 5 essential UDP services
# UDP is used for services where speed matters more than reliability
DEFAULT_UDP_PORTS: list[int] = [
    53,  # DNS - Most DNS queries use UDP for speed
    123,  # NTP - Network Time Protocol (clock synchronization)
    161,  # SNMP - Simple Network Management Protocol (device monitoring)
    500,  # ISAKMP - Internet Security Association and Key Management (IPsec VPN)
    1900,  # SSDP - Simple Service Discovery Protocol (UPnP)
]

# Service name registry: Maps port numbers to their common service names
# This is a subset of the IANA port registry, focused on ports students will encounter.
# In production scanners, this would be loaded from a comprehensive external database.
SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9000: "sonarqube",
}


def guess_service(port: int) -> str:
    """Return the common service name for a given port number.

    Educational note: This demonstrates service fingerprinting - the process of
    identifying what service is likely running on a port based on conventions.
    However, port numbers are just conventions; any service can run on any port.
    Real scanners send service-specific probes to confirm the actual service.

    Args:
        port: The port number to look up (1-65535)

    Returns:
        The service name (e.g., "http", "ssh") or empty string if unknown.
        We return empty string instead of None to simplify output formatting.
    """

    return SERVICE_NAMES.get(port, "")
