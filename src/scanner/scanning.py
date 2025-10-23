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

"""Asynchronous TCP and UDP scanning routines.

This module implements the core port scanning logic using asyncio for concurrent
network operations. It demonstrates:
- TCP scanning via connect() handshake
- UDP scanning by sending probes and interpreting responses
- Rate limiting to avoid network congestion
- Concurrency control to manage system resources

Educational Concepts Covered:
- Network sockets and protocols (TCP vs UDP)
- Three-way handshake in TCP connections
- Asynchronous programming with asyncio
- Network error handling and timeout strategies
- Resource management and cleanup
- Rate limiting algorithms
"""

from __future__ import annotations

import asyncio
import errno
import socket
import time
from collections.abc import Awaitable

from .config import PortScanResult, ResolvedTarget, ScanSettings
from .constants import guess_service


class RateLimiter:
    """Simple token bucket limiter to keep packet emission readable.

    This helps prevent network congestion and makes the scanner more "polite"
    by limiting the number of packets sent per second.
    """

    def __init__(self, rate: float | None) -> None:
        # Calculate time interval between packets based on desired rate
        self._interval = (1.0 / rate) if rate else None
        # Use a lock to serialize access to the rate limiting schedule
        self._lock = asyncio.Lock()
        self._next_time = time.monotonic()

    async def wait(self) -> None:
        """Wait until it's our turn to send a packet according to the rate limit."""
        if not self._interval:
            return
        # Serialize callers so they observe the same token bucket schedule.
        async with self._lock:
            now = time.monotonic()
            delay = self._next_time - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            # Carry the schedule forward even if the coroutine woke up late.
            self._next_time = max(now, self._next_time) + self._interval


async def run_scan(settings: ScanSettings, target: ResolvedTarget) -> list[PortScanResult]:
    """Coordinate TCP/UDP scans according to ``settings``.

    This function sets up the scanning infrastructure and launches concurrent
    scanning tasks for each port in the target lists.
    """

    # Initialize rate limiting and concurrency control
    rate_limiter = RateLimiter(settings.rate)
    semaphore = asyncio.Semaphore(settings.concurrency)

    # Gate each probe behind the concurrency semaphore to prevent overwhelming the system
    async def bounded(coro: Awaitable[PortScanResult]) -> PortScanResult:
        async with semaphore:
            return await coro

    tasks: list[asyncio.Task[PortScanResult]] = []
    # Reuse the event loop for low-level UDP socket operations
    loop = asyncio.get_running_loop()

    # Create TCP scanning tasks
    for port in settings.tcp_ports:
        tasks.append(
            asyncio.create_task(bounded(_scan_tcp_port(port, settings, target, rate_limiter)))
        )

    # Create UDP scanning tasks
    for port in settings.udp_ports:
        tasks.append(
            asyncio.create_task(bounded(_scan_udp_port(port, settings, target, rate_limiter, loop)))
        )

    # Wait for all scans to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out any exceptions and return only successful results
    successful_results = []
    for result in results:
        if isinstance(result, Exception):
            # Log the exception in a production environment, for educational purposes
            # we'll just skip failed scans
            continue
        successful_results.append(result)

    # Sort results so output order does not depend on completion timing
    # This makes the output predictable and easier to read
    # Use a stable sort to maintain consistent ordering
    successful_results.sort(key=lambda r: (r.protocol, r.port))
    return successful_results


async def _scan_tcp_port(
    port: int,
    settings: ScanSettings,
    target: ResolvedTarget,
    limiter: RateLimiter,
) -> PortScanResult:
    """Attempt a TCP three-way handshake using ``connect``.

    TCP scanning works by attempting to complete the TCP three-way handshake:
    1. Send SYN packet (handled by connect())
    2. Receive SYN-ACK (port is open)
    3. Send ACK (handled by the OS)

    If the connection is refused (RST packet), the port is closed.
    If no response arrives, the port may be filtered by a firewall.
    """

    reason = "connect() timed out"
    for _attempt in range(settings.retries):
        # Rate limit before each attempt to keep outbound packets readable
        await limiter.wait()
        reader = None
        writer = None
        try:
            # Attempt to establish a TCP connection
            connect_coro = asyncio.open_connection(
                host=target.address,
                port=port,
                family=target.family,
            )
            # Wait for connection with timeout
            reader, writer = await asyncio.wait_for(connect_coro, timeout=settings.timeout)
            # Clean up the connection
            writer.close()
            try:
                await writer.wait_closed()
            except AttributeError:
                # Python <3.7 compatibility. Educational code keeps the guard.
                pass
            # Successful connection means the port is open
            return PortScanResult(
                port=port,
                protocol="TCP",
                state="open",
                service=guess_service(port),
                reason="connect() succeeded",
            )
        except asyncio.TimeoutError:
            reason = "connect() timed out"
        except ConnectionRefusedError:
            # Connection refused typically means the port is closed
            return PortScanResult(
                port=port,
                protocol="TCP",
                state="closed",
                service=guess_service(port),
                reason="connect() refused (RST)",
            )
        except OSError as exc:
            # Handle various network errors
            # Cross-platform error codes: EHOSTUNREACH (no route to host),
            # ENETUNREACH (network is unreachable), ECONNRESET (connection reset)
            if exc.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ECONNRESET}:
                reason = exc.strerror or str(exc)
            else:
                reason = f"socket error: {exc.strerror or exc}"
        finally:
            # Ensure connection cleanup in all error cases
            if writer:
                try:
                    writer.close()
                    if hasattr(writer, "wait_closed"):
                        await writer.wait_closed()
                except (AttributeError, RuntimeError):
                    # On some platforms, writer operations may raise RuntimeError
                    # after the connection has been closed
                    pass  # Best effort cleanup
        await asyncio.sleep(0)  # Yield so other probes can make progress between retries

    # If all retries failed, report the port as filtered
    return PortScanResult(
        port=port,
        protocol="TCP",
        state="filtered",
        service=guess_service(port),
        reason=reason,
    )


class UDPScanner:
    """A context manager for UDP socket operations to ensure proper resource cleanup."""

    def __init__(self, family: socket.AddressFamily):
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setblocking(False)

    def __enter__(self):
        return self.sock

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.sock:
            self.sock.close()


async def _scan_udp_port(
    port: int,
    settings: ScanSettings,
    target: ResolvedTarget,
    limiter: RateLimiter,
    loop: asyncio.AbstractEventLoop,
) -> PortScanResult:
    """Send a lightweight UDP probe and interpret the response.

    UDP scanning is inherently unreliable because:
    1. Open UDP ports often don't respond to arbitrary probes
    2. Firewalls may block UDP traffic silently
    3. The only reliable closed port indicator is ICMP Port Unreachable

    This implementation sends a UDP packet and waits for either:
    - A UDP response (port is open)
    - An ICMP Port Unreachable error (port is closed)
    - No response (port is open|filtered - ambiguous)
    """

    # Simple probe payload - some services might respond to specific content
    probe = b"educational-scan"
    reason = "no reply (no ICMP)"

    # Use context manager to ensure socket is always closed
    with UDPScanner(target.family) as sock:
        for _attempt in range(settings.retries):
            # Respect rate limiting
            await limiter.wait()
            try:
                # Send the UDP probe packet
                await loop.sock_sendto(sock, probe, (target.address, port))
            except OSError as exc:
                # Handle network unreachable errors
                if exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
                    reason = exc.strerror or str(exc)
                    break
                return PortScanResult(
                    port=port,
                    protocol="UDP",
                    state="filtered",
                    service=guess_service(port),
                    reason=f"send error: {exc.strerror or exc}",
                )

            try:
                # Wait for a response (either UDP data or ICMP error)
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), timeout=settings.timeout
                )
                # If we receive UDP data, the port is open
                return PortScanResult(
                    port=port,
                    protocol="UDP",
                    state="open",
                    service=guess_service(port),
                    reason="application response",
                )
            except asyncio.TimeoutError:
                # No response within timeout period
                reason = "no reply (no ICMP)"
            except OSError as exc:
                # Check for ICMP Port Unreachable (closed port)
                if exc.errno == errno.ECONNREFUSED:
                    return PortScanResult(
                        port=port,
                        protocol="UDP",
                        state="closed",
                        service=guess_service(port),
                        reason="ICMP 3/3 Port Unreachable",
                    )
                # Also handle other ICMP errors that might indicate the port is closed
                elif exc.errno in {errno.EPERM, errno.EACCES}:
                    # ICMP filtering or permission errors
                    return PortScanResult(
                        port=port,
                        protocol="UDP",
                        state="filtered",
                        service=guess_service(port),
                        reason=f"ICMP error: {exc.strerror or str(exc)}",
                    )
                reason = f"socket error: {exc.strerror or exc}"
                break
            await asyncio.sleep(0)  # Hand control back to the loop before retrying

    # No definitive signal arrived, so report the ambiguity open|filtered
    # This is common in UDP scanning - we can't distinguish between:
    # 1. An open port that ignored our probe
    # 2. A firewall blocking the traffic
    return PortScanResult(
        port=port,
        protocol="UDP",
        state="open|filtered",
        service=guess_service(port),
        reason=reason,
    )
