from __future__ import annotations

import asyncio
import errno
from unittest.mock import AsyncMock, Mock, patch

import pytest

from scanner.config import ResolvedTarget, ScanSettings
from scanner.scanning import UDPScanner, _scan_tcp_port, _scan_udp_port, run_scan


class TestUDPScanner:
    """Test the UDPScanner context manager."""

    @patch("socket.socket")
    def test_udp_scanner_closes_socket(self, mock_socket):
        """Test that UDPScanner properly closes the socket."""
        mock_sock_instance = Mock()
        mock_socket.return_value = mock_sock_instance

        # Test context manager usage
        with UDPScanner(2):  # AF_INET = 2
            pass

        # Verify socket was properly created and closed
        mock_socket.assert_called_once()
        mock_sock_instance.setblocking.assert_called_once_with(False)
        mock_sock_instance.close.assert_called_once()


class TestScanTCP:
    """Test TCP scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_tcp_port_open(self):
        """Test scanning an open TCP port."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[80],
            udp_ports=[],
            timeout=1.0,
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        # Mock successful connection
        mock_reader = Mock()
        mock_writer = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        with (
            patch(
                "asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))
            ),
            patch("asyncio.wait_for", new=AsyncMock(return_value=(mock_reader, mock_writer))),
        ):
            result = await _scan_tcp_port(80, settings, target, mock_limiter)

            assert result.port == 80
            assert result.protocol == "TCP"
            assert result.state == "open"
            assert result.reason == "connect() succeeded"

    @pytest.mark.asyncio
    async def test_scan_tcp_port_closed(self):
        """Test scanning a closed TCP port."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[81],
            udp_ports=[],
            timeout=1.0,
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError)):
            result = await _scan_tcp_port(81, settings, target, mock_limiter)

            assert result.port == 81
            assert result.protocol == "TCP"
            assert result.state == "closed"
            assert result.reason == "connect() refused (RST)"

    @pytest.mark.asyncio
    async def test_scan_tcp_port_filtered(self):
        """Test scanning a filtered TCP port."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[82],
            udp_ports=[],
            timeout=0.1,  # Short timeout to trigger timeout
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            result = await _scan_tcp_port(82, settings, target, mock_limiter)

            assert result.port == 82
            assert result.protocol == "TCP"
            assert result.state == "filtered"
            assert result.reason == "connect() timed out"

    @pytest.mark.asyncio
    async def test_scan_tcp_port_network_error(self):
        """Test scanning with network errors."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[83],
            udp_ports=[],
            timeout=1.0,
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        # Create an OSError with a network unreachable error
        os_error = OSError()
        os_error.errno = errno.ENETUNREACH
        os_error.strerror = "Network is unreachable"

        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(side_effect=os_error)):
            result = await _scan_tcp_port(83, settings, target, mock_limiter)

            assert result.port == 83
            assert result.protocol == "TCP"
            assert result.state == "filtered"
            assert "Network is unreachable" in result.reason


class TestScanUDP:
    """Test UDP scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_udp_port_open(self):
        """Test UDP scanner with a simulated response."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[],
            udp_ports=[53],
            timeout=1.0,
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        # Mock UDP socket operations
        loop_mock = Mock()
        loop_mock.sock_sendto = AsyncMock()
        loop_mock.sock_recvfrom = AsyncMock(return_value=(b"response", ("127.0.0.1", 53)))
        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        result = await _scan_udp_port(53, settings, target, mock_limiter, loop_mock)

        assert result.port == 53
        assert result.protocol == "UDP"
        assert result.state == "open"
        assert result.reason == "application response"

    @pytest.mark.asyncio
    async def test_scan_udp_port_closed(self):
        """Test UDP scanner detecting a closed port."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[],
            udp_ports=[54],
            timeout=1.0,
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        # Create an OSError with connection refused (closed port)
        os_error = OSError()
        os_error.errno = errno.ECONNREFUSED
        os_error.strerror = "Connection refused"

        loop_mock = Mock()
        loop_mock.sock_sendto = AsyncMock()
        loop_mock.sock_recvfrom = AsyncMock(side_effect=os_error)
        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        result = await _scan_udp_port(54, settings, target, mock_limiter, loop_mock)

        assert result.port == 54
        assert result.protocol == "UDP"
        assert result.state == "closed"
        assert result.reason == "ICMP 3/3 Port Unreachable"

    @pytest.mark.asyncio
    async def test_scan_udp_port_timeout(self):
        """Test UDP scanner when no response is received (open|filtered)."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[],
            udp_ports=[55],
            timeout=0.1,  # Short timeout
            retries=1,
            concurrency=1,
            rate=None,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        loop_mock = Mock()
        loop_mock.sock_sendto = AsyncMock()
        loop_mock.sock_recvfrom = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_limiter = AsyncMock()
        mock_limiter.wait = AsyncMock()

        result = await _scan_udp_port(55, settings, target, mock_limiter, loop_mock)

        assert result.port == 55
        assert result.protocol == "UDP"
        assert result.state == "open|filtered"
        assert result.reason == "no reply (no ICMP)"


class TestRunScan:
    """Test the main run_scan function."""

    @pytest.mark.asyncio
    async def test_run_scan_tcp_udp(self):
        """Test that run_scan executes both TCP and UDP scans."""
        settings = ScanSettings(
            target="127.0.0.1",
            tcp_ports=[80],
            udp_ports=[53],
            timeout=1.0,
            retries=1,
            concurrency=64,
            rate=128.0,
            resolve_dns=True,
            output_json=False,
        )
        target = ResolvedTarget(
            user_input="127.0.0.1",
            address="127.0.0.1",
            family=2,  # AF_INET
        )

        # Mock the scanning functions to return specific results
        tcp_result_mock = Mock()
        tcp_result_mock.port = 80
        tcp_result_mock.protocol = "TCP"
        tcp_result_mock.state = "open"
        tcp_result_mock.service = "http"
        tcp_result_mock.reason = "connect() succeeded"

        udp_result_mock = Mock()
        udp_result_mock.port = 53
        udp_result_mock.protocol = "UDP"
        udp_result_mock.state = "open"
        udp_result_mock.service = "dns"
        udp_result_mock.reason = "application response"

        with (
            patch("scanner.scanning._scan_tcp_port", new=AsyncMock(return_value=tcp_result_mock)),
            patch("scanner.scanning._scan_udp_port", new=AsyncMock(return_value=udp_result_mock)),
        ):
            results = await run_scan(settings, target)

            assert len(results) == 2
            # Results should be sorted by protocol first, then port number
            assert results[0].port == 80  # TCP comes first alphabetically
            assert results[0].protocol == "TCP"
            assert results[1].port == 53  # UDP comes second
            assert results[1].protocol == "UDP"
