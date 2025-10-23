# Educational Network Scanner in Python

An asyncio-based TCP/UDP port scanner written in Python and designed for educational purposes. It demonstrates real-world networking concepts including connect() TCP scans, best-effort UDP probing, DNS resolution, concurrency control, and structured reporting while keeping the codebase approachable for learners.

**🎓 Perfect for Learning:** Every module includes extensive educational comments explaining networking concepts, design decisions, and Python best practices. Students can read the source code as a tutorial on network programming, asynchronous I/O, and software architecture.

## Learning Objectives

By studying this codebase, students will learn:
- **Network Protocols**: TCP three-way handshake, UDP datagram transmission, ICMP error messages
- **DNS Resolution**: How hostnames translate to IP addresses, IPv4 vs IPv6
- **Asynchronous Programming**: Using `asyncio` for concurrent I/O operations
- **Rate Limiting**: Token bucket algorithm for controlling packet emission
- **Error Handling**: Network timeouts, connection refusals, and socket errors
- **Port States**: Understanding open, closed, filtered, and open|filtered states
- **Python Best Practices**: Type hints, dataclasses, context managers, and immutable objects

## Prerequisites
- Python 3.10 or newer
- POSIX-like environment (Linux, macOS, WSL) recommended for consistent socket behaviour
- `pip` 22+ (upgrade with `python -m pip install --upgrade pip`)
- **Important**: Only scan networks you own or have explicit permission to scan

## Setup
1. Clone the repository and enter the project directory:
   ```bash
   git clone https://github.com/<your-org>/scanner-in-python.git
   cd scanner-in-python
   ```
2. Create an isolated virtual environment:
   ```bash
   python -m venv .venv
   ```
3. Activate the environment:
   ```bash
   source .venv/bin/activate          # Bash/Zsh
   # or
   source .venv/bin/activate.fish     # Fish
   # or on Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   ```
4. Install the package in editable mode together with the development tooling:
   ```bash
   pip install -e .
   pip install -r requirements.txt    # pytest, pytest-cov, ruff
   # alternatively: pip install -e ".[dev]"
   ```

Once installed, the console script `scanner` is available on your `$PATH`.

## Running the Scanner
- Discover CLI options and descriptions:
  ```bash
  python -m scanner.cli --help
  # or, after installation:
  scanner --help
  ```
- Execute a mixed TCP/UDP scan:
  ```bash
  python -m scanner.cli --tcp 22,80-82 --udp 53 example.com
  ```

Key flags:
- `--timeout` / `--retries` tune resilience when networks drop packets.
- `--concurrency` and `--rate` govern simultaneous probes and packets per second.
- `--no-dns` enforces literal IP targets.
- `--json` switches from Markdown tables to a machine-readable document.
- `--about-udp` prints an explainer for open|filtered UDP results.

Results default to a Markdown table with scan summary:
```
Target: example.com (93.184.216.34)

## Scan Summary
Total ports scanned: 2
Protocols: TCP: 1, UDP: 1
States: open: 1, open|filtered: 1

## Detailed Results
| Port | Proto | State        | Service | Reason                   |
|-----:|:-----:|:-------------|:--------|:-------------------------|
|   22 |  TCP  | open         | ssh     | connect() succeeded      |
|   53 |  UDP  | open|filtered| dns     | no reply (no ICMP)       |

## Notes
- **TCP closed**: Connection refused (RST packet received)
- **TCP filtered**: No response (may be firewall blocking)
- **UDP closed**: ICMP Port Unreachable received
- **UDP open|filtered**: No response (port may be open or filtered)
- **UDP open**: Application responded with data
```

## Testing & Quality
```bash
pytest
pytest --cov=src/scanner --cov-report=term-missing
ruff check src tests
ruff format src tests
```

## Build & Distribution
Create distributable artifacts (wheel and sdist) with:
```bash
pip install build
python -m build
ls dist/
```
Install the resulting wheel into another environment to verify the package:
```bash
pip install dist/scanner-<version>-py3-none-any.whl
```

## Project Layout
- `src/scanner/` – CLI, scanning engine, configuration helpers, and output formatters
  - `cli.py` – Command-line interface with argument parsing and validation
  - `scanning.py` – Core async TCP/UDP scanning logic with rate limiting
  - `resolution.py` – DNS resolution and IP address validation
  - `ports.py` – Port expression parsing (e.g., "22,80-443")
  - `output.py` – Markdown and JSON output formatters
  - `config.py` – Immutable dataclasses for configuration and results
  - `constants.py` – Default port lists and service name mappings
  - `messages.py` – User-facing help text and educational content
- `tests/` – Automated test suite mirroring the source tree (pytest)
- `AGENTS.md` – Contributor workflow and coding standards overview
- `SPECIFICATIONS.md` – Detailed technical specifications
- `CLAUDE.md` – AI assistant guidance for working with this codebase

## Educational Features

### Comprehensive Code Comments
Every source file includes:
- **Module docstrings**: Explain the module's purpose and educational concepts covered
- **Function docstrings**: Document parameters, return values, and include examples
- **Inline comments**: Explain tricky logic, design decisions, and networking concepts
- **Educational notes**: Highlight learning opportunities and real-world considerations

### Example Learning Path
1. **Start with `constants.py`**: Learn about port numbers and common services
2. **Read `ports.py`**: Understand regex patterns and input validation
3. **Explore `resolution.py`**: Learn DNS and IP address concepts
4. **Study `scanning.py`**: Understand asyncio, rate limiting, and network protocols
5. **Review `output.py`**: Learn about data formatting and output escaping
6. **Examine `cli.py`**: See how all components integrate

## Ethical Considerations

**⚠️ Important**: This tool is for educational purposes only. Network scanning without authorization is illegal in many jurisdictions and violates ethical hacking principles.

**Authorized Use Cases:**
- Scanning `127.0.0.1` (localhost) for learning
- Scanning your own devices and networks
- Academic assignments with proper lab environments
- Authorized penetration testing engagements
- CTF competitions and security training exercises

**Unauthorized Use:**
- Scanning networks you don't own or have permission to scan
- Scanning public internet targets without explicit authorization
- Using the scanner for malicious purposes

The scanner includes a warning when scanning private network ranges (RFC 1918) to remind users about authorization requirements.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
