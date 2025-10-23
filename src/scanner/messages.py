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

"""Centralised CLI-facing copy for the educational scanner."""

from __future__ import annotations

# Reuse this primer anywhere we need to explain UDP scan semantics.
UDP_SCANNING_PRIMER = (
    "UDP scanning is best-effort: closed ports send ICMP 3/3 Port Unreachable, "
    "but open services often stay silent, so we report open|filtered when "
    "no response arrives."
)
