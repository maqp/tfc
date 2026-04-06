#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

from src.common.statics import AsmPacket

MESSAGE_PAYLOAD_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_S_HEADER,
    AsmPacket.M_L_HEADER,
    AsmPacket.M_A_HEADER,
    AsmPacket.M_E_HEADER,
    AsmPacket.M_C_HEADER,
    AsmPacket.P_N_HEADER,
))

FILE_PAYLOAD_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.F_S_HEADER,
    AsmPacket.F_L_HEADER,
    AsmPacket.F_A_HEADER,
    AsmPacket.F_E_HEADER,
    AsmPacket.F_C_HEADER,
))

COMMAND_PAYLOAD_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.C_S_HEADER,
    AsmPacket.C_L_HEADER,
    AsmPacket.C_A_HEADER,
    AsmPacket.C_E_HEADER,
    AsmPacket.C_C_HEADER,
    AsmPacket.C_N_HEADER,
))

CONTACT_ASSEMBLY_PACKET_HEADERS: frozenset[AsmPacket] = MESSAGE_PAYLOAD_HEADERS | FILE_PAYLOAD_HEADERS

SHORT_PAYLOAD_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_S_HEADER,
    AsmPacket.F_S_HEADER,
    AsmPacket.C_S_HEADER,
))

FIRST_OF_LONG_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_L_HEADER,
    AsmPacket.F_L_HEADER,
    AsmPacket.C_L_HEADER,
))

APPEND_OF_LONG_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_A_HEADER,
    AsmPacket.F_A_HEADER,
    AsmPacket.C_A_HEADER,
))

END_OF_LONG_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_E_HEADER,
    AsmPacket.F_E_HEADER,
    AsmPacket.C_E_HEADER,
))

CANCEL_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.M_C_HEADER,
    AsmPacket.F_C_HEADER,
    AsmPacket.C_C_HEADER,
))

NOISE_HEADERS: frozenset[AsmPacket] = frozenset((
    AsmPacket.P_N_HEADER,
    AsmPacket.C_N_HEADER,
))
