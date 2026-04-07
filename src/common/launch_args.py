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

import argparse
import dataclasses
import sys

from src.common.statics import ProgramName, ProgramID
from src.common.types_custom import BoolLocalTest, BoolDataDiodeSockets, BoolQubes, BoolTestRun


@dataclasses.dataclass(frozen=True, slots=True)
class LaunchArgumentsTCB:
    """Transmitter/Receiver Program launch arguments."""
    program_name       : ProgramName
    program_id         : ProgramID
    local_test         : BoolLocalTest
    data_diode_sockets : BoolDataDiodeSockets
    qubes              : BoolQubes
    test_run           : BoolTestRun = BoolTestRun(False)


@dataclasses.dataclass(frozen=True, slots=True)
class LaunchArgumentsRelay:
    """Relay Program launch arguments."""
    local_test         : BoolLocalTest
    data_diode_sockets : BoolDataDiodeSockets
    qubes              : BoolQubes
    test_run           : BoolTestRun
    program_id         : ProgramID   = ProgramID.NC
    program_name       : ProgramName = ProgramName.RELAY


def process_arguments_tcb() -> LaunchArgumentsTCB:
    """Load program-specific settings from command line arguments.

    The arguments are determined by the desktop entries and in the
    Terminator configuration file for local testing. The descriptions
    here are provided for the sake of completeness.
    """
    parser = argparse.ArgumentParser(f'python3 {sys.argv[0]}',
                                     usage  = '%(prog)s [OPTION]',
                                     epilog = 'Full documentation at: <https://github.com/maqp/tfc/wiki>')

    parser.add_argument('-r',
                        action  = 'store_true',
                        default = False,
                        dest    = 'operation',
                        help    = 'run Receiver instead of Transmitter Program')

    parser.add_argument('-l',
                        action  = 'store_true',
                        default = False,
                        dest    = 'local_test',
                        help    = 'enable local testing mode')

    parser.add_argument('-d',
                        action  = 'store_true',
                        default = False,
                        dest    = 'data_diode_sockets',
                        help    = 'use data diode simulator sockets during local testing mode')

    parser.add_argument('-q',
                        action  = 'store_true',
                        default = False,
                        dest    = 'qubes',
                        help    = 'exchange packets via qrexec RPC. Allows running TFC in qubes')

    args = parser.parse_args()

    return LaunchArgumentsTCB(program_name       = ProgramName.RECEIVER       if args.operation          else ProgramName.TRANSMITTER,
                              program_id         = ProgramID.RX               if args.operation          else ProgramID.TX,
                              local_test         = BoolLocalTest       (True) if args.local_test         else BoolLocalTest       (False),
                              data_diode_sockets = BoolDataDiodeSockets(True) if args.data_diode_sockets else BoolDataDiodeSockets(False),
                              qubes              = BoolQubes           (True) if args.qubes              else BoolQubes           (False))


def process_arguments_relay() -> LaunchArgumentsRelay:
    """Load program-specific settings from command line arguments.

    The arguments are determined by the desktop entries and in the
    Terminator configuration file for local testing. The descriptions
    here are provided for the sake of completeness.
    """
    parser = argparse.ArgumentParser(f'python3 {sys.argv[0]}',
                                     usage  = '%(prog)s [OPTION]',
                                     epilog = 'Full documentation at: <https://github.com/maqp/tfc/wiki>')

    parser.add_argument('-l',
                        action  = 'store_true',
                        default = False,
                        dest    = 'local_test',
                        help    = 'enable local testing mode')

    parser.add_argument('-d',
                        action  = 'store_true',
                        default = False,
                        dest    = 'data_diode_sockets',
                        help    = 'use data diode simulator sockets during local testing mode')

    parser.add_argument('-q',
                        action  = 'store_true',
                        default = False,
                        dest    = 'qubes',
                        help    = 'exchange packets via qrexec RPC. Allows running TFC in qubes')

    parser.add_argument('-t',
                        action  = 'store_true',
                        default = False,
                        dest    = 'test_run',
                        help    = 'Spin random test Onion Service. Used to test Relay Program functions properly.')

    args = parser.parse_args()

    return LaunchArgumentsRelay(local_test         = BoolLocalTest       (True) if args.local_test         else BoolLocalTest       (False),
                                data_diode_sockets = BoolDataDiodeSockets(True) if args.data_diode_sockets else BoolDataDiodeSockets(False),
                                qubes              = BoolQubes           (True) if args.qubes              else BoolQubes           (False),
                                test_run           = BoolTestRun         (True) if args.test_run           else BoolTestRun         (False))
