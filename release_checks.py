#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2022  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""


def test_version_names():
    """Test that versions in desktop launchers match the software version."""
    sw_version = None
    with open('src/common/statics.py') as f:
        lines = f.read().splitlines()

    for l in lines:
        if l.startswith('VERSION'):
            sw_version = l.split('= ')[1].strip("'")


    for launcher in ["TFC-Dev.desktop",
                     "TFC-Local-test.desktop",
                     "TFC-RP.desktop",
                     "TFC-RP-Qubes.desktop",
                     "TFC-RP-Tails.desktop",
                     "TFC-RxP.desktop",
                     "TFC-RxP-Qubes.desktop",
                     "TFC-TxP.desktop",
                     "TFC-TxP-Qubes.desktop"]:
        with open(f'launchers/{launcher}') as f:
            lines = f.read().splitlines()
            for l in lines:
                if l.startswith('Version'):
                    launcher_version = l.split('=')[1]
                    if launcher_version != sw_version:
                        print(f"Error: Launcher {launcher} had version {launcher_version} but software version is {sw_version}.")
                        exit(1)


if __name__ == '__main__':
    test_version_names()
