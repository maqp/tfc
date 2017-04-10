#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import base64
import datetime
import dbus
import dbus.exceptions
import time
import typing

from typing import Any

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository      import GObject

from src.nh.misc        import box_print, c_print, clear_screen, phase
from src.common.statics import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.settings import Settings


def ensure_im_connection() -> None:
    """Check that NH.py has connection to Pidgin before launching other processes."""
    phase("Waiting for enabled account in Pidgin", offset=1)

    while True:
        try:
            bus    = dbus.SessionBus(private=True)
            obj    = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
            purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

            while not purple.PurpleAccountsGetAllActive():
                time.sleep(0.001)
                continue
            phase('OK', done=True)

            accounts = []
            for a in purple.PurpleAccountsGetAllActive():
                accounts.append(purple.PurpleAccountGetUsername(a)[:-1])

            just_len  = len(max(accounts, key=len))
            justified = ["Active accounts in Pidgin:"] + ["* {}".format(a.ljust(just_len)) for a in accounts]
            box_print(justified, head=1, tail=1)
            return None

        except (IndexError, dbus.exceptions.DBusException):
            continue
        except (EOFError, KeyboardInterrupt):
            clear_screen()
            exit()


def im_command(q_im_cmd: 'Queue') -> None:
    """Run IM client command."""
    bus     = dbus.SessionBus(private=True)
    obj     = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
    purple  = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    account = purple.PurpleAccountsGetAllActive()[0]

    while True:
        try:
            if q_im_cmd.empty():
                time.sleep(0.001)
                continue
            command = q_im_cmd.get()

            if command[:2] in [UNENCRYPTED_SCREEN_CLEAR, UNENCRYPTED_SCREEN_RESET]:
                contact  = command[2:]
                new_conv = purple.PurpleConversationNew(1, account, contact)
                purple.PurpleConversationClearMessageHistory(new_conv)

        except (EOFError, KeyboardInterrupt):
            pass
        except dbus.exceptions.DBusException:
            continue


def im_incoming(settings: 'Settings', q_to_rxm: 'Queue') -> None:
    """Start signal receiver for packets from Pidgin."""

    def pidgin_to_rxm(account: str, sender: str, message: str, *_: Any) -> None:
        """Process received packet from Pidgin."""
        sender = sender.split('/')[0]
        ts     = datetime.datetime.now().strftime(settings.t_fmt)
        s_bus  = dbus.SessionBus(private=True)
        obj    = s_bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
        purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

        user = ''
        for a in purple.PurpleAccountsGetAllActive():
            if a == account:
                user = purple.PurpleAccountGetUsername(a)[:-1]

        if not message.startswith('TFC'):
            return None

        try:
            __, header, payload = message.split('|')
        except ValueError:
            return None

        if header.encode() == PUBLIC_KEY_PACKET_HEADER:
            print("{} - pub key {} > {} > RxM".format(ts, sender, user))

        elif header.encode() == MESSAGE_PACKET_HEADER:
            print("{} - message {} > {} > RxM".format(ts, sender, user))

        else:
            print("Received invalid packet from {}".format(sender))
            return None

        decoded = base64.b64decode(payload)
        packet  = header.encode() + decoded + ORIGIN_CONTACT_HEADER + sender.encode()
        q_to_rxm.put(packet)

    while True:
        try:
            bus = dbus.SessionBus(private=True, mainloop=DBusGMainLoop())
            bus.add_signal_receiver(pidgin_to_rxm, dbus_interface="im.pidgin.purple.PurpleInterface", signal_name="ReceivedImMsg")
            GObject.MainLoop().run()
        except (dbus.exceptions.DBusException, EOFError, KeyboardInterrupt):
            continue


def im_outgoing(settings: 'Settings', q_to_pidgin: 'Queue') -> None:
    """Send message from queue to Pidgin."""
    bus    = dbus.SessionBus(private=True)
    obj    = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

    while True:
        try:
            if q_to_pidgin.empty():
                time.sleep(0.001)
                continue

            header, payload, user, contact = q_to_pidgin.get()

            b64_str = base64.b64encode(payload).decode()
            payload = '|'.join(['TFC', header.decode(), b64_str])
            user    = user.decode()
            contact = contact.decode()

            user_found = False
            for u in purple.PurpleAccountsGetAllActive():
                if user == purple.PurpleAccountGetUsername(u)[:-1]:
                    user_found = True
                    if settings.relay_to_im_client:
                        new_conv = purple.PurpleConversationNew(1, u, contact)
                        sel_conv = purple.PurpleConvIm(new_conv)
                        purple.PurpleConvImSend(sel_conv, payload)
                    continue

            if not user_found:
                c_print("Error: No user {} found.".format(user), head=1, tail=1)
                continue

        except (EOFError, KeyboardInterrupt):
            pass
        except dbus.exceptions.DBusException:
            continue
