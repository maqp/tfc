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
import dbus
import dbus.exceptions
import time
import typing

from datetime import datetime
from typing   import Any, Dict, Tuple

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository      import GObject

from src.common.misc    import ignored
from src.common.output  import box_print, c_print, clear_screen, phase
from src.common.statics import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.settings import Settings


def ensure_im_connection() -> None:
    """\
    Check that nh.py has connection to Pidgin
    before launching other processes.
    """
    phase("Waiting for enabled account in Pidgin", offset=1)

    while True:
        try:
            bus    = dbus.SessionBus(private=True)
            obj    = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
            purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

            while not purple.PurpleAccountsGetAllActive():
                time.sleep(0.01)
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


def im_command(queues: Dict[bytes, 'Queue']) -> None:
    """Loop that executes commands on IM client."""
    bus     = dbus.SessionBus(private=True)
    obj     = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
    purple  = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    account = purple.PurpleAccountsGetAllActive()[0]
    queue   = queues[NH_TO_IM_QUEUE]

    while True:
        with ignored(dbus.exceptions.DBusException, EOFError, KeyboardInterrupt):
            while queue.qsize() == 0:
                time.sleep(0.01)

            command = queue.get()

            if command[:2] in [UNENCRYPTED_SCREEN_CLEAR, UNENCRYPTED_SCREEN_RESET]:
                contact  = command[2:]
                new_conv = purple.PurpleConversationNew(1, account, contact)
                purple.PurpleConversationClearMessageHistory(new_conv)


def im_incoming(queues: Dict[bytes, 'Queue']) -> None:
    """Loop that maintains signal receiver process."""

    def pidgin_to_rxm(account: str, sender: str, message: str, *_: Any) -> None:
        """Signal receiver process that receives packets from Pidgin."""
        sender = sender.split('/')[0]
        ts     = datetime.now().strftime("%m-%d / %H:%M:%S")
        d_bus  = dbus.SessionBus(private=True)
        obj    = d_bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
        purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

        user = ''
        for a in purple.PurpleAccountsGetAllActive():
            if a == account:
                user = purple.PurpleAccountGetUsername(a)[:-1]

        if not message.startswith(TFC):
            return None

        try:
            __, header, payload = message.split('|')  # type: Tuple[str, str, str]
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
        queues[RXM_OUTGOING_QUEUE].put(packet)

    while True:
        with ignored(dbus.exceptions.DBusException, EOFError, KeyboardInterrupt):
            bus = dbus.SessionBus(private=True, mainloop=DBusGMainLoop())
            bus.add_signal_receiver(pidgin_to_rxm, dbus_interface="im.pidgin.purple.PurpleInterface", signal_name="ReceivedImMsg")
            GObject.MainLoop().run()


def im_outgoing(queues: Dict[bytes, 'Queue'], settings: 'Settings') -> None:
    """\
    Loop that outputs messages and public keys from
    queue and sends them to contacts over Pidgin.
    """
    bus    = dbus.SessionBus(private=True)
    obj    = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    queue  = queues[TXM_TO_IM_QUEUE]

    while True:
        with ignored(dbus.exceptions.DBusException, EOFError, KeyboardInterrupt):
            while queue.qsize() == 0:
                time.sleep(0.01)

            header, payload, user, contact = queue.get()

            b64_str = base64.b64encode(payload).decode()
            payload = '|'.join([TFC, header.decode(), b64_str])
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
