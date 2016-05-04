#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || dd.py

"""
GPL License

This software is part of the TFC application, which is free software: You can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details. For
a copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.
"""

import multiprocessing.connection
import multiprocessing
import os
import shlex
import subprocess
import sys
import time


###############################################################################
#                              DATA DIODE FRAMES                              #
###############################################################################

def lr_upper():
    print("""
      Data flow
          →
 Tx───┬─╮   ╭──────╮
      │ S > R      █±6V
GND━━━┿━┥   ├──Rx  ├──GND
      │ S   R      █±6V
      ╰─╯   ╰──────╯""")


def lr_lower():
    print("""
      Data flow
          →
 Tx───┬─╮   ╭──────╮
      │ S   R      █±6V
GND━━━┿━┥   ├──Rx  ├──GND
      │ S > R      █±6V
      ╰─╯   ╰──────╯""")


def lr_idle():
    print("""
      Data flow
          →
 Tx───┬─╮   ╭──────╮
      │ S   R      █±6V
GND━━━┿━┥   ├──Rx  ├──GND
      │ S   R      █±6V
      ╰─╯   ╰──────╯""")


def rl_upper():
    print("""
          Data flow
              ←
     ╭──────╮   ╭─┬───Tx
  ±6V█      R < S │
GND──┤  Rx──┤   ┝━┿━━━GND
  ±6V█      R   S │
     ╰──────╯   ╰─╯""")


def rl_lower():
    print("""
          Data flow
              ←
     ╭──────╮   ╭─┬───Tx
  ±6V█      R   S │
GND──┤  Rx──┤   ┝━┿━━━GND
  ±6V█      R < S │
     ╰──────╯   ╰─╯""")


def rl_idle():
    print("""
          Data flow
              ←
     ╭──────╮   ╭─┬───Tx
  ±6V█      R   S │
GND──┤  Rx──┤   ┝━┿━━━GND
  ±6V█      R   S │
     ╰──────╯   ╰─╯""")


###############################################################################
#                             DATA DIODE ANIMATORS                            #
###############################################################################

def lr():
    for _ in range(10):
        os.system("clear")
        lr_lower()
        time.sleep(0.04)
        os.system("clear")
        lr_upper()
        time.sleep(0.04)
    os.system("clear")


def rl():
    for _ in range(10):
        os.system("clear")
        rl_lower()
        time.sleep(0.04)
        os.system("clear")
        rl_upper()
        time.sleep(0.04)
    os.system("clear")


###############################################################################
#                             DATA DIODE PROCESSES                            #
###############################################################################

def tx_process():

    if tx_nh_lr or nh_rx_rl:
        lr_idle()

    if tx_nh_rl or nh_rx_lr:
        rl_idle()

    while True:
        if io_queue.empty():
            time.sleep(0.001)
            continue

        msg = io_queue.get()

        if tx_nh_lr or nh_rx_rl:
            lr()
            lr_idle()

        if tx_nh_rl or nh_rx_lr:
            rl()
            rl_idle()

        ipx_send.send(msg)


def rx_process():

    def ipc_to_queue(conn):
        while True:
            time.sleep(0.001)
            pkg = str(conn.recv())
            io_queue.put(pkg)
    try:
        l = multiprocessing.connection.Listener(('', input_socket))
        while True:
            ipc_to_queue(l.accept())
    except EOFError:
        exit_queue.put("exit")


tx_nh_lr = False
nh_rx_lr = False
tx_nh_rl = False
nh_rx_rl = False

input_socket = 0
output_socket = 0

# Resize terminal
id_cmd = "xdotool getactivewindow"
resize_cmd = "xdotool windowsize --usehints {id} 25 12"
proc = subprocess.Popen(shlex.split(id_cmd), stdout=subprocess.PIPE)
windowid, err = proc.communicate()
proc = subprocess.Popen(shlex.split(resize_cmd.format(id=windowid)))
proc.communicate()

try:
    # Simulates data diode between Tx.py on left, NH.py on right.
    if str(sys.argv[1]) == "txnhlr":
        tx_nh_lr = True
        input_socket = 5000
        output_socket = 5001

    # Simulates data diode between Tx.py on right, NH.py on left.
    elif str(sys.argv[1]) == "txnhrl":
        tx_nh_rl = True
        input_socket = 5000
        output_socket = 5001

    # Simulates data diode between Rx.py on left, NH.py on right.
    elif str(sys.argv[1]) == "nhrxlr":
        nh_rx_lr = True
        input_socket = 5002
        output_socket = 5003

    # Simulates data diode between Rx.py on right, NH.py on left.
    elif str(sys.argv[1]) == "nhrxrl":
        nh_rx_rl = True
        input_socket = 5002
        output_socket = 5003

    else:
        os.system("clear")
        print("\nUsage: python dd.py {txnh{lr,rl}, nhrx{lr,rl}\n")
        exit()

except IndexError:
    os.system("clear")
    print("\nUsage: python dd.py {txnh{lr,rl}, nhrx{lr,rl}}\n")
    exit()

try:
    print("Waiting for socket")
    ipx_send = multiprocessing.connection.Client(("localhost", output_socket))
    print("Connection established.")
    time.sleep(0.3)
    os.system("clear")
except KeyboardInterrupt:
    exit()

exit_queue = multiprocessing.Queue()
io_queue = multiprocessing.Queue()

txp = multiprocessing.Process(target=tx_process)
rxp = multiprocessing.Process(target=rx_process)

txp.start()
rxp.start()

try:
    while True:
        if not exit_queue.empty():
            command = exit_queue.get()
            if command == "exit":
                txp.terminate()
                rxp.terminate()
                exit()
        time.sleep(0.01)

except KeyboardInterrupt:
    txp.terminate()
    rxp.terminate()
    exit()
