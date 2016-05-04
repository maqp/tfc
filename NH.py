#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || NH.py

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

import argparse
import binascii
import curses
import datetime
import dbus.exceptions
import dbus.mainloop.qt
import dbus
import fcntl
import multiprocessing.connection
import multiprocessing
import os
import random
import serial
import struct
import sys
import termios
import time

from PyQt4.QtGui import QApplication
from serial.serialutil import SerialException

# Import crypto libraries
import hashlib

str_version = "0.16.05"
int_version = 1605


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

# UI settings
t_fmt = "%m-%d / %H:%M:%S"  # Format of timestamps when displaying messages

startup_banner = True       # False disables the animated startup banner


# Local Testing
local_testing = False       # True enables testing of TFC on a single computer

dd_sockets = False          # True changes sockets for data diode simulator

output_pidgin = True        # False stops sending messages to Pidgin


# Serial port settings
baud_rate = 9600            # The serial interface speed

checksum_len = 8            # Data diode error detection rate. 8 hex = 32-bit

txm_usb_adapter = True      # False = Use integrated serial interface for TxM

rxm_usb_adapter = True      # False = Use integrated serial interface for RxM


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):

    def __init__(self, function_name, error_message):
        os.system("clear")
        print("\nERROR: M(%s): %s\n" % (function_name, error_message))
        graceful_exit(queue=True)


class FunctionParameterTypeError(Exception):

    def __init__(self, function_name):
        os.system("clear")
        print("\nERROR: M(%s): Wrong input type.\n" % function_name)
        graceful_exit(queue=True)


###############################################################################
#                                   HELPERS                                   #
###############################################################################

def phase(string, dist):
    """
    Print name of next phase. Next message (about completion), printed after
    the phase will be printed on same line as the name specified by 'string'
    at same distance regardless of leading newlines.

    :param string: String to be printed.
    :param dist:   Indentation of completion message.
    :return:       None
    """

    if not isinstance(string, str) or not isinstance(dist, (int, long)):
        raise FunctionParameterTypeError("phase")

    n = 0
    for i in range(len(string)):
        if string[i] == '\n':
            n += 1
        else:
            break

    spaces = (dist - len(string) + n) * ' '
    sys.stdout.write(string + spaces)
    sys.stdout.flush()

    return None


def sha2_256(message):
    """
    Generate SHA256 digest from message.

    :param message: Input to hash function.
    :return:        Hex representation of SHA256 digest.
    """

    if not isinstance(message, str):
        raise FunctionParameterTypeError("sha2_256")

    h_function = hashlib.sha256()
    h_function.update(message)
    hex_digest = binascii.hexlify(h_function.digest())

    return hex_digest


def verify_checksum(packet):
    """
    Detect transmission errors by verifying SHA256-based checksum.

    :param packet: Packet to calculate checksum for.
    :return:       True if checksum was correct, else False.
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("verify_checksum")

    chksum_pckt = packet[-checksum_len:]
    separated_p = packet[:-(checksum_len + 1)]
    chksum_calc = sha2_256(separated_p)[:checksum_len]

    if chksum_calc == chksum_pckt:
        return True
    else:
        print("\nChecksum error: Command / message was discarded.\n"
              "If error persists, check TxM data diode batteries.\n")
        return False


def graceful_exit(message='', queue=False):
    """
    Display a message and exit NH.py.

    If trickle connection is enabled, put an exit command to
    pc_queue so main loop can kill processes and exit NH.py.

    :param: message: Message to print.
    :param: queue:   Add command to pc_queue when True.
    :return:         None
    """

    if not isinstance(message, str) or not isinstance(queue, bool):
        raise FunctionParameterTypeError("graceful_exit")

    os.system("clear")

    if queue and not unittesting:
        pc_queue.put("exit|%s" % message)
        time.sleep(1)

    else:
        if message:
            print("\n%s" % message)
        print("\nExiting TFC-NaCl.\n")
        exit()


def get_tty_wh():
    """
    Get width and height of terminal.

    :return: Width and height of terminal.
    """

    def ioctl_gwin_size(fd):
        """
        No definition.

        :param fd: [no definition]
        :return:   [no definition]
        """

        return struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))

    cr = ioctl_gwin_size(0) or ioctl_gwin_size(1) or ioctl_gwin_size(2)

    return int(cr[1]), int(cr[0])


def print_banner():
    """
    Print animated startup banner.

    Style 3:
        Matrix-Curses - See how deep the rabbit hole goes.
        Copyright (c) 2012 Tom Wallroth
        http://github.com/devsnd/matrix-curses/

        Used and modified under GNU GPL version 3

    :return: None
    """

    string = "Tinfoil Chat NaCl %s" % str_version

    os.system("clear")
    width, height = get_tty_wh()

    print(((height / 2) - 1) * '\n')

    # Style 1
    animation = random.randint(1, 3)
    if animation == 1:
        i = 0
        while i <= len(string):
            sys.stdout.write("\x1b[1A" + ' ')
            sys.stdout.flush()

            if i == len(string):
                print(((width - len(string)) / 2) * ' ' + string[:i])
            else:
                rc = chr(random.randrange(32, 126))
                print(((width - len(string)) / 2) * ' ' + string[:i] + rc)

            i += 1
            time.sleep(0.03)

    # Style 2
    if animation == 2:
        char_l = len(string) * ['']

        while True:
            sys.stdout.write("\x1b[1A" + ' ')
            sys.stdout.flush()
            st = ''

            for i in range(len(string)):
                if char_l[i] != string[i]:
                    char_l[i] = chr(random.randrange(32, 126))
                else:
                    char_l[i] = string[i]
                st += char_l[i]

            print(((width - len(string)) / 2) * ' ' + st)

            time.sleep(0.004)
            if st == string:
                break

    # Style 3
    if animation == 3:

        dropping_chars = 50
        random_cleanup = 80
        min_speed = 3
        max_speed = 7
        sleep_ms = 0.005

        scroll_chars = ''
        for a in range(32, 126):
            scroll_chars += chr(a)

        class FChar(object):

            list_chr = list(scroll_chars)
            normal_attr = curses.A_NORMAL
            highlight_attr = curses.A_REVERSE

            def __init__(self, o_width, speed_min, speed_max):
                self.x = 0
                self.y = 0
                self.speed = 1
                self.char = ' '
                self.offset = randint(0, self.speed)
                self.reset(o_width, speed_min, speed_max)
                self.completed = []

            def reset(self, c_width, speed_min, speed_max):
                self.char = random.choice(FChar.list_chr)
                self.x = randint(1, c_width - 1)
                self.y = 0
                self.speed = randint(speed_min, speed_max)
                self.offset = randint(0, self.speed)

            def get_completed(self):
                return self.completed

            def tick(self, scr, steps):
                win_h, win_w = scr.getmaxyx()
                if self.advances(steps):

                    # If window was re-sized and char is out of bounds, reset
                    self.out_of_bounds_reset(win_w, win_h)

                    # Make previous char curses.A_NORMAL
                    scr.addstr(self.y, self.x, self.char, curses.A_NORMAL)

                    # Choose new char and draw it A_NORMAL if not out of bounds
                    self.y += 1
                    if self.y == win_h / 2:
                        indent_len = (win_w - len(string)) / 2
                        prepended_ind = (indent_len * ' ')
                        final_string = prepended_ind + string + ' '

                        if self.x > indent_len - 1:
                            try:
                                self.char = final_string[self.x]
                                self.completed.append(self.x)
                            except IndexError:
                                self.char = random.choice(FChar.list_chr)
                    else:
                        self.char = random.choice(FChar.list_chr)

                    if not self.out_of_bounds_reset(win_w, win_h):
                        scr.addstr(self.y, self.x, self.char, curses.A_NORMAL)

            def out_of_bounds_reset(self, win_w, win_h):
                if self.x > win_w - 2:
                    self.reset(win_w, min_speed, max_speed)
                    return True
                if self.y > win_h - 2:
                    self.reset(win_w, min_speed, max_speed)
                    return True
                return False

            def advances(self, steps):
                if steps % (self.speed + self.offset) == 0:
                    return True
                return False

        # Use insecure but fast PRNG
        def rand():
            p = random.randint(0, 1000000000)
            while True:
                p ^= (p << 21) & 0xffffffffffffffff
                p ^= (p >> 35)
                p ^= (p << 4) & 0xffffffffffffffff
                yield p

        def randint(_min, _max):
            n = r.next()
            return (n % (_max - _min)) + _min

        def main():
            steps = 0
            scr = curses.initscr()
            scr.nodelay(1)
            curses.curs_set(0)
            curses.noecho()

            win_h, win_w = scr.getmaxyx()

            if win_w < len(string):
                raise KeyboardInterrupt

            window_animation = None
            lines = []

            for _ in range(dropping_chars):
                fc = FChar(win_w, min_speed, max_speed)
                fc.y = randint(0, win_h - 2)
                lines.append(fc)

            scr.refresh()
            completion = []
            delay = 0

            while True:
                win_h, win_w = scr.getmaxyx()

                for line in lines:
                    line.tick(scr, steps)
                    completed = line.get_completed()
                    for c in completed:
                        if c not in completion:
                            completion.append(c)

                if len(completion) >= len(string):
                    if delay > 600:
                        raise KeyboardInterrupt
                    else:
                        delay += 1

                for _ in range(random_cleanup):
                    x = randint(0, win_w - 1)
                    y = randint(0, win_h - 1)

                    indent_len = (win_w - len(string)) / 2
                    prepended_ind = (indent_len * ' ')

                    if y == win_h / 2:
                        if x < len(prepended_ind):
                            scr.addstr(y, x, ' ')
                        if x > len(prepended_ind + string):
                            scr.addstr(y, x, ' ')
                    else:
                        scr.addstr(y, x, ' ')

                if window_animation is not None:
                    if not window_animation.tick(scr, steps):
                        window_animation = None

                scr.refresh()
                time.sleep(sleep_ms)
                steps += 1
        try:
            r = rand()
            main()
        except KeyboardInterrupt:
            curses.endwin()
            curses.curs_set(1)
            curses.reset_shell_mode()
            curses.echo()
            os.system("clear")

    time.sleep(0.3)
    os.system("clear")
    return None


def get_serial_interfaces():
    """
    Depending on NH.py settings, determine correct serial interfaces.

    :return: tx_if: Serial interface that connects to TxM.
             rx_if: Serial interface that connects to RxM.
    """

    dev_files = [df for df in os.listdir("/dev/")]
    dev_files.sort()

    tx_if = ''
    rx_if = ''

    if txm_usb_adapter and not rxm_usb_adapter:

        adapters = []
        for dev_file in dev_files:
            if dev_file.startswith("ttyUSB"):
                adapters.append(dev_file)
                break

        tx_if = "/dev/%s" % adapters[0]
        rx_if = "/dev/ttyS0"

    if rxm_usb_adapter and not txm_usb_adapter:

        adapters = []
        for dev_file in dev_files:
            if dev_file.startswith("ttyUSB"):
                adapters.append(dev_file)
                break

        tx_if = "/dev/ttyS0"
        rx_if = "/dev/%s" % adapters[0]

    if txm_usb_adapter and rxm_usb_adapter:

        adapters = []
        for dev_file in dev_files:
            if dev_file.startswith("ttyUSB"):
                adapters.append(dev_file)

        adapters.sort()

        if not adapters:
            graceful_exit("Error: No USB-serial adapters were not found.")

        if len(adapters) < 2:
            graceful_exit("Error: Settings require two USB-serial adapters.")

        tx_if = "/dev/%s" % adapters[0]
        rx_if = "/dev/%s" % adapters[1]

    if not txm_usb_adapter and not rxm_usb_adapter:

        s0_found = False
        s1_found = False
        for dev_file in dev_files:
            if dev_file.startswith("ttyS0"):
                s0_found = True
            if dev_file.startswith("ttyS1"):
                s1_found = True

        if s0_found:
            tx_if = "/dev/ttyS0"
        else:
            graceful_exit("Error: /dev/ttyS0 not found.")

        if s1_found:
            rx_if = "/dev/ttyS1"
        else:
            graceful_exit("Error: /dev/ttyS1 not found.")

    return tx_if, rx_if


###############################################################################
#                                   RECEIVER                                  #
###############################################################################

def dbus_receiver():
    """
    Start Qt loop that loads messages from Pidgin.

    :return: [no return value]
    """

    dbus.mainloop.qt.DBusQtMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    bus.add_signal_receiver(pidgin_to_rxm_queue,
                            dbus_interface="im.pidgin.purple.PurpleInterface",
                            signal_name="ReceivedImMsg")


def pidgin_to_rxm_queue(account, sender, message, conversation, flags):
    """
    Load message from Pidgin. Put it to queue.

    :param account:      Account ID.
    :param sender:       Sender account address.
    :param message:      Message from sender.
    :param conversation: Conversation ID.
    :param flags:        Flags.
    :return:             [no return value]
    """

    # Clear PEP8 warning
    test = False
    if test:
        print(account, conversation, flags)

    sender = sender.split('/')[0]
    tstamp = datetime.datetime.now().strftime(t_fmt)

    if message.startswith("TFC|N|%s|P|" % int_version):
        to_rxm = str("%s|rx.%s" % (message, sender))  # Unicode to string conv.
        print("%s - pub key %s > RxM" % (tstamp, sender))
        packet_to_rxm.put(to_rxm)

    if message.startswith("TFC|N|%s|M|" % int_version):
        to_rxm = str("%s|rx.%s" % (message, sender))
        print("%s - message %s > RxM" % (tstamp, sender))
        packet_to_rxm.put(to_rxm)


def pidgin_receiver_process():
    """
    Start QApplication as a separate process.

    :return: [no return value]
    """

    try:
        app = QApplication(sys.argv)
        dbus_receiver()
        app.exec_()
    except dbus.exceptions.DBusException:
        pass


###############################################################################
#                                    OTHER                                    #
###############################################################################

def header_printer_process():
    """
    Print NH.py headers.

    :return: [no return value]
    """

    try:
        bus = dbus.SessionBus()
        obj = bus.get_object("im.pidgin.purple.PurpleService",
                             "/im/pidgin/purple/PurpleObject")
        purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
        active = purple.PurpleAccountsGetAllActive()[0]
        acco_u = purple.PurpleAccountGetUsername(active)[:-1]

        print("TFC-NaCl %s | NH.py\n" % str_version)
        print("Active account: %s\n" % acco_u)

    except dbus.exceptions.DBusException:
        raise CriticalError("header_printer_process", "DBusException. Ensure "
                                                      "Pidgin is running.")


def nh_side_command_process():
    """
    Execute command (clear screen or exit) on NH.

    :return: [no return value]
    """

    bus = dbus.SessionBus()
    obj = bus.get_object("im.pidgin.purple.PurpleService",
                         "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    account = purple.PurpleAccountsGetAllActive()[0]

    while True:
        if nh_side_command.empty():
            time.sleep(0.001)
            continue

        cmd = nh_side_command.get()

        if cmd.startswith("TFC|N|%s|U|CLEAR|" % int_version):
            contact = cmd.split('|')[5]
            new_conv = purple.PurpleConversationNew(1, account, contact)
            purple.PurpleConversationClearMessageHistory(new_conv)
            os.system("clear")


def queue_to_pidgin_process():
    """
    Send message from queue to Pidgin.

    :return: [no return value]
    """

    bus = dbus.SessionBus()
    obj = bus.get_object("im.pidgin.purple.PurpleService",
                         "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    account = purple.PurpleAccountsGetAllActive()[0]

    while True:
        if message_to_pidgin.empty():
            time.sleep(0.001)
            continue

        message = message_to_pidgin.get()

        if message.startswith("TFC|N|%s|M|" % int_version):
            tfc, model, ver, pt, ct, key_id, recipient = message.split('|')
            to_pidgin = '|'.join(message.split('|')[:6])

            if output_pidgin:
                new_conv = purple.PurpleConversationNew(1, account, recipient)
                sel_conv = purple.PurpleConvIm(new_conv)
                purple.PurpleConvImSend(sel_conv, to_pidgin)

        if message.startswith("TFC|N|%s|P|" % int_version):
            tfc, model, ver, pt, pub_key, recipient = message.split('|')
            to_pidgin = '|'.join(message.split('|')[:5])

            if output_pidgin:
                new_conv = purple.PurpleConversationNew(1, account, recipient)
                sel_conv = purple.PurpleConvIm(new_conv)
                purple.PurpleConvImSend(sel_conv, to_pidgin)


def nh_to_rxm_sender_process():
    """
    Send message from queue to RxM.

    :return: [no return value]
    """

    while True:
        if packet_to_rxm.empty():
            time.sleep(0.001)
            continue

        packet = packet_to_rxm.get()
        chksum = sha2_256(packet)[:checksum_len]
        packet = "%s|%s\n" % (packet, chksum)

        if local_testing:
            ipc_rx.send(packet)
        else:
            port_to_rxm.write(packet)


###############################################################################
#                               PACKETS FROM TxM                              #
###############################################################################

def choose_txm_packet_queues(packet):
    """
    Copy message from TxM to correct queues.

    :param packet: Packet to copy.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("choose_txm_packet_queues")

    timestamp = datetime.datetime.now().strftime(t_fmt)

    if packet.startswith("TFC|N|%s|M|" % int_version):
        recipient = packet.split('|')[6]
        print("%s - message TxM > %s" % (timestamp, recipient))
        to_rxm = "%s|me.%s" % ('|'.join(packet.split('|')[:6]), recipient)
        packet_to_rxm.put(to_rxm)
        message_to_pidgin.put(packet)

    elif packet.startswith("TFC|N|%s|C|" % int_version):
        print("%s - command TxM > RxM" % timestamp)
        packet_to_rxm.put(packet)

    elif packet.startswith("TFC|N|%s|U|EXIT" % int_version):
        time.sleep(0.5)     # Time for nh_to_rxm_sender_process()
        os.system("clear")  # to send exit-packet.
        graceful_exit(queue=True)

    elif packet.startswith("TFC|N|%s|U|" % int_version):
        packet_to_rxm.put(packet)
        nh_side_command.put(packet)

    elif packet.startswith("TFC|N|%s|I|" % int_version):
        # Skip interface configuration packet
        pass

    elif packet.startswith("TFC|N|%s|P|" % int_version):
        recipient = packet.split('|')[5]
        print("%s - pub key TxM > %s" % (timestamp, recipient))
        message_to_pidgin.put(packet)

    elif packet.startswith("TFC|N|%s|L|" % int_version):
        print("%s - Local key TxM > RxM" % timestamp)
        packet_to_rxm.put(packet)

    else:
        print("Illegal packet from TxM:\n%s" % packet)

    return None


def txm_packet_load_process():
    """
    Load packet from TxM via serial port (or IPC if local_testing is enabled).

    :return: [no return value]
    """

    if local_testing:
        def ipc_to_queue(conn):
            """
            Load packet from IPC.

            :param conn: Listener object.
            :return:     [no return value]
            """

            while True:
                time.sleep(0.001)
                pkg = str(conn.recv())

                if pkg == '':
                    continue

                pkg = pkg.strip('\n')
                if not verify_checksum(pkg):
                    continue
                choose_txm_packet_queues(pkg[:-9])

        try:
            l = multiprocessing.connection.Listener(('', 5001))
            while True:
                ipc_to_queue(l.accept())
        except EOFError:
            graceful_exit("TxM <> NH IPC disconnected.", queue=True)

    else:
        while True:
            time.sleep(0.001)
            packet = port_to_txm.readline()

            if packet == '':
                continue

            packet = packet.strip('\n')
            if not verify_checksum(packet):
                continue
            choose_txm_packet_queues(packet[:-9])


def rxm_port_listener():
    """
    Process that waits for packets from RxM interface during initial serial
    interface configuring.

    :return: [no return value]
    """

    while True:
        data = port_to_rxm.readline()
        if data:
            configure_queue.put("FLIP")
        time.sleep(0.001)


def txm_port_listener():
    """
    Process that waits for packets from TxM interface during initial serial
    interface configuring.

    :return: [no return value]
    """

    while True:
        data = port_to_txm.readline()
        if data:
            configure_queue.put("OK")
        time.sleep(0.001)


def process_arguments():
    """
    Define NH.py settings from arguments passed from command line.

    :return: None
    """

    parser = argparse.ArgumentParser("python NH.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside NH.py")

    parser.add_argument("-p",
                        action="store_true",
                        default=False,
                        dest="quiet",
                        help="do not output messages to Pidgin")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="local",
                        help="enable local testing mode")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="ddsockets",
                        help="enable data diode simulator sockets")

    args = parser.parse_args()

    global dd_sockets
    global output_pidgin
    global local_testing

    if args.ddsockets:
        dd_sockets = True

    if args.quiet:
        output_pidgin = False

    if args.local:
        local_testing = True


###############################################################################
#                                     MAIN                                    #
###############################################################################

unittesting = False  # Alters function input during unittesting

if __name__ == "__main__":

    process_arguments()

    if startup_banner:
        print_banner()

    # If local testing is disabled, initialize serial ports.
    if local_testing:
        if dd_sockets:
            rx_socket = 5002
        else:
            rx_socket = 5003

        try:
            phase("\nWaiting for socket from Rx.py...", 35)
            ipc_rx = multiprocessing.connection.Client(("localhost", 
                                                        rx_socket))
            print("Connection established.\n")
            time.sleep(0.5)
            os.system("clear")

        except KeyboardInterrupt:
            graceful_exit()

    else:
        serial_tx, serial_rx = get_serial_interfaces()

        try:
            port_to_txm = serial.Serial(serial_tx, baud_rate, timeout=0.1)
            port_to_rxm = serial.Serial(serial_rx, baud_rate, timeout=0.1)

        except SerialException:
            graceful_exit("Error: Serial interfaces are set incorrectly.")

        # Auto configure NH side serial ports
        phase("Waiting for configuration packet from TxM...", 46)

        configure_queue = multiprocessing.Queue()
        tl = multiprocessing.Process(target=txm_port_listener)
        rl = multiprocessing.Process(target=rxm_port_listener)
        tl.start()
        rl.start()

        try:
            while True:
                time.sleep(0.001)
                if not configure_queue.empty():
                    command = configure_queue.get()

                    if command == "FLIP":
                        port_to_txm = serial.Serial(serial_rx, baud_rate,
                                                    timeout=0.1)
                        port_to_rxm = serial.Serial(serial_tx, baud_rate,
                                                    timeout=0.1)
                        print("Interfaces flipped.\n")
                        tl.terminate()
                        rl.terminate()
                        break

                    if command == "OK":
                        print("Interfaces OK.\n")
                        tl.terminate()
                        rl.terminate()
                        break

        except KeyboardInterrupt:
            tl.terminate()
            rl.terminate()
            graceful_exit()

    pc_queue = multiprocessing.Queue()
    packet_to_rxm = multiprocessing.Queue()
    packet_from_txm = multiprocessing.Queue()
    nh_side_command = multiprocessing.Queue()
    message_to_pidgin = multiprocessing.Queue()
    message_from_pidgin = multiprocessing.Queue()

    hp = multiprocessing.Process(target=header_printer_process)
    sm = multiprocessing.Process(target=txm_packet_load_process)
    po = multiprocessing.Process(target=queue_to_pidgin_process)
    cp = multiprocessing.Process(target=nh_side_command_process)
    nr = multiprocessing.Process(target=pidgin_receiver_process)
    rs = multiprocessing.Process(target=nh_to_rxm_sender_process)

    hp.start()
    time.sleep(0.5)  # Allow header_printer_process()
    sm.start()       # time to catch DBusException.
    po.start()
    cp.start()
    nr.start()
    rs.start()

    try:
        while True:
            if not pc_queue.empty():
                command = pc_queue.get()
                if command.startswith("exit"):
                    exit_msg = command.split('|')[1]
                    hp.terminate()
                    sm.terminate()
                    po.terminate()
                    cp.terminate()
                    nr.terminate()
                    rs.terminate()
                    graceful_exit(exit_msg)
            time.sleep(0.001)

    except KeyboardInterrupt:
        hp.terminate()
        sm.terminate()
        po.terminate()
        cp.terminate()
        nr.terminate()
        rs.terminate()
        graceful_exit()
