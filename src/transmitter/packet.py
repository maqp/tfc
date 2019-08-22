#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import base64
import os
import typing
import zlib

from typing import Any, Dict, List, Optional, Union

from src.common.crypto     import blake2b, byte_padding, csprng, encrypt_and_sign
from src.common.encoding   import bool_to_bytes, int_to_bytes, str_to_bytes
from src.common.exceptions import CriticalError, FunctionReturn
from src.common.input      import yes
from src.common.misc       import split_byte_string
from src.common.output     import m_print, phase, print_on_previous_line
from src.common.path       import ask_path_gui
from src.common.statics    import *

from src.transmitter.files      import File
from src.transmitter.user_input import UserInput

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_keys      import KeyList
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway
    from src.transmitter.windows import TxWindow, MockWindow
    QueueDict = Dict[bytes, Queue[Any]]


def queue_to_nc(packet:   bytes,
                nc_queue: 'Queue[Any]',
                ) -> None:
    """Queue unencrypted command/exported file to Networked Computer.

    This function queues unencrypted packets intended for Relay Program
    on Networked Computer. These packets are processed in the order of
    priority by the `sender_loop` process of src.transmitter.sender_loop
    module.
    """
    nc_queue.put(packet)


def queue_command(command:  bytes,
                  settings: 'Settings',
                  queues:   'QueueDict'
                  ) -> None:
    """Split command to assembly packets and queue them for sender_loop()."""
    assembly_packets = split_to_assembly_packets(command, COMMAND)

    queue_assembly_packets(assembly_packets, COMMAND, settings, queues)


def queue_message(user_input: 'UserInput',
                  window:     Union['MockWindow', 'TxWindow'],
                  settings:   'Settings',
                  queues:     'QueueDict',
                  header:     bytes = b'',
                  whisper:    bool  = False,
                  log_as_ph:  bool  = False
                  ) -> None:
    """\
    Prepend header to message, split the message into assembly packets,
    and queue the assembly packets.

    In this function the Transmitter Program adds the headers that allow
    the recipient's Receiver Program to redirect the received message to
    the correct window.

    Each message packet starts with a 1 byte whisper-header that
    determines whether the packet should be logged by the recipient. For
    private messages no additional information aside the
    PRIVATE_MESSAGE_HEADER -- that informs the Receiver Program to use
    sender's window -- is required.

    For group messages, the GROUP_MESSAGE_HEADER tells the Receiver
    Program that the header is followed by two additional headers:

        1) 4-byte Group ID that tells to what group the message was
           intended to. If the Receiver Program has not whitelisted the
           group ID, the group message will be ignored. The group ID
           space was chosen so that the birthday bound is at 65536
           because it's unlikely a user will ever have that many groups.

        2) 16-byte group message ID. This random ID is not important for
           the recipient. Instead, it is used by the sender's Receiver
           Program to detect what group messages are copies sent to other
           members of the group (these will be ignored from ephemeral and
           persistent message log). The message ID space was chosen so
           that the birthday bound is 2^64 (the same as the hash ratchet
           counter space).

    Once the headers are determined, the message is split into assembly
    packets, that are then queued for encryption and transmission by the
    `sender_loop` process.
    """
    if not header:
        if window.type == WIN_TYPE_GROUP and window.group is not None:
            header = GROUP_MESSAGE_HEADER + window.group.group_id + os.urandom(GROUP_MSG_ID_LENGTH)
        else:
            header = PRIVATE_MESSAGE_HEADER

    payload          = bool_to_bytes(whisper) + header + user_input.plaintext.encode()
    assembly_packets = split_to_assembly_packets(payload, MESSAGE)

    queue_assembly_packets(assembly_packets, MESSAGE, settings, queues, window, log_as_ph)


def queue_file(window:   'TxWindow',
               settings: 'Settings',
               queues:   'QueueDict'
               ) -> None:
    """Ask file path and load file data.

    In TFC there are two ways to send a file.

    For traffic masking, the file is loaded and sent inside normal
    messages using assembly packet headers dedicated for file
    transmission. This transmission is much slower, so the File object
    will determine metadata about the transmission's estimated transfer
    time, number of packets and the name and size of file. This
    information is inserted to the first assembly packet so that the
    recipient can observe the transmission progress from file transfer
    window.

    When traffic masking is disabled, file transmission is much faster
    as the file is only encrypted and transferred over serial once
    before the Relay Program multi-casts the ciphertext to each
    specified recipient. See the send_file docstring (below) for more
    details.
    """
    path = ask_path_gui("Select file to send...", settings, get_file=True)

    if path.endswith(('tx_contacts', 'tx_groups', 'tx_keys', 'tx_login_data', 'tx_settings',
                      'rx_contacts', 'rx_groups', 'rx_keys', 'rx_login_data', 'rx_settings',
                      'tx_serial_settings.json', 'nc_serial_settings.json',
                      'rx_serial_settings.json', 'tx_onion_db')):
        raise FunctionReturn("Error: Can't send TFC database.", head_clear=True)

    if not settings.traffic_masking:
        send_file(path, settings, queues, window)
        return

    file             = File(path, window, settings)
    assembly_packets = split_to_assembly_packets(file.plaintext, FILE)

    if settings.confirm_sent_files:
        try:
            if not yes(f"Send {file.name.decode()} ({file.size_hr}) to {window.type_print} {window.name} "
                       f"({len(assembly_packets)} packets, time: {file.time_hr})?"):
                raise FunctionReturn("File selection aborted.", head_clear=True)
        except (EOFError, KeyboardInterrupt):
            raise FunctionReturn("File selection aborted.", head_clear=True)

    queue_assembly_packets(assembly_packets, FILE, settings, queues, window, log_as_ph=True)


def send_file(path:     str,
              settings: 'Settings',
              queues:   'QueueDict',
              window:   'TxWindow'
              ) -> None:
    """Send file to window members in a single transmission.

    This is the default mode for file transmission, used when traffic
    masking is not enabled. The file is loaded and compressed before it
    is encrypted. The encrypted file is then exported to Networked
    Computer along with a list of Onion Service public keys (members in
    window) of all recipients to whom the Relay Program will multi-cast
    the file to.

    Once the file ciphertext has been exported, this function will
    multi-cast the file decryption key to each recipient inside an
    automated key delivery message that uses a special FILE_KEY_HEADER
    in place of standard PRIVATE_MESSAGE_HEADER. To know for which file
    ciphertext the key is for, an identifier must be added to the key
    delivery message. The identifier in this case is the BLAKE2b digest
    of the ciphertext itself. The reason of using the digest as the
    identifier is, it authenticates both the ciphertext and its origin.
    To understand this, consider the following attack scenario:

    Let the file ciphertext identifier be just a random 32-byte value "ID".

    1) Alice sends Bob and Chuck (a malicious common peer) a file
       ciphertext and identifier CT|ID (where | denotes concatenation).

    2) Chuck who has compromised Bob's Networked Computer interdicts the
       CT|ID from Alice.

    3) Chuck decrypts CT in his end, makes edits to the plaintext PT to
       create PT'.

    4) Chuck re-encrypts PT' with the same symmetric key to produce CT'.

    5) Chuck re-uses the ID and produces CT'|ID.

    6) Chuck uploads the CT'|ID to Bob's Networked Computer and replaces
       the interdicted CT|ID with it.

    7) When Bob' Receiver Program receives the automated key delivery
       message from Alice, his Receiver program uses the bundled ID to
       identify the key is for CT'.

    8) Bob's Receiver decrypts CT' using the newly received key and
       obtains Chuck's PT', that appears to come from Alice.

    Now, consider a situation where the ID is instead calculated
    ID = BLAKE2b(CT), if Chuck edits the PT, the CT' will by definition
    be different from CT, and the BLAKE2b digest will also be different.
    In order to make Bob decrypt CT', Chuck needs to also change the
    hash in Alice's key delivery message, which means Chuck needs to
    create an existential forgery of the TFC message. Since the Poly1305
    tag prevents this, the calculated ID is enough to authenticate the
    ciphertext.

    If Chuck attempts to send their own key delivery message, Chuck's
    own Onion Service public key used to identify the TFC message key
    (decryption key for the key delivery message) will be permanently
    associated with the file hash, so if they inject a file CT, and Bob
    has decided to enable file reception for Chuck, the file CT will
    appear to come from Chuck, and not from Alice. From the perspective
    of Bob, it's as if Chuck had dropped Alice's file and sent him
    another file instead.
    """
    from src.transmitter.windows import MockWindow  # Avoid circular import

    if settings.traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.", head_clear=True)

    name = path.split('/')[-1]
    data = bytearray()
    data.extend(str_to_bytes(name))

    if not os.path.isfile(path):
        raise FunctionReturn("Error: File not found.", head_clear=True)

    if os.path.getsize(path) == 0:
        raise FunctionReturn("Error: Target file is empty.", head_clear=True)

    phase("Reading data")
    with open(path, 'rb') as f:
        data.extend(f.read())
    phase(DONE)
    print_on_previous_line(flush=True)

    phase("Compressing data")
    comp = bytes(zlib.compress(bytes(data), level=COMPRESSION_LEVEL))
    phase(DONE)
    print_on_previous_line(flush=True)

    phase("Encrypting data")
    file_key = csprng()
    file_ct  = encrypt_and_sign(comp, file_key)
    ct_hash  = blake2b(file_ct)
    phase(DONE)
    print_on_previous_line(flush=True)

    phase("Exporting data")
    no_contacts  = int_to_bytes(len(window))
    ser_contacts = b''.join([c.onion_pub_key for c in window])
    file_packet  = FILE_DATAGRAM_HEADER + no_contacts + ser_contacts + file_ct
    queue_to_nc(file_packet, queues[RELAY_PACKET_QUEUE])

    key_delivery_msg = base64.b85encode(ct_hash + file_key).decode()
    for contact in window:
        queue_message(user_input=UserInput(key_delivery_msg, MESSAGE),
                      window    =MockWindow(contact.onion_pub_key, [contact]),
                      settings  =settings,
                      queues    =queues,
                      header    =FILE_KEY_HEADER,
                      log_as_ph =True)
    phase(DONE)
    print_on_previous_line(flush=True)
    m_print(f"Sent file '{name}' to {window.type_print} {window.name}.")


def split_to_assembly_packets(payload: bytes, p_type: str) -> List[bytes]:
    """Split payload to assembly packets.

    Messages and commands are compressed to reduce transmission time.
    Files directed to this function during traffic masking have been
    compressed at an earlier point.

    If the compressed message cannot be sent over one packet, it is
    split into multiple assembly packets. Long messages are encrypted
    with an inner layer of XChaCha20-Poly1305 to provide sender based
    control over partially transmitted data. Regardless of packet size,
    files always have an inner layer of encryption, and it is added
    before the file data is passed to this function. Commands do not
    need sender-based control, so they are only delivered with a hash
    that makes integrity check easy.

    First assembly packet in file transmission is prepended with an
    8-byte packet counter header that tells the sender and receiver how
    many packets the file transmission requires.

    Each assembly packet is prepended with a header that tells the
    Receiver Program if the packet is a short (single packet)
    transmission or if it's the start packet, a continuation packet, or
    the last packet of a multi-packet transmission.
    """
    s_header = {MESSAGE: M_S_HEADER, FILE: F_S_HEADER, COMMAND: C_S_HEADER}[p_type]
    l_header = {MESSAGE: M_L_HEADER, FILE: F_L_HEADER, COMMAND: C_L_HEADER}[p_type]
    a_header = {MESSAGE: M_A_HEADER, FILE: F_A_HEADER, COMMAND: C_A_HEADER}[p_type]
    e_header = {MESSAGE: M_E_HEADER, FILE: F_E_HEADER, COMMAND: C_E_HEADER}[p_type]

    if p_type in [MESSAGE, COMMAND]:
        payload = zlib.compress(payload, level=COMPRESSION_LEVEL)

    if len(payload) < PADDING_LENGTH:
        padded      = byte_padding(payload)
        packet_list = [s_header + padded]

    else:
        if p_type == MESSAGE:
            msg_key = csprng()
            payload = encrypt_and_sign(payload, msg_key)
            payload += msg_key

        elif p_type == FILE:
            payload = bytes(FILE_PACKET_CTR_LENGTH) + payload

        elif p_type == COMMAND:
            payload += blake2b(payload)

        padded = byte_padding(payload)
        p_list = split_byte_string(padded, item_len=PADDING_LENGTH)

        if p_type == FILE:
            p_list[0] = int_to_bytes(len(p_list)) + p_list[0][FILE_PACKET_CTR_LENGTH:]

        packet_list = ([l_header + p_list[0]] +
                       [a_header + p for p in p_list[1:-1]] +
                       [e_header + p_list[-1]])

    return packet_list


def queue_assembly_packets(assembly_packet_list: List[bytes],
                           p_type:               str,
                           settings:             'Settings',
                           queues:               'QueueDict',
                           window:               Optional[Union['TxWindow', 'MockWindow']] = None,
                           log_as_ph:            bool                                      = False
                           ) -> None:
    """Queue assembly packets for sender_loop().

    This function is the last function on Transmitter Program's
    `input_loop` process. It feeds the assembly packets to
    multiprocessing queues along with metadata required for transmission
    and message logging. The data put into these queues is read by the
    `sender_loop` process in src.transmitter.sender_loop module.
    """
    if p_type in [MESSAGE, FILE] and window is not None:

        if settings.traffic_masking:
            queue = queues[TM_MESSAGE_PACKET_QUEUE] if p_type == MESSAGE else queues[TM_FILE_PACKET_QUEUE]
            for assembly_packet in assembly_packet_list:
                queue.put((assembly_packet, window.log_messages, log_as_ph))
        else:
            queue = queues[MESSAGE_PACKET_QUEUE]
            for c in window:
                for assembly_packet in assembly_packet_list:
                    queue.put((assembly_packet, c.onion_pub_key, window.log_messages, log_as_ph, window.uid))

    elif p_type == COMMAND:
        queue = queues[TM_COMMAND_PACKET_QUEUE] if settings.traffic_masking else queues[COMMAND_PACKET_QUEUE]
        for assembly_packet in assembly_packet_list:
            queue.put(assembly_packet)


def send_packet(key_list:        'KeyList',               # Key list object
                gateway:         'Gateway',               # Gateway object
                log_queue:       'Queue[Any]',            # Multiprocessing queue for logged messages
                assembly_packet: bytes,                   # Padded plaintext assembly packet
                onion_pub_key:   Optional[bytes] = None,  # Recipient v3 Onion Service address
                log_messages:    Optional[bool]  = None,  # When True, log the message assembly packet
                log_as_ph:       Optional[bool]  = None   # When True, log assembly packet as placeholder data
                ) -> None:
    """Encrypt and send assembly packet.

    The assembly packets are encrypted using a symmetric message key.
    TFC provides forward secrecy via a hash ratchet, meaning previous
    message key is replaced by it's BLAKE2b hash. The preimage
    resistance of the hash function prevents retrospective decryption of
    ciphertexts in cases of physical compromise.

    The hash ratchet state (the number of times initial message key has
    been passed through BLAKE2b) is delivered to recipient inside the
    hash ratchet counter. This counter is encrypted with a static
    symmetric key called the header key.

    The encrypted assembly packet and encrypted harac are prepended with
    datagram headers that tell if the encrypted assembly packet is a
    command or a message. Packets with MESSAGE_DATAGRAM_HEADER also
    contain a second header, which is the public key of the recipient's
    Onion Service. This allows the ciphertext to be requested from Relay
    Program's server by the correct contact.

    Once the encrypted_packet has been output, the hash ratchet advances
    to the next state, and the assembly packet is pushed to log_queue,
    which is read by the `log_writer_loop` process (that can be found
    at src.common.db_logs). This approach prevents IO delays caused by
    `input_loop` reading the log file from affecting the `sender_loop`
    process, which could reveal schedule information under traffic
    masking mode.
    """
    if len(assembly_packet) != ASSEMBLY_PACKET_LENGTH:
        raise CriticalError("Invalid assembly packet PT length.")

    if onion_pub_key is None:
        keyset = key_list.get_keyset(LOCAL_PUBKEY)
        header = COMMAND_DATAGRAM_HEADER
    else:
        keyset = key_list.get_keyset(onion_pub_key)
        header = MESSAGE_DATAGRAM_HEADER + onion_pub_key

    harac_in_bytes    = int_to_bytes(keyset.tx_harac)
    encrypted_harac   = encrypt_and_sign(harac_in_bytes,  keyset.tx_hk)
    encrypted_message = encrypt_and_sign(assembly_packet, keyset.tx_mk)
    encrypted_packet  = header + encrypted_harac + encrypted_message
    gateway.write(encrypted_packet)

    keyset.rotate_tx_mk()

    log_queue.put((onion_pub_key, assembly_packet, log_messages, log_as_ph, key_list.master_key))


def cancel_packet(user_input: 'UserInput',
                  window:     'TxWindow',
                  settings:   'Settings',
                  queues:     'QueueDict'
                  ) -> None:
    """Cancel sent message/file to contact/group.

    In cases where the assembly packets have not yet been encrypted or
    output to Networked Computer, the queued messages or files to active
    window can be cancelled. Any single-packet message and file this
    function removes from the queue/transfer buffer are unavailable to
    recipient. However, in the case of multi-packet transmissions, if
    only the last assembly packet is cancelled, the recipient might
    obtain large enough section of the key that protects the inner
    encryption layer to allow them to brute force the rest of the key,
    and thus, decryption of the packet. There is simply no way to
    prevent this kind of attack without making TFC proprietary and
    re-writing it in a compiled language (which is very bad for users'
    rights).
    """
    header, p_type = dict(cm=(M_C_HEADER, 'messages'),
                          cf=(F_C_HEADER, 'files'   ))[user_input.plaintext]

    if settings.traffic_masking:
        queue = queues[TM_MESSAGE_PACKET_QUEUE] if header == M_C_HEADER else queues[TM_FILE_PACKET_QUEUE]
    else:
        if header == F_C_HEADER:
            raise FunctionReturn("Files are only queued during traffic masking.", head_clear=True)
        queue = queues[MESSAGE_PACKET_QUEUE]

    cancel_pt = header + bytes(PADDING_LENGTH)
    log_as_ph = False  # Never log cancel assembly packets as placeholder data

    cancel = False
    if settings.traffic_masking:
        if queue.qsize() != 0:
            cancel = True

            # Get most recent log_messages setting status in queue
            log_messages = False
            while queue.qsize() != 0:
                log_messages = queue.get()[1]

            queue.put((cancel_pt, log_messages, log_as_ph))

        m_print(f"Cancelled queues {p_type}." if cancel else f"No {p_type} to cancel.", head=1, tail=1)

    else:
        p_buffer = []
        while queue.qsize() != 0:
            queue_data = queue.get()
            window_uid = queue_data[4]

            # Put messages unrelated to the active window into the buffer
            if window_uid != window.uid:
                p_buffer.append(queue_data)
            else:
                cancel = True

        # Put cancel packets for each window contact to queue first
        if cancel:
            for c in window:
                queue.put((cancel_pt, c.onion_pub_key, c.log_messages, log_as_ph, window.uid))

        # Put buffered tuples back to the queue
        for p in p_buffer:
            queue.put(p)

        if cancel:
            message = f"Cancelled queued {p_type} to {window.type_print} {window.name}."
        else:
            message = f"No {p_type} queued for {window.type_print} {window.name}."

        raise FunctionReturn(message, head_clear=True)
