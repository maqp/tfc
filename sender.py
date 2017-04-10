#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

import hashlib
import serial


def sha3_256(message: bytes) -> bytes:
    """Generate SHA3-256 digest from message."""
    return hashlib.sha256(message).hexdigest()

port = serial.Serial("/dev/ttyUSB0", 9600)

data = open('install.sh', 'rb').read()

print(sha3_256(data))
port.write(data)
