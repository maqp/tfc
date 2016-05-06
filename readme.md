<img align="right" src="https://cs.helsinki.fi/u/oottela/tfclogo.png" style="position: relative; top: 0; left: 0;">


###Tinfoil Chat NaCl


TFC-NaCl is a high assurance encrypted messaging system that operates on top of
existing IM clients. The free and open source software is used in conjunction
with free hardware to protect users from passive eavesdropping, active MITM
attacks and remote CNE practised by organized crime and state-level adversaries.

TFC-NaCl uses XSalsa-20-Poly1305 AEAD that provides forward secrecy and
deniability. Symmetric keys are either pre-shared, or agreed using Curve25519
ECDHE key exchange.

Key generation utilizes Kernel CSPRNG, but additionally, further entropy can be
loaded from open circuit design HWRNG, that is sampled by a [RPi](https://www.raspberrypi.org/)
through it's GPIO pins either natively, or via SSH. Forward secrecy is obtained
with hash ratchet based on PBKDF2-HMAC-SHA256, where the 256-bit key is changed
after every message.

The software is used in configuration that provides strong endpoint security.
It does this by separating encryption and decryption on separate, isolated
computers, that interact with a networked computer through unidirectional
serial interfaces. Direction of data flow is enforced with open circuit design
hardware data diodes; lack of bidirectional channels prevents exfiltration of
keys and plaintexts even with exploits against zero-day vulnerabilities in
software and operating systems of TCBs.

TFC defeats metadata about quantity and schedule of communication with trickle
connection that outputs constant stream of encrypted noise data. Covert file
transfer can take place in background during the trickle connection.

TFC also supports multicasting of messages to enable basic group messaging.


###How it works

![](https://cs.helsinki.fi/u/oottela/tfc_graph2.png)

TFC uses three computers per endpoint. Alice enters her commands and messages to
program Tx.py running on her Transmitter computer (TxM), a [TCB](https://en.wikipedia.org/wiki/Trusted_computing_base)
separated from network. Tx.py encrypts and signs plaintext data and relays it
to receiver computers (RxM) via networked computer (NH) through RS-232 interface
and a data diode.

Depending on packet type, the program NH.py running on Alice's NH forwards
packets from TxM-side serial interface to Pidgin and local RxM (through another
RS-232 interface and data diode). Local RxM authenticates and decrypts received
data before processing it.

Pidgin sends the packet either directly or through Tor network to IM server,
that then forwards it directly (or again through Tor) to Bob.

NH.py on Bob's NH receives Alice's packet from Pidgin, and forwards it through
RS-232 interface and data diode to Bob's RxM, where the ciphertext is
authenticated, decrypted, and processed. When the Bob responds, he will send
the message/file using his TxM and in the end Alice reads the message from her RxM.


###Why keys can not be exfiltrated

1. Malware that exploits an unknown vulnerability in RxM can infiltrate to
the system, but is unable to exfiltrate keys or plaintexts, as data diode prevents
all outbound traffic.

2. Malware can not breach TxM as data diode prevents all inbound traffic. The
only data input from RxM to TxM is the 72 char public key, manually typed by 
user.

3. The NH is assumed to be compromised, but unencrypted data never touches it.

![](https://cs.helsinki.fi/u/oottela/tfc_attacks2.png)

Optical repeater inside the optocoupler of the data diode (below) enforces
direction of data transmission.

<img src="https://cs.helsinki.fi/u/oottela/data_diode.png" align="center" width="74%" height="74%"/>

###Supported Operating Systems

####TxM and RxM
- *buntu 16.04
- Linux Mint 17.3 Rosa
- Raspbian Jessie

####NH
- Tails 2.3
- *buntu 16.04,
- Linux Mint 17.3 Rosa
- Raspbian Jessie

###Installation
[![Installation](http://img.youtube.com/vi/D5pDoJZj2Uw/0.jpg)](http://www.youtube.com/watch?v=D5pDoJZj2Uw)


###How to use
[![Use](http://img.youtube.com/vi/tH8qbl1USoo/0.jpg)](http://www.youtube.com/watch?v=tH8qbl1USoo)


###More information

White paper and manual for previous versions are listed below. Version specific
updates are listed in the updatelog. Updated white paper and documentation are
under work.

White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf

Manual: https://cs.helsinki.fi/u/oottela/tfc-manual.pdf
