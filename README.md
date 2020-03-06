<img align="right" src="https://cs.helsinki.fi/u/oottela/tfc_logo.png" style="position: relative; top: 0; left: 0;">

### Tinfoil Chat

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.7](https://img.shields.io/badge/python-3.7-informational.svg)](https://www.python.org/downloads/release/python-370/)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Build Status](https://travis-ci.org/maqp/tfc.svg?branch=master)](https://travis-ci.org/maqp/tfc) 
[![Coverage Status](https://coveralls.io/repos/github/maqp/tfc/badge.svg?branch=master)](https://coveralls.io/github/maqp/tfc?branch=master)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/71fa9cc1da424f52a576a04c2722da26)](https://www.codacy.com/manual/maqp/tfc?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=maqp/tfc&amp;utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/maqp/tfc/badge)](https://www.codefactor.io/repository/github/maqp/tfc)
[![Requirements Status](https://requires.io/github/maqp/tfc/requirements.svg?branch=master)](https://requires.io/github/maqp/tfc/requirements/?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/maqp/tfc/badge.svg)](https://snyk.io/test/github/maqp/tfc)

Tinfoil Chat (TFC) is a
[FOSS](https://www.gnu.org/philosophy/free-sw.html)+[FHD](https://www.gnu.org/philosophy/free-hardware-designs.en.html)
[peer-to-peer](https://en.wikipedia.org/wiki/Peer-to-peer)
messaging system that relies on high assurance hardware architecture to protect users from
[passive collection](https://en.wikipedia.org/wiki/Upstream_collection), 
[MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
and most importantly,
[remote key exfiltration](https://www.youtube.com/watch?v=3euYBPlX9LM). 
TFC is designed for people with one of the most complex threat models: organized crime 
groups and nation state hackers who bypass end-to-end encryption of traditional secure 
messaging apps by hacking the endpoint.


#### State-of-the-art cryptography

TFC uses
[XChaCha20](https://cr.yp.to/chacha/chacha-20080128.pdf)-[Poly1305](https://cr.yp.to/mac/poly1305-20050329.pdf)
[end-to-end encryption](https://en.wikipedia.org/wiki/End-to-end_encryption)
with
[deniable authentication](https://en.wikipedia.org/wiki/Deniable_encryption#Deniable_authentication)
to protect all messages and files sent to individual recipients and groups. 
The symmetric keys are either
[pre-shared](https://en.wikipedia.org/wiki/Pre-shared_key),
or exchanged using
[X448](https://eprint.iacr.org/2015/625.pdf),
the base-10
[fingerprints](https://en.wikipedia.org/wiki/Public_key_fingerprint)
of which are verified via an out-of-band channel. TFC provides per-message
[forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)
with
[BLAKE2b](https://blake2.net/blake2.pdf) 
based
[hash ratchet](https://www.youtube.com/watch?v=9sO2qdTci-s#t=1m34s).
All persistent user data is encrypted locally using XChaCha20-Poly1305, the key 
of which is derived from password and salt using 
[Argon2id](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf),
the parameters of which are automatically tuned according to best 
practices. Key generation of TFC relies on Linux kernel's 
[getrandom()](https://manpages.debian.org/testing/manpages-dev/getrandom.2.en.html),
a syscall for its ChaCha20 based 
[CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).


#### Anonymous by design
TFC routes all communication exclusively through the 
[Tor](https://2019.www.torproject.org/about/overview.html.en) 
anonymity network. It uses the next generation
([v3](https://trac.torproject.org/projects/tor/wiki/doc/NextGenOnions))
[Tor Onion Services](https://2019.www.torproject.org/docs/onion-services)
to enable P2P communication that never exits the Tor network. This makes it hard for the 
users to accidentally deanonymize themselves. It also means that unlike (de)centralized 
messengers, there's no third party server with access to user metadata such as who is 
talking to whom, when, and how much. The network architecture means TFC runs exclusively 
on the user's devices. There are no ads or tracking, and it collects no data whatsoever 
about the user. All data is always encrypted with keys the user controls, and the 
databases never leave the user's device.

Using Onion Services also means no account registration is needed. During the first launch 
TFC generates a random TFC account (an Onion Service address) for the user, e.g.
`4sci35xrhp2d45gbm3qpta7ogfedonuw2mucmc36jxemucd7fmgzj3ad`. By knowing this TFC account, 
anyone can send the user a contact request and talk to them without ever learning their 
real life identity, IP-address, or geolocation. Protected geolocation makes physical 
attacks very difficult because the attacker doesn't know where the device is located on 
the planet. At the same time it makes the communication censorship resistant: Blocking TFC 
requires blocking Tor categorically, nation-wide.

TFC also features a traffic masking mode that hides the type, quantity, and schedule of 
communication, even if the network facing device of the user is hacked. To provide even
further metadata protection from hackers, the Internet-facing part of TFC can be run on 
[Tails](https://tails.boum.org/), a privacy and anonymity focused operating system that 
contains no personal files of the user (which makes it hard to deduce to whom the endpoint
belongs to), and that provides 
[additional layers of protection](https://github.com/Whonix/onion-grater)
for their anonymity.


#### First messaging system with endpoint security

TFC is designed to be used in hardware configuration that provides strong
[endpoint security](https://en.wikipedia.org/wiki/Endpoint_security).
This configuration uses three computers per endpoint: Encryption and decryption processes
are separated from each other onto two isolated computers, the Source Computer, and the 
Destination Computer. These two devices are are dedicated for TFC. This split 
[TCB](https://en.wikipedia.org/wiki/Trusted_computing_base)
interacts with the network via the user's daily computer, called the Networked Computer.

In TFC data moves from the Source Computer to the Networked Computer, and from the Networked 
Computer to the Destination Computer, unidirectionally. The unidirectionality of data
flow is enforced, as the data is passed from one device to another only through a free 
hardware design
[data diode](https://en.wikipedia.org/wiki/Unidirectional_network), 
that is connected to the three computers using one USB-cable per device.
The Source and Destination Computers are not connected to the Internet, or to any device 
other than the data diode.


![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/data_diode.jpg)
[TFC data diode](https://www.cs.helsinki.fi/u/oottela/wiki/readme/data_diode.jpg)

Optical repeater inside the
[optocouplers](https://en.wikipedia.org/wiki/Opto-isolator)
of the data diode enforce direction of data transmission with the fundamental laws of 
physics. This protection is so strong, the certified implementations of data diodes are 
typically found in critical infrastructure protection and government networks where the
classification level of data varies between systems. A data diode might e.g. allow access 
to a nuclear power plant's safety system readings, while at the same time preventing 
attackers from exploiting these critical systems. An alternative use case is to allow 
importing data from less secure systems to ones that contain classified documents that 
must be protected from exfiltration.

In TFC the hardware data diode ensures that neither of the TCB-halves can be accessed 
bidirectionally. Since the protection relies on physical limitations of the hardware's
capabilities, no piece of malware, not even a 
[zero-day exploit](https://en.wikipedia.org/wiki/Zero-day_(computing))
can bypass the security provided by the data diode.


### How it works

With the hardware in place, all that's left for the users to do is launch the device 
specific TFC program on each computer.

![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/overview.png)
[System overview](https://www.cs.helsinki.fi/u/oottela/wiki/readme/overview.png)

In the illustration above, Alice enters messages and commands to Transmitter Program 
running on her Source Computer. The Transmitter Program encrypts and signs plaintext 
data and relays the ciphertexts from Source Computer to her Networked Computer 
through the data diode.

Relay Program on Alice's Networked Computer relays commands and copies of outgoing 
messages to her Destination Computer via the data diode. Receiver Program on Alice's 
Destination Computer authenticates, decrypts and processes the received message/command.

Alice's Relay Program shares messages and files to Bob over a Tor Onion Service. 
The web client of Bob's Relay Program fetches the ciphertext from Alice's Onion 
Service and forwards it to his Destination Computer through his data diode. Bob's 
Receiver Program then authenticates, decrypts and processes the received message/file.

When Bob responds, he will type his message to the Transmitter Program on his Source 
Computer, and after a mirrored process, Alice reads the message from the Receiver Program
on her Destination Computer.


### Why keys and plaintexts cannot be exfiltrated

The architecture described above simultaneously utilizes both
[the classical and the alternative data diode models](https://en.wikipedia.org/wiki/Unidirectional_network#Applications) 
to enable bidirectional communication between two users, while at the same time providing 
hardware enforced endpoint security: 

1. The Destination Computer uses the classical data diode model. This means it can receive 
data from the insecure Networked Computer, but is unable to send data back to the Networked 
Computer. The Receiver Program is designed to function under these constraints. However,
even though the program authenticates and validates all incoming data, it is not ruled out 
malware couldn't still infiltrate the Destination Computer. However, in the event that 
would happen, the malware would be unable to exfiltrate sensitive keys or plaintexts back 
to the Networked Computer, as the data diode prevents all outbound traffic.

2. The Source Computer uses the alternative data diode model. This means it can output
encrypted data to the insecure Networked Computer without having to worry about being
compromised: The data diode protects the Source Computer from all attacks by physically
preventing all inbound traffic. The Transmitter Program is also designed to work under
the data flow constraints introduced by the data diode; To allow key exchanges, the short 
elliptic-curve public keys are input manually by the user. 

3. The Networked Computer is designed under the assumption it can be compromised by a
remote attacker: All sensitive data that passes through the Relay Program is encrypted and 
signed with no exceptions. Since the attacker is unable to exfiltrate decryption keys from 
the Source or Destination Computer, the ciphertexts are of no value to the attacker. 


![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/attacks.png)
[Exfiltration security](https://www.cs.helsinki.fi/u/oottela/wiki/readme/attacks.png)


### Qubes-isolated intermediate solution

For some users the
[APTs](https://en.wikipedia.org/wiki/Advanced_persistent_threat) 
of the modern world are not part of the threat model, and for others, the 
requirement of having to build the data diode by themselves is a deal breaker. Yet, for 
all of them, storing private keys on a networked device is still a security risk.

To meet these users' needs, TFC can also be run in three dedicated 
[Qubes](https://www.qubes-os.org/)
virtual machines. With the Qubes configuration, the isolation is provided by the 
[Xen hypervisor](https://xenproject.org/users/security/), 
and the unidirectionality of data flow between the VMs is enforced with strict firewall 
rules. This intermediate isolation mechanism runs on a single computer which means no 
hardware data diode is needed. 


### Supported Operating Systems

#### Source/Destination Computer
- Debian 10
- PureOS 9.0
- *buntu 19.10
- LMDE 4
- Qubes 4 (Debian 10 VM)

#### Networked Computer
- Tails 4.0
- Debian 10
- PureOS 9.0
- *buntu 19.10
- LMDE 4
- Qubes 4 (Debian 10 VM)


### More information
[Threat model](https://github.com/maqp/tfc/wiki/Threat-model)<br>
[FAQ](https://github.com/maqp/tfc/wiki/FAQ)<br>
[Security design](https://github.com/maqp/tfc/wiki/Security-design)<br>

Hardware Data Diode<Br>
&nbsp;&nbsp;&nbsp;&nbsp;[Breadboard version](https://github.com/maqp/tfc/wiki/TTL-Data-Diode-(breadboard)) (Easy)<br> 
&nbsp;&nbsp;&nbsp;&nbsp;[Perfboard version](https://github.com/maqp/tfc/wiki/TTL-Data-Diode-(perfboard)) (Intermediate)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[PCB version](https://github.com/maqp/tfc/wiki/TTL-Data-Diode-(PCB)) (Advanced)<br>

How to use<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Installation](https://github.com/maqp/tfc/wiki/Installation)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Master password setup](https://github.com/maqp/tfc/wiki/Master-Password)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Local key setup](https://github.com/maqp/tfc/wiki/Local-Key-Setup)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Onion Service setup](https://github.com/maqp/tfc/wiki/Onion-Service-Setup)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[X448 key exchange](https://github.com/maqp/tfc/wiki/X448)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Pre-shared keys](https://github.com/maqp/tfc/wiki/PSK)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Commands](https://github.com/maqp/tfc/wiki/Commands)<br>

[Update log](https://github.com/maqp/tfc/wiki/Update-Log)<br>
