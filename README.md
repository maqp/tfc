<img align="right" src="https://cs.helsinki.fi/u/oottela/tfclogo.png" style="position: relative; top: 0; left: 0;">

### Tinfoil Chat

[![Build Status](https://travis-ci.org/maqp/tfc.svg?branch=master)](https://travis-ci.org/maqp/tfc) 
[![Coverage Status](https://coveralls.io/repos/github/maqp/tfc/badge.svg?branch=master)](https://coveralls.io/github/maqp/tfc?branch=master)

Tinfoil Chat (TFC) is a 
[FOSS](https://www.gnu.org/philosophy/free-sw.html)+[FHD](https://www.gnu.org/philosophy/free-hardware-designs.en.html) 
messaging system that relies on high assurance hardware architecture to protect 
users from
[passive eavesdropping](https://en.wikipedia.org/wiki/Upstream_collection), 
[active MITM attacks](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
and
[remote exfiltration](https://www.youtube.com/watch?v=3euYBPlX9LM) 
(=hacking) practised by organized crime and nation state actors.

##### State-of-the-art cryptography
TFC uses
[XChaCha20](https://cr.yp.to/chacha/chacha-20080128.pdf)-[Poly1305](https://cr.yp.to/mac/poly1305-20050329.pdf)
[end-to-end encryption](https://en.wikipedia.org/wiki/End-to-end_encryption)
with
[deniable authentication](https://en.wikipedia.org/wiki/Deniable_encryption#Deniable_authentication).
The symmetric keys are either
[pre-shared](https://en.wikipedia.org/wiki/Pre-shared_key),
or exchanged using
[X448](https://eprint.iacr.org/2015/625.pdf),
the base-10
[fingerprints](https://en.wikipedia.org/wiki/Public_key_fingerprint)
of which are verified via out-of-band channel. TFC provides per-message
[forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)
with
[BLAKE2b](https://blake2.net/blake2.pdf) 
based
[hash ratchet](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm).
All persistent user data is encrypted locally using XChaCha20-Poly1305, the key 
of which is derived from password and salt using 
[Argon2d](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf). 
Key generation of TFC relies on Linux kernel's 
[getrandom()](https://manpages.debian.org/testing/manpages-dev/getrandom.2.en.html),
a syscall for its ChaCha20 based CSPRNG.

##### First messaging system with endpoint security
The software is used in hardware configuration that provides strong
[endpoint security](https://en.wikipedia.org/wiki/Endpoint_security):
Encryption and decryption are separated on two isolated computers. The split
[TCB](https://en.wikipedia.org/wiki/Trusted_computing_base)
interacts with a third, Networked Computer, through unidirectional
[serial](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter) 
interfaces. The direction of data flow is enforced with free hardware design
[data diodes](https://en.wikipedia.org/wiki/Unidirectional_network), 
technology the certified implementations of which are typically found in 
critical infrastructure protection and government networks where classification 
level of data varies.

##### Anonymous by design
TFC routes all communication through next generation
[Tor](https://www.torproject.org/about/overview.html.en)
([v3](https://trac.torproject.org/projects/tor/wiki/doc/NextGenOnions))
[Onion Services](https://www.torproject.org/docs/onion-services) 
to hide metadata about real-life identity and geolocation of users, when and how 
much they communicate, the social graph of the users and the fact TFC is 
running. TFC also features a traffic masking mode that hides the type, quantity,
and schedule of communication, even if the Networked Computer is compromised.


### How it works

![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/how_it_works.png)
[System overview](https://www.cs.helsinki.fi/u/oottela/wiki/readme/how_it_works.png)

TFC uses three computers per endpoint: Source Computer, Networked Computer, and 
Destination Computer.

Alice enters messages and commands to Transmitter Program running on her Source 
Computer. Transmitter Program encrypts and signs plaintext data and relays the 
ciphertexts from Source Computer to her Networked Computer through a serial 
interface and a hardware data diode.

Relay Program on Alice's Networked Computer relays commands and copies of 
outgoing messages to her Destination Computer via the serial interface and data 
diode. Receiver Program on Alice's Destination Computer authenticates, decrypts 
and processes the received message/command.

Alice's Relay Program shares messages and files to Bob over Tor Onion Service. 
The web client of Bob's Relay Program fetches the ciphertext from Alice's Onion 
Service and forwards it to his Destination Computer (again through a serial 
interface and data diode). Bob's Receiver Program then authenticates, decrypts 
and processes the received message/file.

When Bob responds, he will type his message to his Source Computer, and after a 
mirrored process, Alice reads the message from her Destination Computer.


### Why keys and plaintexts cannot be exfiltrated

TFC is designed to combine the 
[classical and alternative data diode models](https://en.wikipedia.org/wiki/Unidirectional_network#Applications) 
to provide hardware enforced endpoint security: 

1. The Destination Computer uses the classical data diode model. It is designed 
to receive data from the insecure Networked Computer while preventing the export 
of any data back to the Networked Computer. Not even malware on Destination 
Computer can exfiltrate keys or plaintexts as the data diode prevents all 
outbound traffic.

2. The Source Computer uses the alternative data diode model that is designed to 
allow the export of data to the Networked Computer. The data diode protects the 
Source Computer from attacks by physically preventing all inbound traffic. To 
allow key exchanges, the short elliptic-curve public keys are input manually by 
the user.

3. The Networked Computer is assumed to be compromised. All sensitive data that 
passes through it is encrypted and signed with no exceptions.

![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/attacks.png)
[Exfiltration security](https://www.cs.helsinki.fi/u/oottela/wiki/readme/attacks.png)

#### Data diode
Optical repeater inside the
[optocouplers](https://en.wikipedia.org/wiki/Opto-isolator)
of the data diode (below) enforce direction of data transmission with the 
fundamental laws of physics.

![](https://www.cs.helsinki.fi/u/oottela/wiki/readme/readme_dd.jpg)
[TFC data diode](https://www.cs.helsinki.fi/u/oottela/wiki/readme/readme_dd.jpg)


### Supported Operating Systems

#### Source/Destination Computer
- *buntu 18.04 (or newer)

#### Networked Computer
- Tails (Debian Buster or newer)
- *buntu 18.04 (or newer)


### More information
[Threat model](https://github.com/maqp/tfc/wiki/Threat-model)<br>
[FAQ](https://github.com/maqp/tfc/wiki/FAQ)<br>
[Security design](https://github.com/maqp/tfc/wiki/Security-design)<br>

Hardware<Br>
&nbsp;&nbsp;&nbsp;&nbsp;[Data diode (breadboard)](https://github.com/maqp/tfc/wiki/TTL-Data-Diode-(breadboard))<br>
&nbsp;&nbsp;&nbsp;&nbsp;[Data diode (perfboard)](https://github.com/maqp/tfc/wiki/TTL-Data-Diode-(perfboard))<br>

Software<Br>
&nbsp;&nbsp;&nbsp;&nbsp;[Installation](https://github.com/maqp/tfc/wiki/Installation)<br>
&nbsp;&nbsp;&nbsp;&nbsp;[How to use](https://github.com/maqp/tfc/wiki/How-to-use)<br>

[Update log](https://github.com/maqp/tfc/wiki/Update-Log)<br>
