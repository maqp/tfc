#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2019  Markus Ottela
#
# This file is part of TFC.
#
# TFC is free software: you can redistribute it and/or modify it under the terms
# of the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with TFC. If not, see <https://www.gnu.org/licenses/>.


compare_digest () {
    # Compare the SHA512 digest of TFC file against the digest pinned in this installer.
    if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
    else
        echo Error: /opt/tfc/$2$3 had invalid SHA512 hash
        exit 1
    fi
}


verify_tcb_requirements_files () {
compare_digest 2191cd9f1bb40dee172ad885edb1402d3e2a961ee5ae3eda607fb84d4b60995687cb3eededb6db326ca64919077481c26f3516e9c1153c069df5ee7307aa58a7 '' requirements.txt
compare_digest d5e6ef9d3743cc81440d0f1024389ce0c10c23771f3aee95886731f1a7cbdf64fa5e0245d370382f8988d3c1758d0548e384e05635216ded3552dee80a03b16a '' requirements-venv.txt
}

verify_files () {
compare_digest f7b8c252517ec7f59d636c1290fa6083b6b90e771f3e40fc961c289bd3bae0a32497eebe4fef9f8e4cae2998bf4aa32f0022e216ce5bcfb322485143617f7b65 '' dd.py
compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
compare_digest 04bc1b0bf748da3f3a69fda001a36b7e8ed36901fa976d6b9a4da0847bb0dcaf20cdeb884065ecb45b80bd520df9a4ebda2c69154696c63d9260a249219ae68a '' LICENSE-3RD-PARTY
compare_digest f8b574dd16eb867dd43b468ac96b7fdee699dc642ad8b412b89d1e4538cc3ec46b49dc3fd6cd8e6d30d838e0f7f1955651d42d82a44450a8567053bda7b523d0 '' relay.py
compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
compare_digest 54bac0d6a9198d57a2e08c012dee46af5d34ccc6577ab834900941dcbeba36c0b3e1222acfcc76a68b3480c173dbf82267ea77b54f432e1e8bfd72d22a898f0d '' requirements-relay.txt
compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
compare_digest d30e4ea7758a2fa3b704f61b0bec3c78af7830f5b1518473bf629660de4c5138df043a2542f174d790b4bda282edb1f8b536913bb9d9f62fb0c6faf87f255ee0 '' tfc.py
compare_digest 7a3d7b58081c0cd8981f9c7f058b7f35384e43b44879f242ebf43f94cec910bab0e40bd2f7fc1a2f7b87ebc8098357f43b5cede8948bd684be4c6d2deaf1a409 '' uninstall.sh

compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
compare_digest 6fac0ac5a90783a6a57bb1819c026935fb1fc830c92fc77df9cec2cd3aff4c7ff30d6cd798a2ce055cf682f3199248ec687f3a500182e2de4e8ea18706e46d00 launchers/ TFC-Local-test.desktop
compare_digest 03a205361c7b9521fd8cb08daed455ccd6793609e9896cdd9079379558f642d44c2d3e69415ac7f403ac7e8008eaf6367aeadb44b9be591624e7992518939af5 launchers/ TFC-RP.desktop
compare_digest de9bd3e7dfe911f39630853244ae82ac1ea6fc52524a6e2ad85eba1bd4f84f74177d622117adcb6db696af48c9e2fe099f0a59a2284f8e5a2b5defd9084be1f3 launchers/ TFC-RP-Tails.desktop
compare_digest 9a9fe7a8020669cc89e71dc8404868d51ad81af278840e117319f156c55f9b6f11c9590e9b3d2764809e2b7b207d44ef80c3b2e89c227764524db903d1726c35 launchers/ TFC-RxP.desktop
compare_digest a128edbaba75155697ebc54af922d2f200a8aa2eee9d1acb039d39b18908deb3bea417abd058049ea8e1e7a217f838ce80204eda73ca74e545fa5cab3a47c09e launchers/ TFC-TxP.desktop

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
compare_digest 10f94d1eb194a1137e9099ff77b936f4935cab7ab5307e38d9bb5dde183fa431356cffaa8f04772df51e9f8b1becb5d46254a35b4d1550ec368bd2d68043db18 src/common/ crypto.py
compare_digest c1e4b2a8266876ccbbb63f8008725a3a14aa841b70b4309c5b23153c963cc5ede855174c7ba92d3968e284ce0538ddc85e81de16c2d9a225b70708aa1753243d src/common/ db_contacts.py
compare_digest 2cd737ece390a5d4f5d5579d49c4afaeebd7e9d40309f8dd08340c881c1e014fc350190520e6e00a2794c1d91df5e77fcead527f804c3e8a7cfd810e6c5f7dde src/common/ db_groups.py
compare_digest a71345dea4e9fcbe7131e3692ec5687e706e069f7aada56856837675fec7b2ee393ae4221fe8fd08f5c359a5f506dbced04586f9b908a27d2f81c99fa42d3b23 src/common/ db_keys.py
compare_digest dee2bcd41c4999890ea4643c4661fabd4fd35bcf04f165faf6409b60071736290a331ef1834292e08290ccf6c6bce980842f6abbf9b52300e15613a18f4efaca src/common/ db_logs.py
compare_digest a29077738fce281fd540df3812307c02b5b8af62cb62234b9f0c20033775fb834f26d00f47cb71e0fc68656375cfa7e66eb7e510e0e2ed1a56ea3e651c7b680e src/common/ db_masterkey.py
compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
compare_digest 404aa061de5a33b910cce126ff55ff28999ea981a971cbd2d198cfb3cf6d186646cc02727ddd8312bfedf5662b2302d46af92175682891f288b06d7c18f1819f src/common/ db_settings.py
compare_digest 13c203b565880ab83f8b54fa2474c17c9b5cea890a1839666515600f876bdf749132b63e48e56d3d43a7042e29acb7d14fd2aa0f5f448622f5eaf8bd933c6b01 src/common/ encoding.py
compare_digest 043a5518a6afb2f3e5c445d26d7f0a3bbcd80cc26679b17fc3342671759cfc9e3f23ba68e4479c795c7455cec73fe7b332febde29944c1e1f69455780ca1f036 src/common/ exceptions.py
compare_digest bcf070f6bc6a6dce043df981e799b05d676607a218544391653c4b1e50f94a548106b5e564d79fc9567a404e305cd0e209bc5690aec30e200b143e7078a4ea07 src/common/ gateway.py
compare_digest 56639c5be9e89abb3305bda4d96fddd74490f125a68ae5cf1de2e0d4dee7bf04b114ce1e52b540484b89493aca772122cbb253ea15a78381a56c29c6a50edff9 src/common/ input.py
compare_digest 55c7ae84935b2ad7f80277cd30fe5297fa9404f3ecd0e8c9fa76f640f4277e38bdd1e61094a2b4eb1b787f0adfdb76d13c06799380e72513ef4ff22bba95d98b src/common/ misc.py
compare_digest c06045121eeb8a4210f153cdbecd83544e00796a704498f6381be2d02be422e013fe98e01f2821e06a35d281423c9cf4dc9c551c8b3a14578b7ba27b031d83eb src/common/ output.py
compare_digest a62724cb2e2ac0f63371fc0dc4be5541c9d9eaf1c8441c69001485f9057bbea16f31b9093ad6f9f6b4d1ed5a70136b8881bb7c09c63b2631a6ce052b2e914253 src/common/ path.py
compare_digest 9c05675ecd3a8a436d24469adbb5ce821632e4fae95452d06ffad92b692a9950d1a0bf4e5875b2f0f6e6fa592fd25f11382ff2354b78d19a84a720aa324005ef src/common/ reed_solomon.py
compare_digest af7b79b7f7f5b677d9804bc222c3109f911286bb4ee79cc66ec75a9115f9439a8b959dbb6bd51f14e59c65b500827edf431a41ff5bece33ea6b75ff39dbfe5b9 src/common/ statics.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
compare_digest 908f0083b503251baf38997a603efb04987c4ebb74bb3caffb6d9fbe77efff0e177626d5e639f8564a417c7a8c4164a76fecdd414f96a0f89af3cd09bac3472b src/receiver/ commands.py
compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
compare_digest 5a728d57c954a1616848fa4839058f28de8960686efa2670549fe98b0b08b28fb99dcc1d15c5fe405615ea69f708845005cd596cfca5345bdde3a33aead2be8c src/receiver/ files.py
compare_digest ed73dece8ccd6f71874ffb8d1e2bdae13621ff7bc44f656b84053dcc199773c9c0533ef12d87f17b7b16551fafef6356cb237b9771487ddceed5763b63059eae src/receiver/ key_exchanges.py
compare_digest 65307a0ea2c9ae69859cc8ef62a5d7e45c27bdf5a4ec44db704df143ce3630fdc077fafc7fd4cfc0cd922f350f49f0aa0a880192c40c614b6d3117804ea683ae src/receiver/ messages.py
compare_digest e1b568104da0f3c3cfa53d379a7b68d8e89718e24db51f0e1deade5e2183523bca4eb673885820721d561e538eb75df1df289fd7d7a25b3c9fce1074b5e14106 src/receiver/ output_loop.py
compare_digest 9e5a15e46b39d39afabac1d8facbf542afdb201084e319e8a098ee5b46a0fe42e59767a5ae9281ad4cd5d9bb9d7ffb87f7c4c77777796631d9736f3f9f181f68 src/receiver/ packet.py
compare_digest 6bdcef60acfc7725488fbe21e74b5d6490b0d9918903231a611aa41cca185153a3f507ee2fa06a91cb657aea15eb1c2131526e56014383e8c5f76a29749b3077 src/receiver/ receiver_loop.py
compare_digest 27cc4f8048b1f7d5e5dee0216d279701258eb468b8452fddfd3402c2eed4bb78673d8f1320412bf2bac43a5a23af07517a90fcca5446621773f8c54cefdfe3e3 src/receiver/ windows.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
compare_digest ba56c76a825bef2b64ce09b6b6a8215451f9da7747e321ec50e2c03af00e896fee67d8a087b6287e892457054a624c85c232df085f73da472c4c3d82ec043589 src/relay/ client.py
compare_digest 48f36d5dccb3e8b06cd4ab8c6bc0c06ae73e63c290a36f0f2e1c756392cd39c78a61db3ee13386f6b888c65d0273533998f65dad46a02bcea4efe2f8c24f2738 src/relay/ commands.py
compare_digest 9e1364e05c7ba9acc65cf7926c94ece8e440e65f21f40affeeade9541c82a15cee47c962bc5478babcc9147dfbaf89276cfeb53547512883cb7fcb14d0f5e496 src/relay/ onion.py
compare_digest 5771ec48e4f1aecc2b9beeb906b4779850fe9069a95023439d7dcc57721e152d0bcba8a39526c6a5c53d7691566c31986e5539c0ae82939ddd36992727061a0b src/relay/ server.py
compare_digest 4c5b5cbce1ba79eca1f17d34d91e7f21aeded9c12d4ad2e1992ccccd41dd24d31722f023fed52bd02df53170777fa3f3273897529160853ae75877438d9317d9 src/relay/ tcb.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
compare_digest d69ef890aeb43f2ddae1d55ffc8304bec3168beabc647905fc1084288fdfc2bb2d87deb2a9f819f2671a029be1174ca8b74244d19f4280b4e80cf2f9000c92aa src/transmitter/ commands.py
compare_digest c912deb82fa99bcab1a0b07a57a9168a926dcc09d8ead3a36a6d7064bea96f3773e136992dfa9c94028f8803183a3db0cd6e0c2ca9d2b6edc4f680dbc83ee560 src/transmitter/ commands_g.py
compare_digest 1fe99e684ca629c6c081979393bb17fc644bd13a8a33e3a3b09001da5f37dc054f3e5d0ca7ed9b8420c5b1a97ded512ea71a328c65547e8097d5bff29ed02ce8 src/transmitter/ contact.py
compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
compare_digest 319a6f33ca0571768b78008c9c746b84df1aeeb9dd13fe663e4143c4af524dafc6ae83923b84430b08f4b598dffa09c1a1a5095e7571a25c0fd811428772ff26 src/transmitter/ input_loop.py
compare_digest cb02629de416059ae56fcbcfe943bc5ea0ebed108f296d13a06693f466e2fa4b4bfb0cb25fe47132a2f3d47dae2b5675aca0f4c44ac36141c75815280f66a027 src/transmitter/ key_exchanges.py
compare_digest bb86d9314bed916a45c36812f419aa9fe663a904ceeaddc4516ad8055fccce3526e9bdac3be8df9e09bcbae1be5fafeed068643b1972d480b3cb13af8c97e69a src/transmitter/ packet.py
compare_digest ca0088c5e7e45f719d3fa813034de07099650c8c8564d8e4aa77e1778f7a58bb9f3d4dc1de4323ffc483b82867984b3cd3eb79461bf47062dc52d838f10630f2 src/transmitter/ sender_loop.py
compare_digest 3e8408b891e446a8b99488703b94ca7e6767bdc29c6218e8b4ab7844a0fb687863620ff3dced5c20e71c11b93238b1bd9f08a9791443f20745e39facaf37f50b src/transmitter/ traffic_masking.py
compare_digest ccbda8415c23b23cc10cda57fb6b32df71e6510f3cb94c7f932b40adcf5f0abdd9842c48a992d56c95755e3024aebd7ecb05f69eb18f3c41656d94cfeabb38fa src/transmitter/ user_input.py
compare_digest a22b4eb71fa2b56d61a27193987b5755bc5eeec8011d99ea7813c830a4cb38f8934fb70acf4b1dd0980dbb4a30e0ec5945cfb869fb40e74c4f0ecd12f129b040 src/transmitter/ windows.py
}


# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
ASN1CRYPTO=asn1crypto-0.24.0-py2.py3-none-any.whl
CERTIFI=certifi-2019.3.9-py2.py3-none-any.whl
CFFI=cffi-1.12.3-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.6.1-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.0.2-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.1-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.6.8.tar.gz
REQUESTS=requests-2.21.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.24.2-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.4.3-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.15.2-py2.py3-none-any.whl


process_tcb_dependencies () {
    sudo $1 /opt/tfc/${SIX}
    sudo $1 /opt/tfc/${PYCPARSER}
    sudo $1 /opt/tfc/${CFFI}
    sudo $1 /opt/tfc/${ARGON2}
    sudo $1 /opt/tfc/${PYNACL}
    sudo $1 /opt/tfc/${PYSERIAL}
    sudo $1 /opt/tfc/${ASN1CRYPTO}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


install_tcb () {
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    kill_network

    verify_files

    create_user_data_dir

    sudo python3.7 -m pip install /opt/tfc/${VIRTUALENV}
    sudo python3.7 -m virtualenv /opt/tfc/venv_tcb --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.7 -m pip install"
    deactivate

    sudo mv /opt/tfc/tfc.png                   /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/TFC-RxP.desktop /usr/share/applications/

    # Remove unnecessary files
    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/src/relay/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


install_local_test () {
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files

    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    verify_files

    sudo torsocks apt install terminator -y

    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.7 -m virtualenv /opt/tfc/venv_tfc --system-site-packages

    . /opt/tfc/venv_tfc/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements.txt       --require-hashes
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                                /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-Local-test.desktop       /usr/share/applications/
    sudo mv /opt/tfc/launchers/terminator-config-local-test /opt/tfc/
    modify_terminator_font_size "sudo" "/opt/tfc/terminator-config-local-test"

    # Remove unnecessary files
    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    install_complete "Installation of TFC for local testing is now complete."
}


install_developer () {
    dpkg_check

    if [[ -d "$HOME/tfc/" ]]; then
        sudo rm -r $HOME/tfc/
    fi

    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk terminator -y

    cd $HOME
    torsocks git clone https://github.com/maqp/tfc.git
    cd $HOME/tfc/

    torsocks python3.7 -m pip install -r requirements-venv.txt --require-hashes
    python3.7 -m virtualenv venv_tfc --system-site-packages

    . /$HOME/tfc/venv_tfc/bin/activate
    torsocks python3.7 -m pip install -r requirements.txt       --require-hashes
    torsocks python3.7 -m pip install -r requirements-relay.txt --require-hashes
    torsocks python3.7 -m pip install -r requirements-dev.txt
    deactivate

    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop

    chmod a+rwx -R $HOME/tfc/

    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


install_relay_ubuntu () {
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files

    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    verify_files

    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    sudo rm -r /opt/tfc/.git/
    sudo rm -r /opt/tfc/launchers/
    sudo rm -r /opt/tfc/src/receiver/
    sudo rm -r /opt/tfc/src/transmitter/
    sudo rm -r /opt/tfc/tests/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/install.sh
    sudo rm    /opt/tfc/install.sh.asc
    sudo rm    /opt/tfc/pubkey.asc
    sudo rm    /opt/tfc/README.md
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-dev.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/tfc.py
    sudo rm    /opt/tfc/${VIRTUALENV}
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc
    process_tcb_dependencies "rm"

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


install_relay_tails () {
    check_tails_tor_version

    # Cache password so that Debian doesn't keep asking
    # for it during install (it won't be stored on disk).
    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip python3-setuptools -y
    t_sudo git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    t_sudo python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay.txt --require-hashes -d /opt/tfc/

    # Pyserial
    t_sudo python3.7 -m pip install /opt/tfc/${PYSERIAL}

    # Stem
    t_sudo python3.7 -m pip install /opt/tfc/${STEM}

    # PySocks
    t_sudo python3.7 -m pip install /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo python3.7 -m pip install /opt/tfc/${URLLIB3}
    t_sudo python3.7 -m pip install /opt/tfc/${IDNA}
    t_sudo python3.7 -m pip install /opt/tfc/${CHARDET}
    t_sudo python3.7 -m pip install /opt/tfc/${CERTIFI}
    t_sudo python3.7 -m pip install /opt/tfc/${REQUESTS}

    # Flask
    t_sudo python3.7 -m pip install /opt/tfc/${WERKZEUG}
    t_sudo python3.7 -m pip install /opt/tfc/${MARKUPSAFE}
    t_sudo python3.7 -m pip install /opt/tfc/${JINJA2}
    t_sudo python3.7 -m pip install /opt/tfc/${ITSDANGEROUS}
    t_sudo python3.7 -m pip install /opt/tfc/${CLICK}
    t_sudo python3.7 -m pip install /opt/tfc/${FLASK}

    # Cryptography
    t_sudo python3.7 -m pip install /opt/tfc/${SIX}
    t_sudo python3.7 -m pip install /opt/tfc/${ASN1CRYPTO}
    t_sudo python3.7 -m pip install /opt/tfc/${PYCPARSER}
    t_sudo python3.7 -m pip install /opt/tfc/${CFFI}
    t_sudo python3.7 -m pip install /opt/tfc/${CRYPTOGRAPHY}

    cd $HOME
    rm -r $HOME/tfc

    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    t_sudo rm -r /opt/tfc/.git/
    t_sudo rm -r /opt/tfc/launchers/
    t_sudo rm -r /opt/tfc/src/receiver/
    t_sudo rm -r /opt/tfc/src/transmitter/
    t_sudo rm -r /opt/tfc/tests/
    t_sudo rm    /opt/tfc/dd.py
    t_sudo rm    /opt/tfc/install.sh
    t_sudo rm    /opt/tfc/install.sh.asc
    t_sudo rm    /opt/tfc/pubkey.asc
    t_sudo rm    /opt/tfc/README.md
    t_sudo rm    /opt/tfc/requirements.txt
    t_sudo rm    /opt/tfc/requirements-dev.txt
    t_sudo rm    /opt/tfc/requirements-relay.txt
    t_sudo rm    /opt/tfc/requirements-venv.txt
    t_sudo rm    /opt/tfc/tfc.py
    t_sudo rm    /opt/tfc/${PYSERIAL}
    t_sudo rm    /opt/tfc/${STEM}
    t_sudo rm    /opt/tfc/${PYSOCKS}
    t_sudo rm    /opt/tfc/${URLLIB3}
    t_sudo rm    /opt/tfc/${IDNA}
    t_sudo rm    /opt/tfc/${CHARDET}
    t_sudo rm    /opt/tfc/${CERTIFI}
    t_sudo rm    /opt/tfc/${REQUESTS}
    t_sudo rm    /opt/tfc/${WERKZEUG}
    t_sudo rm    /opt/tfc/${MARKUPSAFE}
    t_sudo rm    /opt/tfc/${JINJA2}
    t_sudo rm    /opt/tfc/${ITSDANGEROUS}
    t_sudo rm    /opt/tfc/${CLICK}
    t_sudo rm    /opt/tfc/${FLASK}
    t_sudo rm    /opt/tfc/${SIX}
    t_sudo rm    /opt/tfc/${ASN1CRYPTO}
    t_sudo rm    /opt/tfc/${PYCPARSER}
    t_sudo rm    /opt/tfc/${CFFI}
    t_sudo rm    /opt/tfc/${CRYPTOGRAPHY}
    t_sudo rm -f /opt/install.sh
    t_sudo rm -f /opt/install.sh.asc
    t_sudo rm -f /opt/pubkey.asc

    install_complete "Installation of the TFC Relay configuration is now complete."
}

t_sudo () {
    # Execute command as root on Tails
    echo ${sudo_pwd} | sudo -S $@
}


install_relay () {
    if [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


read_sudo_pwd () {
    read -s -p "[sudo] password for ${USER}: " sudo_pwd
    until (t_sudo echo '' 2>/dev/null)
    do
        echo -e '\nSorry, try again.'
        read -s -p "[sudo] password for ${USER}: " sudo_pwd
    done
    echo
}


check_tails_tor_version () {
    included=($(tor --version |awk '{print $3}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$included" | sort -V | head -n1)" = "$required" ]]; then
        clear
        echo -e "\nError: This Tails includes Tor $included but Tor $required is required. Exiting.\n" 1>&2
        exit 1
    fi
}


kill_network () {
    for interface in /sys/class/net/*; do
	    name=`basename ${interface}`
        if [[ $name != "lo" ]]
            then
                echo "Closing network interace ${name}"
                sudo ifconfig ${name} down
        fi
    done

    clear
    c_echo ''
    c_echo " This computer needs to be air gapped. The installer has "
    c_echo "disabled network interfaces as the first line of defense."
    c_echo ''
    c_echo "Disconnect the Ethernet cable and press any key to continue."
    read -n 1 -s -p ''
    echo -e '\n'
}


add_serial_permissions () {
    clear
    c_echo ''
    c_echo "Setting serial permissions. If available, please connect the"
    c_echo "USB-to-serial/TTL adapter now and press any key to continue."
    read -n 1 -s -p ''
    echo -e '\n'
    sleep 3  # Wait for USB serial interfaces to register

    # Add user to the dialout group to allow serial access after reboot
    sudo adduser ${USER} dialout

    # Add temporary permissions for serial interfaces until reboot
    arr=($(ls /sys/class/tty | grep USB)) || true
    for i in "${arr[@]}"; do
        sudo chmod 666 /dev/${i}
    done

    if [[ -e /dev/ttyS0 ]]; then
        sudo chmod 666 /dev/ttyS0
    fi
}


c_echo () {
    # Justify printed text to center of terminal
    printf "%*s\n" $(( ( $(echo $1 | wc -c ) + 80 ) / 2 )) "$1"
}


check_rm_existing_installation () {
    if [[ ${sudo_pwd} ]]; then
        # Tails
        if [[ -d "/opt/tfc" ]]; then
            t_sudo rm -r /opt/tfc
        fi

    else
        # *buntu
        if [[ -d "/opt/tfc" ]]; then
            sudo rm -r /opt/tfc
        fi
    fi
}


create_user_data_dir () {
    if [[ -d "$HOME/tfc" ]]; then                                                 # If directory exists
        if ! [[ -z "$(ls -A $HOME/tfc/)" ]]; then                                 # If directory is not empty
            mv $HOME/tfc $HOME/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)  # Move to timestamped directory
        fi
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


modify_terminator_font_size () {
    width=$(get_screen_width)
    # Defaults in terminator config file are for 1920 pixels wide screens
    if (( $width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   $2  # Data Diode config
    elif (( $width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' $2  # Data Diode config
    fi
}


get_screen_width () {
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


install_complete () {
    clear
    c_echo ''
    c_echo "$*"
    c_echo ''
    c_echo "Press any key to close the installer."
    read -n 1 -s -p ''
    echo ''

    kill -9 $PPID
}


dpkg_check () {
    i=0
    tput sc
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        case $(($i % 4)) in
            0 ) j="." ;;
            1 ) j="o" ;;
            2 ) j="O" ;;
            3 ) j="o" ;;
        esac
        tput rc
        echo -en "\rWaiting for other software managers to finish..$j"
        sleep 0.5
        ((i=i+1))
    done
    echo ''
}


arg_error () {
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 18.04+)"
    echo    "  relay    Install Relay Program                (*buntu 18.04+ / Tails (Debian Buster+))"
    echo -e "  local    Install insecure local testing mode  (*buntu 18.04+)\n"
    exit 1
}


root_check() {
    if [[ !$EUID -ne 0 ]]; then
       clear
       echo -e "\nError: This installer must not be run as root. Exiting.\n" 1>&2
       exit 1
    fi
}


architecture_check () {
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        clear
        echo -e "\nError: Invalid system architecture. Exiting.\n" 1>&2
        exit 1
    fi
}


set -e
architecture_check
root_check
sudo_pwd='';

case $1 in
    tcb   ) install_tcb;;
    relay ) install_relay;;
    local ) install_local_test;;
    dev   ) install_developer;;
    *     ) arg_error;;
esac
