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

# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.9.11-py2.py3-none-any.whl
CFFI=cffi-1.13.1-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.8-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.3-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.1-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-41.4.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.6-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.7-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.16.0-py2.py3-none-any.whl


function compare_digest {
    # Compare the SHA512 digest of TFC file against the digest pinned in
    # this installer.
    if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
    else
        echo Error: /opt/tfc/$2$3 had an invalid SHA512 hash
        exit 1
    fi
}


function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online, only
    # the requirements files are authenticated between downloads.
    compare_digest 99912fe2f7240a9b163292ff83c28b6ab41ee1c10bf96cc57f2c066537d3f153b46280e2c769b0f273c6bc36c74badb42d3c66c6fb3d16862dc96ff27319788d '' requirements.txt
    compare_digest 97558ed189976ccd54e3a25bcf639f1944aa43f4a4f42ff5ef2cf22349a7b649272e91746041b4e04b2f33adf1fab8818c339b1cc58f9353af3e5ac76cb1ec0b '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest bcb8a7ce1eb2d2f064b560ca5a8e467f84e3a0c3d643771e7782c792e89494600436e52c12f0a8471bf4a1da116f82ed732b8e06783534227a31f576f7adbd6c '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 7e519d20fef24e25e88ec4a9c03abadf513b084e05038f17c62ca7899c2f9174a953caa0bfbd3b61e455e243513cdab737c22a34d73ebab07b65d3ce99100f0a '' LICENSE-3RD-PARTY
    compare_digest 99815d0cfbca7d83409b7317947fe940fe93fd94b50e6099a566563ee6999e33830fd883ff61e5367a040d5fda3f2a43165ef0dc6155e14a573e07dc27eba70d '' relay.py
    compare_digest 28d06826a45ca4d64c2b4d06859ee7a0c7152198fe49b85681f7ce6b9c02b1a103fd7f3514b05b24e95e2ec5f48ce02529a2b4f2ea806b333e8141b1650d1257 '' requirements-dev.txt
    compare_digest 8a57366899139b9906f0a75272c702575a6cd5c6ca2dd09f0dbd1be9efd5341178f9d3d64fec113af7d1fdccbb5cbdf384133aa3afa3672292e37405f60cf0a8 '' requirements-relay.txt
    compare_digest 8ecd5957f3bfbe237549e8772720cba5b5899b51a475063edcbc416ad5f77f614da2c9069aeb31bca6d2bb74ce6f2877d29df178ec3ecf6d5dd05daaff51c6b2 '' requirements-relay-tails.txt
    compare_digest 4a44501e21d463ff8569a1665b75c2e4d8de741d445dc3e442479cbb7282646045129233bd7313df4b9c2e64ec86b7615a8196ae2b3350de933731926d39bbda '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest e4dadae63adcd72108fcfa04401f42a1bae956008303d09f22e849b207ebca699306f2bd4034ee96a5531028719f5e41689205ec8ef12cd1726a86376d3aec3e '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest a5611269e2f69a452840ae13d888bd80d6f8e5e78fdab0cb666440491d8431e6c326dc57a52df7d9e68ecd139376606c9f6c945207f2427bb21c114fe26c0af7 launchers/ TFC-Local-test.desktop
    compare_digest 9263737fca4773672515e0f4708e147b634bd09c8d068966806bb77d3b38dcf60b1f933846f9a649e795760ff141a31dc2b58fad38ef2afbaedb33d2f479a29b launchers/ TFC-RP.desktop
    compare_digest 9263737fca4773672515e0f4708e147b634bd09c8d068966806bb77d3b38dcf60b1f933846f9a649e795760ff141a31dc2b58fad38ef2afbaedb33d2f479a29b launchers/ TFC-RP-Tails.desktop
    compare_digest 113d1f8f6bc03009ef1ccfe1aed8a90bdecb54e66bd91ed815bbd83cb695419a25c614de8287475d3beab832cfcaf6d549c06832f2ea098d29ff049d7cd91da7 launchers/ TFC-RxP.desktop
    compare_digest 1f4d4e216039b63f2579eef17dc18df5e2f1e65f09e619b62adb8dceb128de6ffe5784ea0ff1dc846af21e1ce641bc612df51e37e205fee210f94dd87b86f467 launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 580c6453d8649d82973817de1fcfd83c73b0f6bb3e2597c5ffb6c0d3929d10f693c0a3d98dad4f528f1a1b62b220bcb99fa075ccd28e8b53d6cc966697523e25 src/common/ crypto.py
    compare_digest 053c431755b4d6a5a869d2f06213bd23a8fb8743644b127d3622ff0223687880e8b1d510fbc976f2112318e48caa0044a1959c9af21272001e3f107fd9f785ba src/common/ db_contacts.py
    compare_digest 8e4e8ab2dff2400f3fe72d980c95c1780d26e11f0482c555bb47cfa7513d091b06fd901666f415e0b3db291bd7f161d7182ac530a6d118a61f0b72bb665eead1 src/common/ db_groups.py
    compare_digest 712c5422193994a65eff74f0a328107232069784c6c687f700a6823435fe65afb3e31cbd1102dbe07bc1d7e5e1572a4db6e467d477ebd3e4aab6ff3685723ccf src/common/ db_keys.py
    compare_digest a2714c8aab538a5fc273f4eb58ea0d039effa4ce64559ab34dbe9eb92c762aff98a242443e2dffe5e55005b8778a5581f5c2ad3c07a0b6eee58e599e44a951b3 src/common/ db_logs.py
    compare_digest c6bbb2b75f14447ba20bf1ac214b044d5a79b11a5346a1691a823c5e5ac4db05dd24a8de52856021d8d7f7f8582c1871839945323245521f320714cc72994bdf src/common/ db_masterkey.py
    compare_digest 253521b1ed39a73a0fd6108cbcf88bbd1ffadde28be1467c1e7871094392d0a55947032ef5fc19d85727117bacf8516ac1f08f70240be20b9fc2d009a68989ee src/common/ db_onion.py
    compare_digest 2e8ff65270e0165e510f5d330fa2cbfdc6ecf8ed953220bbe18d19a8afa6fa2bf852e56ba875c1c361fdb72016d0610e8c9fa1df302fa47f916eaaecde11e423 src/common/ db_settings.py
    compare_digest 7a673e6feb7a5b2e3417d2c0eee82a59b3730a5d241938a84fd866dfc838c3cd63d7ef96772d43f62df740a2ba1001456746dd6c86e950484eac3ebabed498ce src/common/ encoding.py
    compare_digest 00ad45d8fba1a605817a9f5d64cdfd6aad9c618db66befe682728a2291384c67bf5e80a5257211717a86e4a51c7e8c74f8f7ccccc3b4ac3c6f0f4c4e1b3cc98f src/common/ exceptions.py
    compare_digest 5de68b10dc6b6ff98d7f73a2dc89d6b64c529fb4949b4a51d1b2fb4491006266bf7200b717102987347add666f12d7cfa9afc43a540304290f9a41fe48545078 src/common/ gateway.py
    compare_digest 604893a2814219b2ed4e69b45d9ac2f8c2b5fc066bd085e86b76ef9df9984e6113f79fcaf3b9eb1197a9c9fc92cf524269e595d03b5009c46e8889d813475408 src/common/ input.py
    compare_digest 1cac1bed0779f480de26054867cd732deaba5e7a46728ed8c203948ed92b96e0dbf2d5d1a696cbca445d5db2b79cde318aac28189d8806fe1ea530392a47f406 src/common/ misc.py
    compare_digest e167f8458d1a1fc549f02a42ab9c1dc78ac2540b6a8660c77a06fe32de461eb52361a99582921b00eb50115c9fc70858dff1557c6e7ac69439768481a70b3fa7 src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest 4365ed3b6951525cb1ec8dc1177d7fd74d5dfa5eab1ca8934775391a8736eed4df039684f19ccc2d8022f20c8cf93a57a736b259e8c7235da5060c5f62057c98 src/common/ reed_solomon.py
    compare_digest 1f26c39a8e5ec39a859e90dac2e38c08d86af02e0fc714aa0569b618dbf44de5befde601b0fec23e62e3e3b3f7281727abea37a02818c9994ac47f119a621386 src/common/ statics.py
    compare_digest 339b402790cb3002841a1212d4dc24b07236b65baf68e3a8caf8d61bfd48af12887564be449ae49cfe5d7b88107a73e01a05053e3789398fbd560ef89f14afd4 src/common/ word_list.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest eaf664c520b7a2b4374e258b153940625312262fc54f9435018beff3152073d6dadcf78bedbe081a92cf173b31f2e86582c98a6065be1bba143b6b41b2d4b3b8 src/receiver/ commands.py
    compare_digest 051a1eac8e1e177bdf1c94972ed511d56d9ccfb3dc97c6418355b4415b2d1dff42c4ef5420de05d90e1697375f4db119e04932c05d6a93a89e03e7ca4c7c7346 src/receiver/ commands_g.py
    compare_digest 4a48adedcb839176e6a5f18b430a97c96558a7474d0840d22d31241a2918f1ffaed53211c5c949b545e231cda5280cf42fb5c20e22bdaef03f5fb2c298e22e07 src/receiver/ files.py
    compare_digest 6eae2793bdd72b9581cbbebc012a70b11744c2585fda1d1e253ff4d67cdc1d316d1f3ad7e391f5197aa1447ce21b0ecbc3e34517a8932ecd9eec7ff5d7313b5b src/receiver/ key_exchanges.py
    compare_digest d7d28808635a0425d231770b24c1a0f332ad40dffccfcf4f88801299b121e58363b728b0a70b0bc4d1640b850f7cb069ba88f3be966eb84f9e05f0112d3e76fd src/receiver/ messages.py
    compare_digest d651d87311ec09b8aa0a3964718ea1ea22c5bc1cc078ca87a367b420fc19716438045b31618d34264f483eb009ed1aff33704d135d0d22374df31d5438f9e00c src/receiver/ output_loop.py
    compare_digest a1edb6fe5b04117174ce45739e0737b6e8eedeed134bc95201d837bf6785bb98c86f8404eee18eb398755c8df113d7f8daa9dae43465846b887d514619759ed2 src/receiver/ packet.py
    compare_digest 20c6754ddb6261c7a3b479e6ab7bf78eb0ef8783e2141373d7aba857f413091b78dcc9c32667dd8f8d5c41927102da7e35c4c4fcb0aa7376dc42b08c0c01d6e2 src/receiver/ receiver_loop.py
    compare_digest 7d3f18351dc97bf4c1c5ab5894619d1f34ec07874758751340d53a12da2d7079944e6187d7436990f09a82d39c89d64a0bb747678c85ead8126eebbac9fcddfd src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest 5d34be330731b8b722c3580f12abd2515984ba0589ea95c0960ae099a13b9d66118a5af5cdf137bcf376bde88b0edf055888d2a5fc267081ea118fffc05a2b08 src/relay/ client.py
    compare_digest c32b5b78e28567d5ef0c6f41f1a3c69f6d31b1cb3b9d58faf6516fa27fc62e12b2f359f7b60176b5fe20a2d94725f5fd76a879d4b795513d1588f8ecf9bae5b0 src/relay/ commands.py
    compare_digest c72a57dda6054b9c020f694740751159df4602f11f7759ff76e48a8b7f07ec829b39d6c366613f3a69e36d3dca0823491f3232506f3a03ecc9ded3e2a4f0230a src/relay/ onion.py
    compare_digest fe108f1f642bdfd01d813fd0a183e2f6039c1e64a5ee57f6159fdc67d7574a0ba0ee23608a2a8499071f0844b7d2db6b6a14740046d5d664e09856c35680a0dc src/relay/ server.py
    compare_digest 9459e6cbe17fefac356e5ce183d923efff66f6d304111f2c0dbacdfb22a92df77bb11134faf8c15400bc59174ecbec1ea0b436065a9d49d3af70b46b24a77764 src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest 2d002fe7aab987512534bdb18433d4a626b404aafc0360253056995559b0d2097938604325bc882a36ba456af0fbcf9620909945ebddf668bc44748a31a225c0 src/transmitter/ commands.py
    compare_digest 74291c8b952588caf7c3c6ac3e99679eaf97ba9113bfd560da4c461e16cd36c28d78a4e8750090d18606a9c1610a1a781d37fc6fe52baf47a955e0b5ec801b97 src/transmitter/ commands_g.py
    compare_digest 3a2940afcf8752f33c8f5a06293046a83d245630dde1a6877eb3c724cb03ee7b84147b4a57a62135a32862b40db1dc6c6823bedc52404146aeb6e9ef1f79692f src/transmitter/ contact.py
    compare_digest 2e78e578e62771adf7ae9f2a576d72b69a64e6b28649361244bd7a75959f2022845d73d68c3d6a4586841bb10cce906edf1c5d863fbf99b6d081dfc030f98a3d src/transmitter/ files.py
    compare_digest 7cb9fc9d095f40ce2de6b49c9bd58b9dcab6b835fe7749dce8642c3c87b0eee10c4e53ff986c09ae26fb7b8aad7fe87c5fd56a734f2e013f69195213b9d5e9ec src/transmitter/ input_loop.py
    compare_digest e723db5bc403cec60b7df3e34d80caa7868bed4e8f0d08a6504d060fdd6c188f4afa41ecd8feb3a6520a384ccff7f8c64efeaeddb084f825d40e1854fb528f9f src/transmitter/ key_exchanges.py
    compare_digest 41798dfe91868b37c130a373accac93c4200dc77bd8b6c40a38835ecf4187b955ccfaa53f842ccddf78ce5607b3e361a30a4bb53bd7cb5ab6d2fb4785454dead src/transmitter/ packet.py
    compare_digest 3f1e7a5cb58ba8fcf0ccc66195d589ac0e34153296e2c395ca099304a99bb61c25248078dc453b3cc47e08a0b207a688b0a426d095df4a7bd235d1a95bb3c8d6 src/transmitter/ sender_loop.py
    compare_digest c5a6c85e57d4456353f89fc4b2d30fc60775511720a32287720b3b301e0d6e7539677b47c4ff8c6b6f223b93da7dfbb38d1830f43e6f25c598efd54799262956 src/transmitter/ traffic_masking.py
    compare_digest 678ae2b63667d93b1d4467d029ab04778614ddf6c09dff4bb61d262373353cd7fe6b8b535292fdf28e1be36c8b57534dee9eb745ee94c72b051798ac4e1cbccd src/transmitter/ user_input.py
    compare_digest 00e247854f067194f80c86c9a3b9fbe1975e600844a1f33af79e36618680e0c9ddebaa25ef6df1a48e324e241f2b113f719fc29a2b43626eeeba4b92bdbb8528 src/transmitter/ windows.py
}


function process_tcb_dependencies {
    # Manage TCB dependencies in batch. The command that uses the files
    # is passed to the function as a parameter.
    sudo $1 /opt/tfc/${SIX}
    sudo $1 /opt/tfc/${PYCPARSER}
    sudo $1 /opt/tfc/${CFFI}
    sudo $1 /opt/tfc/${ARGON2}
    sudo $1 /opt/tfc/${SETUPTOOLS}
    sudo $1 /opt/tfc/${PYNACL}
    sudo $1 /opt/tfc/${PYSERIAL}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    t_sudo -E $1 /opt/tfc/${PYSERIAL}
    # t_sudo -E $1 /opt/tfc/${STEM}
    t_sudo -E $1 /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo -E $1 /opt/tfc/${URLLIB3}
    t_sudo -E $1 /opt/tfc/${IDNA}
    t_sudo -E $1 /opt/tfc/${CHARDET}
    t_sudo -E $1 /opt/tfc/${CERTIFI}
    t_sudo -E $1 /opt/tfc/${REQUESTS}

    # Flask
    t_sudo -E $1 /opt/tfc/${WERKZEUG}
    t_sudo -E $1 /opt/tfc/${MARKUPSAFE}
    t_sudo -E $1 /opt/tfc/${JINJA2}
    t_sudo -E $1 /opt/tfc/${ITSDANGEROUS}
    t_sudo -E $1 /opt/tfc/${CLICK}
    t_sudo -E $1 /opt/tfc/${FLASK}

    # Cryptography
    t_sudo -E $1 /opt/tfc/${SIX}
    t_sudo -E $1 /opt/tfc/${PYCPARSER}
    t_sudo -E $1 /opt/tfc/${CFFI}
    t_sudo -E $1 /opt/tfc/${CRYPTOGRAPHY}

    # PyNaCl
    t_sudo -E $1 /opt/tfc/${PYNACL}
}


function move_tails_dependencies {
    # Move Tails dependencies in batch.
    t_sudo mv $HOME/${VIRTUALENV} /opt/tfc/
    t_sudo mv $HOME/${PYSERIAL} /opt/tfc/
    # t_sudo mv $HOME/${STEM}     /opt/tfc/
    t_sudo mv $HOME/${PYSOCKS}  /opt/tfc/

    # Requests
    t_sudo mv $HOME/${URLLIB3}  /opt/tfc/
    t_sudo mv $HOME/${IDNA}     /opt/tfc/
    t_sudo mv $HOME/${CHARDET}  /opt/tfc/
    t_sudo mv $HOME/${CERTIFI}  /opt/tfc/
    t_sudo mv $HOME/${REQUESTS} /opt/tfc/

    # Flask
    t_sudo mv $HOME/${WERKZEUG}     /opt/tfc/
    t_sudo mv $HOME/${MARKUPSAFE}   /opt/tfc/
    t_sudo mv $HOME/${JINJA2}       /opt/tfc/
    t_sudo mv $HOME/${ITSDANGEROUS} /opt/tfc/
    t_sudo mv $HOME/${CLICK}        /opt/tfc/
    t_sudo mv $HOME/${FLASK}        /opt/tfc/

    # Cryptography
    t_sudo mv $HOME/${SIX}          /opt/tfc/
    t_sudo mv $HOME/${PYCPARSER}    /opt/tfc/
    t_sudo mv $HOME/${CFFI}         /opt/tfc/
    t_sudo mv $HOME/${CRYPTOGRAPHY} /opt/tfc/

    # PyNaCl
    t_sudo mv $HOME/${PYNACL} /opt/tfc/
}


function verify_tails_dependencies {
    # Tails doesn't allow downloading over PIP to /opt/tfc, so we
    # first download to $HOME, move the files to /opt/tfc, and then
    # perform additional hash verification
    compare_digest e80eb04615d1dcd2546bd5ceef5408bbb577fa0dd725bc69f20dd7840518af575f0b41e629e8164fdaea398628813720a6f70a42e7748336601391605b79f542 '' ${VIRTUALENV}
    compare_digest 8333ac2843fd136d5d0d63b527b37866f7d18afc3bb33c4938b63af077492aeb118eb32a89ac78547f14d59a2adb1e5d00728728275de62317da48dadf6cdff9 '' ${PYSERIAL}
    # compare_digest a275f59bba650cb5bb151cf53fb1dd820334f9abbeae1a25e64502adc854c7f54c51bc3d6c1656b595d142fc0695ffad53aab3c57bc285421c1f4f10c9c3db4c '' ${STEM}
    compare_digest 313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12 '' ${PYSOCKS}

    # Requests
    compare_digest 719cfa3841d0fe7c7f0a1901b8029df6685825da7f510ba61f095df64f115fae8bfa4118fa7536231ed8187cdf3385cb2d52e53c1b35b8f4aa42f7117cc4d447 '' ${URLLIB3}
    compare_digest fb07dbec1de86efbad82a4f73d98123c59b083c1f1277445204bef75de99ca200377ad2f1db8924ae79b31b3dd984891c87d0a6344ec4d07a0ddbbbc655821a3 '' ${IDNA}
    compare_digest bfae58c8ea19c87cc9c9bf3d0b6146bfdb3630346bd954fe8e9f7da1f09da1fc0d6943ff04802798a665ea3b610ee2d65658ce84fe5a89f9e93625ea396a17f4 '' ${CHARDET}
    compare_digest 06e8e1546d375e528a1486e1dee4fda3e585a03ef23ede85d1dad006e0eda837ebade1edde62fdc987a7f310bda69159e94ec36b79a066e0e13bbe8bf7019cfc '' ${CERTIFI}
    compare_digest 9186ce4e39bb64f5931a205ffc9afac61657bc42078bc4754ed12a2b66a12b7a620583440849fc2e161d1061ac0750ddef4670f54916931ace1e9abd2a9fb09c '' ${REQUESTS}

    # Flask
    compare_digest 3905022d0c398856b30d2ed6bae046c1532e87f56a0a40060030c18124c6c9c98976d9429e2ab03676c4ce75be4ea915ffc2719e04e4b4912a96e498dcd9eb89 '' ${WERKZEUG}
    compare_digest 69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec '' ${MARKUPSAFE}
    compare_digest 658d069944c81f9d8b2e90577a9d2c844b4c6a26764efefd7a86f26c05276baf6c7255f381e20e5178782be1786b7400cab12dec15653e7262b36194228bf649 '' ${JINJA2}
    compare_digest 891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c '' ${ITSDANGEROUS}
    compare_digest 6b30987349df7c45c5f41cff9076ed45b178b444fca1ab1965f4ae33d1631522ce0a2868392c736666e83672b8b20e9503ae9ce5016dce3fa8f77bc8a3674130 '' ${CLICK}
    compare_digest bd49cb364307569480196289fa61fbb5493e46199620333f67617367278e1f56b20fc0d40fd540bef15642a8065e488c24e97f50535e8ec143875095157d8069 '' ${FLASK}

    # Cryptography
    compare_digest 326574c7542110d2cd8071136a36a6cffc7637ba948b55e0abb7f30f3821843073223301ecbec1d48b8361b0d7ccb338725eeb0424696efedc3f6bd2a23331d3 '' ${SIX}
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest fdefd3f63f56adff50723d6a88dc6db816d3d8a31b563599d2a3633ba796f6f70d5a9430510852b3d62b97357f8764f17eeab74b13df16c7cc34e1671a82373b '' ${CFFI}
    compare_digest 184003c89fee74892de25c3e5ec366faea7a5f1fcca3c82b0d5e5f9f797286671a820ca54da5266d6f879ab342c97e25bce9db366c5fb1178690cd5978d4d622 '' ${CRYPTOGRAPHY}  # manylinux1
    # compare_digest d8ddabe127ae8d7330d219e284de68b37fa450a27b4cf05334e9115388295b00148d9861c23b1a2e5ea9df0c33a2d27f3e4b25ce9abd3c334f1979920b19c902 '' ${CRYPTOGRAPHY}  # manylinux2010


    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
}


function install_tails_setuptools {
    # Download setuptools package for Tails and then authenticate and install it.
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-setuptools.txt  --require-hashes -d $HOME/
    t_sudo mv $HOME/${SETUPTOOLS} /opt/tfc/
    compare_digest a27b38d596931dfef81d705d05689b7748ce0e02d21af4a37204fc74b0913fa7241b8135535eb7749f09af361cad90c475af98493fef11c4ad974780ee01243d '' ${SETUPTOOLS}
    t_sudo python3.7 -m pip install /opt/tfc/${SETUPTOOLS}
    t_sudo -E rm /opt/tfc/${SETUPTOOLS}
}


function remove_common_files {
    # Remove files that become unnecessary after installation.
    $1 rm -r /opt/tfc/.git/
    $1 rm -r /opt/tfc/launchers/
    $1 rm -r /opt/tfc/tests/
    $1 rm    /opt/tfc/.coveragerc
    $1 rm    /opt/tfc/.travis.yml
    $1 rm    /opt/tfc/install.sh
    $1 rm    /opt/tfc/install.sh.asc
    $1 rm    /opt/tfc/pubkey.asc
    $1 rm    /opt/tfc/pytest.ini
    $1 rm    /opt/tfc/README.md
    $1 rm    /opt/tfc/requirements.txt
    $1 rm    /opt/tfc/requirements-dev.txt
    $1 rm    /opt/tfc/requirements-relay.txt
    $1 rm    /opt/tfc/requirements-relay-tails.txt
    $1 rm    /opt/tfc/requirements-setuptools.txt
    $1 rm    /opt/tfc/requirements-venv.txt
    $1 rm -f /opt/install.sh
    $1 rm -f /opt/install.sh.asc
    $1 rm -f /opt/pubkey.asc
}


function steps_before_network_kill {
    # These steps are identical in TCB/Relay/Local test configurations.
    # This makes it harder to distinguish from network traffic when the
    # user is installing TFC for Source or Destination computer: By the
    # time `kill_network` is run, it's too late to compromise the TCB.
    # Hopefully this forces adversaries to attempt compromise of more
    # endpoints during installation, which increases their chances of
    # getting caught.
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git gnome-terminal libssl-dev python3-pip python3-tk net-tools -y
    sudo torsocks git clone --depth 1 https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/
}


function install_tcb {
    # Install TFC for Source/Destination Computer.
    #
    # The installer configuration first downloads all necessary files.
    # It then disconnects the computer from network, before completing
    # the rest of the installation steps.
    steps_before_network_kill

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
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm -r /opt/tfc/src/relay/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/relay.py
    sudo rm    /opt/tfc/tfc.yml
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


function install_local_test {
    # Install TFC for local testing on a single computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    sudo torsocks apt install terminator -y

    install_virtualenv
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
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm /opt/tfc/tfc.yml
    sudo rm /opt/tfc/${VIRTUALENV}

    install_complete "Installation of TFC for local testing is now complete."
}


function install_developer {
    # Install TFC development configuration.
    #
    # This configuration will install TFC into `$HOME/tfc/`. This allows
    # you (the user) to easily make edits to the source between runs.
    # Note that it also means, that any malicious program with
    # user-level privileges is also able to modify the source files. For
    # more secure use on a single computer, select the local testing
    # install configuration.
    dpkg_check

    create_user_data_dir

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-tk terminator -y

    torsocks git clone https://github.com/maqp/tfc.git $HOME/tfc

    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-venv.txt --require-hashes

    python3.7 -m virtualenv $HOME/tfc/venv_tfc --system-site-packages

    . $HOME/tfc/venv_tfc/bin/activate
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-dev.txt
    deactivate

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop
    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"
    chmod a+rwx -R $HOME/tfc/

    # Remove unnecessary files
    sudo rm -f /opt/install.sh
    sudo rm -f /opt/install.sh.asc
    sudo rm -f /opt/pubkey.asc

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


function install_relay_ubuntu {
    # Install TFC Relay configuration on Networked Computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    install_virtualenv
    sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_common_files      "sudo"
    process_tcb_dependencies "rm"
    sudo rm -r /opt/tfc/src/receiver/
    sudo rm -r /opt/tfc/src/transmitter/
    sudo rm    /opt/tfc/dd.py
    sudo rm    /opt/tfc/tfc.py
    sudo rm    /opt/tfc/tfc.yml
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    check_tails_tor_version
    read_sudo_pwd

    # Apt dependencies
    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip -y || true  # Ignore error in case packets can not be persistently installed

    torsocks git clone --depth 1 https://github.com/maqp/tfc.git $HOME/tfc
    t_sudo mv $HOME/tfc/ /opt/tfc/
    t_sudo chown -R root /opt/tfc/

    verify_tcb_requirements_files
    verify_files

    create_user_data_dir

    install_tails_setuptools

    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt        --require-hashes -d $HOME/
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay-tails.txt --require-hashes -d $HOME/

    move_tails_dependencies
    verify_tails_dependencies

    t_sudo python3.7 -m pip install /opt/tfc/${VIRTUALENV}
    t_sudo python3.7 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    process_tails_dependencies "python3.7 -m pip install"
    deactivate

    # Complete setup
    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/
    t_sudo mv /opt/tfc/tfc.yml                        /etc/onion-grater.d/

    remove_common_files        "t_sudo"
    process_tails_dependencies "rm"

    t_sudo rm /opt/tfc/${VIRTUALENV}
    t_sudo rm -r /opt/tfc/src/receiver/
    t_sudo rm -r /opt/tfc/src/transmitter/
    t_sudo rm    /opt/tfc/dd.py
    t_sudo rm    /opt/tfc/tfc.py

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function t_sudo {
    # Execute command as root on Tails.
    echo ${sudo_pwd} | sudo -S $@
}


function install_relay {
    # Determine the Networked Computer OS for Relay Program installation.
    if [[ "$(cat /etc/os-release 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


function install_virtualenv {
    # Some distros want virtualenv installed as sudo and other do
    # not. Install both to improve the chances of compatibility.
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
}


function read_sudo_pwd {
    # Cache the sudo password so that Debian doesn't keep asking for it
    # during the installation (it won't be stored on disk).
    read -s -p "[sudo] password for ${USER}: " sudo_pwd
    until (t_sudo echo '' 2>/dev/null)
    do
        echo -e '\nSorry, try again.'
        read -s -p "[sudo] password for ${USER}: " sudo_pwd
    done
    echo
}


function check_tails_tor_version {
    # Check that the Tails distro is running Tor 0.3.5 or newer.
    included=($(tor --version |awk '{print $3}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$included" | sort -V | head -n1)" = "$required" ]]; then
        clear
        echo -e "\nError: This Tails includes Tor $included but Tor $required is required. Exiting.\n" 1>&2
        exit 1
    fi
}


function kill_network {
    # Kill network interfaces to protect the TCB from remote compromise.
    for interface in /sys/class/net/*; do
        name=`basename ${interface}`
        if [[ $name != "lo" ]]; then
            echo "Disabling network interface ${name}"
            sudo ifconfig ${name} down
        fi
    done

    sleep 1
    clear
    c_echo ''
    c_echo " This computer needs to be air gapped. The installer has "
    c_echo "disabled network interfaces as the first line of defense."
    c_echo ''
    c_echo "Disconnect the Ethernet cable and press any key to continue."
    read -n 1 -s -p ''
    echo -e '\n'
}


function add_serial_permissions {
    # Enable serial interface for user-level programs.
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


function c_echo {
    # Justify printed text to the center of the terminal.
    printf "%*s\n" $(( ( $(echo $1 | wc -c ) + 80 ) / 2 )) "$1"
}


function check_rm_existing_installation {
    # Remove TFC installation directory if TFC is already installed.
    if [[ -d "/opt/tfc" ]]; then
        if [[ ${sudo_pwd} ]]; then
            t_sudo rm -r /opt/tfc  # Tails
        else
            sudo rm -r /opt/tfc    # *buntu
        fi
    fi
}


function create_user_data_dir {
    # Backup TFC user data directory if it exists and has files in it.
    if [[ -d "$HOME/tfc" ]]; then
        if ! [[ -z "$(ls -A $HOME/tfc/)" ]]; then
            mv $HOME/tfc $HOME/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
        fi
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


function modify_terminator_font_size {
    # Adjust terminator font size for local testing configurations.
    #
    # The default font sizes in terminator config file are for 1920px
    # wide screens. The lowest resolution (width) supported is 1366px.
    width=$(get_screen_width)

    if (( $width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   $2  # Data diode config
    elif (( $width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     $2  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' $2  # Data diode config
    fi
}


function get_screen_width {
    # Output the width of the screen resolution.
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


function install_complete {
    # Notify the user that the installation is complete.
    clear
    c_echo ''
    c_echo "$*"
    c_echo ''
    c_echo "Press any key to close the installer."
    read -n 1 -s -p ''
    echo ''

    kill -9 $PPID
}


function dpkg_check {
    # Check if the software manager is busy, and if, wait until it
    # completes.
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


function arg_error {
    # Print help message if the user launches the installer with missing
    # or invalid argument.
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 19.04+)"
    echo    "  relay    Install Relay Program                (*buntu 19.04+ / Tails (Debian Buster+))"
    echo -e "  local    Install insecure local testing mode  (*buntu 19.04+)\n"
    exit 1
}


function root_check {
    # Check that the installer was not launched as root.
    if [[ !$EUID -ne 0 ]]; then
        exit_with_message "This installer must not be run as root."
    fi
}


function sudoer_check {
    # Check that the user who launched the installer is on the sudoers list.

    # Tails allows sudo without the user `amnesia` being on sudoers list.
    if ! [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        return
    fi

    sudoers=$(getent group sudo |cut -d: -f4 | tr "," "\n")
    user_is_sudoer=false

    for sudoer in ${sudoers}; do
        if [[ ${sudoer} == ${USER} ]]; then
            user_is_sudoer=true
            break
        fi
    done

    if ! ${user_is_sudoer}; then
        exit_with_message "User ${USER} must be on the sudoers list."
    fi
}


function architecture_check {
    # Check that the OS is 64-bit, and not 32-bit.
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        exit_with_message "Invalid system architecture."
    fi
}


function exit_with_message {
    # Print error message and exit the installer with flag 1.
    clear
    echo ''
    c_echo "Error: $* Exiting." 1>&2
    echo ''
    exit 1
}


set -e
architecture_check
root_check
sudoer_check
sudo_pwd=''

case $1 in
    tcb   ) install_tcb;;
    relay ) install_relay;;
    local ) install_local_test;;
    dev   ) install_developer;;
    *     ) arg_error;;
esac
