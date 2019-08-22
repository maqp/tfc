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
    compare_digest c3f27d766f2795bf0c87ddb0cec43f1f9919c2cf20db5eff62e818d67436f1520b6001bf9e7649c5508e62b221c02039b6cb29f7393ba1dbacf9a442cb3bb8b2 '' requirements.txt
    compare_digest 2c9e865be4231d346504bef99159d987803944b4ed7a1f0dbb7e674d4043e83c45771da34b7c4772f25101b81f41f2bafc75bfd07e58d37ddf7d3dc1aa32da24 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest e4f81f752001dbd04d46314ea6d8867393c3ad5ed85c2d3e336a8018913446f5855525e0ca03671ab8d26d8af1fe16416c8f5a163cad795867284a726adfeb31 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 651fccf97f1a1a3541078a19191b834448cb0c3256c6c2822989b572d67bc4b16932edea226ecf0cbd792fc6a11f4db841367d3ecd93efa67b27eaee0cc04cb7 '' LICENSE-3RD-PARTY
    compare_digest 84a4e5b287ba4f600fc170913f5bdcd3db67c6d75a57804331a04336a9931c7ce9c58257ad874d3f197c097869438bb1d2932f06f5762c44f264617681eab287 '' relay.py
    compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
    compare_digest 1ab71b773a0451807eda87a1442dd79529de62f617e8087a21c0f3ad77e4fe22218e05a94d19d1660b2967a9908fb722f750a64a75e650b178c818c8536f64db '' requirements-relay.txt
    compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
    compare_digest a7b8090855295adfc22528b2f89bed88617b5e990ffe58e3a42142a9a4bea6b1b67c757c9b7d1eafeec22eddee9f9891b44afffa52d31ce5d050f08a1734874d '' tfc.py
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest fed9f056541afe1822ec41bce315fc6ce94652318088ecc905ddc657a15525d740ca83ff335e5090b9e3844027a706990da72a754ffa3dcd255b21e263597c78 launchers/ TFC-Local-test.desktop
    compare_digest 011a64aa7790253b008f0adfe940108dc94c08adec9b3a42efd1ac0d6405a82d828b3d416736ad64235b6b90ef2f6712fc10a70d8e97870670e5b84cf25fe54e launchers/ TFC-RP.desktop
    compare_digest 12c86594b28f5dae48e4d216781034917ab80ca46f30cb3d33a0dec615d415830fdc41228f933c8fef651eb51643390fe5521e70f9efc642ea5c8b2e34442e00 launchers/ TFC-RP-Tails.desktop
    compare_digest 270153a45e5426db326ba2144ca454bb57ddf8f53731c1948ee8fa33dedcb98e32e19506b0fa923e5a7f6fca9a5b67338216c19417e52289726721efe12abd98 launchers/ TFC-RxP.desktop
    compare_digest 691d0cc4f03bd9c2874711ba97e347e705e4eadf53c5b14562e7e1a419ae892a9ce156b6e5a26945bde72c0b3e56ec6ca2d24fb3bf23848fb44808b7681e4141 launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest 92c7f788c41984cf75ad879e281f73a1a334dd759b858be11f91481a0e754e2db1527c9d3ab369aad7b8cf139492d5809c0c0542e46ff27637ee5b4b655b726f src/common/ crypto.py
    compare_digest 0b830ad6705f90dc8e554c8b06f31054d9222d3b35db92470eaf3f9af935aae3107b61142ea68129943e4227a45dfe26a87f23e9dd95a7794ae65c397bd35641 src/common/ db_contacts.py
    compare_digest bad54588b3e713caf94aba3216090410f77f92064aecfea004a33487a21f9fffcf5d05782b91104c27ec499e38196881a76d6002ec1149816d8c53560182fba9 src/common/ db_groups.py
    compare_digest 46e503af15fb7a1ea8387fa8f22674d0926eda0d879d43f99076ca967295d5e3727a411aa11c4bb4d832783c5daa9f4b7ef4491b90112c1be405910d269abaf4 src/common/ db_keys.py
    compare_digest 68b2c7761623ff9e4ce596e170c8e1ce2b6129bbbbb9fc9e48a120974d30db6e471bb5d514f5dc8d7edc8e0abcb0cd0c2b4e5da739f4d98c6fa8c8e07af0d8ef src/common/ db_logs.py
    compare_digest 1a3783e6ea5643bc799b9745d0a8abb82f9e814ca01da3414df86faaa007aaa21609a88e07c8947e43567a787f114db57143f10585053e92f96807858adec96a src/common/ db_masterkey.py
    compare_digest 5befbe864e2b09125be2b04cdfee8d13e7616715fc20a0fa06da270e34b555602b2df825fd429059056b2beb1497c50dafdc682d59a43a483837445861647e9d src/common/ db_onion.py
    compare_digest 328375464a5064829621fb8154c94cf15a1e7564122d99f03c9e578dcd6d6f264a671412b738b4971a6e505062673df40cc89f7b67c7ef2a761236c3f1247e93 src/common/ db_settings.py
    compare_digest e3f760b03eb38d3ec97b04123f8cf36825d616e126bfb9fb575927586cbb1911dce448c08cb8cfb26be0635c2e6abaaad8ea94f0513672c288c78892010ab146 src/common/ encoding.py
    compare_digest f7ff99c8a5f84b892b959fe391cdfe416d103a5a4d25fcd46842f768583a5b241036ee9c4b6713a938e8234f5af82a770ffe28975292d162b6d5bea69a120ad8 src/common/ exceptions.py
    compare_digest 67cbb9e983aeb49d8a0cc8666aa5c1dad4b868e4fc968c72c7fc4290b886fae9a58ef84f5942d8a08b19621cc2fe01b787ac10bff8b63393e6addaa178da4ea7 src/common/ gateway.py
    compare_digest 618cbaccb4f50bc6e551cd13570693d4d53cfdfdc00b7ff42ff9fd14f0dadf7a15c9bc32c8e53801aca42348826568a2aa9117bdbf79bbcc4217a07c94c9efd3 src/common/ input.py
    compare_digest 14f9a5f06443b50251272939b92eaf287fecfb4e3c9882254f13757259d9d791ac1e66c46fd0475d1e3161ff27f16ad7b4de04ac564500cae60d27a631d42e36 src/common/ misc.py
    compare_digest b4efca327d057f9b3304d9f0415d23e95ba88230576a1a8d8be85c3e25364e7420389af36df4b4dacf62b5df11cb62f1ca7d0b6c03aee6b591282d51bbc119e3 src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest 9e9db25e73e0abb312b540d7601be7dfecae8d0aef6497feb2570f9ddf788fa0e261e276ed5a40e75fee0e0c6e86ccf3b05c110846fde804c302d4aa80a930e5 src/common/ reed_solomon.py
    compare_digest 374a9846d2a1f4b462d9fd4b6fd468ecdaf3a1d1ac25916214e949604e83eff66a969a7fe6af79f23f4bf2477f7a390374714602714c42448073392e56065a41 src/common/ statics.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest 12cf1127afc6761e61f6dadf6b6f382f4ff00291bcb00a6e9b21c98d1263596041b31892fbfc4be6348bb622aa19b50f38303d51a651d63c2024e8e466cbef07 src/receiver/ commands.py
    compare_digest 760edaa44ff6175612b02f95b02b291ae369733a18cc5f87d525b46bcebc35c8a2d169a47962417eab434cf26ea6d5bfcd8894153fae668bb4a8cf2ceb8871f0 src/receiver/ commands_g.py
    compare_digest ee192c3529c51031110a49cf919a7b9e516d0eb0cc826da85587323480065cf53d4115f78f8008c305d074628b9de65d9b262ef790c178078cf74d8b3466ae3f src/receiver/ files.py
    compare_digest b3b0a61f3aba200e06bb2c6e05a067931be37ccfbc0768167a9d8651f7a8f6ea47871dcb5d63cf238f040d6c482fc45967a5a2ccbadb1308ec76b287b88fa3a6 src/receiver/ key_exchanges.py
    compare_digest 65307a0ea2c9ae69859cc8ef62a5d7e45c27bdf5a4ec44db704df143ce3630fdc077fafc7fd4cfc0cd922f350f49f0aa0a880192c40c614b6d3117804ea683ae src/receiver/ messages.py
    compare_digest b33a7696b31265027bb137aacd80845d4fefbd112144f3e01cfe4e083e5b6575fcdab387ae9d2435dd1c82bf0cf31b55f934cd12256a7ac78b4b13cc3d593987 src/receiver/ output_loop.py
    compare_digest 7a81a142d21ebf8779fa0fec9aeef922d21bd6d57643061722d91047ecafeea7f0bfdd3a2919251a83a02cecbef909756fdb62881d5d2a844c3daba0e7069bf5 src/receiver/ packet.py
    compare_digest 01b0ce92b4ab8f37eed55356a65f4d25ffff590955b5ca124dbb541bdec6968e8235242bf47ad5c2bfe57a30d54cf494d9f3836e3d53a73748f203ff68381c14 src/receiver/ receiver_loop.py
    compare_digest 17ab4e845274ac6901902537cbea19841de56b5d6e92175599d22b74a3451ecafa3681420e2fcc7f53f6b2ebb7994e5903aabb63a5403fbf7fb892509bb5d11c src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest a324e4b065c2bb8c66c1e0e7fbc11de85f4408e4a3c3afd81bbd6829fae4f6cf6a3bba284864476356a57947670e7dffcd6f30faf03e38b38dbed84305def042 src/relay/ client.py
    compare_digest 6f0f916f7c879c0383e8dc39593385de8f1ab2f7ba99f59b7fcbee947f8fcfae0935a98dcd8de1db3a600a0d8469a369ea38915fe2932c00b6756fb4944c938d src/relay/ commands.py
    compare_digest 261c9a0e7cb552c900f5234136c6251896bb03277c9ceaf175791012433a282373d6af1eec6be916aa955e04d5ffde2fc4bf3d153077baf00731249132b90658 src/relay/ onion.py
    compare_digest a18aa0ca4ffff7be99721c094ae44a95ed407e5e4cb25016ce14bf9fca7fef950d0b0460fd91689f2003aeb7f8385cb4f88a5f2e3f7f4ba7b88634412853d888 src/relay/ server.py
    compare_digest e03b2896049d6c4f98cc9b52ae43a32078ffe93f6a18848fb96cf4051752872ad20463754fad61244e914b2082839d8297f0d3357e20c8dd22881e885bfbd32a src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest bb471267d37c73b37f3695bd3f28929612fe2074f7303b77f40cba0be84e975e3498402cbba2b402e45e35e81512ed2f67629cf0584536f36903b326d35cf557 src/transmitter/ commands.py
    compare_digest b861e16a6fbe2a93bf9f2dcf3f7f42d3f3ebf240aeaa2d752169a6807e2371eaaaf6230e0a71e6fe1e41e7ce5eb0515e8ec95bed5a7a7a263f42d715d23c399c src/transmitter/ commands_g.py
    compare_digest d5ad53e3ba7ae32e0c6255f5fca3a60c267b028d7dfb2f2e28768c2f8824b0ad25afc7edc3a5d6d69bb76986ff8d81549d50d71d8b46ca6a0a9dc37324ae027a src/transmitter/ contact.py
    compare_digest dffc059fc25cbfb17beb9f83fc2d52ce043e9b923580ccf655933cf66fefcf6e18bcb923d7cb42a7d547126f938ff867a7638ffd13c14953b4a2d700f8f0d5c4 src/transmitter/ files.py
    compare_digest 061d7f3c4f737afafacc65bea744ac9bad16c6b064ab6281a3ab2079b18d984afa00b93e3861209425f78807e335925d824e018e80523b5380ac5244b8f5b8c2 src/transmitter/ input_loop.py
    compare_digest 6465a819b1a449145fdb676819446761d8faa96921623433b12b9386b781d7964368c0f2cd5fe48aad5beda3cdc0f6496e95ae89650addd91619c5984979584c src/transmitter/ key_exchanges.py
    compare_digest 1249ba23d30031ec8c1b42e999e52bc0903a0ad00c317d27d51c8d650b3343c9475319db6e0f2f16dfae39a942e01eeaae8eb862d541957b1f51690b1eb0f202 src/transmitter/ packet.py
    compare_digest 93f874a8d97312ab4be10e803ba5b0432a40cf2c05541775c7117aa68c18e78e52e814d38639b33e87dc33df1773e04dc2c789e61e08c12d9c15512dd9e5d4d3 src/transmitter/ sender_loop.py
    compare_digest bcad5d4b9932f1b35b2c74dc083233af584012cacdd1d2cb04b28115b4e224118ce220252754ae532df0adcc6c343b1913f711cf3bd94da9c4cd3eaf23e4b196 src/transmitter/ traffic_masking.py
    compare_digest ccbda8415c23b23cc10cda57fb6b32df71e6510f3cb94c7f932b40adcf5f0abdd9842c48a992d56c95755e3024aebd7ecb05f69eb18f3c41656d94cfeabb38fa src/transmitter/ user_input.py
    compare_digest 4c5b9c877474257d078723d32533ba614d72bad7b108588f49fae6c26dcb2c49994b256b5457caee0e5ab4628f728b25a54551ce778b585cbb8b1f8c947dc7e6 src/transmitter/ windows.py
}


# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
ASN1CRYPTO=asn1crypto-0.24.0-py2.py3-none-any.whl
CERTIFI=certifi-2019.6.16-py2.py3-none-any.whl
CFFI=cffi-1.12.3-cp37-cp37m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.7-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.1.1-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10.1-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.7.0-py3-none-any.whl
REQUESTS=requests-2.22.0-py2.py3-none-any.whl
SETUPTOOLS=setuptools-41.2.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.3-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.7.3-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.15.5-py2.py3-none-any.whl


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
    sudo $1 /opt/tfc/${ASN1CRYPTO}
    sudo $1 /opt/tfc/${CRYPTOGRAPHY}
}


function process_tails_dependencies {
    # Manage Tails dependencies in batch. The command that uses the
    # files is passed to the function as a parameter.

    # Pyserial
    t_sudo $1 /opt/tfc/${PYSERIAL}

    # Stem
    t_sudo $1 /opt/tfc/${STEM}

    # PySocks
    t_sudo $1 /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo $1 /opt/tfc/${URLLIB3}
    t_sudo $1 /opt/tfc/${IDNA}
    t_sudo $1 /opt/tfc/${CHARDET}
    t_sudo $1 /opt/tfc/${CERTIFI}
    t_sudo $1 /opt/tfc/${REQUESTS}

    # Flask
    t_sudo $1 /opt/tfc/${WERKZEUG}
    t_sudo $1 /opt/tfc/${MARKUPSAFE}
    t_sudo $1 /opt/tfc/${JINJA2}
    t_sudo $1 /opt/tfc/${ITSDANGEROUS}
    t_sudo $1 /opt/tfc/${CLICK}
    t_sudo $1 /opt/tfc/${FLASK}

    # Cryptography
    t_sudo $1 /opt/tfc/${SETUPTOOLS}
    t_sudo $1 /opt/tfc/${SIX}
    t_sudo $1 /opt/tfc/${ASN1CRYPTO}
    t_sudo $1 /opt/tfc/${PYCPARSER}
    t_sudo $1 /opt/tfc/${CFFI}
    t_sudo $1 /opt/tfc/${CRYPTOGRAPHY}
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
    sudo torsocks apt install git libssl-dev python3-pip python3-tk net-tools -y
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
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements.txt       --require-hashes
    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-relay.txt --require-hashes
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
    sudo rm    /opt/tfc/${VIRTUALENV}

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer running
    # Tails live distro (https://tails.boum.org/).
    check_tails_tor_version

    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install git libssl-dev python3-pip -y || true  # Ignore error in case packets can not be persistently installed

    git clone --depth 1 https://github.com/maqp/tfc.git $HOME/tfc
    t_sudo mv $HOME/tfc/ /opt/tfc/

    verify_tcb_requirements_files
    verify_files
    create_user_data_dir

    t_sudo python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay.txt --require-hashes -d /opt/tfc/

    process_tails_dependencies "python3.7 -m pip install"

    t_sudo mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    t_sudo mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    remove_common_files        "t_sudo"
    process_tails_dependencies "rm"
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
    if [[ "$(lsb_release -a 2>/dev/null | grep Tails)" ]]; then
        install_relay_tails
    else
        install_relay_ubuntu
    fi
}


function install_virtualenv {
    # Determine if OS is debian and install virtualenv as sudo so that
    # the user (who should be on sudoers list) can see virtualenv on
    # when the installer sets up virtual environment to /opt/tfc/.
    distro=$(lsb_release -d | awk -F"\t" '{print $2}')

    if [[ "$distro" =~ ^Debian* ]]; then
        sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    else
        torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    fi
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
