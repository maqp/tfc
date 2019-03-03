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
compare_digest a27d0a626f0963ee962a9bd9df98f157dcbb1fc7abf30322d8657f5db8b182f3ed7a3f2b736880e32121fb9bc6dce29cd7cb78cb77d5a82e42cadbacbe6b2651 '' requirements.txt
compare_digest d5e6ef9d3743cc81440d0f1024389ce0c10c23771f3aee95886731f1a7cbdf64fa5e0245d370382f8988d3c1758d0548e384e05635216ded3552dee80a03b16a '' requirements-venv.txt
}

verify_files () {
compare_digest dec90e113335d3274d87c3e12dda5a3205df57bd10c1e0532ecad34409520ce0596db21e989478836d4a0ea44da8c42902d2d8f05c9ad027a5560b4d0d5b9f13 '' dd.py
compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
compare_digest 04bc1b0bf748da3f3a69fda001a36b7e8ed36901fa976d6b9a4da0847bb0dcaf20cdeb884065ecb45b80bd520df9a4ebda2c69154696c63d9260a249219ae68a '' LICENSE-3RD-PARTY
compare_digest 1dd17740ffb6bd4da5de8b00da8e0e1e79d9c81771bf62dee9d3e85e3fd6b1254ec1d011c217b0102f08384c03b63a002b6cddc691a2d03eaa3faddd8cef5a15 '' relay.py
compare_digest 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
compare_digest 6a27003e7feb81a2ef7a7ffb114d7130120cad53a2687f7ba7200eb3f65156ad0dc1dcb713234593df7dac9da047c4e1e7306f58ddbaae4751437c63c309c1e4 '' requirements-relay.txt
compare_digest 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png
compare_digest cec2bc228cd3ef6190ea5637e95b0d65ea821fc159ebb2441f8420af0cdf440b964bdffd8e0791a77ab48081f5b6345a59134db4b8e2752062d7c7f4348a4f0f '' tfc.py
compare_digest 7a3d7b58081c0cd8981f9c7f058b7f35384e43b44879f242ebf43f94cec910bab0e40bd2f7fc1a2f7b87ebc8098357f43b5cede8948bd684be4c6d2deaf1a409 '' uninstall.sh

compare_digest 2f426d4d971d67ebf2f59b54fb31cff1a3e2567e343bfa1b3e638b8e0dffed5d0c3cac1f33229b98c302fee0cca3cc43567c2c615b5249a2db6d444e89e5fc70 launchers/ terminator-config-local-test
compare_digest 57110f77d5317cdebd38d478e6836ccea038ae17d6ea46e76e02358b367224468ee12e2a884bcf9f75fe1ae5d3aff5dcb6e7114032e54626ac18b53230b2949d launchers/ TFC-Local-test.desktop
compare_digest 7223cd66c5c9b5850a1c1c81d8751541ae3eb0b4e44b989ae6ec06618c167ee4f0c4e8ae374a1da654afa8eb751468cd06bd0f27638420b9f5befb7352c85ba9 launchers/ TFC-RP.desktop
compare_digest a72ce74903aafa47bbcced11b87396445916d53651aedc8fd1f0a03b87463673eed8b312e624bd559d5f382cc8f484c8e891932588e241c711bd082fda88f8ff launchers/ TFC-RP-Tails.desktop
compare_digest 0fc9b6e7ccbfe87ef39d2d1cd4434becd2070cdab72b3a215e9879fe060ce3c2a46251168ecc69e64c10d70210e50733f8e61abf6429ba6a811d91682683a8a8 launchers/ TFC-RxP.desktop
compare_digest 4c61d5f11da0f2b673a26f2070d8040df71fba9285f36880a718fa711c7cefbaf5d47fd506ae4ddb1f7a6a1d5afccfdbfe096a0204ad6a78fde9fcefa3c88908 launchers/ TFC-TxP.desktop

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
compare_digest 6a6434cdbb35c5dc0ebce6ee961da0d3afffe09b9cf0988cf08cc55d9cd9195462c1b986ec96e3521f88dea7c390daa7419446efd4bf3ed7383991e7f7347828 src/common/ crypto.py
compare_digest ce3a2b1890393801cad88162772a4d90799f95dc7d438c64856db92fa0a9b02431077e4c856a18c0953b242efc37e035fce96740b9379c966bd9fd76338889ef src/common/ db_contacts.py
compare_digest a071463fbc0e83237cc482ef709c0957f8774c325730c89a3deb7839d0997e47a3163c896df70e96e1c150f2f7dda7b096c808bba3dededddcb0036bfcc0f63c src/common/ db_groups.py
compare_digest 4855baf9d9bd48d210981e380ebc2d7ff65b7e13392606f386769e10ba918843e50ba6174e51a74f2d6841aa8b1f466e7f65a901143f484bdbe312ccbf9eb11e src/common/ db_keys.py
compare_digest 13138abd171b7b8db7b7443aa2cef5a5b000aa96a23a9169089c12b8ae6c4f23b5519b248a54be8767862adce03e98def314e471ffd74fdfc9bf1fa8f31c8e90 src/common/ db_logs.py
compare_digest 8d53e7348abf71aa1e054e5e852e171e58ed409c394213d97edc392f016c38ce43ed67090d3623aaa5a3f335992fd5b0681cfb6b3170b639c2fa0e80a62af3a4 src/common/ db_masterkey.py
compare_digest 516577100e4e03068cfcb0169975b86a258b8aafddddf995f434c98d0b2d81a2d96a45bca473ddeb6980dfd71420f489eee2d82a9053bf02c87d1acddf9b7ecf src/common/ db_onion.py
compare_digest 83b2a6d36de528106202eebccc50ca412fc4f0b6d0e5566c8f5e42e25dd18c67ae1b65cf4c19d3824123c59a23d6258e8af739c3d9147f2be04813c7ede3761d src/common/ db_settings.py
compare_digest 804e8124688e808440db585f6b1a05667666353684a4b31535100df7e54f0c5b91f5d61998a64717e710a62c7d8185b99b6012f713f3becaa7d73a39dcb5e774 src/common/ encoding.py
compare_digest 0e3e6a40928ab781dbbca03f2378a14d6390444b13e85392ea4bdfb8e58ae63f25d6f55b2637f6749e463844784ea9242db5d18291e891ee88776d4c14498060 src/common/ exceptions.py
compare_digest 77b810f709739543dc40b1d1fbafb2a95d1c1772b929d3a4247c32e20b9bb40039c900ff4967c4b41118567463e59b7523fbbbf993b34251e46c60b8588f34ab src/common/ gateway.py
compare_digest e27f950719760cc2f72db8e4a3c17389b2a52f34476c0ac4aeb17b050d27cb86209d49b83b049943c2bd97228de433834061dc0abffd61459502cd1303aca9c1 src/common/ input.py
compare_digest 18efc508382167d3259c2eb2b8adcddda280c7dbc73e3b958a10cf4895c6eb8e7d4407bc4dc0ee1d0ab7cc974a609786649491874e72b4c31ad45b34d6e91be3 src/common/ misc.py
compare_digest f47308851d7f239237ed2ae82dd1e7cf92921c83bfb89ad44d976ebc0c78db722203c92a93b8b668c6fab6baeca8db207016ca401d4c548f505972d9aaa76b83 src/common/ output.py
compare_digest dc5fdd0f8262815386896e91e08324cda4aa27b5829d8f114e00128eb8e341c3d648ef2522f8eb5b413907975b1270771f60f9f6cdf0ddfaf01f288ba2768e14 src/common/ path.py
compare_digest f80a9906b7de273cec5ca32df80048a70ea95e7877cd093e50f9a8357c2459e5cffb9257c15bf0b44b5475cdd5aaf94eeec903cc72114210e19ac12f139e87f3 src/common/ reed_solomon.py
compare_digest 0f58763f172daa457237f103146fb4c61b3cf8b06875f44ed934a2677c57041fa7902ac2730e6340c18a2b8ac5459ff1c2854fee325bd0d343885bb582c68c38 src/common/ statics.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
compare_digest 35b035f2794b5d7618eeafd91781246a0100bac9ff6a1f643b16068d5b2dc2946c799e91beba77d94e4118f99d6d6653974ebd5d4008133131f3bf44a7a190fb src/receiver/ commands.py
compare_digest 09f921aaaeae96ee6e9ff787990864ba491d4f8b10c613ab2a01f74c00b62d570270323ea2f5dc08befd8aa7bf4be0c609f8dca1862e4465e521b8016dff14da src/receiver/ commands_g.py
compare_digest 7b1d45caf3faf28c484d7d8d0c96ff9ba6e840682b002e438eac620904d3ca39483009a079d300489d80e22025ba301fa483f235193de5b55a62e9dedb25967f src/receiver/ files.py
compare_digest 5dee12fdbb8bade16e2d7f97c8791a39f408ec7eaeee89c75beac799584f9ae4d6d3e9495693630d7cb2c8a167c3e542f0d28b78725821ff14f04eb706afbe71 src/receiver/ key_exchanges.py
compare_digest 2894c847fe3f69a829ed7d8e7933b4c5f97355a0d99df7125cee17fffdca9c8740b17aa512513ae02f8f70443d3143f26baea268ace7a197609f6b47b17360b7 src/receiver/ messages.py
compare_digest 57ebdf412723b5ab4f683afeda55f771ef6ef81fde5a18f05c470bca5262f9ff5eefd04a3648f12f749cec58a25fa62e6dfb1c35e3d03082c3ea464ef98168b1 src/receiver/ output_loop.py
compare_digest 3b84dbe9faffeab8b1d5953619e38aefc278ce4e603fd63beaee878af7b5daff46b8ed053ad56f11db164b1a3f5b694c6704c66588386b06db697281c9f81bbf src/receiver/ packet.py
compare_digest 1e5240d346a016b154faf877199227edf76e027d75e1e921f2024c5dd1d0a40c1de7e9197077786a21474a4bbf2c305d290214aacdea50f5abaeb39963ca08a6 src/receiver/ receiver_loop.py
compare_digest e84a92fa500492af0cc16038fd388c74c387334898b870e57bc599d1b95da85b579d50ba403cdfc82ce8d4d5765fc59e772796d54faa914d0b5874150428d762 src/receiver/ windows.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
compare_digest 62ac101830793c4bbf9b85f714b6d3609ae8f05aa7be36d32c54df1b27ec8c0b17e71de8ad3db4af9ebba6886d0ec4cf7990c36a13469fa316b4bc19b2fe7086 src/relay/ client.py
compare_digest 02c764d58ef8d02f95050cec41aa41fa90938ea08e0107ed49d3ae73357115b48f23f291dfc238ec3e45b12a705089b5c2ad3a1b30f27abb0a4c7498271161a3 src/relay/ commands.py
compare_digest d5cf0b3522490ca34b9171b036704fe0a2c79f338c8bbbaea6fcd4d186c4e30f6d9fe96634babfce3afa5c043eadb360d83bdf2c14d5c34616d4cab09eef29ce src/relay/ onion.py
compare_digest bc6d33d5e9439c1e7baf82c1eb43fbb21af6109db366082d124be2b3c70f90e6dda7f38f0e5cd55e3de0019ced0e0548f10fbe3792f0f621a4f2e31a0ef8496d src/relay/ server.py
compare_digest 380a78c8c0918e33fb6be39a4c51f51a93aa35b0cf320370d6fb892b5dade920e8ca4e4fe9d319c0a0cdc5b3a97f609fdee392b2b41175379200b1d793b75593 src/relay/ tcb.py

compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
compare_digest f91c0f616555725e0d2a4d8e2ee2bf39e1ebc4cbdf0a2547f4e4b5e4f1ee88743273cffb422a43dff98ba42772b18ceb4c270628f933392e27fa5cd6cae991ce src/transmitter/ commands.py
compare_digest f7cf493506a19b9732ae9f780aeb131342a47644632fcf88f0df01f0bda88252fdbad37a4b80e87f97e57feb50079ac2e5194598d745163846e30fdd6d32fe60 src/transmitter/ commands_g.py
compare_digest a1b6af28645df531be3a670375ce3a3da1a48b279d646f04b3c14cfbdf7006060955f33595a2963f98a495ec16dfe969325842495d8fbfae5f93e1459ed047c4 src/transmitter/ contact.py
compare_digest 184c35a32a3858893c67622a21fc7fdbd88bc61f82d4b655ad26ef008563cdb31430a3b713b92c98ea8d983ebadd0db6f9de3f9b1c07ac3dce4cf405aedf21ae src/transmitter/ files.py
compare_digest 019c178982f89b93ba69d26e60625a868380ac102b10351ac42c4d1321a45dd7186694d86028371185a096cce2e2bbe2d68210552439e34c3d5166f67b3578ee src/transmitter/ input_loop.py
compare_digest 742fba91ebd67dca247d03df4cf1820fc6b07e6966449282d7c4019f48cc902dc8dfc4120be9fdd6e61a4f00dd7753a08565a1b04395bc347064631d957c9d82 src/transmitter/ key_exchanges.py
compare_digest a59619b239b747298cc676a53aa6f87a9ef6511f5e84ec9e8a8e323c65ab5e9234cb7878bd25d2e763d5f74b8ff9fe395035637b8340a5fd525c3dc5ccbf7223 src/transmitter/ packet.py
compare_digest c2f77f8d3ebf12c3816c5876cd748dc4d7e9cd11fe8305d247783df510685a9f7a6157762d8c80afda55572dcae5fe60c9f39d5ec599a64d40928a09dd789c35 src/transmitter/ sender_loop.py
compare_digest 5d42f94bf6a6a4b70c3059fd827449af5b0e169095d8c50b37a922d70955bf79058adc10da77ebb79fb565830168dccb774547b6af513b7c866faf786da7c324 src/transmitter/ traffic_masking.py
compare_digest 22e8ba63c1391233612155099f5f9017d33918180f35c2552e31213862c76e3048d552f193f9cd3e4e9a240c0ef9bef4eabefe70b37e911553afeceede1133ca src/transmitter/ user_input.py
compare_digest 39a7b3e4457d9aa6d53cb53d38c3ed9adbd9e3250008b4e79b5a174b9227fd0fac6dad30e6e9b8fe3d635b25b2d4dfc049804df48d04f5dfcc1016b2e0a42577 src/transmitter/ windows.py
}


# PIP dependency file names
ARGON2=argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
ASN1CRYPTO=asn1crypto-0.24.0-py2.py3-none-any.whl
CERTIFI=certifi-2018.11.29-py2.py3-none-any.whl
CFFI=cffi-1.12.2-cp36-cp36m-manylinux1_x86_64.whl
CHARDET=chardet-3.0.4-py2.py3-none-any.whl
CLICK=Click-7.0-py2.py3-none-any.whl
CRYPTOGRAPHY=cryptography-2.6.1-cp34-abi3-manylinux1_x86_64.whl
FLASK=Flask-1.0.2-py2.py3-none-any.whl
IDNA=idna-2.8-py2.py3-none-any.whl
ITSDANGEROUS=itsdangerous-1.1.0-py2.py3-none-any.whl
JINJA2=Jinja2-2.10-py2.py3-none-any.whl
MARKUPSAFE=MarkupSafe-1.1.1-cp36-cp36m-manylinux1_x86_64.whl
PYCPARSER=pycparser-2.19.tar.gz
PYNACL=PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
PYSERIAL=pyserial-3.4-py2.py3-none-any.whl
PYSOCKS=PySocks-1.6.8.tar.gz
REQUESTS=requests-2.21.0-py2.py3-none-any.whl
SIX=six-1.12.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.24.1-py2.py3-none-any.whl
VIRTUALENV=virtualenv-16.4.3-py2.py3-none-any.whl
WERKZEUG=Werkzeug-0.14.1-py2.py3-none-any.whl


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

    sudo apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files
    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    kill_network

    create_user_data_dir

    verify_files

    sudo python3.6 -m pip install /opt/tfc/${VIRTUALENV}
    sudo python3.6 -m virtualenv /opt/tfc/venv_tcb --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    process_tcb_dependencies "python3.6 -m pip install"
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
    sudo rm    /opt/install.sh
    sudo rm    /opt/install.sh.asc
    sudo rm    /opt/pubkey.asc
    process_tcb_dependencies "rm"

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


install_local_test () {
    dpkg_check
    check_rm_existing_installation

    sudo apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files
    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    upgrade_tor

    sudo torsocks apt install terminator -y

    torsocks python3.6 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.6 -m virtualenv /opt/tfc/venv_tfc --system-site-packages

    . /opt/tfc/venv_tfc/bin/activate
    sudo torsocks python3.6 -m pip install -r /opt/tfc/requirements.txt       --require-hashes
    sudo torsocks python3.6 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
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
    sudo rm    /opt/install.sh
    sudo rm    /opt/install.sh.asc
    sudo rm    /opt/pubkey.asc
    process_tcb_dependencies "rm"

    install_complete "Installation of TFC for local testing is now complete."
}


install_developer () {
    dpkg_check

    upgrade_tor
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk terminator -y

    cd $HOME
    torsocks git clone https://github.com/maqp/tfc.git
    cd $HOME/tfc/

    torsocks python3.6 -m pip install -r requirements-venv.txt --require-hashes
    python3.6 -m virtualenv venv_tfc --system-site-packages

    . /$HOME/tfc/venv_tfc/bin/activate
    torsocks python3.6 -m pip install -r requirements.txt       --require-hashes
    torsocks python3.6 -m pip install -r requirements-relay.txt --require-hashes
    torsocks python3.6 -m pip install -r requirements-dev.txt
    deactivate

    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"

    sudo cp $HOME/tfc/tfc.png                   /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-Dev.desktop /usr/share/applications/
    sudo sed -i "s|\$HOME|${HOME}|g"            /usr/share/applications/TFC-Dev.desktop

    chmod a+rwx -R $HOME/tfc/

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


install_relay_ubuntu () {
    dpkg_check
    check_rm_existing_installation

    sudo apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-setuptools python3-tk net-tools -y
    sudo torsocks git clone https://github.com/maqp/tfc.git /opt/tfc

    verify_tcb_requirements_files

    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes -d /opt/tfc/
    sudo torsocks python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes -d /opt/tfc/

    upgrade_tor

    torsocks python3.6 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.6 -m virtualenv /opt/tfc/venv_relay --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torsocks python3.6 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes
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
    sudo rm    /opt/install.sh
    sudo rm    /opt/install.sh.asc
    sudo rm    /opt/pubkey.asc
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

    create_user_data_dir

    t_sudo python3.6 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay.txt --require-hashes -d /opt/tfc/

    # Pyserial
    t_sudo python3.6 -m pip install /opt/tfc/${PYSERIAL}

    # Stem
    t_sudo python3.6 -m pip install /opt/tfc/${STEM}

    # PySocks
    t_sudo python3.6 -m pip install /opt/tfc/${PYSOCKS}

    # Requests
    t_sudo python3.6 -m pip install /opt/tfc/${URLLIB3}
    t_sudo python3.6 -m pip install /opt/tfc/${IDNA}
    t_sudo python3.6 -m pip install /opt/tfc/${CHARDET}
    t_sudo python3.6 -m pip install /opt/tfc/${CERTIFI}
    t_sudo python3.6 -m pip install /opt/tfc/${REQUESTS}

    # Flask
    t_sudo python3.6 -m pip install /opt/tfc/${WERKZEUG}
    t_sudo python3.6 -m pip install /opt/tfc/${MARKUPSAFE}
    t_sudo python3.6 -m pip install /opt/tfc/${JINJA2}
    t_sudo python3.6 -m pip install /opt/tfc/${ITSDANGEROUS}
    t_sudo python3.6 -m pip install /opt/tfc/${CLICK}
    t_sudo python3.6 -m pip install /opt/tfc/${FLASK}

    # Cryptography
    t_sudo python3.6 -m pip install /opt/tfc/${SIX}
    t_sudo python3.6 -m pip install /opt/tfc/${ASN1CRYPTO}
    t_sudo python3.6 -m pip install /opt/tfc/${PYCPARSER}
    t_sudo python3.6 -m pip install /opt/tfc/${CFFI}
    t_sudo python3.6 -m pip install /opt/tfc/${CRYPTOGRAPHY}

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
    t_sudo rm    /opt/install.sh
    t_sudo rm    /opt/install.sh.asc
    t_sudo rm    /opt/pubkey.asc

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


upgrade_tor () {
    available=($(apt-cache policy tor |grep Candidate | awk '{print $2}' |head -c 5))
    required="0.3.5"

    # If OS repository does not provide 0.3.5, add Tor Project's repository
    if ! [[ "$(printf '%s\n' "$required" "$available" | sort -V | head -n1)" = "$required" ]]; then

        sudo torsocks apt install apt-transport-tor -y

        # Remove .list-file
        if [[ -f /etc/apt/sources.list.d/torproject.list ]]; then
            sudo rm /etc/apt/sources.list.d/torproject.list
        fi

        # Set codename
        if [[ -f /etc/upstream-release/lsb-release ]]; then
            codename=($(cat /etc/upstream-release/lsb-release |grep DISTRIB_CODENAME |cut -c 18-))  # Linux Mint etc.
        else
            codename=($(lsb_release -a 2>/dev/null |grep Codename |awk '{print $2}'))  # *buntu
        fi

        # Add .list-file
        # The authenticity of the Onion URL for deb.torproject.org can be confirmed from https://www.torproject.org/docs/debian.html.en#apt-over-tor
        echo "deb tor://sdscoq7snqtznauu.onion/torproject.org ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list
        sudo cp -f /etc/apt/sources.list.d/torproject.list /etc/apt/sources.list.d/torproject.list.save

        # Import key
        torsocks wget -O - -o /dev/null http://sdscoq7snqtznauu.onion/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
        gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -

        sudo apt update
        sudo apt install tor -y

    else
        if grep -q "tor://" -R /etc/apt/; then
            sudo apt update
        else
            sudo torsocks apt update
        fi

    fi
}


kill_network () {
    for interface in /sys/class/net/*; do
        sudo ifconfig `basename ${interface}` down
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
