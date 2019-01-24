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


dl_verify () {
    # Download a TFC file from the GitHub repository and authenticate it
    # by comparing its SHA512 hash against the hash pinned in this
    # installer file.

    torify wget https://raw.githubusercontent.com/maqp/tfc/master/$2$3 -q

    # Check the SHA512 hash of the downloaded file
    if sha512sum $3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
        if [[ ${sudo_pwd} ]]; then
            echo ${sudo_pwd} | sudo -S mkdir --parents /opt/tfc/$2
            echo ${sudo_pwd} | sudo -S mv $3           /opt/tfc/$2
            echo ${sudo_pwd} | sudo -S chown root      /opt/tfc/$2$3
            echo ${sudo_pwd} | sudo -S chmod 644       /opt/tfc/$2$3
        else
            sudo mkdir --parents /opt/tfc/$2
            sudo mv $3           /opt/tfc/$2
            sudo chown root      /opt/tfc/$2$3
            sudo chmod 644       /opt/tfc/$2$3
        fi

        # Check the SHA512 hash of the moved file
        if sha512sum /opt/tfc/$2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1"); then
            echo OK - Pinned SHA512 hash matched file /opt/tfc/$2$3
        else
            echo Error: /opt/tfc/$2$3 had invalid SHA512 hash
            exit 1
        fi

    else
        echo Error: $3 had invalid SHA512 hash
        exit 1
    fi
}


download_common () {
dl_verify d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
dl_verify 04bc1b0bf748da3f3a69fda001a36b7e8ed36901fa976d6b9a4da0847bb0dcaf20cdeb884065ecb45b80bd520df9a4ebda2c69154696c63d9260a249219ae68a '' LICENSE-3RD-PARTY
dl_verify 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
dl_verify 003915a43670bbb3185e045de1d9cede67160d9da0a24a72650862e978106c451d94a2da4aa2e1d161315db7575251933b80881294f33f195531c75462bbcf9c src/common/ crypto.py
dl_verify 0dfae6aa49c399983a990ca672e24eef9aa3ed7782686dd6c78ab8041023650e195304a07d40b934ea6f73bb46189529983de4093144ffdef40e718263232365 src/common/ db_contacts.py
dl_verify 49ebf5dff5f34a373dccfaa0a8152e5bea11e6c3afc997d4c83d45b19351b62e0138555647c2ca796faf3cfc946f16d779af4ef9938b5ebffafa9ab155761696 src/common/ db_groups.py
dl_verify 157bc8b1cfea322118b880d9bcc76b695405668af718276246c334f76226781a55779da4adcea571472bfcc7ced2cdd908d49e181268707b16ef71ff4c8ff833 src/common/ db_keys.py
dl_verify 04cc3f2816b903d82e7baaa0bc9e406d7058c27537e8d07db67882a88deb4289fdff84150eb0dd1806721bf0ae1dd7f2757b916670eff6d1c122c660ac6d4ba2 src/common/ db_logs.py
dl_verify 8d53e7348abf71aa1e054e5e852e171e58ed409c394213d97edc392f016c38ce43ed67090d3623aaa5a3f335992fd5b0681cfb6b3170b639c2fa0e80a62af3a4 src/common/ db_masterkey.py
dl_verify 907c8997158a160b71bb964191848db42260a201e80b61133be1e7c7a650604792164499b85eaa4e84c58a7bc1598aff6ed10fda8442d60eb7f939d9de7f09c8 src/common/ db_onion.py
dl_verify 83b2a6d36de528106202eebccc50ca412fc4f0b6d0e5566c8f5e42e25dd18c67ae1b65cf4c19d3824123c59a23d6258e8af739c3d9147f2be04813c7ede3761d src/common/ db_settings.py
dl_verify 88f628cef1973cf0c9a9c8661a527570e01311efbbb6903760abec2b7ff6f4f42b3ff0e00c020d7b1912d66ac647b59b502942199334a83bb9d9dddc2a70c943 src/common/ encoding.py
dl_verify 0e3e6a40928ab781dbbca03f2378a14d6390444b13e85392ea4bdfb8e58ae63f25d6f55b2637f6749e463844784ea9242db5d18291e891ee88776d4c14498060 src/common/ exceptions.py
dl_verify 77b810f709739543dc40b1d1fbafb2a95d1c1772b929d3a4247c32e20b9bb40039c900ff4967c4b41118567463e59b7523fbbbf993b34251e46c60b8588f34ab src/common/ gateway.py
dl_verify 42742ab0e0f6f61bd6b8d7d32644a98e526fa7fd0fd7ed8e790c25e365874d77a6611849c168649160b84774059675a066dd0711db59ed41ffc449790fb5ffa0 src/common/ input.py
dl_verify 18efc508382167d3259c2eb2b8adcddda280c7dbc73e3b958a10cf4895c6eb8e7d4407bc4dc0ee1d0ab7cc974a609786649491874e72b4c31ad45b34d6e91be3 src/common/ misc.py
dl_verify f47308851d7f239237ed2ae82dd1e7cf92921c83bfb89ad44d976ebc0c78db722203c92a93b8b668c6fab6baeca8db207016ca401d4c548f505972d9aaa76b83 src/common/ output.py
dl_verify dc5fdd0f8262815386896e91e08324cda4aa27b5829d8f114e00128eb8e341c3d648ef2522f8eb5b413907975b1270771f60f9f6cdf0ddfaf01f288ba2768e14 src/common/ path.py
dl_verify f80a9906b7de273cec5ca32df80048a70ea95e7877cd093e50f9a8357c2459e5cffb9257c15bf0b44b5475cdd5aaf94eeec903cc72114210e19ac12f139e87f3 src/common/ reed_solomon.py
dl_verify 421fa2ec82f35a384baf5f5a4000afa4701e814ff28b4e8fa45478226cbf2f9272854ddf171def4ad7a489a77531457b9b6d62b68c4417b26b026e0ee6e521e8 src/common/ statics.py
}


download_relay () {
dl_verify 9ff2e54072e9cd9a87d167961bb5dd299caa035f634c08223262cda562faf9407ec09435c63e9cce7cb4121a6273ae0300835334e03f859df3e7f85b367d685c '' relay.py
dl_verify ddcefcf52d992f9027b530471a213e224382db5fbb516cc8dee73d519e40110f9fcca1de834a34e226c8621a96870f546b9a6b2f0e937b11fd8cd35198589e8b '' requirements-relay.txt

dl_verify f2b23d37a3753a906492fcb3e84df42b62bed660f568a0a5503b188f140fa91f86b6efa733b653fceff650168934e2f3f1174c892e7c28712eda7676b076dab8 launchers/ TFC-RP.desktop
dl_verify a86f3ac28bbd902dfec74451034c68c01e74bbe6b6ec609014329fba17cc1224dc34942b103620109ef19336daa72e50dae1a0b25a1a2720445863427724d544 launchers/ TFC-RP-Tails.desktop

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
dl_verify d009954abc9fa78350f721458071aeec78b6cd8773db588626a248f0756d1e39b32a8c8c58c370e87e9e4eb63f0ea150a427ad2b92b641c8fd71117933059db8 src/relay/ client.py
dl_verify 02c764d58ef8d02f95050cec41aa41fa90938ea08e0107ed49d3ae73357115b48f23f291dfc238ec3e45b12a705089b5c2ad3a1b30f27abb0a4c7498271161a3 src/relay/ commands.py
dl_verify fa7350a1dafe7e27638cb505a30e43815e157b08fc26b700f15633ab34f8ac3ad782a4396cc6b9aba3b59cd48d2e37b6f72befcafbd14772e135bc40fc080050 src/relay/ onion.py
dl_verify fe666032c2448d87355931bef235085039087b701b7b79a74b23f663d06b78264686c53800729f8a4197bf419076d76d1fe3ae74afa9141180035a6b807f0bb5 src/relay/ server.py
dl_verify 380a78c8c0918e33fb6be39a4c51f51a93aa35b0cf320370d6fb892b5dade920e8ca4e4fe9d319c0a0cdc5b3a97f609fdee392b2b41175379200b1d793b75593 src/relay/ tcb.py
}


download_tcb () {
dl_verify cec2bc228cd3ef6190ea5637e95b0d65ea821fc159ebb2441f8420af0cdf440b964bdffd8e0791a77ab48081f5b6345a59134db4b8e2752062d7c7f4348a4f0f '' tfc.py
dl_verify 0711aabf9c0a60f6bd4afec9f272ab1dd7e85f1a92ee03b02395f65ed51f130d594d82565df98888dbf3e0bd6dfa30159f8bd1afed9b5ed3b9c6df2766b99793 '' requirements.txt

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
dl_verify f91c0f616555725e0d2a4d8e2ee2bf39e1ebc4cbdf0a2547f4e4b5e4f1ee88743273cffb422a43dff98ba42772b18ceb4c270628f933392e27fa5cd6cae991ce src/transmitter/ commands.py
dl_verify f7cf493506a19b9732ae9f780aeb131342a47644632fcf88f0df01f0bda88252fdbad37a4b80e87f97e57feb50079ac2e5194598d745163846e30fdd6d32fe60 src/transmitter/ commands_g.py
dl_verify a1b6af28645df531be3a670375ce3a3da1a48b279d646f04b3c14cfbdf7006060955f33595a2963f98a495ec16dfe969325842495d8fbfae5f93e1459ed047c4 src/transmitter/ contact.py
dl_verify 184c35a32a3858893c67622a21fc7fdbd88bc61f82d4b655ad26ef008563cdb31430a3b713b92c98ea8d983ebadd0db6f9de3f9b1c07ac3dce4cf405aedf21ae src/transmitter/ files.py
dl_verify 019c178982f89b93ba69d26e60625a868380ac102b10351ac42c4d1321a45dd7186694d86028371185a096cce2e2bbe2d68210552439e34c3d5166f67b3578ee src/transmitter/ input_loop.py
dl_verify 742fba91ebd67dca247d03df4cf1820fc6b07e6966449282d7c4019f48cc902dc8dfc4120be9fdd6e61a4f00dd7753a08565a1b04395bc347064631d957c9d82 src/transmitter/ key_exchanges.py
dl_verify a59619b239b747298cc676a53aa6f87a9ef6511f5e84ec9e8a8e323c65ab5e9234cb7878bd25d2e763d5f74b8ff9fe395035637b8340a5fd525c3dc5ccbf7223 src/transmitter/ packet.py
dl_verify c2f77f8d3ebf12c3816c5876cd748dc4d7e9cd11fe8305d247783df510685a9f7a6157762d8c80afda55572dcae5fe60c9f39d5ec599a64d40928a09dd789c35 src/transmitter/ sender_loop.py
dl_verify 5d42f94bf6a6a4b70c3059fd827449af5b0e169095d8c50b37a922d70955bf79058adc10da77ebb79fb565830168dccb774547b6af513b7c866faf786da7c324 src/transmitter/ traffic_masking.py
dl_verify 22e8ba63c1391233612155099f5f9017d33918180f35c2552e31213862c76e3048d552f193f9cd3e4e9a240c0ef9bef4eabefe70b37e911553afeceede1133ca src/transmitter/ user_input.py
dl_verify 39a7b3e4457d9aa6d53cb53d38c3ed9adbd9e3250008b4e79b5a174b9227fd0fac6dad30e6e9b8fe3d635b25b2d4dfc049804df48d04f5dfcc1016b2e0a42577 src/transmitter/ windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
dl_verify 35b035f2794b5d7618eeafd91781246a0100bac9ff6a1f643b16068d5b2dc2946c799e91beba77d94e4118f99d6d6653974ebd5d4008133131f3bf44a7a190fb src/receiver/ commands.py
dl_verify 09f921aaaeae96ee6e9ff787990864ba491d4f8b10c613ab2a01f74c00b62d570270323ea2f5dc08befd8aa7bf4be0c609f8dca1862e4465e521b8016dff14da src/receiver/ commands_g.py
dl_verify 7b1d45caf3faf28c484d7d8d0c96ff9ba6e840682b002e438eac620904d3ca39483009a079d300489d80e22025ba301fa483f235193de5b55a62e9dedb25967f src/receiver/ files.py
dl_verify eab31c334f09930f1167b15fae4d0126711d6fb0efbe5b8ca9e6e49bdbf0a9ca90279be6d2cd0080d588cf15d83686ba895ee60dc6a2bb2cba0f8ed8005c99eb src/receiver/ key_exchanges.py
dl_verify 2894c847fe3f69a829ed7d8e7933b4c5f97355a0d99df7125cee17fffdca9c8740b17aa512513ae02f8f70443d3143f26baea268ace7a197609f6b47b17360b7 src/receiver/ messages.py
dl_verify 57ebdf412723b5ab4f683afeda55f771ef6ef81fde5a18f05c470bca5262f9ff5eefd04a3648f12f749cec58a25fa62e6dfb1c35e3d03082c3ea464ef98168b1 src/receiver/ output_loop.py
dl_verify 3b84dbe9faffeab8b1d5953619e38aefc278ce4e603fd63beaee878af7b5daff46b8ed053ad56f11db164b1a3f5b694c6704c66588386b06db697281c9f81bbf src/receiver/ packet.py
dl_verify 1e5240d346a016b154faf877199227edf76e027d75e1e921f2024c5dd1d0a40c1de7e9197077786a21474a4bbf2c305d290214aacdea50f5abaeb39963ca08a6 src/receiver/ receiver_loop.py
dl_verify e84a92fa500492af0cc16038fd388c74c387334898b870e57bc599d1b95da85b579d50ba403cdfc82ce8d4d5765fc59e772796d54faa914d0b5874150428d762 src/receiver/ windows.py
}


download_common_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/ __init__.py
dl_verify c20421e2293f058df4e03dee49e609b51fc1d39e69b4c44dd7580f88a5b2bf0729261167cb69fb0ff81b3838e3edca0e408c5c6410e4d43d06d6c0aa1ef6f805 tests/ mock_classes.py
dl_verify 2acdcd76d44caa417e9d1b3439816c4f07f763258b8240aa165a1dc0c948d68c4d4d5ac5e0ff7c02a0abc594e3d23883463a9578455749c92769fea8ee81490d tests/ utils.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/common/ __init__.py
dl_verify b62eeed36733c4ddcbb657cf7b2b37737f2a1b0b5d11c7720cb13703f09a99ccb0ead2a379caeff073955a31a5ae123342c925d93bbdd3338cfc8e4efb83fa38 tests/common/ test_crypto.py
dl_verify 7c222cc89248f09992def8fa30c32a9c98a9188c0b30af5f352eeef7b1932bdbf070a87879b47fe09c5cb6f19ad69038f3f8e906479773987e3f47908119f444 tests/common/ test_db_contacts.py
dl_verify cb8e18ba393d05e89c635d9ee22f0a15bc3a2039c68c85cc0e3eafe6d5855601b0c00473d6284bb33c4f88184932f2413793e185e5478e6cb456976bc79ad790 tests/common/ test_db_groups.py
dl_verify b894e5719bbf666b2e86f911b422c857c8e3795b527e346e510ff636c8b9733607c8e4115168584fba3fd6144d64b53b85f65cbba18b21c7dd80ff6e0de2a271 tests/common/ test_db_keys.py
dl_verify ed68245632dcab1a0ff63aa18408514a8c902ffdaa509ee5f9ae6a4f4b57fc11d64d5a4b70cc2884b8f428afb2ee23a586ba0595ad9b921f66b735ae90f257a2 tests/common/ test_db_logs.py
dl_verify 4e7436d7316d56f50f604a900eddc6427bb2fe348073848b1d7845484f51739686c781935118a18bdc52d7848a46f24909ea630306c46f518ec9b72768c3f648 tests/common/ test_db_masterkey.py
dl_verify 9eb4af866f9e5f1561401a3b62f924e8133464dfc3bb06f5e17dc18f2c09b785133ad38cf45d6d218ef7c5eadad4207d53ad6492e82754753ed568884ba4d383 tests/common/ test_db_onion.py
dl_verify 58ed5e733ac373a6c3d69ff7218207a60b9e4138a549da1a9de158d770f5b2514d7042e4ec7feed86966388523ace278797535a77be926f34c406ac3bc4e96ce tests/common/ test_db_settings.py
dl_verify a2036517d264bbaf2db9683e573000fa222067c6a8e3e72337e5b31c6554c1c33259f885540aad73f2cc454f8d0ef289df9557106e43ca4504fbad447c7e4c04 tests/common/ test_encoding.py
dl_verify 3dea267fa9b4361890f374157b137c9f76946f3289f4faf4b293814f26f9769fb202ec98c6fd044891b2a51a3bb69f67fec46022210ebaf27f7270e9dfc779eb tests/common/ test_exceptions.py
dl_verify 3d2d5077bc946a1327c64598a3d7bb30786a6ccb089f5fc67330b05a3d867c46deb0d5cec593927782e1bfbf7efe74678f6aa4b62a3306ba33fa406537ee6499 tests/common/ test_gateway.py
dl_verify dad966ace979c486134dd3146a50eb2d26054984ca8fcad203d61bf9ae804db04664df21e8293e307fbfe9c331cb59a06a46626fb36f445f50ef0fba63b5d93d tests/common/ test_input.py
dl_verify 23d4ddd293defa5ac3dd4eada0e8e9263203c51d9d0260d370a362557f93bb74dbfff75620463e4c046db3350b54ee75889398c58be16df8dcffb928220815a9 tests/common/ test_misc.py
dl_verify d595d7b6c0e05f1c99a89f8dc2e662eff4127f0ad0b807156a4e6f42c9113e33302c00b311e9fdfcfce20e1fea331da02bbeb41a7c44d8e05795317711da8225 tests/common/ test_output.py
dl_verify 4a38809c9afad404b563cbaffe89d9a23b9785ab246c71136b9bb2c802f7b1039ad375580a3076ba671f97beb48bb3f51a6bded4f8179d3c5b8f73899101cd9b tests/common/ test_path.py
dl_verify 1e320f69f236daed5f0fb2e6fda4b5b533dd628fff7db0ee8a6b405efe3c24138a43f24b45693017219cd885779f5ae57d3523d264e077ba9d3b9d2027b95d9c tests/common/ test_reed_solomon.py
dl_verify 223f66cbb3ff0567eba27b66c3be30bd292b6ab1405ea52af79e4adafc87901212998576665bfee5e40e9ece7cc0d369179945be903ae36e5016942cf8c7fd2b tests/common/ test_statics.py
}


download_relay_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/relay/ __init__.py
dl_verify 9d132ad47baca57c5ce8d7f07222b6c778aec697c190c48b82c86c4eb8588de1935f2309994c05bcdfd44fe2d8d85d20980520aa22771f3846e5ce89ac68a232 tests/relay/ test_client.py
dl_verify 2431fd853a9a0089a3837f1e20455c2d58d96722d5b803fe9e3dc9aa09a3e5fbffa3b0fa9e3e723d81a2aa2abd6b19275777ba6eb541ec1b403854260dd14591 tests/relay/ test_commands.py
dl_verify b64b8cef7f1c4699e34344b6c6ba255d6ead3e8f4765dfd5fb88d2a676962a7d8231d261f68d3399d9eb65196ea0cefb31e6800aa6cc6662dcf0fd927be8c1a4 tests/relay/ test_onion.py
dl_verify 42e494245869a5e652fe6bdcf5e21d1a0299c9ad7485d075fe7cf1d2d53118b444d8563bbea837316f00cbfea31117d569cf4e8694443ab5b50f606369aec987 tests/relay/ test_server.py
dl_verify 54c3026e797e75c46ca1d1493f6a396643948f707f1bc8ad377b7c625fda39d4e0fa6b0ec0fe39149ef0250568caf954e22ae8ebe7e7ac00ca8802ffbc6ae324 tests/relay/ test_tcb.py
}


download_tcb_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/transmitter/ __init__.py
dl_verify 3bdb8fd64bb2b4070da025e0187e434b5178b645fb08ec822bdd732bac3824316a8d13ded95e5e7bf754dddda5ea1f5805b6c2a3b46e8100509d3f5b32d18278 tests/transmitter/ test_commands.py
dl_verify c2429b5ffc32aa4a6377fef726553d7c731672367cb4eaa338c0a2099b3fe0455fa8a79c4b86afd9077a53422403649bc1fcf7540e4f996dc0890819c34d9135 tests/transmitter/ test_commands_g.py
dl_verify 3baaa1dc6dff7771f6167d699a81c6cb14f7b0ea307b83797d342a95b21f89d9f2c21e54feac0474f61174a1c708b3f02bc0e3a6b0b504bda8c03cdd16e5fefe tests/transmitter/ test_contact.py
dl_verify 3d86131dfd775aea2ea7c0500759befac8a5d7fe35f590974b2af56da42929db927c0bd86a352a38412fbb79c2bff09d33271b26ebd9aead1bf2b702918cc02a tests/transmitter/ test_files.py
dl_verify 3bc9c3275353f49516fdb2bc9d9a86286c121f085d5382980e118b0ea123da9b9829edeb172448416f30955c9a1c1c3704f36cfa4700ced86c33009e362d0b69 tests/transmitter/ test_input_loop.py
dl_verify 284fefc2a4986948a5ee4de1f935482b43011347b5454ab685f4a79a1036d1bf0518db536381dfddf706318bb44b584db37cfbf8fa07aac1b631a278dfe298d7 tests/transmitter/ test_key_exchanges.py
dl_verify 0c16f45ad9fda006b58a45a7c9a4b9777cf05d08f59c9207addbc27936c29a6aa2aa59146f0ef32fb883a5e24211c5dbdfbf5ad9cf9b72e999e599e9eda0d2ef tests/transmitter/ test_packet.py
dl_verify 49aa0e761771893e8bc057c8e305eb8b5e7103df9a31c80eba333db739f0b2c521eca59901f35bf2e319360902c8be12b112a29948461b73662554bdf55bf6d4 tests/transmitter/ test_sender_loop.py
dl_verify fd4d6cf68a4e555a60caf8efc6ebc6747990ed1c582036c6cc92012c5af82b49b32c42398bf822fda8257e84c822bdb8158260164a8774aea72723ddbe99e639 tests/transmitter/ test_traffic_masking.py
dl_verify b71f7d8e3ce943dca2516f730c9919633f40568af905ac32e05b126e06f2c968c9b0b795cfad81a696511cd07534a0593ef1c9b5d5299ab88b2aff32b9059b64 tests/transmitter/ test_user_input.py
dl_verify 5be56563cab2c9007b6be7ff767778e3fb0df1d3374174d6b6ef7dc6d66b0c692cd798a0a77f156c3eb1ad979a3b532b681db97c4d1948ff8f85cd4a1fa2d51d tests/transmitter/ test_windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/receiver/ __init__.py
dl_verify d80af580f76c3c58d72828ab190a055a03f7e74ae17ccbaa2f70dd94e01b7efd85888ac51eefed94d6671027660a8080600f2e1e908bd77622c36ba258a8936e tests/receiver/ test_commands.py
dl_verify dce0fe6cd05915f1a0450259a08e9935b077f9b3af61f315812834811a5c82095b72bea5e4b283fd2b8285e86f8ee4897d43f42a99261767b77841deb471d980 tests/receiver/ test_commands_g.py
dl_verify eb86007ca9b0cfeb4d364b1fb53409443c8b9f95770979c471b8462c1c41205b96afd357670a9cd5949e8360b738d9284a9e726ee6ab89e09a0306b105f1a720 tests/receiver/ test_files.py
dl_verify 01bf3274c675b8cbe6379f8fb1883e0d4ed6c69d164b2c6a44794786d21f2604efc262b34372dfb581607655e6e1e73c178660d3e97f4f2c9bdfb11e4166b2fd tests/receiver/ test_key_exchanges.py
dl_verify 7b9d27497d5765739ee435c02a379e792ad510dd893ff0d3871a7d3f97d196274921a2d26fa656edb5e7974a390155e7c1914135d3e1b6a82ed8f94d46263b66 tests/receiver/ test_messages.py
dl_verify affbd5bccd0fcd87bb50e13b497b1ba3c29ccec954fa53f62bff1a28baa7b35376f614fb54c922ed4605a37f6aa1463efff43a6267619b04a605a2181222e873 tests/receiver/ test_output_loop.py
dl_verify da34f5bdcd8b108b45e955d545954de32c9d8959c26e9d2e3104106139fb2fec69aabd6d5d127beacef7a09ee4f16aab0a92ee7d76b0fa6cd199e56032c12257 tests/receiver/ test_packet.py
dl_verify 717722763a41267929b6038abe859eececee20e68497d0f3c04268b6b8274a04e39e3f8d37d0928c8459c7ef52478176c933d8ec8b2bd0b93ff952a9b92b86f4 tests/receiver/ test_receiver_loop.py
dl_verify e6df26dc7b829b8536e454b99c6c448330fc5cff3ff12a5ebc70103a5fb15ab4fcb8fcb785e27201228b6f50ec610ef214bee4f2d5ff35995b4f00ae23217bc0 tests/receiver/ test_windows.py
}


download_local_test_specific () {
dl_verify dec90e113335d3274d87c3e12dda5a3205df57bd10c1e0532ecad34409520ce0596db21e989478836d4a0ea44da8c42902d2d8f05c9ad027a5560b4d0d5b9f13 '' dd.py

dl_verify 2f426d4d971d67ebf2f59b54fb31cff1a3e2567e343bfa1b3e638b8e0dffed5d0c3cac1f33229b98c302fee0cca3cc43567c2c615b5249a2db6d444e89e5fc70 launchers/ config
dl_verify 5d5351dd24d7afd4dc717835cfffee718fca707133127d1826ae099c66b0bddd878d104c1ad43546c8157807c984bd26b562e455fe219c1a00cf49df6bb73009 launchers/ TFC-local-test.desktop
}


download_tcb_specific () {
dl_verify 883d8df82240d840a215a4a946ba3a15def11b9c50f659e84bdb3543e484fed3e520c471cc10301743d38a7560c2672f1cfd22efa99de495685a90b8559db4ee launchers/ TFC-TxP.desktop
dl_verify c10fb76486ada483cfdd9e351b6d9b89907ae6ccccb32cf4299bc4e67ba565aac7b05a2d62a89c0146a1783c9d0616ee3c9a9660173a98ca6b03f72c3fbe6202 launchers/ TFC-RxP.desktop
}


download_dev_specific () {
dl_verify 2865708ab24c3ceeaf0a6ec382fb7c331fdee52af55a111c1afb862a336dd757d597f91b94267da009eb74bbc77d01bf78824474fa6f0aa820cd8c62ddb72138 '' requirements-dev.txt
}


download_venv () {
dl_verify f74b9aeb3a17ef86782afb8c2f621709801631430423d13025310809e6d14ffecb3805ee600cd3740287105b7a0e0726f8ced202e7b55be7bf5b79240e34d35d '' requirements-venv.txt
}


install_tcb () {
    create_install_dir
    dpkg_check

    sudo torify apt update
    sudo torify apt install libssl-dev python3-pip python3-setuptools python3-tk net-tools -y

    download_venv
    download_common
    download_tcb
    download_tcb_specific
    #download_common_tests
    #download_tcb_tests

    create_user_data_dir
    cd $HOME/tfc/

    torify pip3 download -r /opt/tfc/requirements-venv.txt --require-hashes
    torify pip3 download -r /opt/tfc/requirements.txt      --require-hashes

    kill_network

    pip3 install setuptools-40.6.3-py2.py3-none-any.whl
    pip3 install virtualenv-16.2.0-py2.py3-none-any.whl
    sudo python3 -m virtualenv /opt/tfc/venv_tcb --system-site-packages --never-download

    . /opt/tfc/venv_tcb/bin/activate
    sudo pip3 install six-1.12.0-py2.py3-none-any.whl
    sudo pip3 install pycparser-2.19.tar.gz
    sudo pip3 install cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    sudo pip3 install argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
    sudo pip3 install PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
    sudo pip3 install pyserial-3.4-py2.py3-none-any.whl
    sudo pip3 install asn1crypto-0.24.0-py2.py3-none-any.whl
    sudo pip3 install cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl
    deactivate

    sudo mv /opt/tfc/tfc.png                   /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv /opt/tfc/launchers/TFC-RxP.desktop /usr/share/applications/

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-venv.txt

    rm $HOME/tfc/setuptools-40.6.3-py2.py3-none-any.whl
    rm $HOME/tfc/virtualenv-16.2.0-py2.py3-none-any.whl
    rm $HOME/tfc/six-1.12.0-py2.py3-none-any.whl
    rm $HOME/tfc/pycparser-2.19.tar.gz
    rm $HOME/tfc/cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    rm $HOME/tfc/argon2_cffi-19.1.0-cp34-abi3-manylinux1_x86_64.whl
    rm $HOME/tfc/PyNaCl-1.3.0-cp34-abi3-manylinux1_x86_64.whl
    rm $HOME/tfc/pyserial-3.4-py2.py3-none-any.whl
    rm $HOME/tfc/asn1crypto-0.24.0-py2.py3-none-any.whl
    rm $HOME/tfc/cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


install_local_test () {
    create_install_dir
    dpkg_check

    tor_dependencies
    sudo torify apt update
    sudo torify apt install libssl-dev python3-pip python3-setuptools python3-tk tor deb.torproject.org-keyring terminator -y

    download_venv
    download_common
    download_tcb
    download_relay
    download_local_test_specific
    #download_common_tests
    #download_tcb_tests
    #download_relay_tests

    torify pip3 install -r     /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3 -m virtualenv /opt/tfc/venv_tfc              --system-site-packages

    . /opt/tfc/venv_tfc/bin/activate
    sudo torify pip3 install -r /opt/tfc/requirements.txt       --require-hashes
    sudo torify pip3 install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                          /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-local-test.desktop /usr/share/applications/

    create_terminator_config "/opt/tfc/launchers/config"

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements.txt
    sudo rm    /opt/tfc/requirements-relay.txt
    sudo rm    /opt/tfc/requirements-venv.txt

    install_complete "Installation of TFC for local testing is now complete."
}


install_developer () {
    dpkg_check

    tor_dependencies
    sudo torify apt update
    sudo torify apt install git libssl-dev python3-pip python3-setuptools python3-tk tor deb.torproject.org-keyring terminator -y

    cd $HOME
    torify git clone https://github.com/maqp/tfc.git
    cd $HOME/tfc/

    torify pip3 install -r requirements-venv.txt --require-hashes
    python3.6 -m virtualenv venv_tfc --system-site-packages

    . /$HOME/tfc/venv_tfc/bin/activate
    torify pip3 install -r requirements.txt       --require-hashes
    torify pip3 install -r requirements-relay.txt --require-hashes
    torify pip3 install -r requirements-dev.txt
    deactivate

    sudo cp $HOME/tfc/launchers/TFC-local-test.desktop /usr/share/applications/
    sudo cp $HOME/tfc/tfc.png                          /usr/share/pixmaps/

    create_terminator_config "$HOME/tfc/launchers/config"

    chmod a+rwx -R $HOME/tfc/

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


install_relay_ubuntu () {
    create_install_dir
    dpkg_check

    tor_dependencies
    sudo torify apt update
    sudo torify apt install libssl-dev python3-pip python3-setuptools tor deb.torproject.org-keyring -y

    download_venv
    download_common
    download_relay
    #download_common_tests
    #download_relay_tests

    torify pip3 install -r       /opt/tfc/requirements-venv.txt --require-hashes
    sudo python3.6 -m virtualenv /opt/tfc/venv_relay            --system-site-packages

    . /opt/tfc/venv_relay/bin/activate
    sudo torify pip3 install -r /opt/tfc/requirements-relay.txt --require-hashes
    deactivate

    sudo mv /opt/tfc/tfc.png                  /usr/share/pixmaps/
    sudo mv /opt/tfc/launchers/TFC-RP.desktop /usr/share/applications/

    sudo rm -r /opt/tfc/launchers/
    sudo rm    /opt/tfc/requirements-venv.txt
    sudo rm    /opt/tfc/requirements-relay.txt

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


install_relay_tails () {
    check_tails_tor_version

    # Cache password so that Debian doesn't keep asking
    # for it during install (it won't be stored on disk).
    read_sudo_pwd
    create_install_dir

    echo ${sudo_pwd} | sudo -S apt update
    echo ${sudo_pwd} | sudo -S apt install libssl-dev python3-pip python3-setuptools -y

    download_common
    download_relay
    #download_common_tests
    #download_relay_tests

    create_user_data_dir
    cd $HOME/tfc/

    torify pip3 download -r /opt/tfc/requirements-relay.txt --require-hashes

    # Pyserial
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install pyserial-3.4-py2.py3-none-any.whl

    # Stem
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install stem-1.7.1.tar.gz

    # PySocks
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install PySocks-1.6.8.tar.gz

    # Requests
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install urllib3-1.24.1-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install idna-2.8-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install chardet-3.0.4-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install certifi-2018.11.29-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install requests-2.21.0-py2.py3-none-any.whl

    # Flask
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Werkzeug-0.14.1-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install MarkupSafe-1.1.0-cp36-cp36m-manylinux1_x86_64.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Jinja2-2.10-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install itsdangerous-1.1.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Click-7.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install Flask-1.0.2-py2.py3-none-any.whl

    # Cryptography
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install six-1.12.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install asn1crypto-0.24.0-py2.py3-none-any.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install pycparser-2.19.tar.gz
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install cffi-1.11.5-cp36-cp36m-manylinux1_x86_64.whl
    echo ${sudo_pwd} | sudo -S python3.6 -m pip install cryptography-2.5-cp34-abi3-manylinux1_x86_64.whl

    cd $HOME
    rm -r $HOME/tfc

    echo ${sudo_pwd} | sudo -S mv /opt/tfc/tfc.png                        /usr/share/pixmaps/
    echo ${sudo_pwd} | sudo -S mv /opt/tfc/launchers/TFC-RP-Tails.desktop /usr/share/applications/

    echo ${sudo_pwd} | sudo -S rm -r /opt/tfc/launchers/
    echo ${sudo_pwd} | sudo -S rm    /opt/tfc/requirements-relay.txt

    install_complete "Installation of the TFC Relay configuration is now complete."
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
    until (echo ${sudo_pwd} | sudo -S echo '' 2>/dev/null)
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


tor_dependencies () {
    available=($(apt-cache policy tor |grep Candidate | awk '{print $2}' |head -c 5))
    required="0.3.5"

    if ! [[ "$(printf '%s\n' "$required" "$available" | sort -V | head -n1)" = "$required" ]]; then
        # If repository does not provide 0.3.5, default to 0.3.5 experimental.
        sudo sudo rm /etc/apt/sources.list.d/torproject.list 2>/dev/null || true

        if [[ -f /etc/upstream-release/lsb-release ]]; then
            # Linux Mint etc.
            codename=($(cat /etc/upstream-release/lsb-release |grep DISTRIB_CODENAME |cut -c 18-))
        else
            # *buntu
            codename=($(lsb_release -a 2>/dev/null |grep Codename |awk '{print $2}'))
        fi

        url="https://deb.torproject.org/torproject.org"

        echo     "deb ${url} ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list
        echo "deb-src ${url} ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list
        echo     "deb ${url} ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list
        echo "deb-src ${url} ${codename} main" | sudo tee -a /etc/apt/sources.list.d/torproject.list

        # SKS Keyservers' Onion Service URL is verifiable via https://sks-keyservers.net/overview-of-pools.php
        gpg --keyserver hkp://jirk5u4osbsr34t5.onion --recv-keys A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
        gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
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


create_install_dir () {
    if [[ ${sudo_pwd} ]]; then
        # Tails
        if [[ -d "/opt/tfc" ]]; then
            echo ${sudo_pwd} | sudo -S rm -r /opt/tfc
        fi
        echo ${sudo_pwd} | sudo -S mkdir -p /opt/tfc 2>/dev/null

    else
        # *buntu
        if [[ -d "/opt/tfc" ]]; then
            sudo rm -r /opt/tfc
        fi
        sudo mkdir -p /opt/tfc 2>/dev/null
    fi
}


create_user_data_dir () {
    if [[ -d "$HOME/tfc" ]]; then
        mv $HOME/tfc tfc_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


create_terminator_config () {
    mkdir -p $HOME/.config/terminator 2>/dev/null
    if [[ -f $HOME/.config/terminator/config ]]; then

        backup_file="$HOME/.config/terminator/config_backup_at_$(date +%Y-%m-%d_%H-%M-%S)"
        mv $HOME/.config/terminator/config ${backup_file} 2>/dev/null

        clear
        c_echo ''
        c_echo "NOTICE"
        c_echo "An existing configuration file for the Terminator"
        c_echo "application was found and backed up into"
        c_echo ''
        c_echo "${backup_file}"
        c_echo ''
        c_echo "Press any key to continue."
        read -n 1 -s -p ''
        echo ''
    fi

    cp $1 $HOME/.config/terminator/config
    sudo chown ${USER} -R $HOME/.config/terminator/
    modify_terminator_font_size
}


modify_terminator_font_size () {
    width=$(get_screen_width)
    # Defaults in terminator config file are for 1920 pixels wide screens
    if (( $width < 1600 )); then
        sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     $HOME/.config/terminator/config  # Normal config
        sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   $HOME/.config/terminator/config  # Data Diode config
    elif (( $width < 1920 )); then
        sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     $HOME/.config/terminator/config  # Normal config
        sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' $HOME/.config/terminator/config  # Data Diode config
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
