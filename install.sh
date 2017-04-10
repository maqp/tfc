#!/usr/bin/env bash

# Copyright (C) 2013-2017  Markus Ottela
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
# along with TFC. If not, see <http://www.gnu.org/licenses/>.


dl_verify () {
    wget https://raw.githubusercontent.com/maqp/tfc/master$2$3 -q

    if sha256sum $3 | grep -Eo '^\w+' | cmp -s <(echo "$1")
        then
            echo Valid SHA256 hash for file $3
        else
            echo Error: $3 had invalid SHA256 hash.
            exit 1
    fi
}

activate_nh_venv () {
    . $HOME/tfc/venv_nh/bin/activate
}
activate_tfc_venv () {
    . $HOME/tfc/venv_tfc/bin/activate
}

tfc_download () {

mkdir tfc/
cd tfc/

mkdir src/
cd src/

mkdir nh/
cd nh/
dl_verify e88c26e22f1fadde164fb177c5f4ec476f1f3aaf4c2a726b8a4af8b79ba0859a /src/nh/ pidgin.py
dl_verify c1a71d9bbf843c5e51833e6429cfd7cbf6eff76e8fd1777c84c00b257f352ada /src/nh/ misc.py
dl_verify b5414b9288253be6af758713d8e49815bcb28d4c213c8e2d995c55c98f4c3a74 /src/nh/ gateway.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /src/nh/ __init__.py
dl_verify 95e3a2d4e1df6f67aa813b619b94299d42b744b281873c6b661e65077f0c7a17 /src/nh/ settings.py
dl_verify 838515f786943744d8c67138f17e1b00211f9b11fa11a5d87b012466aff6c1cf /src/nh/ tcb.py
dl_verify b54c28dacea537c50a0f9b9ebb6a598e08978a2050a095d74c04b9caf95d9953 /src/nh/ commands.py
cd ..

mkdir tx/
cd tx/
dl_verify 7d1a0474e8100bfabfaa95b8c1c75f96fb2f8c4d0f06ba5bc08929896de15734 /src/tx/ contact.py
dl_verify 9399695807414de36d5a10258a28c065dc845440dcb8178ca27dce0949977d28 /src/tx/ files.py
dl_verify a65859da2c1ee16ab8917aa7698233a1fee6a0ad02236a118b848e7b5fa55cb6 /src/tx/ key_exchanges.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /src/tx/ __init__.py
dl_verify 96214c2268599cc146cc03b1d250dc50b0884ccbe01ee8df90db401562b0e4a6 /src/tx/ windows.py
dl_verify 3581ccfbeac71e5290c336c8ad41024afa27fa876598cead927a0f37fc91c99b /src/tx/ messages.py
dl_verify 56cdefb3651a4085dca821048a3f78dc4c55033b127f375c4dcf0ac6431e70ff /src/tx/ tx_loop.py
dl_verify 32322e37d93afe66b2434781093116f20c279948bcb97742d3f58ef8e129b085 /src/tx/ trickle.py
dl_verify a65ebc3ab0c402a078342993bd0d0a94ec4d9eb99f118b92ec3fc72cee30c1f0 /src/tx/ commands_g.py
dl_verify 80e441c99e47b980fe88c8cf05dfe9cd25bb7d10268830b80fef13a0f09f6253 /src/tx/ commands.py
dl_verify 39e9060875116f0ea99a2dd3b42df7111364c2ef9e47f460e606e4f9d5789926 /src/tx/ packet.py
dl_verify 9e50cc93f4a35f42820a1f39daee92c8699c4b7c700413ca9cf82f9a149b5484 /src/tx/ sender_loop.py
dl_verify 0d31c7f87692e3e3836cd144b3a6d38728832ae1febcad3f8a25fba407843842 /src/tx/ user_input.py
cd ..

mkdir common/
cd common/
dl_verify 57c5c827264bf43f73207d6906c1834131c406db945ff7c8310b6efaeac169e2 /src/common/ statics.py
dl_verify a9e1f97dc03be04554f57d39c74c979527210965098ab87e30e768db13f1337f /src/common/ reed_solomon.py
dl_verify b40dcdb6a23d35f2969ec097fbb94c08fc9a366eca2c6f32c56dc68ae73a595e /src/common/ db_settings.py
dl_verify 45caef85023b3f60335bf4abc10c31b9e1c9da9ef1c2cdf42f1a77921c80f91d /src/common/ misc.py
dl_verify b4477ccd38895be7fc04d76a00a7e0f629ad8f97c21fb157ef83ecc09669d276 /src/common/ db_logs.py
dl_verify 487c7993c8fc2953f8741edede9af11f34fdc8531f96dc70ce16cd3557cc1487 /src/common/ gateway.py
dl_verify 994cb1be594d7f97bd9d096ea4d8e4d3d723d1ffa95e21d8cac38d09e576fb20 /src/common/ input.py
dl_verify 1ef8b21c6f57396cb4536a40ce86fd5acac930a2f7f1412f520071a66ba0bf43 /src/common/ db_masterkey.py
dl_verify eed56cb166cdafa02584270d5a658aa8ddcaa9c48b1a5156ad471ac8e3bbf551 /src/common/ db_keys.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /src/common/ __init__.py
dl_verify 2ada11493417bb6f31b3c6270c6b2c525f20310f750057d385b578d1caf96c3a /src/common/ encoding.py
dl_verify 72c753182896e5e8f45f278bcb785b0debc8e0bb9feddabd86488214e33484b8 /src/common/ crypto.py
dl_verify 540478dc7f25c76b1f058c3a54b8a1ac115d237e2858d87fb9ac95bf6981dae5 /src/common/ db_groups.py
dl_verify 89cf69a77b15d68d4f1a3bcf6d0a28e162b4dedc4e760d0681fc14913b12a0b3 /src/common/ output.py
dl_verify 6c22c62ec9083ebe16163363b3cbe4dc3c115a855de91a172e29ecc8a65367b9 /src/common/ path.py
dl_verify d3db9172b3752887506944a6ec4a03c86eb41fb4eaaa537fe626a67ec3dc5cde /src/common/ errors.py
dl_verify 4762ae73254b594f96f66f312895c843dc918d73d085cef9e64e56f77fde589c /src/common/ db_contacts.py
cd ..

mkdir rx/
cd rx/
dl_verify f9414a1147a894c745c73638b390a93e327854bb942d0949c872ef0dec1a0515 /src/rx/ files.py
dl_verify 3536a64fafe7d52e0d87f8317ac1af2f4146d9259fc5dc5c000af038c30bb33b /src/rx/ key_exchanges.py
dl_verify 0ecc6b59e71e3be181b3e0817ebbb3f0b974d56944d5896669ad274575d0be7b /src/rx/ receiver_loop.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /src/rx/ __init__.py
dl_verify 537b33ca75a04c305b36ba422f758dc4e1f86681a0cce0ce56b4b22db293eee8 /src/rx/ windows.py
dl_verify d46660aff0aed8b977e751641f244001a24ebb1614de828dcb3266f564796c80 /src/rx/ messages.py
dl_verify e889cc3e2d5893679d76215072790723847e785401f7dddea61462e2f280578c /src/rx/ commands_g.py
dl_verify a281f42889649c6962b081e32962a881591894d795c81b20ba6346e2201a230c /src/rx/ commands.py
dl_verify 5a1bc935a6e34bc2c009a280ce74f44132861b2bc6267dbf41738aa9aecd0722 /src/rx/ packet.py
dl_verify a86110caad1ee2569f109e9e94a5dd88b1c8e3f2798fd2c4c262550fb71143fe /src/rx/ rx_loop.py
cd ..

dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /src/ __init__.py
cd ..

dl_verify 188352b6f8408a552ef72b1c45851141f0b3de0286f6374bd1c9f78c488d5e8d /'' requirements.txt
dl_verify 043f6f1738fc85c8b6c8b7943b08e0aeb5f82397175503fb69427d869c706251 /'' tfc.png

mkdir tests
cd tests

mkdir nh/
cd nh/
dl_verify 03d9a010aed6085353b218baffd66345aee6d85ce821b1abfdd0bfce92e254ab /tests/nh/ test_settings.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tests/nh/ __init__.py
dl_verify 8f7c82acecf1de5bb7b575e6564a1d802d862d30d2883ef7d2ebcd92e1a05943 /tests/nh/ test_gateway.py
dl_verify b24af3ec561ba4ce8c48d29ecd64211677df1993b431ac66ce4d875cf2ab2a21 /tests/nh/ test_misc.py
cd ..

dl_verify c6d9d76546b4a5a68c16e3f9156ca5a09ee215245828a35c05cd2e2dcaa4ab2e /tests/ utils.py

mkdir tx/
cd tx/
dl_verify 5b7fa7843fb84f59a7e41f4be8c12da9de6cbccd88519ea7f9e9b6247b532b1e /tests/tx/ test_commands_g.py
dl_verify e36a0286d6f70f10ede4204c8ee7a8e98ab6d4f64e88366a073ff0269b0ac60a /tests/tx/ test_packet.py
dl_verify bfccac83b9a4e88b1918701091dcee4425af23932603922999da612003b88ec0 /tests/tx/ test_trickle.py
dl_verify 5f33e4c9aac2cd438f3aeb4b5f6157a0b1d34026ae19d2bbf2ffeef237a76a12 /tests/tx/ test_files.py
dl_verify e25a63fd7f8f69f42cd5176cba53f6ac41b5b278a6e5bed36400a6b8e345227f /tests/tx/ test_windows.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tests/tx/ __init__.py
dl_verify 12cf5d7eb667aa5be33d70b6abe04704efd848e0c8ead4fe4a8bb34177135cbd /tests/tx/ test_messages.py
dl_verify af7cc6140093370f0500a87626821ac68845eb439df6205edec2fbfd791853e8 /tests/tx/ test_contact.py
dl_verify cb516eb6171c68054343a1639a1c7066843c4a440f7bfa7c2fc2a5d0fc4f6940 /tests/tx/ test_commands.py
dl_verify 693e4ee72e75160f787a9bd40dc7d89696ec665938b6377d5fd9a6a7eb09550c /tests/tx/ test_user_input.py
dl_verify 1c5cba9aa5131d362e96ca01deb91f728a78174deb13ca0d3367a06ec2fcb3cd /tests/tx/ test_key_exchanges.py
cd ..

mkdir common/
cd common/
dl_verify 885b7f4013dc85b4faf41195ac6eb598bc6051df51c212ea559ffa7f21d8b7c8 /tests/common/ test_crypto.py
dl_verify e869f29c51e0ed22f89efc0a836a22c7446703b14519e1aa0d1746f473f89f20 /tests/common/ test_reed_solomon.py
dl_verify 6c7e8e693f828d577faaadea3c7236af5fcdad8b714df9787aba18d56fa267d6 /tests/common/ test_db_groups.py
dl_verify 62b9df59579efc7ffccec750419af0dccfd821d64d4f9e400681a682ffa18630 /tests/common/ test_path.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tests/common/ __init__.py
dl_verify 809044c6ec5bc0da9f24f373c757ae28ed2237430318b44a4be2469dda0f9c46 /tests/common/ test_db_masterkey.py
dl_verify 9363c2d65f0278e55c7bb8d9c896460fe012d28f2195bbb76d4d543b57ebdf68 /tests/common/ test_gateway.py
dl_verify 7dfab78f13031da2702fb468a4cfdd3706bf34ea097ea419aca18391bc617d10 /tests/common/ test_db_contacts.py
dl_verify 6bf42b295a192e68077f3839b6b3b91cafc53ddf8ad2db7f430ec19a9dd68870 /tests/common/ test_db_settings.py
dl_verify 97fb88aa500d9e56192554825c335dd07471dd108a1885180bd61b13fabe26ff /tests/common/ test_input.py
dl_verify 0fbd8a70bf97db1694b4e0aa46b1da46179868df107ff104df115cf421e84c66 /tests/common/ test_db_logs.py
dl_verify 40718dc469185870edc2439ea3c5bbee1a97c9af87d5996de2e2257e5fa6fc4e /tests/common/ test_output.py
dl_verify 9fc64a9f3913be44b0ea523c18854f6e984c2947ceafe2b28d16c1c761373821 /tests/common/ test_errors.py
dl_verify dbe47433f41566db093db1e6512da528074f002332d57b9ad70570f609d65d7c /tests/common/ test_encoding.py
dl_verify 9540c6de160eca24be8458cd10106ddde7e83c16d06ceff828d0788fe7a635b5 /tests/common/ test_misc.py
dl_verify 06c104f28a6a77860041b18a9b717087ff5dd722af319858299c0113e6dde252 /tests/common/ test_db_keys.py
cd ..

mkdir rx/
cd rx/
dl_verify feb93d9f57651a7407f7a8126da4021cb2d92799f2d859061969bc41820be9fc /tests/rx/ test_commands_g.py
dl_verify 2587a94659e9f8d06ae6a506490da5a6e4d2b38ce493eb276d47145406db5591 /tests/rx/ test_packet.py
dl_verify 97947c4c7a33f115356a66db1e668b6cb58e1163471fe760613071da57f58977 /tests/rx/ test_files.py
dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tests/rx/ __init__.py
dl_verify 721b5edf6696661016a99e891a4f0faeed2bf577709fac529497225d3b96aac8 /tests/rx/ test_messages.py
dl_verify 63758cbb491d55a4ddaf7ec581766f5b1e3487cda0bf89fe1243a9e56534fb1c /tests/rx/ test_commands.py
dl_verify ced0b513630818168077d4aec2d2b60da335b16592d221798dfb2dc1932d3e0e /tests/rx/ test_window.py
dl_verify 3481ba01673f2c989caa06c2d961ad265fc8de8d2b5ec8322147c6c928bd95d7 /tests/rx/ test_key_exchanges.py
cd ..

dl_verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /tests/ __init__.py
dl_verify 2e38cc5cb01cb9e2280d0f90620818ac992c44ae13aa8b2e03ed4aeb17ff6b8e /tests/ mock_classes.py
cd ..

mkdir launchers/
cd launchers/
dl_verify 4d4db7915fcf2126695283dc63ab6fae8f1277e12f8bd3961f8e00bca77fa508 /launchers/ TFC-NH-Tails.desktop
dl_verify a3e976e37eab126b828c3001714aeaa82cc50ebbbca2af4daf22fc252202fd8c /launchers/ TFC-NH.desktop
dl_verify 6e760a543685141787ce320c425ada1c5880c79cf928d2e08b7becc322cf4408 /launchers/ TFC-DD-RL.desktop
dl_verify 43f60afaf0dc7b26828a052c7c679d8e6f188975ea66fa4f173952dd72e3ac43 /launchers/ TFC-RxM.desktop
dl_verify ed5b54e7846738dc10950187e6a49f40220ae11bde340726429305cc89cc78b9 /launchers/ config
dl_verify 3ad19e79e95555cceee52c7fc9805989eff8c0b0a997820656ab337369eb5948 /launchers/ TFC-LR.desktop
dl_verify 62f64d0037f9f860d3afbb682e5e087156b4e42c38e177ea1d9e070b9d453bfe /launchers/ TFC-RL.desktop
dl_verify d877f71fd9b9b46eb16371c9a7613d682332638b467a1f4752739f9f543212cf /launchers/ TFC-DD-LR.desktop
dl_verify cd1cf1e403c0b4d308abb6bfb0f12ab8929840c49051dbb22f5c56f910ae8aef /launchers/ TFC-TxM.desktop
cd ..

dl_verify 8639e791dab49ab8a7bb9bbfa722911d4edd9e46cfb0c832dcfec02ea772bfc5 /'' LICENSE.md

dl_verify 559bef13cabc7cc907bc9287cd9638bf2778d5ed5b1015cc4ed54935ee0d9b93 /'' tfc.py
dl_verify a31565c6563f97ea019e70fc551817af6d3db06d96ce6072aab77702f52b9bb6 /'' nh.py
dl_verify e7cfd80de08972865efb143f0a845a5327a5b8a67bcfe8cadf9ec9764d407fce /'' requirements-nh.txt
dl_verify a50e90cfe7ece7796d064b6f457e64087c1cc68305a1c0160980ff21e2af17b1 /'' dd.py
}

kill_network () {
    for interface in /sys/class/net/*; do
        sudo ifconfig `basename $interface` down
    done
    clear
    echo "\nThis computer needs to be airgapped. Installer has disabled network interfaces."\
         "Disconnect ethernet cable now. If you're using a wireless network interface, it"\
         "must be removed immediately after this installer completes.\n"
}

cleanup() {
    rm $HOME/tfc/requirements.txt
    rm $HOME/tfc/requirements-nh.txt
    rm -r $HOME/tfc/launchers/
}

install_tcb () {
    sudo add-apt-repository ppa:jonathonf/python-3.6 -y
    sudo apt update
    sudo apt install python3.6 python3.6-dev python3-setuptools python3-pip python3-tk libffi-dev -y

    tfc_download

    python3.6 -m pip download -r requirements.txt --require-hashes

    kill_network

    python3.6 -m pip install virtualenv-15.1.0-py2.py3-none-any.whl
    python3.6 -m virtualenv --system-site-packages venv_tfc

    activate_tfc_venv
    python3.6 -m pip install pycparser-2.17.tar.gz
    python3.6 -m pip install cffi-1.9.1-cp36-cp36m-manylinux1_x86_64.whl
    python3.6 -m pip install PyNaCl-1.1.1.tar.gz
    python3.6 -m pip install argon2-0.1.10.tar.gz
    python3.6 -m pip install pyserial-3.3-py2.py3-none-any.whl
    deactivate

    sudo mv $HOME/tfc/tfc.png /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-RxM.desktop /usr/share/applications/
    sudo cp $HOME/tfc/launchers/TFC-TxM.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/
    cleanup
    rm $HOME/tfc/*.tar.gz
    rm $HOME/tfc/*.whl
    rm -r $HOME/tfc/src/nh
    rm $HOME/tfc/nh.py
    rm $HOME/tfc/dd.py

    sudo adduser $USER dialout
    clear
    echo 'Installation of TFC on this device is now complete.'
    echo 'Reboot the computer to update serial port use rights'
}

install_local_test () {
    for r in ppa:jonathonf/python-3.6 ppa:gnome-terminator; do sudo add-apt-repository $r -y; done
    sudo apt update
    sudo apt install python3.6 python3.6-dev python3-setuptools python3-pip python3-tk libffi-dev pidgin pidgin-otr terminator -y

    tfc_download

    python3.5 -m pip install virtualenv
    python3.6 -m pip install virtualenv
    python3.5 -m virtualenv --system-site-packages venv_nh
    python3.6 -m virtualenv --system-site-packages venv_tfc

    activate_nh_venv
    python3.5 -m pip install -r requirements-nh.txt --require-hashes
    deactivate

    activate_tfc_venv
    python3.6 -m pip install -r requirements.txt --require-hashes
    deactivate

    sudo mv $HOME/tfc/tfc.png /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-DD-LR.desktop /usr/share/applications/
    sudo cp $HOME/tfc/launchers/TFC-DD-RL.desktop /usr/share/applications/
    sudo cp $HOME/tfc/launchers/TFC-LR.desktop /usr/share/applications/
    sudo cp $HOME/tfc/launchers/TFC-RL.desktop /usr/share/applications/

    mkdir -p $HOME/.config/terminator
    mv $HOME/.config/terminator/config $HOME/.config/terminator/config_before_tfc 2>/dev/null
    mv $HOME/tfc/launchers/config $HOME/.config/terminator/config
    sudo chown $USER -R $HOME/.config/terminator/

    chmod a+rwx -R $HOME/tfc/
    cleanup
    clear
    echo 'Installation of TFC for local testing is now complete.'
}

install_nh_ubuntu () {
    sudo apt update
    sudo apt install python3-pip pidgin pidgin-otr -y

    tfc_download

    python3.5 -m pip install virtualenv
    python3.5 -m virtualenv --system-site-packages venv_nh

    activate_nh_venv
    python3.5 -m pip install -r requirements-nh.txt --require-hashes
    deactivate

    sudo mv $HOME/tfc/tfc.png /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-NH.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/
    cleanup

    rm -r $HOME/tfc/src/tx
    rm -r $HOME/tfc/src/rx
    rm $HOME/tfc/tfc.py
    rm $HOME/tfc/dd.py

    sudo adduser $USER dialout
    clear
    echo 'Installation of NH configuration is now complete.'
    echo 'Reboot the computer to update serial port use rights'
}

install_nh_tails () {
    tfc_download

    sudo mv tfc.png /usr/share/pixmaps/
    sudo cp $HOME/tfc/launchers/TFC-NH-Tails.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/
    cleanup

    rm -r $HOME/tfc/src/tx
    rm -r $HOME/tfc/src/rx
    rm $HOME/tfc/tfc.py
    rm $HOME/tfc/dd.py
    clear
    echo 'Installation of NH configuration is now complete.'
    # Tails user is already in dialout group so no restart is required.
}

arg_error () {
    clear
    echo 'Usage: bash install [OPTION]'
    echo -e '\nMandatory arguments'
    echo '  tcb    Install TxM/RxM configuration (Ubuntu)'
    echo '  nhu    Install NH configuration (Ubuntu)'
    echo '  nht    Install NH configuration (Tails 3.0+)'
    echo '  lt     local testing mode (Ubuntu)'
    exit
}

if [[ !$EUID -ne 0 ]]; then
   clear
   echo "Error: This installer must not be run as root." 1>&2
   exit 1
fi

cd $HOME

case $1 in
    tcb ) install_tcb;;
    nhu ) install_nh_ubuntu;;
    nht ) install_nh_tails;;
    lt  ) install_local_test;;
    *   ) arg_error;;
esac
