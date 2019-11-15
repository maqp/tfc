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
ARGON2=argon2_cffi-19.2.0-cp34-abi3-manylinux1_x86_64.whl
CERTIFI=certifi-2019.9.11-py2.py3-none-any.whl
CFFI=cffi-1.13.2-cp37-cp37m-manylinux1_x86_64.whl
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
SETUPTOOLS=setuptools-41.6.0-py2.py3-none-any.whl
SIX=six-1.13.0-py2.py3-none-any.whl
STEM=stem-1.7.1.tar.gz
URLLIB3=urllib3-1.25.7-py2.py3-none-any.whl
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
    compare_digest 3a3f8a79420ddb792f647c0bb2a82ac6bfec70f4497005a6ca77ba113cfda40bda502456156860b2a92b464eaf26b23e78bcf907d849ec40a08357955f31549d '' requirements.txt
    compare_digest 97558ed189976ccd54e3a25bcf639f1944aa43f4a4f42ff5ef2cf22349a7b649272e91746041b4e04b2f33adf1fab8818c339b1cc58f9353af3e5ac76cb1ec0b '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest bcb8a7ce1eb2d2f064b560ca5a8e467f84e3a0c3d643771e7782c792e89494600436e52c12f0a8471bf4a1da116f82ed732b8e06783534227a31f576f7adbd6c '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest 7e519d20fef24e25e88ec4a9c03abadf513b084e05038f17c62ca7899c2f9174a953caa0bfbd3b61e455e243513cdab737c22a34d73ebab07b65d3ce99100f0a '' LICENSE-3RD-PARTY
    compare_digest 99815d0cfbca7d83409b7317947fe940fe93fd94b50e6099a566563ee6999e33830fd883ff61e5367a040d5fda3f2a43165ef0dc6155e14a573e07dc27eba70d '' relay.py
    compare_digest 3904003688f993c6566fb8cc39e7bd8f820ef3ec0d097b7e467a5aa3019f480a026ae424bfb5473ff71c01002dc386528a010a8fb36cd0f5a03eb0c355450d61 '' requirements-dev.txt
    compare_digest 119fbe604a01ad0ef1d6e758ed6ee8dc46be4d746207b0cda1d4c17ba12621d32e6f479229856c6008a77f796bbd778dbecc27bb38dca817d88c257a9d3b27b8 '' requirements-relay.txt
    compare_digest 1696663138ca74e4c85caeeea82e34168ddbb1dd1a626a12064c43515859590e17c982dd0f1de2d807039794884bf053c147060760c84751143214e2af3611de '' requirements-relay-tails.txt
    compare_digest 550a82b9c07376e9eaf1117f77362f89c401169a848010110c2f8f2d99d50376f4cc5308d8b7e1928e68f15834aca7d5c9a9a7e7b8db956e5e55755ab7ea0a25 '' requirements-setuptools.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 7e24d0962e0be4b8e206d9390e888caab10604f5bf1bb29af4b91c4c20e42bcc04ef4ef15ce3248ac68c0acfd2e391a96a5567d87d91223f7be63a05b9dbf843 '' tfc.py
    compare_digest 7ae1c2a393d96761843bea90edd569244bfb4e0f9943e68a4549ee46d93180d26d4101c2471c1a37785ccdfaef45eedecf15057c0a9cc6c056460c5f9a69d37b '' tfc.yml
    compare_digest c6a61b3050624874cabc28cc51e947aa1ba629b0fd62564466b902cc433c08be6ae64d53bb2f33158e198c60ef2eb7c38b0bee1a64ef9659d101dee07557ddc7 '' uninstall.sh

    compare_digest d4f503df2186db02641f54a545739d90974b6d9d920f76ad7e93fe1a38a68a85c167da6c19f7574d11fbb69e57d563845d174d420c55691bc2cd75a1a72806dc launchers/ terminator-config-local-test
    compare_digest 9e670036e264cc9f5e5fa33d71f903e996ecc317e8958d99a73dd873639ce5921e31789041813b20ad89b0d09194fea3c0439619e16e7a9331c98917dee762b3 launchers/ TFC-Local-test.desktop
    compare_digest 496a0828096944b067feb5210d46a89b320ff2789d8b17f9a4faf787d93559b93335cec77139304981654195b7d32474dc62624209510a8ae5c4690e27d26fce launchers/ TFC-RP.desktop
    compare_digest 496a0828096944b067feb5210d46a89b320ff2789d8b17f9a4faf787d93559b93335cec77139304981654195b7d32474dc62624209510a8ae5c4690e27d26fce launchers/ TFC-RP-Tails.desktop
    compare_digest 98db2dcc5226632383c1924b678d0bfeceaaf7696071ea5b22116fa46216e40af140b0bd127da53c6cde5f09ba200d2afa7e643284f12b6214f4c353d307ef6e launchers/ TFC-RxP.desktop
    compare_digest eec5b006779bbdfe5a3e3da0ea5ea4655f5b77a45ac9834941fba5b5861ca503808400d29ad0b2d9790dea3ce5ba9e6747f345dbaf4398025778cf4b70de8dee launchers/ TFC-TxP.desktop

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
    compare_digest baac9291c49fb4b963e200757b5abefbda4f19fa30e27066a41d51009db946d882ed36e4d62f984b33b1b5d0b27de2238200b4b3bdc40b114061639cd9d3deba src/common/ crypto.py
    compare_digest c7c8b3782f7a5fd3e035ee2ffc776860caf62f501cb7f1cc8438f03c83e474e2f6b2fbbf9b8dae815fa0a44305e6978b38889cd78349f6ac4814fd2f96eddc8e src/common/ database.py
    compare_digest 2f912fdf06b4ca20df7192b9f927473e05d4633d541f0f33346bdeb561a08ac5ee267d513ce02bfd21d2324d1ae615df1653cd4be99516464f770bc84957eb0d src/common/ db_contacts.py
    compare_digest 226fa936d6306f7beba36d3fa9ddf9191eb45b7bd217404cdb46824b127e8e906da95c2b53083c7dd4d05cf598b159135c08049c4493b2231081822ef02a7a2f src/common/ db_groups.py
    compare_digest b7f0b1ce630c41ded5d36a86cd0e6b17c7f708b059e613235faf4e868adcf51226d233f2e0bfe47ac54454c1561af8b77426d30f94ae26433392eeb70087c517 src/common/ db_keys.py
    compare_digest db37a75872c207e82e83377d03bab7d72496e94a311cccbcdeccbbb089bf4ff385fa9c5a2e6a836b7a6cd552493cb215a8296e346727035a41a00e7f6d6980f2 src/common/ db_logs.py
    compare_digest b1134de8a791cfcb7aea0dab9f2f9439621badf236cd850b344117fb791f0a2c1597445317f7e35b070dcc10e40a635801cf55b555ccfb12e354df930cdcfdd6 src/common/ db_masterkey.py
    compare_digest c9000d541149835aa0812aa4b3108356d2f9465a767ea4273ece6340212eff287447af9247df4cea309ef7f8a5cfc887a01c8190523d1616164dd0f98718905f src/common/ db_onion.py
    compare_digest 8b9feb9fc4a9897b00cd01a2970fea98e2139676149b75891376d4714c477a06a2cffc42f31e927e12f063c7c673d6f05a3a8e5f0a8f0194d3450192f619921d src/common/ db_settings.py
    compare_digest 7a673e6feb7a5b2e3417d2c0eee82a59b3730a5d241938a84fd866dfc838c3cd63d7ef96772d43f62df740a2ba1001456746dd6c86e950484eac3ebabed498ce src/common/ encoding.py
    compare_digest 00ad45d8fba1a605817a9f5d64cdfd6aad9c618db66befe682728a2291384c67bf5e80a5257211717a86e4a51c7e8c74f8f7ccccc3b4ac3c6f0f4c4e1b3cc98f src/common/ exceptions.py
    compare_digest 36fe744ac924cdf4c43babc037392e1717c6be0b5ef518be896ca76c74385a93dfe84fe5d2e4437e00b24ce694e0be243305c7c1f1b8722adbd0ae9f5806114c src/common/ gateway.py
    compare_digest 604893a2814219b2ed4e69b45d9ac2f8c2b5fc066bd085e86b76ef9df9984e6113f79fcaf3b9eb1197a9c9fc92cf524269e595d03b5009c46e8889d813475408 src/common/ input.py
    compare_digest 3379d330272e599bfb07f0591256725eabdf503423993e29f0d2f335581c23934b13ad9d477d198b866bf2c7bb2f59f2a93d634046ed619f1441019e6172aa93 src/common/ misc.py
    compare_digest a4246dc24cccf5d1751a1c80ec6f195954fd6541b7b1573acdf29bd8d3fd4085949201a2950a298c8ec7bb153fe33626a24e0fa8856d0bc4cfd3183a5ef931fa src/common/ output.py
    compare_digest c4d97b497b341f0e7865a4e27a2a2ffd3b3c5a7bfbf72f4676f6b65d6ba66a2adb8fed563f88fa25cef555f0042290ef0ae4cbeed1697a2e19a3b8cff0b9ef1b src/common/ path.py
    compare_digest 4365ed3b6951525cb1ec8dc1177d7fd74d5dfa5eab1ca8934775391a8736eed4df039684f19ccc2d8022f20c8cf93a57a736b259e8c7235da5060c5f62057c98 src/common/ reed_solomon.py
    compare_digest 0de1ca8036e50c24cd0637b44ea7444d601cdde4d247e96a3bfc5ad817de99f0a8a53257a16296fe92c254a7e566b1d4abde93dccdaa416c3bb139fc0f3393a5 src/common/ statics.py
    compare_digest f05c27de8d1a90dc72aeefc9e9b7ac350140668cf2ec2a18c8f33ab7219fe5e13557717f68bada8357bb98d41fbafd56754eaae523d9e660670066727ef137f7 src/common/ word_list.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/receiver/ __init__.py
    compare_digest ace8e64f6fddb546154fc912876240227d83b817780225f122320b99990c60743e9d98af1c45dd070d3f49f3e6a7a9eea621e565b4edd51536ff8b2cf56ca2ac src/receiver/ commands.py
    compare_digest 051a1eac8e1e177bdf1c94972ed511d56d9ccfb3dc97c6418355b4415b2d1dff42c4ef5420de05d90e1697375f4db119e04932c05d6a93a89e03e7ca4c7c7346 src/receiver/ commands_g.py
    compare_digest 9f8fe1cfdeeb1a8bef02b213626f77cd86d6013c55b868497a5976a04e458abdd7957a9287fe02caa050835124a2880e578d1172d72093e7099431a3fe07d8f9 src/receiver/ files.py
    compare_digest 6eae2793bdd72b9581cbbebc012a70b11744c2585fda1d1e253ff4d67cdc1d316d1f3ad7e391f5197aa1447ce21b0ecbc3e34517a8932ecd9eec7ff5d7313b5b src/receiver/ key_exchanges.py
    compare_digest 5b933072ba33349d2ef46bd253748a6ca82ef503de83761e7aa2e8bca5880f12d0c20b6eecd8ae71fe300094d78e18bb8a7a0af5d0de21144e8e27cf51bfe3a7 src/receiver/ messages.py
    compare_digest 755774a1954690abcb4905a03377f6367c8ea4f9b08b05dac53326c0576ffab38cf49f4e5a4357f56d3597385489800b2e1e0cbfb5f858510328cbded4a9d002 src/receiver/ output_loop.py
    compare_digest a69bb7fb303072c813917e008126726cb93d921232051d9276901afb72287d79bdaf4e98f8547754c64aeb4453f723dbb59906e59e78b3c8fcd7d4d3194504a3 src/receiver/ packet.py
    compare_digest 20c6754ddb6261c7a3b479e6ab7bf78eb0ef8783e2141373d7aba857f413091b78dcc9c32667dd8f8d5c41927102da7e35c4c4fcb0aa7376dc42b08c0c01d6e2 src/receiver/ receiver_loop.py
    compare_digest 96550b54c0b9a287974debadf838294dfc7d2f1b59340f8af7b0cfe91bedde8b35c5f6d0e5d61b359524513c6f15c50de6bf7d55b350c26329986493dfadd5f7 src/receiver/ windows.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/relay/ __init__.py
    compare_digest 5d34be330731b8b722c3580f12abd2515984ba0589ea95c0960ae099a13b9d66118a5af5cdf137bcf376bde88b0edf055888d2a5fc267081ea118fffc05a2b08 src/relay/ client.py
    compare_digest c32b5b78e28567d5ef0c6f41f1a3c69f6d31b1cb3b9d58faf6516fa27fc62e12b2f359f7b60176b5fe20a2d94725f5fd76a879d4b795513d1588f8ecf9bae5b0 src/relay/ commands.py
    compare_digest c72a57dda6054b9c020f694740751159df4602f11f7759ff76e48a8b7f07ec829b39d6c366613f3a69e36d3dca0823491f3232506f3a03ecc9ded3e2a4f0230a src/relay/ onion.py
    compare_digest fe108f1f642bdfd01d813fd0a183e2f6039c1e64a5ee57f6159fdc67d7574a0ba0ee23608a2a8499071f0844b7d2db6b6a14740046d5d664e09856c35680a0dc src/relay/ server.py
    compare_digest 9459e6cbe17fefac356e5ce183d923efff66f6d304111f2c0dbacdfb22a92df77bb11134faf8c15400bc59174ecbec1ea0b436065a9d49d3af70b46b24a77764 src/relay/ tcb.py

    compare_digest cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/transmitter/ __init__.py
    compare_digest 1fe0fda8d611ab7db6aa2911e7f6362007b1bbd53172eb213b69f9a14bb14e87c27a9ffad6def1357b926b3b51cb429d7b8db03f54c7465f6d8c95baedc23988 src/transmitter/ commands.py
    compare_digest 74291c8b952588caf7c3c6ac3e99679eaf97ba9113bfd560da4c461e16cd36c28d78a4e8750090d18606a9c1610a1a781d37fc6fe52baf47a955e0b5ec801b97 src/transmitter/ commands_g.py
    compare_digest 3a2940afcf8752f33c8f5a06293046a83d245630dde1a6877eb3c724cb03ee7b84147b4a57a62135a32862b40db1dc6c6823bedc52404146aeb6e9ef1f79692f src/transmitter/ contact.py
    compare_digest 2e78e578e62771adf7ae9f2a576d72b69a64e6b28649361244bd7a75959f2022845d73d68c3d6a4586841bb10cce906edf1c5d863fbf99b6d081dfc030f98a3d src/transmitter/ files.py
    compare_digest 7cb9fc9d095f40ce2de6b49c9bd58b9dcab6b835fe7749dce8642c3c87b0eee10c4e53ff986c09ae26fb7b8aad7fe87c5fd56a734f2e013f69195213b9d5e9ec src/transmitter/ input_loop.py
    compare_digest 29b71c3341395eec84b5f68719cd434da5ecc8a4a7ad1da91d49a5177b50c13a7d33e4a051fa5e0dba5639b2ffabd1c0bba367af27490fc711d4a0c340ca24f8 src/transmitter/ key_exchanges.py
    compare_digest 41798dfe91868b37c130a373accac93c4200dc77bd8b6c40a38835ecf4187b955ccfaa53f842ccddf78ce5607b3e361a30a4bb53bd7cb5ab6d2fb4785454dead src/transmitter/ packet.py
    compare_digest 31c6bbe595a1966ce3f0396ea7bfd5a7e070b2f5dce1987de2e471fddc698159b51a60a2734be1d4921c3e66a92ca7519d99793c1e61e626bf30607f6966137a src/transmitter/ sender_loop.py
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
    compare_digest f6a78508cb87050e176005a088118f8ad87b17cf541457d949e5712c356f8c4de7e7516ba066e5c4bb9ced5c7e7590ba7e07d4ae7fc7190487bf27f1bb9d0668 '' ${URLLIB3}
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
    compare_digest 387d94f37a74e2d86ac0a41f482638dd9aec9e94215ffc50f314eb2f8e0cfc2f15afc3e508ea37a4fbcca7e4bcfc65efa1e5cab5f8094ccedc18bee2b0f2e3a8 '' ${SIX}
    compare_digest 7f830e1c9066ee2d297a55e2bf6db4bf6447b6d9da0145d11a88c3bb98505755fb7986eafa6e06ae0b7680838f5e5d6a6d188245ca5ad45c2a727587bac93ab5 '' ${PYCPARSER}
    compare_digest b8753a0435cc7a2176f8748badc074ec6ffab6698d6be42b1770c85871f85aa7cf60152a8be053c3031b234a286c5cef07267cb812accb704783d74a2675ed3b '' ${CFFI}
    compare_digest 184003c89fee74892de25c3e5ec366faea7a5f1fcca3c82b0d5e5f9f797286671a820ca54da5266d6f879ab342c97e25bce9db366c5fb1178690cd5978d4d622 '' ${CRYPTOGRAPHY}  # manylinux1
    # compare_digest d8ddabe127ae8d7330d219e284de68b37fa450a27b4cf05334e9115388295b00148d9861c23b1a2e5ea9df0c33a2d27f3e4b25ce9abd3c334f1979920b19c902 '' ${CRYPTOGRAPHY}  # manylinux2010

    # PyNaCl
    compare_digest c4017c38b026a5c531b15839b8d61d1fae9907ba1960c2f97f4cd67fe0827729346d5186a6d6927ba84f64b4cbfdece12b287aa7750a039f4160831be871cea3 '' ${PYNACL}
}


function install_tails_setuptools {
    # Download setuptools package for Tails and then authenticate and install it.
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-setuptools.txt --require-hashes --no-deps -d $HOME/
    t_sudo mv $HOME/${SETUPTOOLS} /opt/tfc/
    compare_digest 2e90929aa61c847e1d414d427b08403679ba5f512a56d58b92ee64d47e8a2c5da18e47126e5f59faca335b3a4b5ec9857aa323d866252546a6df42c3e3ef3884 '' ${SETUPTOOLS}
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
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt --require-hashes --no-deps -d /opt/tfc/
    sudo torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements.txt      --require-hashes --no-deps -d /opt/tfc/
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
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements.txt       --require-hashes --no-deps
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes --no-deps
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

    torsocks python3.7 -m pip install -r $HOME/tfc/requirements-venv.txt --require-hashes --no-deps

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
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-relay.txt --require-hashes --no-deps
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

    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-venv.txt        --require-hashes --no-deps -d $HOME/
    torsocks python3.7 -m pip download --no-cache-dir -r /opt/tfc/requirements-relay-tails.txt --require-hashes --no-deps -d $HOME/

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
    sudo torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes --no-deps
    torsocks python3.7 -m pip install -r /opt/tfc/requirements-venv.txt --require-hashes --no-deps
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
    echo    "  tcb      Install Transmitter/Receiver Program (*buntu 19.10+ / Debian 10 / PureOS 9.0+ )"
    echo    "  relay    Install Relay Program                (*buntu 19.10+ / Debian 10 / PureOS 9.0+ / Tails 4.0+)"
    echo -e "  local    Install insecure local testing mode  (*buntu 19.10+ / Debian 10 / PureOS 9.0+ )\n"
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
