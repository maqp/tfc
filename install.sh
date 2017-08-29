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
    if ! [ -z "$2" ]; then
        mkdir -p $2 2>/dev/null
    fi

    wget https://raw.githubusercontent.com/maqp/tfc/master/$2$3 -q -O $2$3

    if sha512sum $2$3 | grep -Eo '^\w+' | cmp -s <(echo "$1")
        then
            echo Valid SHA512 hash for file $2$3
        else
            echo Error: $2$3 had invalid SHA512 hash
            exit 1
    fi
}


download_common () {
dl_verify f91061cbff71f74b65f3dc1df5420d95a6a0f152e7fbda1aa8be1cccbad37966310b8e89f087a4bb0da8ef3b3e1d0af87c1210b2f930b0a43b90b59e74dfb1ed '' LICENSE.md
dl_verify 6d93d5513f66389778262031cbba95e1e38138edaec66ced278db2c2897573247d1de749cf85362ec715355c5dfa5c276c8a07a394fd5cf9b45c7a7ae6249a66 '' tfc.png

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/ __init__.py
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/common/ __init__.py
dl_verify e8030b710ecde510330b40a00e64bee2604f63368182355774ba21ce814bbe079f7cb19d5c69ac357d28a883fc14343ee5c8d6b274ea43ccabe9b12be914ef78 src/common/ crypto.py
dl_verify b4407e85a84d6e070b252f2c1c91268005d1ae6f69c9309723d2564d89b585e558fa80b7a8f1f52cc7d40e6595c3395cb5b68e3594af9d3e720a4a31ee8ba592 src/common/ db_contacts.py
dl_verify 1cc269c493969ccf98ef51a89895d0f279efdcf0e5c89c2e2e384e0cc7f1fea425566bc619e02ff0ed5ab3d28c3bd9bad93652f08f088c2915cfc3d28cd00d76 src/common/ db_groups.py
dl_verify 0c27e847aee638883928f4437adb8077de2a9444e7f06f48c45ec17e46bda43d8434934b8a04cfc6cfb4006554b5578cfba402f9a4ef96f7329a33d26fc0ac39 src/common/ db_keys.py
dl_verify a38dd34dd681dc7993623921010d5e50ecee5192cd45e37db25a90ebe1e58c1a44864d95b11a607021773d6fe2578f1ac9eb287bfe6d5004a816f88770ab2b6b src/common/ db_logs.py
dl_verify 1516e939ff34838586389b4f920d310d79d09baa7173ef3a5a844d5982d747f4a120be9ac977189fd94d6b97792bb5e52ec78478781ecaa55d2643226a05fdd0 src/common/ db_masterkey.py
dl_verify c9ddfc92ec0043e3253950dd5d0b551bd5b92bc1c5b12aac14b99274e73d891dc10bc4081b9eae71f50af30a52d31507fef5ca309d9e6043aa93fd1dba5ff441 src/common/ db_settings.py
dl_verify a3911e2e60e31154f40d548edc7470c1ed963f4225e0005eba9499dd7b752879b5fd65fae983b513b0d76523b5a7cd3b9744721213a27f4e844a6c797e7780a0 src/common/ encoding.py
dl_verify f67c414fea948fd9b81bf8a53158b159085a34bae562d74cb2aa56fa317b65323b92a3a2d787377900cdecb65a1af8c224a9c7efd3969c377149284fd8a5882f src/common/ exceptions.py
dl_verify be34431336fb68429a9f6ec8603b9a475104a2e0c15b3c4beac63a50d2c4024863d769c7b8d154872afc80a0b8d82635448c29c89b40edcc74595db28a7364d4 src/common/ gateway.py
dl_verify aa1f94542fc78d4a9dd7212d02e4cf710ecbef1edc31662445e6682469e32059e5c3047fe512f751354c869fe9cb03bb3126ca987d7d1570ca9dacc1870ec759 src/common/ input.py
dl_verify 27b562f0d9083aa906465e9ece1817a3a03cf6980a9262ad1fc855e1989491d331871d41530919ee1cd35db8564f54b3c44492b6ef90f2836a2c3a8404f5b3d2 src/common/ misc.py
dl_verify 87e62112217263d4eda7d0a2a0cfdc0a3a698be136e650f3e32c7ffae7450706d059dc307abc40a1ce2b225c718ef34cca9ceaff1dcb51e28a2eb0972b9122cf src/common/ output.py
dl_verify 20a7ec5b54834c54fdaf889bb6261165b630f0f801a7055cab347d26e58cdde16d27d84ff0b437a318bdc5a12c575ee6e7f1d7d3c3897140f3c5ef1f75019f94 src/common/ path.py
dl_verify adea6b33ff23f9fe34539d38b3eb602b3a1075d92d9b8c5fdb4f12ebdf06fdcf6833edb3d94f91c4c0a2d160e0d152594aed776310cbd7cb5f2baf1579edd21d src/common/ reed_solomon.py
dl_verify 71f9221ad6ac787f1ee391487d5f14a31518c496e164022b83eac293d8e717751f1240449206b8f7cdee06fa625f407a32ba2add823f63d4b5eda073eb141308 src/common/ statics.py
}


download_nh () {
dl_verify 27a60f6f2c4024c41ae11669d6695662b47aa0b1efb21c6cc0af19a20ad66c6e8a34ac57db1558f1d5e84300d43618b72542bb80c3b0aa309fadeacaae14f339 '' nh.py
dl_verify 569f3baa7ad3589f8c95f9ae1c00f2fe19e4031b04f31e68536fb924b19d433adfeff788a6eeb21a4960e44d2f575eaa7479de268ca2333781d4de618295156f '' requirements-nh.txt

dl_verify 3444adc5cd050351bc975397da22a04becefc49a69234bd9d6b41f2333feb5cf0a31765ad6c832f69280120d159e2792dba3d9ed0fd269e0b8e04ec053c2095d launchers/ TFC-NH.desktop
dl_verify 8138bb15be64281c35310a711a136d6953985a0819bc5e47c1b224a848c70a01a4f60bb56e04724a919b1f84a4adfe5bf090109ace48d294f19349c051d3e443 launchers/ TFC-NH-Tails.desktop

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/nh/ __init__.py
dl_verify 5cfc25f56763c4ce96013eb3062ab62646f1a9300a8c596d83e4d7bb4e08754bcee4179301290489ab667ba2229d9a599767e2271f081d0035e4cf0783eddc95 src/nh/ commands.py
dl_verify 98c53fb80482e1941d74ce34b222c9457f4d2a346f352f7624f3e6376843598b3b2a3ad1136c3f6fc9e4df2e42f372d7470dcde2c8ada40b4cef896ae8ed61a5 src/nh/ gateway.py
dl_verify 4c293c3abd62aa0997014423d1b145df144247e834a552a1172a4c06e3dad487ac9c7c0ee56de74c29a4f89a538902206dfda62b8a105e47acb22b842d98f55e src/nh/ misc.py
dl_verify 93c7d4ec6f80e46b5a46a404a5eb676d8efd1700e74fdd06a65bc823fb566a6eee63bccd6da520e56bb54310089aebbffb12483a6c908c66348a4f34c13d600e src/nh/ pidgin.py
dl_verify 97a8d945ebf88708180186f6a7c19cf3bba314da656b46dae2a1fbbeaeda143fd3f31d2ba9ed1981960bd8b04c1143a4b580643595d394f9bdf8ecb560d33d10 src/nh/ settings.py
dl_verify d83d3b0f1157e60589c7428f33091c2239e910e410c94e3254fcbaea8cffbe8a783cc7175dc6230fb10525d17f6056579810100ba0600f0d4a5127bfd4ee0dd2 src/nh/ tcb.py
}


download_tcb () {
dl_verify ba9fc6dad29b91a78d58f6a7c430e42eb75363d14de69668d293041bf36bb5eea0666007535c8f5a122e0a72d0da7122ff45d8e6c081c9ccacdaeeb47cb93b44 '' tfc.py
dl_verify c2f6afa281f91b88da85668dcfe0cade4af01927ac748ee1dc76c6f160149742980b3d6996c7d04e7fbbf5abca8f79100fd746e71187990d972f4b1aa2c1bf63 '' requirements.txt

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/tx/ __init__.py
dl_verify d2a9cda8e9af9d45657bf9d28d0cd53b5ae63212e20801a3cb133e15cfa5f34a6250c0620633945cfb276a90c5cde23588694045a0401d671ede7c2354c1d72e src/tx/ commands.py
dl_verify 63bf0e11f46d8e5544e091110fd24e1241ddd650daa9cf76c39ed7db43a7062dc252a6b37ef26d55fb875fbc51314b47d23c98176d4fc1bf51fafef7a1f69763 src/tx/ commands_g.py
dl_verify e660fc6368a430a82a8a2d0e38bd4e8aaf94bc0ac5fc6b2c63eceb58f1579ce75ac3cb83382202e929da76fe3617d553732d1798beaded4f52ce0bf7e53b75bc src/tx/ contact.py
dl_verify d215e8983de808526cf9b76b0d299b7cc93a1cb15316113930028fbb0cf66bde51daa57a1e7ef6cfbd9f65e515553631943e142ab78ab89b78571f8612355b51 src/tx/ files.py
dl_verify 4f0fe9684e1aa9caf665fcfa037e7ccba61c9e4385621178912e2875e1a28fed72b9fc48581782dab3c25c29e0cb38bfed2906b2e19179b43a8b35da72656112 src/tx/ input_loop.py
dl_verify 69a90b3e908769821c419ac80779d0b09401103e4b8f79a0bf444fda8f6a20d0c559679f1595869c4bfa569631211f1297141ada7e91b1c3d28ce804961e00f4 src/tx/ key_exchanges.py
dl_verify c782cdeda0faf946a4c97924668697a479d7d60051988e96bb4e62bf0e1ef82bfc982b8fb3465e5371b446d3f042b1c54a32a31393ea64764d281abac95850d9 src/tx/ packet.py
dl_verify 05e76b6d62e694d1f887853ed987a770debf44acf8da12091f9a4f614a8a26c5771593d14f53beeafb7f684d56e0ecaa000f3a73bb69342cb6667f9758b56c9d src/tx/ sender_loop.py
dl_verify afcf71e6d407bc7ef391e795441c3343fd2f172f2636fd1b06ffbadb8d0d38368007be9d8e69916a02679f576407200e836c1eaddf0dd3255d8dc073993d07b1 src/tx/ traffic_masking.py
dl_verify c806320893ecd097ed5f8d14619cb453315fc369d0c081ef40d48cbdce46630fcd3006bd11d8712c0f6d89d7468b674e78b50257048a3a99180093f0a361615f src/tx/ user_input.py
dl_verify 827ecad844d1fb3709b81e59f6f1ad88362a3140517a8a5d36506415e1494d554d00e2dc1dc7cc65db06d09a1182acb1150b939fcffdcd0939e70229de03f3bc src/tx/ windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e src/rx/ __init__.py
dl_verify 04f23a236a7f8b5c43a532ef2b3278202a17b026a47b6d1f880a6fb2e775824aff3be78a14167905c955f98a01239bd1c5e63cd08566dc759fe259a4b0c6a74a src/rx/ commands.py
dl_verify eb307d3b780dd90ab2618909707c4cd56db829dc94d49408c4a6b84f46292f395927fde0d36451c90a595fbf948cbcb3f1aa8676ca5658d6b113a3b45f2216db src/rx/ commands_g.py
dl_verify ede3aa62af2b120078f12bbdf7d21364484652c5204817436e30cc5af70ba73fba68a6a7cfd08f43734f6c5778e710508674f7a9653d4b51922460ba1cbec796 src/rx/ files.py
dl_verify 835f6f673b7bc1785b8c311f21aebc7ffab1a4570152f3888d13e00d763c66c81b5a77f602e7488962737c6b675beeda0bb347dfb1d11af51ea036be8932398d src/rx/ key_exchanges.py
dl_verify c06e19c1fc279346d8454eed45fc9d2f6c1b3c561d9b9b45957b145f23ca9ba016cef51d1fad4fadabd9669c6ab4443679ac98630194073294c1ee20afc725de src/rx/ messages.py
dl_verify 425e9bbd17c13f62732687cc798e7fd49159d5f5a291ee4ff292dd45a65bdc8146f2a90c0d4abe7fb28baea855c396335832c484a0c753067db4fa7974cce651 src/rx/ output_loop.py
dl_verify 5f7d66daedb0cf60737a14fe428e3f420b66a08ae7c5b63135d11e17a1f3e11ce43f50d54516249fe7a065b69a17082ee81297f7f4a8c4c9a1f26918575c8dbc src/rx/ packet.py
dl_verify 9f5f9ddf01af12e43cbb7d8423bff2cdaa4a6d3848f1ba9e1e2bbb20da08221b84de4538700c642fdcfa3637db6ad03cd2f7dfe04e67544559b8e4cc96608e61 src/rx/ receiver_loop.py
dl_verify d26e949e7fa57b43a6489e3fe01e2bc26f7e7dfa8ec99915afd2f54f7a3e2a1e86ac16f3d95642e80ae431e35f933a07244d8ca49b3861aad6bcf462dcf2791a src/rx/ windows.py
}


download_common_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/ __init__.py
dl_verify 9cba0c6eb96f5e827a669312c2c8d4d52b24ca5133d294ab946fca8d508b71f898328487ec8213af639a61fcf7fee8fef3102c5f1341cd4c588289a03e820003 tests/ mock_classes.py
dl_verify c6432382c52a7665bf2da5ff4c6e502d46b0d29f7d8eeab2feacd77e4e4bd954227c57f9baf1251feb0f4d6923380fe64a38ca8d12d0d7cbb2b8d34c5b803b5a tests/ utils.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/common/ __init__.py
dl_verify 83af707f0018df689f5b12368603308bb2a0c255e66c78b8063b8a66338c3018d7f4300074ec21e024693a9ee264f4ccb927c27dad447fbc632cc3dcbc7c0ff7 tests/common/ test_crypto.py
dl_verify 8e1b790d9143a7d2decd5dab97826cc3fdf85c071da95340da7a4fdc862d94099408675ad7422c8d105e988aa39eb5b5ef1a39fce9be5a6ae6877fd820e1f899 tests/common/ test_db_contacts.py
dl_verify 8190d1525f5f603293f30a07d2e8e15becad13094458d6b3e75a8f45bf7751019ed9fea8df9b366c09bef083d3eb1b4bf0e3c165912069ddfa862f86107cd420 tests/common/ test_db_groups.py
dl_verify e11f05a0193bfa013c487ff4b646f8f54b5b3ac71e136d69d38d4e572afffd0849ce3f4b0c1639b77f6506c33e6f13c65ca5b4b3f3e8a421a17f89fe2113141f tests/common/ test_db_keys.py
dl_verify 019f014bd443f1659aecc6b84e262b525f0ef990edbd47023575780da1b2a91169e15ceeb451d05115c393b055e636719277fd8272f6445388516d357b31a032 tests/common/ test_db_logs.py
dl_verify e5c0fd0fcff438b92933e81389053b3d5a4440d0b37d5e9744a96c6a8cf5c14169ae90a2714d5490f4f920b0335235d9d5cd6f42e806698333a0ef2821b56e92 tests/common/ test_db_masterkey.py
dl_verify 19233b6f6aa19e50f36d8ca595e93b8a782c20a9f6076e966da8a7c5619ff33a0b8b02a93d16903ecc873930e0a263a79edc4a2c85e39aeaac81279ba1a65d0e tests/common/ test_db_settings.py
dl_verify 4472f5528c6c9c60b4c4dbbc6c41dbe19734710be37b9ffdb27081c84fe308230c4e5b0180c006fdf47e75bb05050e41958df25b6feb752fb7951141bd59c6fa tests/common/ test_encoding.py
dl_verify aad18d42e5366223a88d14e809f8897cf4f989de5e7115b1b5052675b134d9e5bfe30c21bef2cc8d5150385dbb029350f1ce36d388fffbb184b8872014209acb tests/common/ test_exceptions.py
dl_verify 12f791c529dc447c6940049e3b9b44cfd3847c25089864820677e23446ed72d212bdf1dcd849bf80d0ebb1a438337730e5fab395b1f183b98190e49575391038 tests/common/ test_gateway.py
dl_verify 01df5269c6189a55bbed7e5894aa126d5e16d16f6b945160e63c929b397f06ef238b3a4be8fa3d5431567d1b62a0d4eb86faa320cb6df9dcfed971d98df936da tests/common/ test_input.py
dl_verify 029cc1f4cd983c32a4b2ee0b78c0f3f9e40ed3ff417ed323927325a582d5e77c52c2ca48e3ea38471fbe431d87a4e35355de0a6b17e2cb6331d04a25ecda1358 tests/common/ test_misc.py
dl_verify 7ca3a76b69a96e33ce8ef0404bbed696f3c82d63cc8940e25763ec241e7d8be2cf033c54d28a193bed911b3646bf4c111450a30d90f25af347a323e3018da04c tests/common/ test_output.py
dl_verify 7b5d4519d3cde35b25a120bf9f68219c60fb168e3dade54d2b2dc94a9eaea9c010c5391b8c85606de3a66b20f9d3cdd72e78f7ec861747e923aff3eed6ceeca6 tests/common/ test_path.py
dl_verify bdea73b00b14b8de136112e9c6e1257aca971a704bf0a104e3aefd1014a0d94ce0cd941a2568e058b27202ec595476692c22ac1244d626759965b8242fa3ea74 tests/common/ test_reed_solomon.py
dl_verify 946812a0c4e368b349b31622ddd21ed863cd2feeec1ff145c45a96a5953a47c5865eade0fbe391510cfd116fa35d9f8253e4314187884762e3ae3000dcbc9db3 tests/common/ test_statics.py
}


download_nh_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/nh/ __init__.py
dl_verify 85512170168f3fcd3f5a9e97bec6b5d8b0e4d2532347a12d13f7f284f74a68288ab40e2f69532791edd269917b169214d10a40a555cc458a66ed8072c5d92368 tests/nh/ test_commands.py
dl_verify 045f61820b739ad86d475a460788f27a92cfcf651ad4b4d4e798f6f3f4672e3e10fee2941057c919dac23fd1231df06b78f6be3e3a749e7b9d51504ec49044a2 tests/nh/ test_gateway.py
dl_verify 512ad346e350713bd551447e1c305d25d038a6c1a6faaf2a9880c52352255bcf5b057c89148804ec495cd5d996b832f7d139691ef9a3fc3fd65b927a3548aee9 tests/nh/ test_misc.py
dl_verify a32e36680caa2bbcb841369062996d1a1656c13c5eca6bdd75f15841a5123c6a90bf65b85acfc3d8536a888b4e41a1b591a2b44b3b871cb3f0ebe50b63509b1d tests/nh/ test_settings.py
dl_verify 825f26a6baf24fc650a9e3dfc09a2361b1000e48b754273c2b0321b7c01f08f71ebb40bf1617f948ba13bec925158b8f1db974003aa8ef3363ad69f4fd88e843 tests/nh/ test_tcb.py
}


download_tcb_tests () {
dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/tx/ __init__.py
dl_verify 84c64ff9fc9908a5140d037e6afb7f1ce05e012f4fe3e39e446ed5468747098a4ca5f73f500cca3fe15d101cca5d5c75267c47d1887bed47c6427ac587eae7fb tests/tx/ test_commands.py
dl_verify 8be45e9c005d6ddb89d0d8a1dc3477c39e13e5b95dfac1d38f94f45a886ee0af64f9b95bf25ee26b1ad2085fbd285237b68145dba916fc56844dbb740ba0d52c tests/tx/ test_commands_g.py
dl_verify b9a27910eba3f09b09c5d88c41ec95629ec0a8cfae8cd393bbabe5ffb699b5a1db98bca825fbf320eae48c8fd9125a7d2dc64e94c992dbd4799d7f00ad0a34b0 tests/tx/ test_contact.py
dl_verify 2b15f293950ce0961e2975a20b60e7dc7e5668507941ce01bcb9147799c2b4f72a1ee35206e58f4e9d3f40f6ff758e0206c3bd6eb428c2d504aded8c254792f7 tests/tx/ test_files.py
dl_verify 1c8eb650a908f53d1ef798b31a969aa36fd19f79511697a1d71fef74460f8290a35b13284f16019fa06668f3f23dfc5744aed06b36cc5d260bff3f8c9f6a8062 tests/tx/ test_input_loop.py
dl_verify e19eb3d3bca69056ed5e93ab1e504f4ed64f49be01ffca736a59cb80269f445d92f4c21ca0ac0eb691c4ba545ef903001a12e475304f140ee26c11c37b493633 tests/tx/ test_key_exchanges.py
dl_verify 485f6ea31486b6aeceb7c6359bfb46c4a107f2f971b84c3bc36eeddf6cbec0dbbe730ca5109673d66dda61bf1ccb24dfb3f15575dfc0279b6adb6a1c504a2ce4 tests/tx/ test_packet.py
dl_verify 3967b417f32779187a9dff95187a63dc02a7c8dc314f92c029351c9be180344e560574007566050dac58b4c3f066ac9e3e11ea8047b61801f8530808d4d55ed8 tests/tx/ test_sender_loop.py
dl_verify dc783f22c8e0e48430269ef5001c7e4c361a3b555b5e48a9cff136007534f4c093f1d1cfe2b55751adc1c9145d6de08e2cd21332c75e2533d50c2fda70060d21 tests/tx/ test_traffic_masking.py
dl_verify 35774f4d935ba91600b11b73b75aa12605a64297914cfd2eba793d3ebaaf4cc6ad48d8e8ffed43a37d3dd5054bf134b9e7cae693ef7d7232d02c9a0e5b54386d tests/tx/ test_user_input.py
dl_verify ba9abe1222c4bf409c00e5cbbcdcfb28753f3c0b85e52aa89e45c81a2831a461cff6ec16d1ebc7690419b6d02bf220de0ac6b30b7eabd0c040fa571fc4e61f9f tests/tx/ test_windows.py

dl_verify cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e tests/rx/ __init__.py
dl_verify 6636ec696e79f9899e8b420efdb0969d71f0782d5b3e35ce34bcc99447b6a5fa9e9da3f05631abbab039309801701a72d917b0e7e813c3981e6b577413973a23 tests/rx/ test_commands.py
dl_verify 467a91fa2161c172506036ba36f8f31cbcf1b9aa1a91f1e7aef2727e3113edae8b24b26488b82b1ba1d4d00411e79944568b8d9c9e2d7e22c3b30ce759ab0137 tests/rx/ test_commands_g.py
dl_verify 081ff658de5c46327ea840038e44d1d1dd5682d31950145affc8f2536e2c06ab779f672db779a555a75a2bed9a1e323117e07bf89d20d5f2ba06a09dedd87e8f tests/rx/ test_files.py
dl_verify 7c0d97bfd5dca727ee36573cdc1b5683077524ff28236e01d8b011da8d51c09988985b76e054c2cdebf6a95fd2e68a14d7a976f1c03a1a39ab9d2a3672e89143 tests/rx/ test_key_exchanges.py
dl_verify aef0fe0e208ce91002924ec2d103c4575079ca3c72544774ba904e44f99ae78aa13cb242a61f2b1fa7c5e7ab8095b0836d17ce276e888792dcdc2b34b8603339 tests/rx/ test_messages.py
dl_verify b6a33ed791e6daab20ee10f304390a8bc890a984c1bf1bec4a57d04741797cfc242d1f1067a0a2854f4daf35fb1302d652fc5ed17749884b5424d700ffb32642 tests/rx/ test_output_loop.py
dl_verify 8dbd77abca3bdab031f5a2e16d5789c2359088c9817a53188a4d6b6b45d4bce087e0ec872810401f35d6cdb170b3052dc27f826e4906ab3f41bb71e49fcfb29e tests/rx/ test_packet.py
dl_verify 6b87bc6c6beaf421c8f9f27ec6ced2d3248efb7b7cd966646b41a486d82d7665f7d2bb2879e1b6baf84fdf77dbef1eba565adcafd8228e7dde5919f8a12e47d1 tests/rx/ test_receiver_loop.py
dl_verify 2b77819b9e06ce0cdc2a965c063000cd7b22e69fc3219f1885eb56f6185fcb49b0c922dcf6594a18f8909e330aa1722fa128607f74ede7ac237c10ff4294d877 tests/rx/ test_windows.py
}


download_local_test_specific () {
dl_verify b42135363e8ba718e76756496de34a5fad0510162677eeaa584b083342e20c91732b6589bc6c14a7951f100b52f1612634a3c640857276edabccf423daecc705 launchers/ config
dl_verify 17c83b0fe035fe4412531e06e795e6d5b2aa97ea1827e3c7249f9746067cf1f6c7d2351cbd291851fa91d27c565409e66f0e01ec432b040a74123fa4f1631611 launchers/ TFC-local-test.desktop
dl_verify 1defc149fec09999ab424b68c768b8aa43dc171a49016cff069f01c096542d2c3092124e95d4a140f72f7ba9098e9c148eb2297688771eb2404b204a9f88131b '' dd.py
}


download_tcb_specific () {
dl_verify f4f46d0d44234c094f566e88cc257d07399ee9552ff203181ca415ea2265b091bf14adf570122be7253b3d7fe22cac71f476b2d1fce5a6263f3c3cc7aaa2e8dc launchers/ TFC-TxM.desktop
dl_verify f3c0f471e8046cda7e66c153403c76ea55558bc06e2ee574f300b7507fa81bd2f8e5542ef342b4329f9cb6aee0d050ef4cad43170fbb2f36ac69358e74c035f5 launchers/ TFC-RxM.desktop
}


activate_nh_venv () {
    . $HOME/tfc/venv_nh/bin/activate
}


activate_tfc_venv () {
    . $HOME/tfc/venv_tfc/bin/activate
}


kill_network () {
    for interface in /sys/class/net/*; do
        sudo ifconfig `basename ${interface}` down
    done

    clear
    echo -e "\nThis computer needs to be airgapped. The installer has"\
            "\ndisabled network interfaces as a first line of defense."

    read -n 1 -s -p "\nDisconnect Ethernet cable now and press any key to continue the installation."
    echo -e '\n'
}


install_tcb () {
    sudo apt update
    sudo apt install python3-pip python3-tk python3.6 python3.6-dev libffi-dev net-tools -y

    download_common
    download_tcb
    download_tcb_specific
    # download_common_tests
    # download_tcb_tests

    python3.6 -m pip download -r requirements.txt --require-hashes

    kill_network

    python3.6 -m pip install virtualenv-15.1.0-py2.py3-none-any.whl
    python3.6 -m virtualenv --system-site-packages venv_tfc

    activate_tfc_venv
    python3.6 -m pip install six-1.10.0-py2.py3-none-any.whl
    python3.6 -m pip install pycparser-2.18.tar.gz
    python3.6 -m pip install cffi-1.10.0-cp36-cp36m-manylinux1_x86_64.whl
    python3.6 -m pip install argon2_cffi-16.3.0-cp36-cp36m-manylinux1_x86_64.whl
    python3.6 -m pip install PyNaCl-1.1.2-cp36-cp36m-manylinux1_x86_64.whl
    python3.6 -m pip install pyserial-3.4-py2.py3-none-any.whl
    deactivate

    sudo mv $HOME/tfc/tfc.png /usr/share/pixmaps/
    sudo mv $HOME/tfc/launchers/TFC-TxM.desktop /usr/share/applications/
    sudo mv $HOME/tfc/launchers/TFC-RxM.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/

    rm -r $HOME/tfc/launchers/
    rm $HOME/tfc/requirements.txt
    rm $HOME/tfc/virtualenv-15.1.0-py2.py3-none-any.whl
    rm $HOME/tfc/six-1.10.0-py2.py3-none-any.whl
    rm $HOME/tfc/pycparser-2.18.tar.gz
    rm $HOME/tfc/cffi-1.10.0-cp36-cp36m-manylinux1_x86_64.whl
    rm $HOME/tfc/argon2_cffi-16.3.0-cp36-cp36m-manylinux1_x86_64.whl
    rm $HOME/tfc/PyNaCl-1.1.2-cp36-cp36m-manylinux1_x86_64.whl
    rm $HOME/tfc/pyserial-3.4-py2.py3-none-any.whl

    sudo adduser $USER dialout

    clear
    echo -e "\nInstallation of TFC on this device is now complete."\
            "\nReboot the computer to update serial port use rights.\n"
}


install_local_test () {
    sudo apt update
    sudo apt install python3-pip python3-tk python3.6 python3.6-dev libffi-dev pidgin pidgin-otr terminator -y

    download_common
    download_tcb
    download_nh
    download_local_test_specific
    # download_common_tests
    # download_tcb_tests
    # download_nh_tests

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
    sudo mv $HOME/tfc/launchers/TFC-local-test.desktop /usr/share/applications/

    mkdir -p $HOME/.config/terminator 2>/dev/null
    if [ -f $HOME/.config/terminator/config ]; then
        mv $HOME/.config/terminator/config "$HOME/.config/terminator/config_backup_at_$(date +%Y-%m-%d_%H-%M-%S)" 2>/dev/null
    fi
    mv $HOME/tfc/launchers/config $HOME/.config/terminator/config
    sudo chown $USER -R $HOME/.config/terminator/

    chmod a+rwx -R $HOME/tfc/

    rm -r $HOME/tfc/launchers/
    rm $HOME/tfc/requirements.txt
    rm $HOME/tfc/requirements-nh.txt

    clear
    echo -e "\nInstallation of TFC for local testing is now complete.\n"
}


install_nh_ubuntu () {
    sudo apt update
    sudo apt install python3-pip python3-tk pidgin pidgin-otr -y

    download_common
    download_nh
    # download_common_tests
    # download_nh_tests

    python3.5 -m pip install virtualenv
    python3.5 -m virtualenv --system-site-packages venv_nh

    activate_nh_venv
    python3.5 -m pip install -r requirements-nh.txt --require-hashes
    deactivate

    sudo mv $HOME/tfc/tfc.png /usr/share/pixmaps/
    sudo mv $HOME/tfc/launchers/TFC-NH.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/

    rm -r $HOME/tfc/launchers/
    rm $HOME/tfc/requirements-nh.txt

    sudo adduser $USER dialout

    clear
    echo -e "\nInstallation of NH configuration is now complete."\
            "\nReboot the computer to update serial port use rights.\n"
}


install_nh_tails () {
    sudo apt update
    sudo apt install python3-tk

    download_common
    download_nh
    # download_common_tests
    # download_nh_tests

    sudo mv tfc.png /usr/share/pixmaps/
    sudo mv $HOME/tfc/launchers/TFC-NH-Tails.desktop /usr/share/applications/

    chmod a+rwx -R $HOME/tfc/

    rm -r $HOME/tfc/launchers/
    rm $HOME/tfc/requirements-nh.txt

    clear
    echo -e "\nInstallation of NH configuration is now complete.\n"
    # Tails user is already in dialout group so no restart is required.
}


install_nh () {
    if [ "$(lsb_release -a 2>/dev/null | grep Tails)" ]; then
        install_nh_tails
    else
        install_nh_ubuntu
    fi
}


architecture_check () {
    if ! [ "$(uname -m 2>/dev/null | grep x86_64)" ]; then
        echo -e "\nError: Invalid system architecture. Exiting.\n" 1>&2
        exit 1
    fi
}


root_check() {
    if [[ !$EUID -ne 0 ]]; then
       clear
       echo -e "\nError: This installer must not be run as root.\n" 1>&2
       exit 1
    fi
}


dpkg_check () {
    i=0
    tput sc
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        case $(($i % 4)) in
            0 ) j="-" ;;
            1 ) j="\\" ;;
            2 ) j="|" ;;
            3 ) j="/" ;;
        esac
        tput rc
        echo -en "\r[$j] Waiting for other software managers to finish..."
        sleep 0.5
        ((i=i+1))
    done
}


arg_error () {
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb    Install TxM/RxM configuration (Ubuntu 17.04 64-bit)"
    echo    "  nh     Install NH configuration      (Ubuntu 17.04 64-bit / Tails 3.0+)"
    echo -e "  lt     local testing mode            (Ubuntu 17.04 64-bit)\n"
    exit 1
}


create_install_dir () {
    if [ -d "$HOME/tfc" ]; then
        mv $HOME/tfc tfc_backup_at_$(date +%Y-%m-%d_%H-%M-%S)
    fi
    mkdir -p $HOME/tfc 2>/dev/null
}


set -e
architecture_check
root_check
dpkg_check

create_install_dir
cd $HOME/tfc/

case $1 in
    tcb ) install_tcb;;
    nh  ) install_nh;;
    lt  ) install_local_test;;
    *   ) arg_error;;
esac
