#!/usr/bin/env bash

# TFC - Onion-routed, endpoint secure messaging system
# Copyright (C) 2013-2021  Markus Ottela
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

# Installer configuration

INSTALL_DIR="/opt/tfc"


# ----------------------------------------------------------------------------------------

# PIP dependency file hashes
declare -A dependency_hashes
dependency_hashes['appdirs-1.4.4-py2.py3-none-any.whl']='8e6c1ea544013ea2567cda2d8b8c7b441bc50ac689aa7f95de67e3795aa083e9592c687d74fdbb37f5a75e0beab398fe47df5bced14ee9c204cfe5ecc364ef44'
dependency_hashes['appdirs-1.4.4.tar.gz']='8b0cdd9fd471d45b186aa47607691cf378dabd3edc7b7026a57bd6d6f57698e86f440818a5e23ba4288b35d6bb8cb6eb0106eae8aab09d8863ee15025d300883'
dependency_hashes['argon2_cffi-20.1.0-cp35-abi3-manylinux1_x86_64.whl']='4427657e9be95b4b68ec8d26e5571042068da3308b91ad82f289cfe94de196ecef71f437cf3f2e8f106fb7e743d85a69f24eece5257393e8bf5b1a6bbf9286cc'
dependency_hashes['argon2-cffi-20.1.0.tar.gz']='d1d798e3e51ed67c4f523a66081fea99479ee986b5cfc36b250954e757b9846625681445447f9347519d9988f8a2ace2e3c8ce5817c5c6b4767819cf56ee0af2'
dependency_hashes['certifi-2020.12.5-py2.py3-none-any.whl']='a0f753977d0e9e6c7eb4670eefafaffbbf2f44f22799eaffb45ffa458003b8d27b400254935a778e1daff769009f41b8686658e876b142376db54a0a14b59010'
dependency_hashes['certifi-2020.12.5.tar.gz']='3425d98f19025e70d885458629071c8531271d93d1461fadea6afbaafc763881a42b3c05be391a938d84a0d1ab729c3ac5df4f3328e8ef63a7b56ead1445bddd'
dependency_hashes['cffi-1.14.5-cp35-cp35m-manylinux1_i686.whl']='0575f1eb38353dc7de21b92be541f0ab23354709b12a18946d23d952f21ac11a0f2c3ebdeecf4005a89747384312a20accb740b19c543a5736ea9baf743229ea'
dependency_hashes['cffi-1.14.5-cp35-cp35m-manylinux1_x86_64.whl']='35c33090afbd1cd9a91c9b7970382480fd44cc64df68e9305f2d9aeda5c12f694665bc33ebc01e31701f64da1429c77d2e415da51710fce734bd166a504242be'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux1_i686.whl']='6940d8ea2b3749ad2c0588428f901d2addcbbb2003ac6aa1ee1ec5c763bca888604381f55ac8f348ac3092a7b70e47da627119c558672086d66d680be33c7ac5'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux1_x86_64.whl']='3d76ffa87cc140334df4ce5f50949e1e9360312e7102d8d912f049ee1c014395ec3677f4b56705fa7555107cb74e283255b6292319ee6d821ee52c450d7e1559'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux2014_aarch64.whl']='0db3f6946ef3cca66de9cb6178dd6378bfdda3a71d9abf29d1ff2c46dc3df86410328a41b4e6ee89cd8ed0859bf2c9e036a157975e2c73cdb545b4b52068526c'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux1_i686.whl']='6f95bbc5331cc5a775c7af7571c706a341779541dddf429fea76478d75337ee7ec7b412ed539fdd87df9f88516429ac9b346413da1ca8a6413c47ca65fbc122e'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux1_x86_64.whl']='d5a9b816a7c030d1cead4c432419ec28586d9b044f90ad0b589337feea8afca496a54bd24d653770cdcca8fb7bd74ec1da9fa5ffd4c2f94ebafedae2dbb1672a'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux2014_aarch64.whl']='129b9b31263ceb1cfc4c60cedb21c3e3ee8feb52b85f0156a63104bcabde8d506ce84b9bf60f9ed52cc743340e3d2252d434683bed0be7f9e3a75e60b0431248'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux1_i686.whl']='e8e1e06279d76ea5ede4449ed20ca927449b3e89977216d4b89915a97a8c977744744175ea25cc85638b8ff0a959145b58b527e4bbba417c7b521bbfb43d3616'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux1_x86_64.whl']='72bdb71b1ef5d0b3c88fd4d73c0d2857bda0b3945bde3355b8910f48ff6115f700753184190074994c0ba6b893e6259f073e10512231f7f674c82a4155b885f9'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux2014_aarch64.whl']='798754d337b116b2aa6d5d3e24de6468d43955c88f738bd60d41dac1665f4251b3636b6c3fe466c5b2206c765c5c1a68708848d51293b407d1f56ecc4e508e95'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux1_i686.whl']='2d0bd3f6e6119747c9dd36a90e9d31f3209e78142b87283bbd965d92fbca96074a008a904963de4e9437244e013302e8ba16635af4922c895963056de74f2d81'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl']='3c73e06bef8e9646beacc584d59ecf42de013034194d6eb59f1abf279e8fe5468e106fcd47802ce1d264d3c1d9122af3c66ea1229db78a768f7ea069ddc2fd72'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux2014_aarch64.whl']='e880f602dad400e742fb7e1907b5ae78cfe3002fa2556bc090366eb51a5114d023885b33c6bd640cd7ce5d18389c682d0dce346a8efdccabb7f6bd631133de30'
dependency_hashes['cffi-1.14.5.tar.gz']='7428b3f6e4ee9f3b91011e43304dd63e5cc48479120ae58298c646c1ec1f5c24525d5f08655a7fed70c5fad7ae0c2e0539e512b5fa49d2bc57669c4ab703cc2a'
dependency_hashes['chardet-4.0.0-py2.py3-none-any.whl']='cc8cdd5e73b4eace0131bbeaf6099e322ba5c2f827f26ad3316c674c60529d77f39f68d9fb83199ab78d16902021ab1ae58d74ab62d770cf95ceb804b9242e90'
dependency_hashes['chardet-4.0.0.tar.gz']='ebd7f420e1094445270db993f6373ffe7370419e002b0bb13299dc6c9b0f7c4e77b0f44f871fba6371e6869e7c86728514367db377e3137487a3acf50cb81e96'
dependency_hashes['click-7.1.2-py2.py3-none-any.whl']='bf12d793b0c29ed36d9ba1ce058ea3eb4a2ba528e0e0266f1573d2a66504e935b553671e2b8bf9ebd75aaed2e8d9d36b41cc260dcdecba329ea87c3b1b54a69c'
dependency_hashes['click-7.1.2.tar.gz']='b9fba8a30f57e380a2005b45c4f37074a27637ace9e16fb0fb0cce88aac72cfa806eea2829dac665fe2b558b8753a40b811dbfcca94dfccf999ad494865d7888'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2010_x86_64.whl']='be89565a54f7941198a994fe1e8aad3dbd15b27d1ca547c2f0edd81eadf74082737c183e7c539bd27eeaa17cdbfacb346dcb7a0b3c611c3ae51e9b983c8d97c2'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2014_aarch64.whl']='c7c2c6905a7321e1b046f2114c9d04f38b3f79b549896ad4e646aa64eef190b8e41cf5284ef049a11e8a7fcd5826a27c2eb9e4557ce5a7703d2d8c6be1c5c621'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl']='6b4eaa52b17065e5723ac2d70f38f05c5a550aea5a50cd4ffac78ec61fa363ac9d1ef29d9c9ca876e69cf9ac681bf6e9941f2027fd6126e472d425d0b5cdf788'
dependency_hashes['cryptography-3.4.7-pp36-pypy36_pp73-manylinux2010_x86_64.whl']='9c07aa6855e9bb28be14bbeab2feb56e9a05d13c25bf555878c1917722c9836beb4ad07f5bd7a2b9adf3327f35c55c6217a8d67103c4c2a5288e7b10acd92cc7'
dependency_hashes['cryptography-3.4.7-pp36-pypy36_pp73-manylinux2014_x86_64.whl']='772f918ec271837eee56e8b90f9cb6d759fe8b255ee99108d37c583b9bfa5077155a867fc60ce51c6c022bc3923b28ffbb38c1324ef2d1721959cae185169c57'
dependency_hashes['cryptography-3.4.7-pp37-pypy37_pp73-manylinux2010_x86_64.whl']='8017907f85eead22d4ec05c628cb90699312c68cd791459de853601db7848ebca448b52570505484981783a2a19113e3165f11ece08e3539d2e94ece87c96e9a'
dependency_hashes['cryptography-3.4.7-pp37-pypy37_pp73-manylinux2014_x86_64.whl']='890846b89dc97df25487ea66216884c0d3365ff6020fc71e338a7bf5c2224864a155b3d34f338b8a42d724d4bbb8dfb9842913e5405ba113b5e545fe398b87ca'
dependency_hashes['cryptography-3.4.7.tar.gz']='3c4cf64bc0b067ccdbb71efe04c32ac9d673faea6cc4ccd13d6b1b61920be4785806d19359b7657d032a2ff1c011a8b4f16ec4924d9df8a59d1a875a7f844473'
dependency_hashes['distlib-0.3.1-py2.py3-none-any.whl']='ac65d35a5309ec22db5b1e9ab6c20014084feab11e86e81bee6d0bfcc65940dfdcaa2711ac1e98c1ef179b110a4ea03dbaf042b894d3051da9d339c534664e00'
dependency_hashes['distlib-0.3.1.zip']='4c004b09eb93a6bfdd8b9b58175b756aa376c45fdef43a362a52fbffa19feef4850f0eb0f958bbf1eb9d2b8bfc1fc8a67c5b926d954e934c777b5c8b5c18e9d4'
dependency_hashes['filelock-3.0.12-py3-none-any.whl']='d13edd50779bca9842694e0da157ca1fdad9d28166771275049f41dea4b8d8466fc5604b610b6ad64552cdf4c1d3cada9977ca37c6b775c4cc92f333709e8ea3'
dependency_hashes['filelock-3.0.12.tar.gz']='09b8b16c12a60044a259a5d644bc8066660871104a7f4cd431431173d475b9f15744adfb8d86ec8cda69f2a1b52bd14cb8a066d70fa5e49c449bc5ee702ec2a0'
dependency_hashes['Flask-1.1.2-py2.py3-none-any.whl']='3bcd417e5b93590944ebdba05ff4ae37aab31aadcda2e4514d8be275d52877191ffbc58d89ea603900afe39264c899fc1e4fd77cd5e24880c03601551d8f1aac'
dependency_hashes['Flask-1.1.2.tar.gz']='9feb6a9a8f34fadbea508d465f73c24b1d81b3f66243804dc3904d198c2fd78e2e1bef94df6a4940a7eec6b9b54abea06557a87de8b27b0a9497d18b3e071384'
dependency_hashes['idna-2.10-py2.py3-none-any.whl']='7b7be129e1a99288aa74a15971377cb17bee1618843c03c8f782e287d0f3ecf3b8f26e3ea736444eb358f1d6079131a7eb291446f3279874eb8e00b624d9471c'
dependency_hashes['idna-2.10.tar.gz']='83b412de2f79a4bc86fb4bdac7252521b9d84f0be54f4fb1bde1ee13a210bbfa4b1a98247affbc7921046fb117a591316c12694c1be72865767646554c5207ac'
dependency_hashes['importlib_metadata-3.9.0-py3-none-any.whl']='59d6118df387ba779ae7ec631cefb91ed9e13e851d521d417236c73316f4f323b05adc068f4eec7b065366d6b22bc6544d7ffbaedb59a32dd4d0a360dc18bb68'
dependency_hashes['importlib_metadata-3.9.0.tar.gz']='fe635ed3ada20e6209315d619c918cac3782b52edb95099d41d9a6849b1bc56940f50641be17b859f54b9b33eac86c7c059b3a58d1d119fb1f90e2d6de62529d'
dependency_hashes['itsdangerous-1.1.0-py2.py3-none-any.whl']='891c294867f705eb9c66274bd04ac5d93140d6e9beea6cbf9a44e7f9c13c0e2efa3554bdf56620712759a5cd579e112a782d25f3f91ba9419d60b2b4d2bc5b7c'
dependency_hashes['itsdangerous-1.1.0.tar.gz']='61bab3fce5f87a3b5fc8fad61e735a63df6aa039416ee3494e1c99a2a1162b4fb72793bc5dc949de0985724c40121810b159513606c4c3976a7666dba3a1b93d'
dependency_hashes['Jinja2-2.11.3-py2.py3-none-any.whl']='fe6e0bbdeb9911ae0b173282e7546d3b3c3a29d0cdd60b4bf300897311f3d4227e7f550fe2b126eab503b880b249e1c133c817b0c299b607fd8de7f6206b87fe'
dependency_hashes['Jinja2-2.11.3.tar.gz']='fce4f835795fe9afb622f8106f60344032a811f3f693806f31ba482f9b7c1400f93dfa1701b4db0b472cbed4b0793cb329778c8091811ef0e3b577150d28e004'
dependency_hashes['MarkupSafe-1.1.1-cp34-cp34m-manylinux1_i686.whl']='38c41276979fe2cefea8ecf554ea30f6b9bb29a3103396c6b350269845c23d2965529a3b6b2a08126fb6d8dd6b5ce2ee84b066f7c6610a1563c904ed6fa3d544'
dependency_hashes['MarkupSafe-1.1.1-cp34-cp34m-manylinux1_x86_64.whl']='b7d5a56958203e798f020f55fece553bd90f5413d7dd697d27ee4d07a48a6c293d481c7ddf6f223c1a4c36ea0d2b8f26d130d49cc603f941ae3a059cb176ef8c'
dependency_hashes['MarkupSafe-1.1.1-cp35-cp35m-manylinux1_i686.whl']='1bb625a0959e046fd5b0a9856fd3bc0700d497046f24d29ccdcf583f36d816fc403e5be41133b8a6705dacccaaadfb81821773e33bf26a9e19152a583ca3e07e'
dependency_hashes['MarkupSafe-1.1.1-cp35-cp35m-manylinux1_x86_64.whl']='fd7f432d0004a498c1d71aaf2344fe8b9b680b5d67aa64935e01831e41754c5049c8a0710dfc13b33bb089f1aed2412fb1c8e36e1a7c72b27a8ae0c823d9fe6a'
dependency_hashes['MarkupSafe-1.1.1-cp36-cp36m-manylinux1_i686.whl']='4b567d577d37d025b48d547ba6cf35cff5e9407b1b6d37ee63eb9c8edb981e68d0abe6f490e98ffed5f2c8f3bedbcf8f35c6c83149b86afeb748253a7ed73698'
dependency_hashes['MarkupSafe-1.1.1-cp36-cp36m-manylinux1_x86_64.whl']='a82f797400b692e39efcb76f680c6988651381da7afdd764816a312d0e65cdc999a4bf97b474e89b03941d914ff1b73e8e8e8cd5b210bab157ce2c93a8a92ff2'
dependency_hashes['MarkupSafe-1.1.1-cp36-cp36m-manylinux2010_i686.whl']='959e16835864a1654c617b8429b7bd8237f1702df5caeb4d0409f01d34b4b25ec6650f583fefe92c3a3520f0bd7daf19d80770b59db9061e66841bba95bf2ad6'
dependency_hashes['MarkupSafe-1.1.1-cp36-cp36m-manylinux2010_x86_64.whl']='11bf544e9477df1e00c1c549dbcf9f47ddeaf226e3b74319184de47fc72b8095ab1d023f2c9be03cbfa9fb382db83977d244af42a8142a13bea5ef8594ad16bd'
dependency_hashes['MarkupSafe-1.1.1-cp36-cp36m-manylinux2014_aarch64.whl']='cca8634e64a1568a6774cc652c21d24473c5368f8a10b867b12942b4f107689832f8f4ccb0cc373f32b5ea865e590390e97fb0abc5c3a47ecb2dca228edbcc79'
dependency_hashes['MarkupSafe-1.1.1-cp37-cp37m-manylinux1_i686.whl']='5fda1521aefcaf1a09b8d5212b605f6fd4c2b66940188ee7cd19a8e1c89635fe548ed4dbc2e09eab4188cbcda7b5629f13d0ddb1888c68439f42c25625667d93'
dependency_hashes['MarkupSafe-1.1.1-cp37-cp37m-manylinux1_x86_64.whl']='69e9b9c9ac4fdf3cfa1a3de23d14964b843989128f8cc6ea58617fc5d6ef937bcc3eae9cb32b5164b5f54b06f96bdff9bc249529f20671cc26adc9e6ce8f6bec'
dependency_hashes['MarkupSafe-1.1.1-cp37-cp37m-manylinux2010_i686.whl']='222fa261ecc8ad914b50234cd22dbd7371baeada77821bf88c85f43d91524ae4c2af1028c921c0494c427efec8bbf75d8d7169270cffe3a095f17aa1d23373f7'
dependency_hashes['MarkupSafe-1.1.1-cp37-cp37m-manylinux2010_x86_64.whl']='e2fca30f30e66f88ff62492fbd2f41ecf803b95e5f68537bad0b1d9c4949800d49ef4a7fad990d0f003ec16f2bcd25377057c18f098f8f2be2f1ab0b130060e8'
dependency_hashes['MarkupSafe-1.1.1-cp37-cp37m-manylinux2014_aarch64.whl']='175441c76a469e9c2f9006f644e69790b05da20452e25d75d07b1534c0e1ebedab762f3cd0343f67fd6d73f66df35e7eb0f8569008d47bb45d94c63c08de3c24'
dependency_hashes['MarkupSafe-1.1.1-cp38-cp38-manylinux1_i686.whl']='655928dbf554dfd046cb82caddc4d5f6bd54c039ae6d8593644a6e33134a67c6d204e765d9de394741f930a30d40cf8b85f8f0d2a4dbc72999dd4600a9f17293'
dependency_hashes['MarkupSafe-1.1.1-cp38-cp38-manylinux1_x86_64.whl']='3b721bfefeaa1740ccba35fd78353b7d7ae6f6c32d198f83033f40d95533688dea475bc5d2452525562456b446832157920aadae205fac2196c0d8009d04fc3b'
dependency_hashes['MarkupSafe-1.1.1-cp38-cp38-manylinux2010_i686.whl']='2e58a9341ff518bd9088710a93ac9e3805767a72c98243494b1b4f503fc8ad1ad8d621e824431b62af797612d0d4ee26c9d9cacb04eb4a10b0f0491ef7028c1b'
dependency_hashes['MarkupSafe-1.1.1-cp38-cp38-manylinux2010_x86_64.whl']='2069b126fbd37292ac99fa3e4b8107af48d55ce1b21207bff2b185af3783dade29205865a5f665f20cd77aaa8a6a86186fc53334cd814ece6c3428c90e6e7692'
dependency_hashes['MarkupSafe-1.1.1-cp38-cp38-manylinux2014_aarch64.whl']='32935bacdd7e314df0ecedbd202fb48673d79e3fd78af87363369de05dde49dd72fc66c67fa61d5e4482208796021f71cf92ffb94e4133ad22fc806f340fc50e'
dependency_hashes['MarkupSafe-1.1.1-cp39-cp39-manylinux1_i686.whl']='d782b2854fd4ab6534e5a510683a7a374900c195ad98fe6d02c767697f7773a59424ba64371505e9283733349e568f6045c829d95bdcae762c94a7cd85bd5908'
dependency_hashes['MarkupSafe-1.1.1-cp39-cp39-manylinux1_x86_64.whl']='f0398ca11ee1b957182a836fc05f390196709a3a004464b12b4907412302bd7cb13fedb96fec6c518fd658d69818072d117bba61dec46d5c1d398935dac1f31c'
dependency_hashes['MarkupSafe-1.1.1-cp39-cp39-manylinux2010_i686.whl']='abbcb752661f1d7a84ffc289e8b18acb2310570ee1690067d00b1c06bd3c0d69cc2107de0061dfc42a37d9bb7e314d4de1ac6f3fc5ae0b90387d9da69305bbd0'
dependency_hashes['MarkupSafe-1.1.1-cp39-cp39-manylinux2010_x86_64.whl']='f3c426dcca737eec06699b466402533b6800b40a3c0767a8acf002016680fe4e02c2eccdc8d8e2f4664bc1330afb12ccbd0a0c7e10970442788da182971cf166'
dependency_hashes['MarkupSafe-1.1.1-cp39-cp39-manylinux2014_aarch64.whl']='c8b65122b1f68f1f15f2225020c0cd53042bac4bfa73a71fe66e5da7f560962a48f636c059901d16ea03381015dbbffdd8f58a2286f9d641465d6776c19d6975'
dependency_hashes['MarkupSafe-1.1.1.tar.gz']='f3014e6131a3ab866914c5635b5397ef71906bffb1b6f8c5f2ed2acf167429ff7914236d38943e872683a57a9be9669f4c5aace6274f3307ab21ef25373db0b6'
dependency_hashes['pip-21.0.1-py3-none-any.whl']='dac0d2b2479930d603747497488601dbabe1a38e67db48e920864df08bc35c256a486aa6fdc2bc2a9dc957e91222f4affb053d1b7988e162dbd9873cb6c7a902'
dependency_hashes['pip-21.0.1.tar.gz']='b80387fed6abf64cb4794686a82a415cf58b4516b9db17a5db496152b432b81bc638d8de91d40578f6dac08e26c0d0d4099901b9a186d73cf36691f24c4b4ee9'
dependency_hashes['pycparser-2.20-py2.py3-none-any.whl']='06dc9cefdcde6b97c96d0452a77db42a629c48ee545edd7ab241763e50e3b3c56d21f9fcce4e206817aa1a597763d948a10ccc73572490d739c89eea7fede0a1'
dependency_hashes['pycparser-2.20.tar.gz']='ff0853c9f981b43b4f2e879350715c07b02cf9dab223d4980d8fe0a3138c98041b5f848a9355ae4f1cb45e7f137c03a88843008e18d77af9250e0d9c55f5ca1b'
dependency_hashes['PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl']='bf1bb46d23419cb375bcf620a37b5e9ce925cb0dd55eadf851a4bbb9039c8846ed13ae33966436a96655ea41ad1fc282f9139a958fd55ea10597fd3859635a2f'
dependency_hashes['PyNaCl-1.4.0.tar.gz']='355b974010f94d551f631a2dd5ae792da3d4d0abf8ed70b6decc78aad24a9f965636988aebd14947b137ea14cdcbb73531775f08b1b4d5a9d72b5df3dba0b022'
dependency_hashes['pyserial-3.5-py2.py3-none-any.whl']='29bce14c59e60f54ce476d919c9b9477190ef6bb44a6102f71345840f5c0f1d0a323c4c3c302c5f380bfaae32cf04142ee528b6dd7184f17789632a31d5ecab6'
dependency_hashes['pyserial-3.5.tar.gz']='c8df5e50d952d5a6dcf1d9253a6ba953e9763c545a867da66c22c90dfa015aba0194f2a8f29a229d0a5f4dc8bfeeaaab8bcfda4066ed78a18b151bc05e6ae327'
dependency_hashes['PySocks-1.7.1-py27-none-any.whl']='3e0b1775c14fe091d10e30b03f7f0c770861152e493cf3a3143b0de01aadbc73f684f0d4305f1a694932d4bdcac8056c422437130640e19028cd9fba59ff0b3f'
dependency_hashes['PySocks-1.7.1-py3-none-any.whl']='313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12'
dependency_hashes['PySocks-1.7.1.tar.gz']='cef4a5ce8c67fb485644696a23bf68a721db47f3211212de2d4431eaf9ebd26077dd5a06f6dfa7fde2dcb9d7c1ed551facd014e999929cb4d7b504972c464016'
dependency_hashes['requests-2.25.1-py2.py3-none-any.whl']='cc0afada76d46295c685ac060d15a1ccb9af671522cb7b4fa0ad11988853715d1b7c31d42fa1e72a576cbd775db174da5bc03ab25c1e31c234c37740a63a6bcf'
dependency_hashes['requests-2.25.1.tar.gz']='ca6b0a257b448a999cade0ae173c29cddc9cfffb319d16fc3d051d3e1cd77161536e3cab279b3cba59c60d29d7864a9281c1fa1f689ce48d3bce2ca9f1cd8d45'
dependency_hashes['setuptools-54.2.0-py3-none-any.whl']='54e7df1fc96c9f3ee0de64c87c5f76eb95dca70a5566ba45d814566f507a26385b188155ca24d5e94a540df42483a4f23db5b38e7437d90e3983bbbe0c673d6f'
dependency_hashes['setuptools-54.2.0.tar.gz']='b18cd075cf59b8648611eef1874de41199ede6ffe6d7f5047586c6ac8783fe18b9a4f537783e590e7aec127033f612b93925e92f039bd6416a609fcfb262e354'
dependency_hashes['six-1.15.0-py2.py3-none-any.whl']='0416d59434623604de755601c919722c2b800042612a2a7b221ecd3ccf556aca3a78f0f926fd640032a3d74d153457628a89c25065dfcdbb96892d5bf7279904'
dependency_hashes['six-1.15.0.tar.gz']='eb840ac17f433f1fc4af56de75cfbfe0b54e6a737bb23c453bf09a4a13d768d153e46064880dc763f4c5cc2785b78ea6d3d3b4a41fed181cb9064837e3f699a9'
dependency_hashes['stem-1.8.0.tar.gz']='aa2033567b79aef960f8321e4c6cbc28105c59d6513ff49a9f12509d8f97b1a2e8a3b04dc28abb07fad59b0f6ba66443b92bbefa0d08b26038bbaf24f7f2846d'
dependency_hashes['typing_extensions-3.7.4.3-py2-none-any.whl']='210e580fa98cb5c0ecb0c7ef70973d2471397dae323add47c5a730a190c4a13d134ed46f10b51451b56823a71be3f92a2488e8d57a722bf42da496ebfd384eff'
dependency_hashes['typing_extensions-3.7.4.3-py3-none-any.whl']='490129aca9e3b6360c9f9042010fb2b6a4c9fee00a6cb3abadd6796c973727b88ab50cc5ba7a066b6cd55c16a7c26602d64e5bae1a4a74a6b5a9320d5d251c22'
dependency_hashes['typing_extensions-3.7.4.3.tar.gz']='fa1f96b73b13308ddb2676684862916aac8741be4523387c6a0f682a52d307190aac3e4149317842e686d14483d8a37a9e1de2514a2d1ca86f9ae9c8b0e18eb1'
dependency_hashes['urllib3-1.26.4-py2.py3-none-any.whl']='ca602ae6dd925648c8ff87ef00bcef2d0ebebf1090b44e8dd43b75403f07db50269e5078f709cbce8e7cfaedaf1b754d02dda08b6970b6a157cbf4c31ebc16a7'
dependency_hashes['urllib3-1.26.4.tar.gz']='daf2ba432f2e4edaa6aa8c6bdaaea21fcb77cc5fdfd991f89b1f753b4f9901faab04120841e9fa8d93e2bd3d72cbdb647f1492d882266b4e0281c725e8d55a7a'
dependency_hashes['virtualenv-20.4.3-py2.py3-none-any.whl']='996cf6d8de6be67c8d42d4db749b65592237d4c3da1061a161ea2729f47a0b09a8448025ede34c4dcb910820c00098262412ca0045a243feadb7d5dfaec8d9d5'
dependency_hashes['virtualenv-20.4.3.tar.gz']='d79479d73fc87f34462e775629306bd20ff5d25eb1829c6719f08c800df6a5db03254b04773766a703d903d577cf74b8409a026196ba98d0f5f94f70604ed576'
dependency_hashes['Werkzeug-1.0.1-py2.py3-none-any.whl']='8f05b3632d00b1a9c3d85f46dccc7eb55c032bc8cc7b688219865487c96127ecccdd44f9724159299d14db98c1951b552b478811d292d93aa2d12817c88c8527'
dependency_hashes['Werkzeug-1.0.1.tar.gz']='ba76ee6f39cf8f6b2c8988e6119be78cc6c868ea78bd2014837b4e9f59e8b790fb3a7b5a45b392cabdc61f32b8a6902cf5f43d7e20b1f4571e0bef102a3e88fa'
dependency_hashes['zipp-3.4.1-py3-none-any.whl']='150df28aa8f1debfbcbcf08100f5bd0eb71ea6123b088e80e82e0389066ef63d20b7151896abecad31fcb774a1a99382c99299dcbc8165a5d4a643f842f6806e'
dependency_hashes['zipp-3.4.1.tar.gz']='2ba50109efd0ceea9eb1d57e2d839f522b5a78a8dae344d6da54b79305dd46bff23f1116f562127290152c0b100369439c17fe9dc3fb14d0b42beaa48348ebe6'


# ----------------------------------------------------------------------------------------
# Package lists (the list must be ordered so that sub-dependencies are listed
# before packages that use them, and the list items must use the same capitalization
# as the dependency filename).

pre_packages=("pip" "setuptools")
virtualenv_packages=("zipp" "filelock" "importlib_metadata" "six" "distlib" "appdirs" "typing_extensions" "virtualenv")
tcb_packages=("pycparser" "cffi" "setuptools" "argon2" "PyNaCl" "cryptography" "pyserial")
requests_packages=("urllib3" "idna" "chardet" "certifi" "requests")
flask_packages=("Werkzeug" "MarkupSafe" "Jinja2" "itsdangerous" "click" "Flask")
tails_packages=("pyserial" "PySocks" "pycparser" "cffi" "cryptography" "PyNaCl" "argon2")
tails_packages+=("${requests_packages[@]}" "${flask_packages[@]}")

# ----------------------------------------------------------------------------------------
# TFC Source file verification

function compare_digest {
    # Compare the SHA512 digest of TFC file against the digest pinned in this installer.
    purp_digest=$(sha512sum "${INSTALL_DIR}/${2}${3}" | awk '{print $1}')
    if echo "${purp_digest}" | cmp -s <(echo "$1"); then
        echo "OK - Pinned SHA512 hash matched file ${INSTALL_DIR}/${2}${3}"
    else
        echo "Error: ${INSTALL_DIR}/${2}${3} had an invalid SHA512 hash:"
        echo "${purp_digest}"
        echo "Expected following hash:"
        echo "${1}"
        exit 1
    fi
}


function verify_tcb_requirements_files {
    # To minimize the time TCB installer configuration stays online,
    # only the requirements files are authenticated between downloads.
    compare_digest 492b5cc2ef68d82a49e5aaa635d27330086233c4244fc342a3f53187c9f688da9de9b18af28437cff7ed5b5b5a3670c8f821ce05f9ab21eba442e22d4350ee65 '' requirements.txt
    compare_digest bc714d62a7069b7d4ef98b9863894c7d57f87cc3894cf2aee4260d96ae75848e0705ab585f5901ec50fbe97c4c73754ccfa8e92922655c9c4efb839e2343c2d0 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 084ff0fa2974cb196af43841c43c20c408253ee8a08723d3f8bd75665301b087313c64fd33c70abc3bbd82e8a7e51cbd2aa8cb9185ceefd101c8d4d71eb8ac47 '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest c96801213615c13752ec3a5f3436bb749cd3efbf25443a5a634e708fbd5fdec67df646f8db150b3dc2d0aefdf9bf0614e383a54ce0e0aa82f2b554842680ca58 '' LICENSE-3RD-PARTY
    compare_digest 9d8b08c7631d7f7a3bff531b1f5870cda85ed3067627a1a426cc90dd5a87e65429a526194c7e323dd949000818d0e31a5a7664075733700ae1218f9e881bd12f '' relay.py
    compare_digest 75657e966e95ea9922240a056f2ac076599999ee4164eb5ef84688c5b505b7359f5ae95f8b943fda6221983d7ae3af576f118426296e5a93037452df1eecc2a2 '' requirements-dev.txt
    compare_digest c10b0440b385cb8071ad6be7748da6f162a7c598b81b4258d537c03a7ca7643821893e284a55d1cec5b05c094fd940ccac7302aa23d1c437d68bfcd1cf40d4be '' requirements-relay.txt
    compare_digest 5e7bcc3ccb426b0daba004612b7b41d15c9663fe2345b5f34a538a723d235b8912aee3f13a109dd893f35cc0597e1804fa2eb8ba18ef967b38bb727aa4d40463 '' requirements-relay-tails.txt
    compare_digest ed6e3e41fd4ab69e7067c643431f89fd4bd1e45fbf98f8106432a351d24643b7023959ff4c7581ebded73d8ed0556998f55e785762d6ef81d3d100eafe43f9b3 '' requirements-pre.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 6ec4e2f4422bec2c4dfcb4ec630bfbb332f7a1f6b9d500a26bb7641dd9882f1f7297a0ef2b3f0603d669ec69eed001a5cf1cb1b2e74d5e53a0cefa0fc8ee8c95 '' tfc.py
    compare_digest 62f26d2805570ee70fad3a076579a554008e7d9f2c9ff310f3bb5876d361cc03dbae7ab63b144ac215a35f920ac56d359481352805a356479d622ab00da15f7f '' tfc.yml
    compare_digest 524e2809046cf0d91caa970a6aa7399c86dbf746ab2b5ab1d3002730ee78f02a6e748221511e4fc98f795f19ff8249070ffe11a2eb521dc1f82ede4fad4e4264 '' uninstall.sh

    compare_digest dd2dc76c186e718cd6eb501985f3f8c639d303e44186c5f21ca8e8cf6a25b329c573ca489eda80877be51ccaa6b72b4e763060d0f0f27c0217e8c6b1016d75ca launchers/ terminator-config-local-test
    compare_digest 423a06969fe07676d8d365b2af0fd7c41cb77416da9b20c83b2ec275b2b241908cf3d21ec0b5ebc8d0d5a44c1ade38c7d75e46d71f061e5ecc6f9ab6b22e4624 launchers/ TFC-Local-test.desktop
    compare_digest 0a4ca9d76912d27cdea4f36b7334ab561eca2b056eef24ff3b1484cb5dd56c5d79e68145402dbf40c87d4a86340cadeeeadf63a8c3774b89921906a1df603c25 launchers/ tfc-qubes-receiver
    compare_digest a8257a49bc5b9c76ab7a228b69d518e7f7ef338cbf4ebe3df64e99d96d7939130b9005b35c962542e5427ae00c1f2623c06a357614a3122d0a3b161e5d59bb0b launchers/ tfc-qubes-relay
    compare_digest b8a7b0614924e000495c1a4f380c5fd772e85ed93b58b8762c1b1f54381730ef3ec1fd7c7bc0541ef6ce9d857402f2153c8abb9c4b05ee2e57630fcf53ef3c35 launchers/ tfc-qubes-transmitter
    compare_digest a9179c33af8e0024d0c5139169b44f6a19cc4d221ee4332388c99d3de45dcfb8ed484c8fc926a925ad814b735b24e86a000e98a8f315e34e894fd4d2f78dbfdf launchers/ TFC-RP.desktop
    compare_digest be9a47d768f8a2908cfb9879fcff414e9990acb680a92bfcd5ba7748caf0bdd12d840b46242269421c5cac953460f7eeaaac338c72bf6cbc3ef8ef025b2f3fa8 launchers/ TFC-RP-Qubes.desktop
    compare_digest a9179c33af8e0024d0c5139169b44f6a19cc4d221ee4332388c99d3de45dcfb8ed484c8fc926a925ad814b735b24e86a000e98a8f315e34e894fd4d2f78dbfdf launchers/ TFC-RP-Tails.desktop
    compare_digest 60f1a613edcecf0527496c32c3210786007b68ce827b042a404c7424dde19240b4ba17f8f490d3903f8411a8c0a0c7eaea2c23ef70345d6f01942183f8da4e7c launchers/ TFC-RxP.desktop
    compare_digest e4e1aa1eaa0d67eb0692ef47f86ce8db351ef4e4956c4d1c99c2dc2e220bd4689809cacca4ebe78b5f138e62cff84ff7225e46bd20cd3b75531ac614f1249a10 launchers/ TFC-RxP-Qubes.desktop
    compare_digest c101bbab5a74b7cb35b88a406788a357229821db370e636d2e65b70d83f2628507715eae0cc3e125d5e3b1634330c4485c9a3f513bbb213c6aa8788f6947a551 launchers/ TFC-TxP.desktop
    compare_digest 68a46b9139aecd51279ccff0ddc50debeb08dd40e14a5c6065571b52da135190731906bfaad3713e75a76a09f5fce0c69c627340df723b8d352591048ed63e0c launchers/ TFC-TxP-Qubes.desktop

    compare_digest aea3558d9f2855e79b715e92147411d9ddc9ea43617ad2418497466d82fc749f2cb7b1278c87bfd4a93e334cdaac24c66b2a8d95c33adc5e3c4081365d0c2d23 qubes/ service.sh
    compare_digest 8929de27a32f001f5bb73070868b5e5c8bc9ad74afad63b27ce4ffe946dc0b81e83a178ea7ed752d79be53f9ce84343175b18f0254482dac377c8143ad56a3c4 qubes/ writer.py

    compare_digest 895b722c3cea8f5aa1d4bbcf228cfefc93882098ea35473d205d839cca70bd234f6786dd2ac8004ef854ec7b5e3a3aeaa7c55ccf3797ccb8dcbe530a4f64642c src/ __init__.py
    compare_digest 895b722c3cea8f5aa1d4bbcf228cfefc93882098ea35473d205d839cca70bd234f6786dd2ac8004ef854ec7b5e3a3aeaa7c55ccf3797ccb8dcbe530a4f64642c src/common/ __init__.py
    compare_digest 259f9b5cf3a1ebc6288a5120d8d98f1bc81cb2cf2d0dd03d9ea5ac831f1bf2c004cd89109c0c3c60d25c487d83b3ba6e6d3ef6747e7b33a4bf4a59daaea9e8fe src/common/ crypto.py
    compare_digest 8dbd4aa15f46f57b9e10278333eddd626de55e742176570edf1b5aa4e2ebbd9cb850723441d2961f163aeb59062464caf3952d9f19151021a22e1bbaf3c794c9 src/common/ database.py
    compare_digest 51b556a5ccd6bc1c2b677dce9170fea4244e5d6fe578fe4ade315764806ad95f28a32fdd9f7f549e89e4667feb934f93923ac10b0eb6db96ecfe8717314fdc6c src/common/ db_contacts.py
    compare_digest 52bb5eaa36727a2c977cb20811501af9b4d044546ba8de3844b0077d5a18ce6b1a5e828b79b6e5044603532c0d2fbe205dcea6cbb2e7a2985359774798b4dd77 src/common/ db_groups.py
    compare_digest f2da629d149582a01e5bea92d66cbe3120fa32bbe3bed3af12a5ce88b44876b12ecedddd799baa09c93c459d9d9befd38b35418f11c709d094fe685ec679a437 src/common/ db_keys.py
    compare_digest 02a5320292048a7b5a8e2c65753f38607ef4446d0ca60bf0e9fcb188da4bac2769eccc378fff824b4be75e325f79ca8da115260d9d3535d45e4fee5e2e8b6d34 src/common/ db_logs.py
    compare_digest 026ebe896f27c539f9d11b7f97a690fec9d5f6288048ae924a8c27be0569ea3d25c62ce0d8fc8b14c1c209e196a7aba18ee5ec0ba60842c627157bdafc136bdf src/common/ db_masterkey.py
    compare_digest e51732cb3197d6d6fa9a3a6d6d1edd9f2f217487aab913deab7d9b3990c87093723d462d9e180e6c5917e26cf3d2dac34b5f6d305a8193eea111abefeebc90f4 src/common/ db_onion.py
    compare_digest f77a4f2860b0778a24b9d7d3b27ad4eb5413a128d8c2abfff7a6c3e551fd07b4013bc4dc5221a57fa45b16aba25a16b27cc24033b1f270148905efa0a17828c1 src/common/ db_settings.py
    compare_digest bc8d7c9a4ed4ce80e5c4951ec5f59cd108f407cd511c2984f535c4e43d71c61030f00053f2ba230c16726cd84fbd6f761395527a947b5c0daafe26cb9aa509e9 src/common/ encoding.py
    compare_digest 270ce6ff837376ec3d6653faeaedd40ff69f083dbad32ca625fcb00f940e5338de9dab5710c8171d43e29ba73bddae5e670d11e7817404daab0eb3a565ea2316 src/common/ exceptions.py
    compare_digest d2f6184054344da185d4e52a6957de6e53bca1250ef02839c41e8a8cc0ebdb05567fc2fc0d7c52ea3e91098b1660664ee28cc4b945492797ee684387f857d1b1 src/common/ gateway.py
    compare_digest 9881dde36489c590746257e064f8800b56ef3fa4a78738c15f421998c8ac8469e1191da7ae4a37d5beb54f59bf2ae5d0c20fdae40a4ba66e4c21e9d0675ca6af src/common/ input.py
    compare_digest dc87c205de22e3301a5707d61ae2960cade2d064a02ee6d8da86ffad1194071517426b67ad2bcb0cf94bec07ef3b2bdf50ba94fe8f89dc8945a8aa4fba7d0837 src/common/ misc.py
    compare_digest f23e5b4618a63ea2161707b53131c5ad894fd53d2d3481cc874e02d63eca7043d6010edd601298d38a16e86104acc59fc80d0fe89a9693084709365b188b3c7b src/common/ output.py
    compare_digest 83dce0462374789f04d16d47e05cfb9aa5a9ce1e0bb0e280706d0c6f291a2bf680ffe83481b22b28f89d39345f07065c847135620726b29da7c22b349a3aa06b src/common/ path.py
    compare_digest 39e48b0b55f4f1a48bc558f47b5f7c872583f3f3925fd829de28710024b000fcb03799cb36da3a31806143bc3cbb98e5d357a8d62674c23e1e8bf957aece79f6 src/common/ reed_solomon.py
    compare_digest 832fe78b12224ca694eed1325dffcde27b8ab8e445f05053041be6c1d66153b9417c403de8bba5e1112273a569956625258c043aceddbf795e7ceb23c6ff1b16 src/common/ statics.py
    compare_digest 6b80a369e1bd3bb72b58b309f4559d47201d16ae1cc02f2da0184c4bfb7d086a28d3575e031b78dd7d4d720b1ee2a948412daa83d95ca540e57d07ba59aadd6a src/common/ word_list.py

    compare_digest 895b722c3cea8f5aa1d4bbcf228cfefc93882098ea35473d205d839cca70bd234f6786dd2ac8004ef854ec7b5e3a3aeaa7c55ccf3797ccb8dcbe530a4f64642c src/receiver/ __init__.py
    compare_digest 407273ef8bdaf4bcd482fef5da30f815ae231ca93af67b4f1c07cbc01fa24a046b8f80f9ed1ed900ef60873ba26807e90514292d2b15da035e80c21fcd1285ca src/receiver/ commands.py
    compare_digest 5c9319da7704209deb4e8c770e1c1760a5ca2ff24b5cba99ec87d8398e3f2ea64afb303297b03d229f9ce4bac7a4e81d75e0036c11a8611de5e7e423f1427cd9 src/receiver/ commands_g.py
    compare_digest 6dc42761152d36549f5e9393575fc42d39fed726b03c5f6801f6db7c731bbcfcf22d330bb4bd8b71fc6765f730526e18d5cd0d81dda8792765df614cfa5d5e84 src/receiver/ files.py
    compare_digest dd1584f8d76cc9c31669f2274e98c3f45faff445c1114efcdba0d1c309cd96d2504b835e7a741faa93d35900cf2e90a4543135f3aae3d80eedc9b4f0b1702ce6 src/receiver/ key_exchanges.py
    compare_digest 70f9a8f7a3c9492784933c1feadf975379aa99989c8e1669fc8f9dd41f84beea781fb18a75872c7aca32af89d859f60ed199d0ee89d610c7d21641c46bcbacd2 src/receiver/ messages.py
    compare_digest 40abbb00d4658196d14c49aa36cf9dff0834d73913d28017aa73b58e257990c8d1e3c89de2e446bdd04f4c127d8a9ed1d19ce91b3ade8aa117af3fe8dfe675f7 src/receiver/ output_loop.py
    compare_digest a65905f9d603502052508c8dd5c9a9fd0ed084e2820c0fdebad11aca285434eec77e9809fbfc7239126a052625de5e7269af94c58fb9abb626314a103f77dbd2 src/receiver/ packet.py
    compare_digest 89280eb11322f00570e9b4c0b1f08a333e4af272c11dbcbadfe62e66fba08b507e4139d02254fc59993e80c3388e7ee0ec1d42ec31eadc0c6175f33fbd854c7d src/receiver/ receiver_loop.py
    compare_digest cb00a949b96af8d85a3ae735b3565a22ed8ce32dcbdffc20b5effdaa21c45ee09d12fa80944ec399bb1e2d94d265b570abcf566aa6533179be693957b4b57586 src/receiver/ windows.py

    compare_digest 895b722c3cea8f5aa1d4bbcf228cfefc93882098ea35473d205d839cca70bd234f6786dd2ac8004ef854ec7b5e3a3aeaa7c55ccf3797ccb8dcbe530a4f64642c src/relay/ __init__.py
    compare_digest 91c3d4c61b7ab782716b3fad93fdbfa8a14fadf78f42827e642bea00d41a3ca5fc13d5ce552353ea955fe031e63f79878122302bd0e6d7b85a11917f60fdca27 src/relay/ client.py
    compare_digest a876e5863bad6f1ccca425ae33b539b9a5c88ea3e560efb3c5b16df8f80adf47defe2b0c829f835ea9c57032c648fc7186269b05049d9a129aaf5b787991fad1 src/relay/ commands.py
    compare_digest 40de0fe708a9a925a7475c407f57444cbdd0b5ba7d1045ce7f80c3437f38f278e7ee5fb11e8dc503e3d0d06ee786aad9f77970073f61dc57517dba0af2533216 src/relay/ diffs.py
    compare_digest c211e781f24d8275cd9b338bfd8b2f432d8e7a4a3db0364904c025fd7cedc7ef3bcb1d178a67762af2ecd6d1ef6c3f77c3467748cf9cbf61be98478aa59835c6 src/relay/ onion.py
    compare_digest 127913f8d9fe07cc8675dca1ec29702185fbdce927c1edfabce65a36d5f9ff2b35593c7bbdb3fdd017cd18a79f7606e9c37f8d4b4d6031d7788d35c1f434bd37 src/relay/ server.py
    compare_digest d413dc230cc2e52cbf771a9c141e35c76ca2fa3188876207a0bbe12112459608858f5ad22017dcf7946797d2a39f2f506cb43407c9a3b1e27eb72e09f93906c1 src/relay/ tcb.py

    compare_digest 895b722c3cea8f5aa1d4bbcf228cfefc93882098ea35473d205d839cca70bd234f6786dd2ac8004ef854ec7b5e3a3aeaa7c55ccf3797ccb8dcbe530a4f64642c src/transmitter/ __init__.py
    compare_digest ea7c17e06353b6b2f770b520a11d3b608303da42a0c4c0dc4ba79c9f2df0df4530c2185b532eb188f603505fa37259541bd2e0bf1589917db4e00f158d69d20c src/transmitter/ commands.py
    compare_digest a5467d96d12ea1c9c504719a67630b3f5e0923af2800a0c30e4e0b18811317735e5eb87cd4b1524266ffa69568746c01ed48e2c3ff54be32beb8b2f64b3be1d2 src/transmitter/ commands_g.py
    compare_digest 7f42fcc038fc33336bb16ddd5673c700ea763ffa19cd5aabb7828379e52f35d6187415038cbfed1f1216e08b4b12e644b4241d8753e9bb5a0b24c4a14e06af73 src/transmitter/ contact.py
    compare_digest c961fff77c2386e77ae7c861f2419f65d47a9062969cdf4061821124f2c5e2bfead1eb0f29934804c34612e893947c240ca773213ff585d46553c9bbc81f9271 src/transmitter/ files.py
    compare_digest 585c768965def312b95e97098b770d0e427d6d6c360708318dbd16ba5c032049d96475828824fae1ccb298d6ff1017900d132c54ed3b297f499cea63b9ae2cb4 src/transmitter/ input_loop.py
    compare_digest d1c6bb65722247f8be2bba9db489b289ab0c3909a4c97fd7c96b1ab838da932e627968086138a7a809fe9f876734a560e4a14d2d2b5ef8e0227b6549bc4bc767 src/transmitter/ key_exchanges.py
    compare_digest b113540d628788159781fb75546395690a2bdcf5129c2886a0ad38be0d8ca5e13588491a2b211a7ba59214fecb7e76846723112d7502b3cedf17b5bd55ed762f src/transmitter/ packet.py
    compare_digest fb5d90be329ad6c5392dfdd85ca4373b8e77ed80f6ddb8c2dd1de721a19fa8734b6543aae0f94c3dd32004c45619cf5b45b08599da10bb0aaf7b19dc0d875ebd src/transmitter/ sender_loop.py
    compare_digest 5df1f280a7e5395fd2800242ca83c3d3415515e3ce0c5e1471b6c959600d22119d9bfc2322897b336252bffcd010c96afa4a947ca95e3bbd602ec7dcc6695997 src/transmitter/ traffic_masking.py
    compare_digest cdc94940b53517ac263b9d6a189176dabf7ddd5239b5fb792ba2229707691a1db2094a104cd1b9525232bacdf12f235bf9683b511adc3088f722a3aec00225b4 src/transmitter/ user_input.py
    compare_digest df6ab1205f39d89879016611a32c6d4ca5add324a20acfa731fb2fbef332221b9b67e9e242725915602ba653c1083a8d749a11eb47187930c2de2cf4227c68dd src/transmitter/ window_mock.py
    compare_digest ea02d0cdd2edcc87e68aed6c15a6c8516c3b838c96d7d83d8de53d7ef3aaf9b48f215b84e6ef4cc88baf6bf4d8c1985ea1e1078bc915ecda7cf5f67fb1044b16 src/transmitter/ windows.py
}


# ----------------------------------------------------------------------------------------
# Printing utilities

function c_echo {
    # Justify printed text to the center of the terminal.
    printf "%*s\n" "$(( ( $(echo "${1}" | wc -c) + 80 ) / 2 ))" "${1}"
}


function exit_with_message {
    # Print error message and exit the installer with flag 1.
    clear
    echo ''
    c_echo "Error: $* Exiting." 1>&2
    echo ''
    exit 1
}


function install_complete {
    # Notify the user that the installation is complete.
    clear
    c_echo ''
    c_echo "$*"
    c_echo ''
    c_echo "Press any key to close the installer."
    read -r -n 1 -s -p ''
    echo ''

    kill -9 $PPID
}


function install_complete_qubes {
    # Notify the user that the installation for Qubes VM is complete.
    clear
    c_echo ''
    c_echo "Installation of TFC on this Qube is now complete."
    c_echo ''
    c_echo "Press any key to close the installer."
    read -r -n 1 -s -p ''
    clear

    kill -9 $PPID
}


# ----------------------------------------------------------------------------------------
# Installation utilities

function t_sudo {
    # Execute command as root on Tails.
    echo "${sudo_pwd}" | sudo -S "${@}"
}


function check_rm_existing_installation {
    # Remove TFC installation directory if TFC is already installed.
    if [[ -d "${INSTALL_DIR}" ]]; then
        if [[ ${sudo_pwd} ]]; then
            t_sudo rm -r ${INSTALL_DIR}  # Tails
        else
            sudo rm -r ${INSTALL_DIR}    # Debian etc.
        fi
    fi
}


function dpkg_check {
    # Check if the software manager is busy, and if, wait until it completes.
    i=0
    tput sc
    while sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
        case $((i % 4)) in
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


function steps_before_network_kill {
    # These steps are identical in TCB/Relay/Local test configurations.
    # This makes it harder to distinguish from network traffic when the
    # user is installing TFC for Source or Destination Computer: By the
    # time `kill_network` is run, it's too late to compromise the TCB.
    # Hopefully this forces adversaries to attempt compromise of more
    # endpoints during installation, which increases their chances of
    # getting caught.
    dpkg_check
    check_rm_existing_installation

    sudo torsocks apt update
    sudo torsocks apt install git gnome-terminal libssl-dev python3-pip python3-tk net-tools -y
    sudo torsocks git clone --depth 1 https://github.com/maqp/tfc.git ${INSTALL_DIR}

    verify_tcb_requirements_files
    sudo torsocks python3 -m pip install  -r "${INSTALL_DIR}/requirements-pre.txt"  --require-hashes --no-deps --no-cache-dir
    sudo torsocks python3 -m pip download -r "${INSTALL_DIR}/requirements-venv.txt" --require-hashes --no-deps --no-cache-dir -d ${INSTALL_DIR}/
    sudo torsocks python3 -m pip download -r "${INSTALL_DIR}/requirements.txt"      --require-hashes --no-deps --no-cache-dir -d ${INSTALL_DIR}/
}


function verify_packages() {
    # Verify authenticity of downloaded dependency file.
    dependency_list=("$@")
    for dependency in "${dependency_list[@]}"; do

        dep_file_name=$(ls "${HOME}/" | grep "^${dependency}")

        # Move the dependency to root controlled dir
        if [[ ${sudo_pwd} ]]; then
            t_sudo mv "${HOME}/${dep_file_name}" "${INSTALL_DIR}/${dep_file_name}"  # Tails
            t_sudo chown root                    "${INSTALL_DIR}/${dep_file_name}"
        else
            sudo mv "${HOME}/${dep_file_name}" "${INSTALL_DIR}/${dep_file_name}"    # Debian etc.
            sudo chown root                    "${INSTALL_DIR}/${dep_file_name}"
        fi

        # Calculate the purported hash from the downloaded file
        purp_hash=$(sha512sum "${INSTALL_DIR}/${dep_file_name}" | awk '{print $1}')

        # Load pinned hash from the hashmap based on filename
        pinned_hash=${dependency_hashes[${dep_file_name}]}

        # Compare the purported hash to the pinned hash
        if echo "${purp_hash}" | cmp -s <(echo "$pinned_hash"); then
            echo "OK - Pinned SHA512 hash matched file ${dep_file_name}"
        else
            echo "Error: ${dep_file_name} had an invalid SHA512 hash:"
            echo "${purp_hash}"
            echo "Expected following hash:"
            echo "${pinned_hash}"
            exit 1
        fi

    done
}


function install_packages_as_root() {
    # Install list of verified packages
    dependency_list=("$@")
    for dependency in "${dependency_list[@]}"; do

        # Find file that starts with the dependency name
        dep_file_name=$(ls "${INSTALL_DIR}" | grep "^${dependency}")

        # Install the dependency
        if [[ ${sudo_pwd} ]]; then
            t_sudo python3 -m pip install "${INSTALL_DIR}/${dep_file_name}" --no-deps  # Tails
        else
            sudo python3 -m pip install "${INSTALL_DIR}/${dep_file_name}" --no-deps    # Debian etc.
        fi

    done
}

function install_to_venv() {
    # Install list of verified packages to virtualenv
    dependency_list=("$@")
    for dependency in "${dependency_list[@]}"; do

        # Find file that starts with the dependency name
        dep_file_name=$(ls "${INSTALL_DIR}" | grep "^${dependency}")

        # Install the dependency to virtualenv
        if [[ ${sudo_pwd} ]]; then
            t_sudo "${INSTALL_DIR}/${VENV_NAME}/bin/pip3" install "${INSTALL_DIR}/${dep_file_name}" --no-deps  # Tails
        else
            sudo "${INSTALL_DIR}/${VENV_NAME}/bin/pip3" install "${INSTALL_DIR}/${dep_file_name}" --no-deps    # Debian etc.
        fi

    done
}


function remove_packages() {
    # Remove the dependency installation files.
    dependency_list=("$@")
    for dependency in "${dependency_list[@]}"; do

        # Find file that starts with the dependency name
        dep_file_name=$(ls "${INSTALL_DIR}" | grep "^${dependency}")

        # Delete the file
        if [[ ${sudo_pwd} ]]; then
            t_sudo -E rm -f "${INSTALL_DIR}/${dep_file_name}"  # Tails
        else
            sudo -E rm -f "${INSTALL_DIR}/${dep_file_name}"    # Debian etc.
        fi

    done
}


function remove_common_files {
    # Remove files that become unnecessary after installation.
    $1 rm -r ${INSTALL_DIR}/.git/
    $1 rm -r ${INSTALL_DIR}/launchers/
    $1 rm -r ${INSTALL_DIR}/tests/
    $1 rm    ${INSTALL_DIR}/.coveragerc
    $1 rm    ${INSTALL_DIR}/.travis.yml
    $1 rm    ${INSTALL_DIR}/install.sh
    $1 rm    ${INSTALL_DIR}/install.sh.asc
    $1 rm    ${INSTALL_DIR}/pubkey.asc
    $1 rm    ${INSTALL_DIR}/README.md
    $1 rm    ${INSTALL_DIR}/requirements.txt
    $1 rm    ${INSTALL_DIR}/requirements-dev.txt
    $1 rm    ${INSTALL_DIR}/requirements-relay.txt
    $1 rm    ${INSTALL_DIR}/requirements-relay-tails.txt
    $1 rm    ${INSTALL_DIR}/requirements-pre.txt
    $1 rm    ${INSTALL_DIR}/requirements-venv.txt
    $1 rm -f /opt/install.sh
    $1 rm -f /opt/install.sh.asc
    $1 rm -f /opt/pubkey.asc
}


function install_virtualenv {
    # Some distros want virtualenv installed as sudo and other don't.
    # Install as both users to improve the chances of compatibility.
    sudo torsocks python3 -m pip install -r ${INSTALL_DIR}/requirements-venv.txt --require-hashes --no-deps
    torsocks      python3 -m pip install -r ${INSTALL_DIR}/requirements-venv.txt --require-hashes --no-deps
}


function kill_network {
    # Kill network interfaces to protect the TCB from remote compromise.
    for interface in /sys/class/net/*; do
        name=$(basename "${interface}")
        if [[ ${name} != "lo" ]]; then
            echo "Disabling network interface ${name}"
            sudo ifconfig "${name}" down
        fi
    done

    sleep 1
    clear
    c_echo ''
    c_echo " This computer needs to be air gapped. The installer has "
    c_echo "disabled network interfaces as the first line of defense."
    c_echo ''
    c_echo "Disconnect the Ethernet cable and press any key to continue."
    read -r -n 1 -s -p ''
    echo -e '\n'
}


function add_serial_permissions {
    # Enable serial interface for user-level programs.
    clear
    c_echo ''
    c_echo "Setting serial permissions. If available, please connect the"
    c_echo "USB-to-serial/TTL adapter now and press any key to continue."
    read -r -n 1 -s -p ''
    echo -e '\n'
    sleep 3  # Wait for USB serial interfaces to register

    # Add user to the dialout group to allow serial access after reboot
    sudo adduser "${USER}" dialout

    # Add temporary permissions for serial interfaces until reboot
    arr=($(ls /sys/class/tty | grep USB)) || true
    for i in "${arr[@]}"; do
        sudo chmod 666 "/dev/${i}"
    done

    if [[ -e /dev/ttyS0 ]]; then
        sudo chmod 666 "/dev/ttyS0"
    fi
}


function create_user_data_dir {
    # Backup TFC user data directory if it exists and has files in it.
    if [[ -d "$HOME/tfc" ]]; then
        if [[ -n "$(ls -A "${HOME}/tfc/")" ]]; then
            mv "${HOME}/tfc" "${HOME}/tfc_userdata_backup_at_$(date +%Y-%m-%d_%H-%M-%S)"
        fi
    fi
    mkdir -p "${HOME}/tfc" 2>/dev/null
}


function get_screen_width {
    # Output the width of the screen resolution.
    xdpyinfo | grep dimensions | sed -r 's/^[^0-9]*([0-9]+).*$/\1/'
}


function modify_terminator_font_size {
    # Adjust terminator font size for tiling terminal emulator configurations.
    #
    # The default font sizes in terminator config file are for 1920px
    # wide screens. The lowest resolution (width) supported is 1366px.
    width=$(get_screen_width)

    if (( width < 1600 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 8/g'     "${2}"  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 7/g'   "${2}"  # Data diode config
    elif (( width < 1920 )); then
        $1 sed -i -e 's/font                = Monospace 11/font                = Monospace 9/g'     "${2}"  # Normal config
        $1 sed -i -e 's/font                = Monospace 10.5/font                = Monospace 8.5/g' "${2}"  # Data diode config
    fi
}


# Installation configurations for Debian/PureOS/Ubuntu/LMDE
# ----------------------------------------------------------------------------------------

function install_tcb {
    # Install TFC for Source/Destination Computer.
    steps_before_network_kill
    kill_network

    verify_files
    create_user_data_dir

    VENV_NAME="venv_tcb"

    install_packages_as_root "${virtualenv_packages[@]}"
    sudo python3 -m virtualenv "${INSTALL_DIR}/${VENV_NAME}" --system-site-packages --never-download --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    install_to_venv "${tcb_packages[@]}"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                   /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-TxP.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RxP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    add_serial_permissions

    install_complete "Installation of TFC on this device is now complete."
}


function install_relay {
    # Install TFC Relay configuration on Networked Computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    VENV_NAME="venv_relay"

    install_virtualenv
    sudo python3 -m virtualenv ${INSTALL_DIR}/${VENV_NAME} --system-site-packages --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    sudo torsocks ${INSTALL_DIR}/${VENV_NAME}/bin/pip3 install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                  /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RP.desktop /usr/share/applications/

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/src/receiver/"
    sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/tfc.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    add_serial_permissions

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# ----------------------------------------------------------------------------------------
# Installation configuration for Tails

function read_sudo_pwd {
    # Cache the sudo password so that Debian doesn't keep asking
    # for it during the installation (it won't be stored on disk).
    read -r -s -p "[sudo] password for ${USER}: " sudo_pwd
    until (t_sudo echo '' 2>/dev/null)
    do
        echo -e '\nSorry, try again.'
        read -r -s -p "[sudo] password for ${USER}: " sudo_pwd
    done
    echo
}


function install_relay_tails {
    # Install TFC Relay configuration on Networked Computer
    # running Tails live distro (https://tails.boum.org/).
    read_sudo_pwd

    t_sudo apt update
    t_sudo apt install libssl-dev python3-pip python3-tk -y || true  # Ignore error in case packets can not be persistently installed

    create_user_data_dir

    VENV_NAME="venv_relay"

    torsocks git clone --depth 1 https://github.com/maqp/tfc.git "${HOME}/tfc"
    t_sudo mv "${HOME}/tfc/" "${INSTALL_DIR}/"
    t_sudo chown -R root ${INSTALL_DIR}/

    verify_tcb_requirements_files
    verify_files

    # Tails doesn't allow downloading over PIP to /opt/tfc, so we first download
    # to $HOME, move the files to /opt/tfc, and then perform the hash verification

    # Install prerequisites before downloading other packages: This ensures pip accepts manylinux2014 wheels
    torsocks python3 -m pip download -r "${INSTALL_DIR}/requirements-pre.txt"   --require-hashes --no-deps --no-cache-dir -d "${HOME}/"
    verify_packages "${pre_packages[@]}"
    install_packages_as_root "${pre_packages[@]}"

    torsocks python3 -m pip download -r "${INSTALL_DIR}/requirements-venv.txt"        --require-hashes --no-deps --no-cache-dir -d "${HOME}/"
    torsocks python3 -m pip download -r "${INSTALL_DIR}/requirements-relay-tails.txt" --require-hashes --no-deps --no-cache-dir -d "${HOME}/"

    verify_packages "${virtualenv_packages[@]}"
    verify_packages "${tails_packages[@]}"

    install_packages_as_root "${virtualenv_packages[@]}"

    # Install Relay Program dependencies to virtualenv
    t_sudo python3 -m virtualenv ${INSTALL_DIR}/${VENV_NAME} --system-site-packages --always-copy
    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    install_to_venv "${tails_packages[@]}"
    deactivate

    t_sudo mv ${INSTALL_DIR}/tfc.png                        /usr/share/pixmaps/
    t_sudo mv ${INSTALL_DIR}/launchers/TFC-RP-Tails.desktop /usr/share/applications/
    t_sudo mv ${INSTALL_DIR}/tfc.yml                        /etc/onion-grater.d/

    # Remove unnecessary files
    remove_packages "${pre_packages[@]}"
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tails_packages[@]}"
    remove_common_files "t_sudo"
    t_sudo rm -r "${INSTALL_DIR}/src/receiver/"
    t_sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    t_sudo rm -r "${INSTALL_DIR}/qubes/"
    t_sudo rm    "${INSTALL_DIR}/dd.py"
    t_sudo rm    "${INSTALL_DIR}/tfc.py"

    install_complete "Installation of the TFC Relay configuration is now complete."
}


# ----------------------------------------------------------------------------------------
# Installation configurations for Qubes OS (https://www.qubes-os.org/)

function install_qubes_src {
    # Qubes Source VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    VENV_NAME="venv_tcb"

    verify_files

    install_packages_as_root "${virtualenv_packages[@]}"
    sudo python3 -m virtualenv "${INSTALL_DIR}/${VENV_NAME}" --system-site-packages --never-download --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    install_to_venv "${tcb_packages[@]}"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                         /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-TxP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-transmitter /usr/bin/tfc-transmitter

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm -r "${INSTALL_DIR}/qubes/"  # Listening service only needed on NET/DST
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}


function install_qubes_dst {
    # Qubes Destination VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    VENV_NAME="venv_tcb"

    verify_files

    # Configure listening service for qrexec RPC
    sudo ln -sf /opt/tfc/qubes/service.sh /etc/qubes-rpc/tfc.NetworkerDestination
    sudo chmod a+x /opt/tfc/qubes/writer.py
    sudo chmod a+x /opt/tfc/qubes/service.sh

    install_packages_as_root "${virtualenv_packages[@]}"
    sudo python3 -m virtualenv "${INSTALL_DIR}/${VENV_NAME}" --system-site-packages --never-download --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    install_to_venv "${tcb_packages[@]}"
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                         /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RxP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-receiver    /usr/bin/tfc-receiver

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/src/relay/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/relay.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}


function install_qubes_net {
    # Qubes Networked VM installation configuration for Debian 10 domains.
    create_user_data_dir

    steps_before_network_kill

    VENV_NAME="venv_relay"

    verify_files

    # Configure listening service for qrexec RPC
    sudo ln -sf /opt/tfc/qubes/service.sh /etc/qubes-rpc/tfc.SourceNetworker
    sudo chmod a+x /opt/tfc/qubes/writer.py
    sudo chmod a+x /opt/tfc/qubes/service.sh

    install_packages_as_root "${virtualenv_packages[@]}"
    sudo python3 -m virtualenv ${INSTALL_DIR}/${VENV_NAME} --system-site-packages --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    sudo torsocks ${INSTALL_DIR}/${VENV_NAME}/bin/pip3 install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                        /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-RP-Qubes.desktop /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/tfc-qubes-relay      /usr/bin/tfc-relay

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/src/receiver/"
    sudo rm -r "${INSTALL_DIR}/src/transmitter/"
    sudo rm    "${INSTALL_DIR}/dd.py"
    sudo rm    "${INSTALL_DIR}/tfc.py"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

    install_complete_qubes
}


# ----------------------------------------------------------------------------------------
# Tiling terminal emulator configurations for single OS

function install_local_test {
    # Install TFC for local testing on a single computer.
    steps_before_network_kill

    verify_files
    create_user_data_dir

    VENV_NAME="venv_tfc"

    sudo torsocks apt install terminator -y

    install_virtualenv
    sudo python3 -m virtualenv ${INSTALL_DIR}/${VENV_NAME} --system-site-packages --always-copy

    . ${INSTALL_DIR}/${VENV_NAME}/bin/activate
    sudo torsocks ${INSTALL_DIR}/${VENV_NAME}/bin/pip3 install -r ${INSTALL_DIR}/requirements.txt       --require-hashes --no-deps
    sudo torsocks ${INSTALL_DIR}/${VENV_NAME}/bin/pip3 install -r ${INSTALL_DIR}/requirements-relay.txt --require-hashes --no-deps
    deactivate

    sudo mv ${INSTALL_DIR}/tfc.png                                /usr/share/pixmaps/
    sudo mv ${INSTALL_DIR}/launchers/TFC-Local-test.desktop       /usr/share/applications/
    sudo mv ${INSTALL_DIR}/launchers/terminator-config-local-test ${INSTALL_DIR}/
    modify_terminator_font_size "sudo" "${INSTALL_DIR}/terminator-config-local-test"

    # Remove unnecessary files
    remove_packages "${virtualenv_packages[@]}"
    remove_packages "${tcb_packages[@]}"
    remove_common_files "sudo"
    sudo rm -r "${INSTALL_DIR}/qubes/"
    sudo rm    "${INSTALL_DIR}/tfc.yml"

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
    # install configuration, or preferably use the Qubes configuration.
    dpkg_check

    create_user_data_dir

    VENV_NAME="venv_tfc"

    sudo torsocks apt update
    sudo torsocks apt install git libssl-dev python3-pip python3-tk terminator -y

    torsocks git clone https://github.com/maqp/tfc.git "${HOME}/tfc"

    torsocks python3 -m pip install -r "${HOME}/tfc/requirements-venv.txt" --require-hashes --no-deps

    python3 -m virtualenv "${HOME}/tfc/${VENV_NAME}" --system-site-packages --always-copy

    . "${HOME}/tfc/${VENV_NAME}/bin/activate"
    torsocks ${HOME}/tfc/${VENV_NAME}/bin/pip3 install -r "${HOME}/tfc/requirements-dev.txt"
    deactivate

    sudo cp "${HOME}/tfc/tfc.png"                   "/usr/share/pixmaps/"
    sudo cp "${HOME}/tfc/launchers/TFC-Dev.desktop" "/usr/share/applications/"
    sudo sed -i "s|\$HOME|${HOME}|g"                "/usr/share/applications/TFC-Dev.desktop"
    modify_terminator_font_size "" "${HOME}/tfc/launchers/terminator-config-dev"
    chmod a+rwx -R "${HOME}/tfc/"

    # Remove unnecessary files
    sudo rm -f "/opt/install.sh"
    sudo rm -f "/opt/install.sh.asc"
    sudo rm -f "/opt/pubkey.asc"

    add_serial_permissions

    install_complete "Installation of the TFC dev environment is now complete."
}


function arg_error {
    # Print help message if the user launches the
    # installer with missing or invalid argument.
    clear
    echo -e "\nUsage: bash install.sh [OPTION]\n"
    echo    "Mandatory arguments"
    echo    "  tcb      Install Transmitter/Receiver Program (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.1)"
    echo    "  relay    Install Relay Program                (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.1 / Tails 4.6+)"
    echo -e "  local    Install insecure local testing mode  (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.1)\n"
    echo    "  qsrc     Install Transmitter Program          (Qubes 4.0.4)"
    echo    "  qdst     Install Receiver Program             (Qubes 4.0.4)"
    echo -e "  qnet     Install Relay Program                (Qubes 4.0.4)\n"
    exit 1
}


# ----------------------------------------------------------------------------------------
# Pre-install checks

function architecture_check {
    # Check that the OS is 64-bit, and not 32-bit.
    if ! [[ "$(uname -m 2>/dev/null | grep x86_64)" ]]; then
        exit_with_message "Invalid system architecture. Only 64-bit OSs are supported"
    fi
}


function root_check {
    # Check that the installer was not launched as root.
    if [[ ! $EUID -ne 0 ]]; then
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


function python_version_check {
    # Check Python version and select file names based on it.
    python_minor_version=$(python3 -c 'import sys; version=sys.version_info[:3]; print("{1}".format(*version))')
    supported_minor_versions=("7" "8" "9")

    if [[ ! "${supported_minor_versions[*]}" =~ ${python_minor_version} ]]; then
        exit_with_message "Invalid Python version (3.${python_minor_version}). Only 3.7, 3.8 and 3.9 are supported."
    fi

}


# ----------------------------------------------------------------------------------------
# Main routine

set -e
architecture_check
root_check
sudoer_check
python_version_check
sudo_pwd=''

case $1 in
    tcb    ) install_tcb;;
    relay  ) install_relay;;
    tails  ) install_relay_tails;;
    local  ) install_local_test;;
    qsrc   ) install_qubes_src;;
    qdst   ) install_qubes_dst;;
    qnet   ) install_qubes_net;;
    dev    ) install_developer;;
    *      ) arg_error;;
esac
