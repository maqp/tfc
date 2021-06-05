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
dependency_hashes['certifi-2021.5.30-py2.py3-none-any.whl']='395c349cef4f8247af20a763a1927fe243e52d7fe846874f100b33e46119e48a3b7b681d3f3e879fe18a07ae81ba791ac7d0ed61017990d722f29d17e2573811'
dependency_hashes['certifi-2021.5.30.tar.gz']='77a5ce25d3ea297160d3dd8e97a582cc79985acf989257755a3693696aeeefbba31b8f9e4b6afca101058a4ef7075fc5fc8780b389800354d7a1de6398612d03'
dependency_hashes['cffi-1.14.5-cp35-cp35m-manylinux1_i686.whl']='0575f1eb38353dc7de21b92be541f0ab23354709b12a18946d23d952f21ac11a0f2c3ebdeecf4005a89747384312a20accb740b19c543a5736ea9baf743229ea'
dependency_hashes['cffi-1.14.5-cp35-cp35m-manylinux1_x86_64.whl']='35c33090afbd1cd9a91c9b7970382480fd44cc64df68e9305f2d9aeda5c12f694665bc33ebc01e31701f64da1429c77d2e415da51710fce734bd166a504242be'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux1_i686.whl']='6940d8ea2b3749ad2c0588428f901d2addcbbb2003ac6aa1ee1ec5c763bca888604381f55ac8f348ac3092a7b70e47da627119c558672086d66d680be33c7ac5'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux1_x86_64.whl']='3d76ffa87cc140334df4ce5f50949e1e9360312e7102d8d912f049ee1c014395ec3677f4b56705fa7555107cb74e283255b6292319ee6d821ee52c450d7e1559'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux2014_aarch64.whl']='0db3f6946ef3cca66de9cb6178dd6378bfdda3a71d9abf29d1ff2c46dc3df86410328a41b4e6ee89cd8ed0859bf2c9e036a157975e2c73cdb545b4b52068526c'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='71f413ee0e4f41bdbc616c794dc578ebd60afa6aa67c0c3199bc3ccf9e3c01ea5b8b30cd692bc903f448520f44add3fafadc3f517d13183985e89443102e23cb'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='b858663dedd76c676c76decc1fb6d5b24a62917b49297397c0baf867942ae8c7b367bfb3083ec158eb7f120a6f1f20527bff87a66ea166869a78e7e6a48be6fc'
dependency_hashes['cffi-1.14.5-cp36-cp36m-manylinux_2_17_s390x.manylinux2014_s390x.whl']='9ef41e27d9f201933dc0908991283ca53aac176c8a3f420b3ffd1434bf0862a71704e8737ca9d0b8e122f947eca7d56d1e9cb100addfb333b5ebea527017643e'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux1_i686.whl']='6f95bbc5331cc5a775c7af7571c706a341779541dddf429fea76478d75337ee7ec7b412ed539fdd87df9f88516429ac9b346413da1ca8a6413c47ca65fbc122e'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux1_x86_64.whl']='d5a9b816a7c030d1cead4c432419ec28586d9b044f90ad0b589337feea8afca496a54bd24d653770cdcca8fb7bd74ec1da9fa5ffd4c2f94ebafedae2dbb1672a'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux2014_aarch64.whl']='129b9b31263ceb1cfc4c60cedb21c3e3ee8feb52b85f0156a63104bcabde8d506ce84b9bf60f9ed52cc743340e3d2252d434683bed0be7f9e3a75e60b0431248'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='15ce596bcef1712a0502665b906deb2d9bd53d851178e106227416ca07f714da000aea1c75a420907b0931a6e73e683657aae062f10c5cdff3671d839c32e59b'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='3f64ca08c6cc0eaa00dc2bbf095e2fb0c00a2aa4cc5ee8917ea62a6b6df9b88c758013c5ee1be0536eabef0d0a9ab049be676652681996aa49677aaa273e4566'
dependency_hashes['cffi-1.14.5-cp37-cp37m-manylinux_2_17_s390x.manylinux2014_s390x.whl']='7484178a1f1da525740e9ca7fabe7ec38727418ecb4cfa4ff3e43e390082720ee5b5d3fd987304cba6be5af4ab12c9f71dc9ea408a84758ce1daa916d4e215d2'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux1_i686.whl']='e8e1e06279d76ea5ede4449ed20ca927449b3e89977216d4b89915a97a8c977744744175ea25cc85638b8ff0a959145b58b527e4bbba417c7b521bbfb43d3616'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux1_x86_64.whl']='72bdb71b1ef5d0b3c88fd4d73c0d2857bda0b3945bde3355b8910f48ff6115f700753184190074994c0ba6b893e6259f073e10512231f7f674c82a4155b885f9'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux2014_aarch64.whl']='798754d337b116b2aa6d5d3e24de6468d43955c88f738bd60d41dac1665f4251b3636b6c3fe466c5b2206c765c5c1a68708848d51293b407d1f56ecc4e508e95'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='2e633d925df6906be14205c8013a2faeac9e1cfbee014dd11c9934fdb14bfc7558d451dc8c010bf1c9ff4cca969859076179c4c1bb1a5de886e1b1082df40dd4'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='807d619e6ce18d59eca408fdd8b88bc0ff8bf687515f46c8b20f152db7bccfa317b36a1ab5e13f2123653702783c9e2adb5e2e33ad512cd311e1daa604c362ca'
dependency_hashes['cffi-1.14.5-cp38-cp38-manylinux_2_17_s390x.manylinux2014_s390x.whl']='746972fe54f8e4965347979b17ff888c9e869fae1e42d8d7e1e42022edb57dff70a2410bfa09734f6c47701564d05dddf246d95f6a351022f18aa6cf483d870c'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux1_i686.whl']='2d0bd3f6e6119747c9dd36a90e9d31f3209e78142b87283bbd965d92fbca96074a008a904963de4e9437244e013302e8ba16635af4922c895963056de74f2d81'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl']='3c73e06bef8e9646beacc584d59ecf42de013034194d6eb59f1abf279e8fe5468e106fcd47802ce1d264d3c1d9122af3c66ea1229db78a768f7ea069ddc2fd72'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux2014_aarch64.whl']='e880f602dad400e742fb7e1907b5ae78cfe3002fa2556bc090366eb51a5114d023885b33c6bd640cd7ce5d18389c682d0dce346a8efdccabb7f6bd631133de30'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='453f12afe31d0ba110ce37d344985503c2b2d10f4bf5ce7f7d096f895f133b341ce861df73f09c9df9cd31c6f496f844d8444f3b84bcf08d64559f5f03cfb3da'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='49a9896b7f96e39890c3eea2323c8c4e72bd342cee45244da608d2093959ca46f6d6643013898617dbc941fb80160a227ba41a27df2696544526c62aea6c86dd'
dependency_hashes['cffi-1.14.5-cp39-cp39-manylinux_2_17_s390x.manylinux2014_s390x.whl']='7a6c83ff8d9e74fdf0b8066905d31335c5998c753923a383cee5cdd2bd377241f97afe78fadf26e39d093705fa9573ae6f960f2ec0ff86383441496a41effe59'
dependency_hashes['cffi-1.14.5.tar.gz']='7428b3f6e4ee9f3b91011e43304dd63e5cc48479120ae58298c646c1ec1f5c24525d5f08655a7fed70c5fad7ae0c2e0539e512b5fa49d2bc57669c4ab703cc2a'
dependency_hashes['chardet-4.0.0-py2.py3-none-any.whl']='cc8cdd5e73b4eace0131bbeaf6099e322ba5c2f827f26ad3316c674c60529d77f39f68d9fb83199ab78d16902021ab1ae58d74ab62d770cf95ceb804b9242e90'
dependency_hashes['chardet-4.0.0.tar.gz']='ebd7f420e1094445270db993f6373ffe7370419e002b0bb13299dc6c9b0f7c4e77b0f44f871fba6371e6869e7c86728514367db377e3137487a3acf50cb81e96'
dependency_hashes['click-8.0.1-py3-none-any.whl']='0d3ff0950d96ff85397b8556f5899e3a42f75a1fd6414148ed7b0bd4725f787956b5e2df9110a101eeafd05388dd5f5fb99d11b89186e5b22769dbc3d2ab65a0'
dependency_hashes['click-8.0.1.tar.gz']='6a6d66c68dae4cfcfdab5d77dab4ab280b18f8e9ec326b4860012253d8f6b4fa57a5a3794ddebd228da85f893b0c6a737d8be3ad361d31098ef0a2ad684d6d0a'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2010_x86_64.whl']='be89565a54f7941198a994fe1e8aad3dbd15b27d1ca547c2f0edd81eadf74082737c183e7c539bd27eeaa17cdbfacb346dcb7a0b3c611c3ae51e9b983c8d97c2'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2014_aarch64.whl']='c7c2c6905a7321e1b046f2114c9d04f38b3f79b549896ad4e646aa64eef190b8e41cf5284ef049a11e8a7fcd5826a27c2eb9e4557ce5a7703d2d8c6be1c5c621'
dependency_hashes['cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl']='6b4eaa52b17065e5723ac2d70f38f05c5a550aea5a50cd4ffac78ec61fa363ac9d1ef29d9c9ca876e69cf9ac681bf6e9941f2027fd6126e472d425d0b5cdf788'
dependency_hashes['cryptography-3.4.7-pp36-pypy36_pp73-manylinux2010_x86_64.whl']='9c07aa6855e9bb28be14bbeab2feb56e9a05d13c25bf555878c1917722c9836beb4ad07f5bd7a2b9adf3327f35c55c6217a8d67103c4c2a5288e7b10acd92cc7'
dependency_hashes['cryptography-3.4.7-pp36-pypy36_pp73-manylinux2014_x86_64.whl']='772f918ec271837eee56e8b90f9cb6d759fe8b255ee99108d37c583b9bfa5077155a867fc60ce51c6c022bc3923b28ffbb38c1324ef2d1721959cae185169c57'
dependency_hashes['cryptography-3.4.7-pp37-pypy37_pp73-manylinux2010_x86_64.whl']='8017907f85eead22d4ec05c628cb90699312c68cd791459de853601db7848ebca448b52570505484981783a2a19113e3165f11ece08e3539d2e94ece87c96e9a'
dependency_hashes['cryptography-3.4.7-pp37-pypy37_pp73-manylinux2014_x86_64.whl']='890846b89dc97df25487ea66216884c0d3365ff6020fc71e338a7bf5c2224864a155b3d34f338b8a42d724d4bbb8dfb9842913e5405ba113b5e545fe398b87ca'
dependency_hashes['cryptography-3.4.7.tar.gz']='3c4cf64bc0b067ccdbb71efe04c32ac9d673faea6cc4ccd13d6b1b61920be4785806d19359b7657d032a2ff1c011a8b4f16ec4924d9df8a59d1a875a7f844473'
dependency_hashes['distlib-0.3.2-py2.py3-none-any.whl']='5865b4216afeb43e86bf282e7b6bcee28dbdf718211e15e5a8d10b1f9af8e3684f76f33b0b7194956de1f5290aa67db938533f6546df46fdc58bd7170bee0765'
dependency_hashes['distlib-0.3.2.zip']='a39f8c7df9c07554769153268bae09d8abd8b59b8360d470c1bc011944936a1dcfbe34134a03eb63e377ee594e68b07c676289fbdbf53e90968f1b9cd6e7003b'
dependency_hashes['filelock-3.0.12-py3-none-any.whl']='d13edd50779bca9842694e0da157ca1fdad9d28166771275049f41dea4b8d8466fc5604b610b6ad64552cdf4c1d3cada9977ca37c6b775c4cc92f333709e8ea3'
dependency_hashes['filelock-3.0.12.tar.gz']='09b8b16c12a60044a259a5d644bc8066660871104a7f4cd431431173d475b9f15744adfb8d86ec8cda69f2a1b52bd14cb8a066d70fa5e49c449bc5ee702ec2a0'
dependency_hashes['Flask-2.0.1-py3-none-any.whl']='9ed20ea64efd0d9563c39de48b732be815015e5a04aab2601a55b011af38e28009d4dc783fae91266f628f06566f286bc45a6ea61c208b05f36bf7f9215b6749'
dependency_hashes['Flask-2.0.1.tar.gz']='fefed4971f0542b25ba2867919aa54a83b6e3f47e7cee94586543843e7e00ba209ac15d8fe28a3c53981f587aebcf2f3915a49e1a9cd1b729099dccbed3783c2'
dependency_hashes['idna-2.10-py2.py3-none-any.whl']='7b7be129e1a99288aa74a15971377cb17bee1618843c03c8f782e287d0f3ecf3b8f26e3ea736444eb358f1d6079131a7eb291446f3279874eb8e00b624d9471c'
dependency_hashes['idna-2.10.tar.gz']='83b412de2f79a4bc86fb4bdac7252521b9d84f0be54f4fb1bde1ee13a210bbfa4b1a98247affbc7921046fb117a591316c12694c1be72865767646554c5207ac'
dependency_hashes['importlib_metadata-4.5.0-py3-none-any.whl']='738fcfc5034c48a000c9c8f970e3dba771e92e8527d03e70a5138c990d6935fcff636151009513107fea283ec50071da6b8d109d487a39c077e6b2a5f0285e27'
dependency_hashes['importlib_metadata-4.5.0.tar.gz']='62b9cefa502d751d36b5f43606ea86c46574fea159941b68319e5dd9aa53d6d990e630c36d72830c54eb2bba2f2be53201be2482974f833cc1da8869eb2a8dc2'
dependency_hashes['itsdangerous-2.0.1-py3-none-any.whl']='93c1319854aad7614ed9c98cf94ff61ca3abb8719c79ebbfe3f07e741559e3e1db8b0ba137c688c8bb80f616438d18aff9e1ef62d2829d8dba4f1194582056eb'
dependency_hashes['itsdangerous-2.0.1.tar.gz']='bc1e51eb861c13b4e3c4c1c655a3b6f28e326d70db23679269d2bea84f0f8f94afd4fccecb745cf40f5a5956a14a336dfa42f0f5149666ae43061feb1366302b'
dependency_hashes['Jinja2-3.0.1-py3-none-any.whl']='7aaa402986a553942de321b3f7462ae2419539e05ea0892aad54a31736f57bc2330f510e7a8341c48fb01e19a3003bd0cc4260ee2feb9aa8c2155e8c780118a1'
dependency_hashes['Jinja2-3.0.1.tar.gz']='18ca56fb2271885c41982d2a3b2daa8bdc7a95191f54d8eec96ddbe001ac995b3fae766b603d8c9287413e5227062b771575012cd92a3f64ed76067d5f168701'
dependency_hashes['MarkupSafe-2.0.1-cp36-cp36m-manylinux1_i686.whl']='1d046eae0c7a18fc9a09ff2ca52e8d05834eed7135dace51cc17286d4a98aebe32e806e9c581d445ce43eb7299856bdc3ca4870565ff2ba40dfbdae087904fd0'
dependency_hashes['MarkupSafe-2.0.1-cp36-cp36m-manylinux1_x86_64.whl']='796b4d69860be9dc49a3642b477a1ba161a2ed21144a42d981aef0f8c9926d773cb7380af3b54088b84ec5b0007fda484a32c05b928788fc81b63039f95a8f2e'
dependency_hashes['MarkupSafe-2.0.1-cp36-cp36m-manylinux2010_i686.whl']='f28effef1954e22ad163b70ca6dde1d53010aacac4b33244372027383ded575fd68a193ebe0be76044f6dad4fea380b743dfd72bd87de1e8d84af2aa4291048e'
dependency_hashes['MarkupSafe-2.0.1-cp36-cp36m-manylinux2010_x86_64.whl']='7d72c81a908daae9f9c1a9ae220b6a24af7b8fb4cc7765f209c74616328236a7fc08e598aa1a68af6e8c563262f38eb6d869fcb445c4e39c4fb21bbfe49d140d'
dependency_hashes['MarkupSafe-2.0.1-cp36-cp36m-manylinux2014_aarch64.whl']='e393dc7df3f8c8afba005d8706d97bce2981ab43c83743b6f7d3c73e53f2844c9e1b67c929355cc06b938b8fb989efa92e3ace4e491a8c30857bc735893d7b4c'
dependency_hashes['MarkupSafe-2.0.1-cp37-cp37m-manylinux1_i686.whl']='41e98e2179f19955b0149a447154a1e9eec6358baa28476823547e0b4cecbc2621a266d93af009263511b86f56830c68ab063c20b6bf6edb7291fc938ea5b23f'
dependency_hashes['MarkupSafe-2.0.1-cp37-cp37m-manylinux1_x86_64.whl']='996409dc75f8b74fd6d061d597a00799c3157f4aa33d15e51dc7d7c5c527000d7dde79eace1924b5974c113ac90827ab354a2e58ec4707c62ed6a2136cc0c940'
dependency_hashes['MarkupSafe-2.0.1-cp37-cp37m-manylinux2010_i686.whl']='ad1ae4d16d8a8887b018e0f991ed0cc7414cafc92fd2d0dc8549dfd7e528e8be3d4085ce3419b06ccb06e96a4aebc1466522236dba480ac8d639b4bc7c8d6b25'
dependency_hashes['MarkupSafe-2.0.1-cp37-cp37m-manylinux2010_x86_64.whl']='8c02a6f72f55c8789c17b5795061b72b2964bfdc47a4956fcce9c5d7bef060ba682b9fce494256d135274407a37ab31e0048fe71ade5c0c4efefbfab18061b5c'
dependency_hashes['MarkupSafe-2.0.1-cp37-cp37m-manylinux2014_aarch64.whl']='b367223335bd0017bad2ffe6fab84214867d0b5b8aec7c849872bcf51f586c3fc3066d1f2155dc8ce75c6f8d7361a3daf6de086365ef54f609daa9f5cf50bc1f'
dependency_hashes['MarkupSafe-2.0.1-cp38-cp38-manylinux1_i686.whl']='b60deb0b4f5a34c70433f723a523434b56ccd76381abf71a2a57da86b8962b01ddc3d5ebeb090419f141a20583a43a23558c587ce97246687745b6c6ae47657d'
dependency_hashes['MarkupSafe-2.0.1-cp38-cp38-manylinux1_x86_64.whl']='f6a2d6e0ce38f8262aeed074c31cdabc46963b5e3970ed1a7af7f7557934fc08f15d53a017265a8c0a76b7be6133ffa257d3d92e6e4c2977cef329de94be5c57'
dependency_hashes['MarkupSafe-2.0.1-cp38-cp38-manylinux2010_i686.whl']='a946e2bd83c3babd5e5d5ff7d7320f023023cc5aac5928855f0fa8bc3bb56199c5b8dce09b06fde008432f753c6a7863779d6feb7c747e9efb8ee1938f3f8819'
dependency_hashes['MarkupSafe-2.0.1-cp38-cp38-manylinux2010_x86_64.whl']='d1a20c3fdc42f73476e2ac25c81d6220e915395651aa4e671539f349bca40135e4c9556a7ea04cae4cc426985035637a951a66a013897913984d44cf2628a789'
dependency_hashes['MarkupSafe-2.0.1-cp38-cp38-manylinux2014_aarch64.whl']='e19b733bedd8ccc3e50ab54fea39d20ebb2af81a6137c0aed55315c1f7c8e13c3976ada5773e159935334f1aa6abcc4d7fff153d90d86de9e81d92bb90434f41'
dependency_hashes['MarkupSafe-2.0.1-cp39-cp39-manylinux1_i686.whl']='10dbd4ab97a6ad405a938f0736f3ba5ec33c66b59b8420800e1df46c656e420566ba27e9917dfd11220e62028afad355fb21667f46a2c1cc765c987442a4b208'
dependency_hashes['MarkupSafe-2.0.1-cp39-cp39-manylinux1_x86_64.whl']='7121a844bbd6738e28de4aca24cc2f49a810d468da519c5cf64e940afc80b6b01229125d6856b0b099a7f84f39da1327cab7a1cec5b1ab8a3aeaa4dcfe973646'
dependency_hashes['MarkupSafe-2.0.1-cp39-cp39-manylinux2010_i686.whl']='46accdded7f03c49a6bb12d5e3765446ab59d5bf42fdd831e4cf04d591c434ae6642efe1208b06fb22192c979a5b5cbf8a242fb120d1402f048b6fe1f3e0627e'
dependency_hashes['MarkupSafe-2.0.1-cp39-cp39-manylinux2010_x86_64.whl']='450469a14bb03cda262b70eaf6533cee5890695e30424e87866d829d4e97312a5766480fff7f55dae16733e56daa45cbeaf033e326a1580d18823108cba437d8'
dependency_hashes['MarkupSafe-2.0.1-cp39-cp39-manylinux2014_aarch64.whl']='e01a67f1d1dd3d55d5a377d062c9e95ba80030ce279777a074cbfe363258ad246ed1ecdea981a3d16420468d994e6ae9aae42276ff18558a14e146d28de5ae8c'
dependency_hashes['MarkupSafe-2.0.1.tar.gz']='77249bda784111ece15d59eb3de1cbb37a58fb9f22902fe6b73fea9eb0f23857ccbe53dc55463278e3b91f78dc35e2b027fd823ca50d88d8985d5a98ce2327f1'
dependency_hashes['pip-21.1.2-py3-none-any.whl']='a197804cba6c97366625597389f0749668a76bf8bf00d9de640565347332807dc9f8f44560bf17705f3244f2f5f7b6889947c74ab9da3c3c1b476599ad2dc038'
dependency_hashes['pip-21.1.2.tar.gz']='5b8c7151717e0138a9ccf0926133cfad96dd10f52e3629a2e3ce3306d904142506a718302a9ca919e5ec3689a9c24790b4ef478c20ecab6cc16787a23c6e23b9'
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
dependency_hashes['setuptools-57.0.0-py3-none-any.whl']='ada554059e107829053c86d67b270250de96d06e6650c07abfbfb544f04dcdeec19fd174f34c4b0c6b5bad64a6cd7306857d0b1753ec2af1164375be18388db5'
dependency_hashes['setuptools-57.0.0.tar.gz']='5277d8630367d6b16a49e36ed84d8cc6abfaedf87dac3f795b204626a8f15ca9fd80d158a465d8bcabe9c074c76b87c3378d82a4ba5feee1ac6a5f2c91db061e'
dependency_hashes['six-1.16.0-py2.py3-none-any.whl']='656b010ed36d7486c07891c0247c7258faf0d1a68c5fb0a35db9c5b670eb712d5e470b023ffd568d7617e0ae77340820397014790d14fda4d13593fa2bd1c76f'
dependency_hashes['six-1.16.0.tar.gz']='076fe31c8f03b0b52ff44346759c7dc8317da0972403b84dfe5898179f55acdba6c78827e0f8a53ff20afe8b76432c6fe0d655a75c24259d9acbaa4d9e8015c0'
dependency_hashes['stem-1.8.0.tar.gz']='aa2033567b79aef960f8321e4c6cbc28105c59d6513ff49a9f12509d8f97b1a2e8a3b04dc28abb07fad59b0f6ba66443b92bbefa0d08b26038bbaf24f7f2846d'
dependency_hashes['typing_extensions-3.10.0.0-py2-none-any.whl']='c6ee39f76e2f8f10eaeb05b16a3d9bfeba541ec3ca1644a6e72ff5c28d11c98468bba758c0f8c4c10ad2e6ade714bd4de9c15def25f9c62b23ac20eea9724540'
dependency_hashes['typing_extensions-3.10.0.0-py3-none-any.whl']='cfefc92eeab267f030c8834759c2d9a021b70730cae1abd0695cceddd860a3ca1b2aa1dc25f558ee2acf23d9f662503ccb149ad85c8e48f0b66af6fee418077e'
dependency_hashes['typing_extensions-3.10.0.0.tar.gz']='1c262aedb092d506bcd90d033a640fa6e1f9131f95eafb77d30ed21ff7d6b0f492b6092d3523ecb773bc54904679e0fa1aa8c3b4af62d77f1a7e6fe5fd6cb10c'
dependency_hashes['urllib3-1.26.5-py2.py3-none-any.whl']='72d79e58078a5c73b69c6f2f15c39af461fe4360e5811aec8f6ae4187635bcd867ad7557c504be2cd36e2f5b232c62765a9896efb573747d472f3034c04390c8'
dependency_hashes['urllib3-1.26.5.tar.gz']='4a1899b223b00894d49f6dff5fc95d410e5b0ab28c11f7e3cd82d03e50438b0c5b0adf693a33fd80f1586312dc0012836713998674da15531bf82d52645881f6'
dependency_hashes['virtualenv-20.4.7-py2.py3-none-any.whl']='ba4e5b2333f2a9d12ee1b6072c757655130536bbe26ca9a66fd549a44dfa39ba95932861505251b88e88d6456389ca1a20fce1e276df23e51276786b60cec00f'
dependency_hashes['virtualenv-20.4.7.tar.gz']='a554fb32cc46cb1cef2a2655bdae598efb52a4e71223eb10d9a36b124390546250aa11cf7da991a41ef4697523ec4562a31e35b5ab7ee8aba748ea4ff28e088b'
dependency_hashes['Werkzeug-2.0.1-py3-none-any.whl']='57b5dfe63feca7ed061d6fb334097f414bbf73fa0f9ac8c32f31b5b05582cf6ffd02dce514ff7855c3ee62071e594ea5f12d3cfc469e58277f61a711b731aa8f'
dependency_hashes['Werkzeug-2.0.1.tar.gz']='6fb1e4fafcc352b47f2600d13db633ee2fcbcd678d453859415f792654de62135c89443ba15341efb7ff10270ae5cbf8d5120608d7dfab347d98af650f4d69f6'
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
    compare_digest e7c6d2b2f18c55bada0d32f4d57565c1e43eda33f12c79327d2fa404ce8062b0c3d14cab449c46e1735d6c4961e81c2f066e0d782ee5e2d16e51fbfb89384085 '' requirements.txt
    compare_digest e23c6a262edb032070ec8c0909394e83a3162306d1e0a79a2b0e4ee2b39b059389250ee38783794871eba210340515fc8be6cb4d9e4f98596ae42f59294c1edd '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 91903d08a440192030dee10d1099a5c612280b5f8c63847a48faf2ddf99dd198271b132a24ce3921a91113946598f17ac0af15d4a41982e4dde5d5857b05b61c '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest c96801213615c13752ec3a5f3436bb749cd3efbf25443a5a634e708fbd5fdec67df646f8db150b3dc2d0aefdf9bf0614e383a54ce0e0aa82f2b554842680ca58 '' LICENSE-3RD-PARTY
    compare_digest 9d8b08c7631d7f7a3bff531b1f5870cda85ed3067627a1a426cc90dd5a87e65429a526194c7e323dd949000818d0e31a5a7664075733700ae1218f9e881bd12f '' relay.py
    compare_digest d0ea4e71a2d6e6da1d9f81f13d6ac565fa76d1b0f8f937dce8bced320898461cec3e0f1e9d9afe294d09a120b45278f898f9ca23a417506ca0aeb6a2b789aa57 '' requirements-dev.txt
    compare_digest 9cd53766176cb7585320928a14f08511de5a6b19f70fd26c841bdd92dbb8d72e859db1f48b89a11692733727b00ce3f50f43c53c0af6c88da172aca406192c87 '' requirements-relay.txt
    compare_digest 1340dd850c5e40a3cef08b6f9d3c61e36f27f118e986f72e8f229ab1f19923a4d9632c7245fc09d4791635d3a023d86000ab8e7079ffa0cca9e6a749bebcc0f5 '' requirements-relay-tails.txt
    compare_digest 977c92a469f31b01c753f7f9e0b8c699774c7f8037dae102dae5139b127c88386e956be00feb7dd762cac153c56536639df05792f14db1cca4e629c3f3fcee80 '' requirements-pre.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 6ec4e2f4422bec2c4dfcb4ec630bfbb332f7a1f6b9d500a26bb7641dd9882f1f7297a0ef2b3f0603d669ec69eed001a5cf1cb1b2e74d5e53a0cefa0fc8ee8c95 '' tfc.py
    compare_digest 62f26d2805570ee70fad3a076579a554008e7d9f2c9ff310f3bb5876d361cc03dbae7ab63b144ac215a35f920ac56d359481352805a356479d622ab00da15f7f '' tfc.yml
    compare_digest 524e2809046cf0d91caa970a6aa7399c86dbf746ab2b5ab1d3002730ee78f02a6e748221511e4fc98f795f19ff8249070ffe11a2eb521dc1f82ede4fad4e4264 '' uninstall.sh

    compare_digest dd2dc76c186e718cd6eb501985f3f8c639d303e44186c5f21ca8e8cf6a25b329c573ca489eda80877be51ccaa6b72b4e763060d0f0f27c0217e8c6b1016d75ca launchers/ terminator-config-local-test
    compare_digest da4f1cc6f9f212f41f68610c196bdaf9a25572cc8f3952b69dc510635e059159f9e9625f6260abaaff2b5f5def01dd4f968e28bfe855a3133299b62030ce28e7 launchers/ TFC-Local-test.desktop
    compare_digest 0a4ca9d76912d27cdea4f36b7334ab561eca2b056eef24ff3b1484cb5dd56c5d79e68145402dbf40c87d4a86340cadeeeadf63a8c3774b89921906a1df603c25 launchers/ tfc-qubes-receiver
    compare_digest a8257a49bc5b9c76ab7a228b69d518e7f7ef338cbf4ebe3df64e99d96d7939130b9005b35c962542e5427ae00c1f2623c06a357614a3122d0a3b161e5d59bb0b launchers/ tfc-qubes-relay
    compare_digest b8a7b0614924e000495c1a4f380c5fd772e85ed93b58b8762c1b1f54381730ef3ec1fd7c7bc0541ef6ce9d857402f2153c8abb9c4b05ee2e57630fcf53ef3c35 launchers/ tfc-qubes-transmitter
    compare_digest 088acc506a037e4e442fad3b0c7a524142a579eda2c5d85456891f8118d64862a17cce4cd4fb7f60370bf3b357db3385da38c6c3b62fba2721ccbd5c27f3fb34 launchers/ TFC-RP.desktop
    compare_digest 062efbab47532d62fddd45e51f7c1797bad711a6924e735af31d73fdcd2aa0a313f66275a1e573dba061f375a0ba8be800753aed8a2d9a1ada51f5892bba6a1a launchers/ TFC-RP-Qubes.desktop
    compare_digest 088acc506a037e4e442fad3b0c7a524142a579eda2c5d85456891f8118d64862a17cce4cd4fb7f60370bf3b357db3385da38c6c3b62fba2721ccbd5c27f3fb34 launchers/ TFC-RP-Tails.desktop
    compare_digest f68f4f4dffa69e03689bcf26d32a3a23ed705890d8d138ba0e1ced0ab71e18e12afcba709955a0677603c33ded512ab36238d448dcd1d705a09e081891947063 launchers/ TFC-RxP.desktop
    compare_digest e0c524559b7a8f6c7adaa58ed53ad5fedcedeaabe2f182c177395e998c47c9dd6b5415687df3c1bb3283fc0426f54108efbc0ca7a325153a25c57c0b5c22b4e3 launchers/ TFC-RxP-Qubes.desktop
    compare_digest 8dfa4d055e0d9d915482edb14932386330da6cb2f7af0ba685c8eed06870ccdbf45150117211107b6e671a13901a11c9d21a767f38dd0e45648ee61b93f55efb launchers/ TFC-TxP.desktop
    compare_digest a41cfd20514fa7d29a6f92cf8cff9be2e092b23c2e8547f27f6651abb1b20e1f042b990d49b9a80164f235e79292333f8706d2070cfd48c66bb1f0560932962c launchers/ TFC-TxP-Qubes.desktop

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
    compare_digest 3e09c6bb28bee40d7ddf67eb4d24ea38ef3ac5c649f92a95a165e9532f3570bf747a8c7cffe09ad55a4cc1b7f9dc6b60204cc5a212afa9fa3f510c65d85a3086 src/common/ misc.py
    compare_digest f23e5b4618a63ea2161707b53131c5ad894fd53d2d3481cc874e02d63eca7043d6010edd601298d38a16e86104acc59fc80d0fe89a9693084709365b188b3c7b src/common/ output.py
    compare_digest 83dce0462374789f04d16d47e05cfb9aa5a9ce1e0bb0e280706d0c6f291a2bf680ffe83481b22b28f89d39345f07065c847135620726b29da7c22b349a3aa06b src/common/ path.py
    compare_digest 39e48b0b55f4f1a48bc558f47b5f7c872583f3f3925fd829de28710024b000fcb03799cb36da3a31806143bc3cbb98e5d357a8d62674c23e1e8bf957aece79f6 src/common/ reed_solomon.py
    compare_digest 0d6550473e4796b84e458a0442673a720ed37eac7d96733d11657153fd9c8db99867a6308955a28381e6b99806a5b857a7b307b9e4a0dd9ac5b45d18cb904531 src/common/ statics.py
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
