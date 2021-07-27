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
dependency_hashes['backports.entry_points_selectable-1.1.0-py2.py3-none-any.whl']='3e1bb8c596b7e8de24eaa4a7360fc691ee2fcd8d106488a988c88ba18fd3d2bd2f4bf05aa88c24e855ffedceb1f0c7c2699556a214d7d7903e91ba5c30e1e8e2'
dependency_hashes['backports.entry_points_selectable-1.1.0.tar.gz']='86c794899cac2f916b36388fd071a619ef27743ac94f0bb058e6157d02481109088ed7891c7775c2f859b92150315acce9052b04ae000363c54af052fbf50ea7'
dependency_hashes['certifi-2021.5.30-py2.py3-none-any.whl']='395c349cef4f8247af20a763a1927fe243e52d7fe846874f100b33e46119e48a3b7b681d3f3e879fe18a07ae81ba791ac7d0ed61017990d722f29d17e2573811'
dependency_hashes['certifi-2021.5.30.tar.gz']='77a5ce25d3ea297160d3dd8e97a582cc79985acf989257755a3693696aeeefbba31b8f9e4b6afca101058a4ef7075fc5fc8780b389800354d7a1de6398612d03'
dependency_hashes['cffi-1.14.6-cp35-cp35m-manylinux1_i686.whl']='c27403338de652c5d81918b36a4eb43b35d06ba43aef89b1caced5a15b0da0923f6fbde5222a53cf0ef1c0d8dc186cc7cc931e654fa23d5d53e34181899aa927'
dependency_hashes['cffi-1.14.6-cp35-cp35m-manylinux1_x86_64.whl']='43e326c346b27a3396b33ba6065867e712e911186d59d60309d1459ad3eb54e26ae9ada4cfa9ca8dc3acfc84d10e8c533851f6aa4b1660cd85134f2342a02ab0'
dependency_hashes['cffi-1.14.6-cp36-cp36m-manylinux1_i686.whl']='e916ee329d6198b7423e9a71aeb10a9073ae53a7bc7f4fd14ab5a083157ce9b786e7da5c8956eb6e2959e120df2094a3c81baa1c5cfeb77cca200ba50c9586d4'
dependency_hashes['cffi-1.14.6-cp36-cp36m-manylinux1_x86_64.whl']='7ec769704bdef49762ccf66a9cef1d3bdeffe803bf1882c663e32c46cd943ef75167957058c77bb98a916dd49ef23b7eb8b749acb5d0d83ce1ad5d9d1e48380e'
dependency_hashes['cffi-1.14.6-cp36-cp36m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='52321d0f776af38a98135dedaf7688a4b4126c582ea26923419eca033997e5f550f77e7dea9c4e28c9838ceef84a81e516c87a96e8c0b8f0ecf1815212e92c64'
dependency_hashes['cffi-1.14.6-cp36-cp36m-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='bc50c4e128b2a8030dcfc77d2a8e853e145705288664b38da6e72c6b93d815d3c52696facc202ba8cf1e40c4ccc548c3efefaf113fc89214125335d2303ac713'
dependency_hashes['cffi-1.14.6-cp36-cp36m-manylinux_2_17_s390x.manylinux2014_s390x.whl']='453f77155cbf96bce7813fd4f1f741c05cce923b5c71a541709e5b78c0fcfc6343881c05485ebc6b22b1f282d8b182247a8cc2b4329bd3663d042aabb4fab0fd'
dependency_hashes['cffi-1.14.6-cp37-cp37m-manylinux1_i686.whl']='dd14f25542e3fe945775ff46a18da5e96c6d038267258850099edf7b605ba4a073e41ee5e9b33c0f405689210502f0e1ea5dcac2d546b41c6efbe241046d3dd1'
dependency_hashes['cffi-1.14.6-cp37-cp37m-manylinux1_x86_64.whl']='4e49312c40a809210f74676a7d0655c4e7d7f4ae122f464df6f85eefb39696b5a22f2f721e5ce890f5873efe14f756110b2baf7e80644c6dd0e7822bc1690969'
dependency_hashes['cffi-1.14.6-cp37-cp37m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='ebdfe0b7970b6261e0aa641121afd3eb79fcff054c588e0adcbf5e27b0abfbc4ac597f0574d5dc7b9f428c653e7696a513ac5ac0927a9f6bbdcf6ba835fbd434'
dependency_hashes['cffi-1.14.6-cp37-cp37m-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='1172f7aa8d26723d745e16631a6c2890dfabc43c02f6e1bc182f192bb532cb3c8a99e9d4da68c2877f2f701fe19c56c0c55c11b7f901cd9038da35479cb21de2'
dependency_hashes['cffi-1.14.6-cp37-cp37m-manylinux_2_17_s390x.manylinux2014_s390x.whl']='68f6ea4ea8e4ae24b7008ccbd901d501f46ef5eac01f60dd70af876eced0df1f15ad53f5991b348293d556aed623b4140a5ee7f396c0899d3a9b002dc1673458'
dependency_hashes['cffi-1.14.6-cp38-cp38-manylinux1_i686.whl']='4cd6cb513e48ef140cf1c8500674dce0153326003ccc524e08532afcf7498eeeaccedd4e10b940722b20a905f2f45119c37b988ab9908069e362fd0c84bc696d'
dependency_hashes['cffi-1.14.6-cp38-cp38-manylinux1_x86_64.whl']='e13a1d95dccbf81c39575288fde146665f3ddf7ff720030aea5d035523d12928e40be2cae88888302f8b9fa9f917957a78e3ffe4a8e79d419c9d7b32d9be36c7'
dependency_hashes['cffi-1.14.6-cp38-cp38-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='f527a667955268add408e1980950c18bf66c6c6f469a043c1e10a2b252d97e25352389bf9cb8d08f38c7f99b25657ba588ccd1f50424017138dff83fe80e61eb'
dependency_hashes['cffi-1.14.6-cp38-cp38-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='20e9bb492598a53067c86c1066b7f8e8e57f40bc028602e246fc6b6614e6f212807e8cb9ad9a69d735779f5d4161973ee6e09c10a30f0d1a9db312167d3941ca'
dependency_hashes['cffi-1.14.6-cp38-cp38-manylinux_2_17_s390x.manylinux2014_s390x.whl']='4f581ceb4432ba28f7769d201cfd2e3ad67a56bd7e9cdac852a4ec9141dc219dcc7248d318f78596d37fdf315fd55b73530b3d5ea15b2ad2c2673e4a64a235ad'
dependency_hashes['cffi-1.14.6-cp39-cp39-manylinux1_i686.whl']='a430ab528742753811c4a77201caa6b11b92d85539cfee49700b864b2358b91b6a816a08eb5e3b14faabbdb852e13c7596d914d8cfa2aa385499a616505c1805'
dependency_hashes['cffi-1.14.6-cp39-cp39-manylinux1_x86_64.whl']='9621df4d564819d6a394adb6b40117243527719ca4c39d23fb47d9bf729fe454d72623fe7db24ac49ab338f251a0cb5177a3adeee811a35bffb84eec5d21b3fb'
dependency_hashes['cffi-1.14.6-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl']='f9037e742fabaed43b5b981008bbe8bccafab348cca2e56ed6fd4c1d184e6554d3344f84eaf7e5c9128b0382f06ebd344caf0ffb644d7e1e0ca1a76928de4040'
dependency_hashes['cffi-1.14.6-cp39-cp39-manylinux_2_17_ppc64le.manylinux2014_ppc64le.whl']='92d0151d627dad187dbea4b4e1d1c86e073944561e95d179b74c428c294c5a329cf10a5a3ed9821a9ba18ac54dbb8dcf714e8662a67903919514c962a273ec23'
dependency_hashes['cffi-1.14.6-cp39-cp39-manylinux_2_17_s390x.manylinux2014_s390x.whl']='9a88988988d858f2ab813befb0219006cebdfe1f26112a700faab2b2a24bffa031f3664dd78c615513a265a2fdd5da0dc8b7658a4b2e4e3317bffb82a91f7145'
dependency_hashes['cffi-1.14.6.tar.gz']='30a8b25b74921a90a1fa96d05de1f25437d0fbbf73b7de0bb9ce22dfcaccbd78376b605525fe970212221d3e598357a9b1da420bfbd1a3e513263ed2b789e813'
dependency_hashes['chardet-4.0.0-py2.py3-none-any.whl']='cc8cdd5e73b4eace0131bbeaf6099e322ba5c2f827f26ad3316c674c60529d77f39f68d9fb83199ab78d16902021ab1ae58d74ab62d770cf95ceb804b9242e90'
dependency_hashes['chardet-4.0.0.tar.gz']='ebd7f420e1094445270db993f6373ffe7370419e002b0bb13299dc6c9b0f7c4e77b0f44f871fba6371e6869e7c86728514367db377e3137487a3acf50cb81e96'
dependency_hashes['charset_normalizer-2.0.3-py3-none-any.whl']='e8aaae2c55507b195bd132986f10b90c6839d5d7f184af1fea1057842058187b5ba2a33d276521974e9bce6bce086bf44db6c555f6ca4e30146c5ea0dab09f7c'
dependency_hashes['charset-normalizer-2.0.3.tar.gz']='daf84526f620f5565d3ad9dbbcf1c6e83af47ae1b267a1e3925ce0c79ddff6c3a0f50663dabd7897882500771ec27fbc1935ff0109c8ca97fbc4049ed9e33b6a'
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
dependency_hashes['idna-3.2-py3-none-any.whl']='10dc4905aec2c6c9cd0abfb4335cc13ef13809d817d0a58da3326cb5e3a8a91321a6225715887aa195f464776a4d5e61fd45b972dfaf67e7c8f874787191cbfb'
dependency_hashes['idna-3.2.tar.gz']='2bc8e37abdc0570e5e13c9064f51630605806c3246a8d292511dad6f971610288212a2d881f9356ecb383f871e1477ccd60c4a5d6d7fd05254ff740d36543f35'
dependency_hashes['importlib_metadata-4.6.1-py3-none-any.whl']='c76ec90905eddddfd93570e353fe31b42c66e7195ebd84af7f8ee74ba78a69922d5bf58d6cbbfd7e4316b20fdf0548286056e3a571cf730a00a01229a909d9cc'
dependency_hashes['importlib_metadata-4.6.1.tar.gz']='2a0bcef3d49de00a1013eac48f1ce020cb89ab895f5e4a1673b46a1ad8f84515148eff33608847331de8ee05d7e10040e128b2c887065d3ca16d0bd338c761c0'
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
dependency_hashes['pip-21.2.1-py3-none-any.whl']='1485ae752e277d5318a3522d70e1374db530ec99d99ba55a2e206beb20e2a3020a41023d78e130abcd73cfe696f3d4b23470809614be6f07347fde9d0f861b8c'
dependency_hashes['pip-21.2.1.tar.gz']='2a02d4c341a37d775070f4ffdce26e7992bbc4b912555a4cc96ca80f47ca72cf09d0ab36765cc96a446019fb9a7f4a01e8d03557a7d90a8c1a09280aa17d70dd'
dependency_hashes['platformdirs-2.1.0-py3-none-any.whl']='dab7b1646428982eb867a56c56d284612e91ef24ae82bd09212ac8cf86e2d42a572af0813c19c3a41c224ee4356d3dc531d2e5a8ab9b47fed999ec27c4664eb4'
dependency_hashes['platformdirs-2.1.0.tar.gz']='88a4feb7cee7d1e5b216ff34af3f29be9358d3e7697a1269732770fa734b1d83f919eff8baafa8e3a6cbf38f80a4903ccc0523288e6b56b3f1b4b0d681ffd004'
dependency_hashes['pycparser-2.20-py2.py3-none-any.whl']='06dc9cefdcde6b97c96d0452a77db42a629c48ee545edd7ab241763e50e3b3c56d21f9fcce4e206817aa1a597763d948a10ccc73572490d739c89eea7fede0a1'
dependency_hashes['pycparser-2.20.tar.gz']='ff0853c9f981b43b4f2e879350715c07b02cf9dab223d4980d8fe0a3138c98041b5f848a9355ae4f1cb45e7f137c03a88843008e18d77af9250e0d9c55f5ca1b'
dependency_hashes['PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl']='bf1bb46d23419cb375bcf620a37b5e9ce925cb0dd55eadf851a4bbb9039c8846ed13ae33966436a96655ea41ad1fc282f9139a958fd55ea10597fd3859635a2f'
dependency_hashes['PyNaCl-1.4.0.tar.gz']='355b974010f94d551f631a2dd5ae792da3d4d0abf8ed70b6decc78aad24a9f965636988aebd14947b137ea14cdcbb73531775f08b1b4d5a9d72b5df3dba0b022'
dependency_hashes['pyserial-3.5-py2.py3-none-any.whl']='29bce14c59e60f54ce476d919c9b9477190ef6bb44a6102f71345840f5c0f1d0a323c4c3c302c5f380bfaae32cf04142ee528b6dd7184f17789632a31d5ecab6'
dependency_hashes['pyserial-3.5.tar.gz']='c8df5e50d952d5a6dcf1d9253a6ba953e9763c545a867da66c22c90dfa015aba0194f2a8f29a229d0a5f4dc8bfeeaaab8bcfda4066ed78a18b151bc05e6ae327'
dependency_hashes['PySocks-1.7.1-py27-none-any.whl']='3e0b1775c14fe091d10e30b03f7f0c770861152e493cf3a3143b0de01aadbc73f684f0d4305f1a694932d4bdcac8056c422437130640e19028cd9fba59ff0b3f'
dependency_hashes['PySocks-1.7.1-py3-none-any.whl']='313b954102231d038d52ab58f41e3642579be29f827135b8dd92c06acb362effcb0a7fd5f35de9273372b92d9fe29f38381ae44f8b41aa90d2564d6dd07ecd12'
dependency_hashes['PySocks-1.7.1.tar.gz']='cef4a5ce8c67fb485644696a23bf68a721db47f3211212de2d4431eaf9ebd26077dd5a06f6dfa7fde2dcb9d7c1ed551facd014e999929cb4d7b504972c464016'
dependency_hashes['requests-2.26.0-py2.py3-none-any.whl']='ab0b245535ed57b6b05699a5e032d6114be081e682ffd4cd0414f861d1b216db5bce640c3996bfce9cbdbca6490c999d5925cfe713c6026adb0d4b035084dc76'
dependency_hashes['requests-2.26.0.tar.gz']='c3397d77f0d2f1afb05661c4b98adad6c1ddaf360906254150b33ab0d9479fd306905bd6d61b8cf8becd9a40bdcf9b03542e8267c644ef19f03f44bfca0bc461'
dependency_hashes['setuptools-57.4.0-py3-none-any.whl']='9bf230f4e0e72acab07ab372a6ca05adb3d175a8079d2f73d327c632f3d27b8ee10442d3e60f4c94a6e61d5ba2212fc78187ca6e1717e15bb570bdce4263fd0b'
dependency_hashes['setuptools-57.4.0.tar.gz']='7fcc297ea3e6310f2ec8ba5bf0d509e3f4acbce6bde7e5f0fe1b022c147cf88a047471bd4aa278724e86ebc6be800015fb935c7a31dbb6a0801a2d380ddd89f2'
dependency_hashes['six-1.16.0-py2.py3-none-any.whl']='656b010ed36d7486c07891c0247c7258faf0d1a68c5fb0a35db9c5b670eb712d5e470b023ffd568d7617e0ae77340820397014790d14fda4d13593fa2bd1c76f'
dependency_hashes['six-1.16.0.tar.gz']='076fe31c8f03b0b52ff44346759c7dc8317da0972403b84dfe5898179f55acdba6c78827e0f8a53ff20afe8b76432c6fe0d655a75c24259d9acbaa4d9e8015c0'
dependency_hashes['stem-1.8.0.tar.gz']='aa2033567b79aef960f8321e4c6cbc28105c59d6513ff49a9f12509d8f97b1a2e8a3b04dc28abb07fad59b0f6ba66443b92bbefa0d08b26038bbaf24f7f2846d'
dependency_hashes['typing_extensions-3.10.0.0-py2-none-any.whl']='c6ee39f76e2f8f10eaeb05b16a3d9bfeba541ec3ca1644a6e72ff5c28d11c98468bba758c0f8c4c10ad2e6ade714bd4de9c15def25f9c62b23ac20eea9724540'
dependency_hashes['typing_extensions-3.10.0.0-py3-none-any.whl']='cfefc92eeab267f030c8834759c2d9a021b70730cae1abd0695cceddd860a3ca1b2aa1dc25f558ee2acf23d9f662503ccb149ad85c8e48f0b66af6fee418077e'
dependency_hashes['typing_extensions-3.10.0.0.tar.gz']='1c262aedb092d506bcd90d033a640fa6e1f9131f95eafb77d30ed21ff7d6b0f492b6092d3523ecb773bc54904679e0fa1aa8c3b4af62d77f1a7e6fe5fd6cb10c'
dependency_hashes['urllib3-1.26.6-py2.py3-none-any.whl']='a51e1d445735abbd264875bc8aaa46a939645419586fab399ce0e7cabd6d166efe79943a300b326d6a1f932609b03b0356bb4687d4a8c6e143757efa87328377'
dependency_hashes['urllib3-1.26.6.tar.gz']='19eb4b88b7a575db717db420ff79b304769d9a6d2b576a236d69719101c4d52d6b0079bd049c885e630f0dfd60471f8bb33836847e0569652cddece910ec2979'
dependency_hashes['virtualenv-20.6.0-py2.py3-none-any.whl']='e8226423cf793c60a6942c99cd6205491cbf3407903062b7c55ff72d65b940d8e6afe1eb7f9c227730b5115375a4f0aafa61d2a268669b0ad77013b3670c5e21'
dependency_hashes['virtualenv-20.6.0.tar.gz']='7eff570f407a4986336d5a34bdcab1621d953aa6900d41962a85a5a44d7b68d378cda4a1bc1ddbfbc468580e051a98c37be17b0a52babbb00166718a987a591c'
dependency_hashes['Werkzeug-2.0.1-py3-none-any.whl']='57b5dfe63feca7ed061d6fb334097f414bbf73fa0f9ac8c32f31b5b05582cf6ffd02dce514ff7855c3ee62071e594ea5f12d3cfc469e58277f61a711b731aa8f'
dependency_hashes['Werkzeug-2.0.1.tar.gz']='6fb1e4fafcc352b47f2600d13db633ee2fcbcd678d453859415f792654de62135c89443ba15341efb7ff10270ae5cbf8d5120608d7dfab347d98af650f4d69f6'
dependency_hashes['zipp-3.5.0-py3-none-any.whl']='2ecd0a9966ae5e0ebc2bf98dde4c2d6cb4eb8f466b4480b37f727f74ee8ea65da5b6b626a0e5adcb38fe55d4d02bcd420fd7752560e696cd917f3514d40ef5fd'
dependency_hashes['zipp-3.5.0.tar.gz']='676d7e9a7fde386b57a213975121aba015461453f0809a97d39d030b06918a4c54ba1cad21877ddf007560941ae285883098d81d5e6f17eb4636379345b4513d'


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
    compare_digest 36292518306915bf8256fd492682fd22f199525423db73d27cf60abe0df1552e4935e3da27aa2d62bf8da2d1342eaf86b18f3ed3ddc661667bf4786a4c7043f9 '' requirements.txt
    compare_digest 354db46b2296945d502415ae556580240dfb3a0f0c1c02227807f7ea3de4be20580e9f7574afa69a1d280498d82b5395106eb9871a10d086296247fc11e534f9 '' requirements-venv.txt
}


function verify_files {
    # Verify the authenticity of the rest of the TFC files.
    compare_digest 91903d08a440192030dee10d1099a5c612280b5f8c63847a48faf2ddf99dd198271b132a24ce3921a91113946598f17ac0af15d4a41982e4dde5d5857b05b61c '' dd.py
    compare_digest d361e5e8201481c6346ee6a886592c51265112be550d5224f1a7a6e116255c2f1ab8788df579d9b8372ed7bfd19bac4b6e70e00b472642966ab5b319b99a2686 '' LICENSE
    compare_digest c96801213615c13752ec3a5f3436bb749cd3efbf25443a5a634e708fbd5fdec67df646f8db150b3dc2d0aefdf9bf0614e383a54ce0e0aa82f2b554842680ca58 '' LICENSE-3RD-PARTY
    compare_digest 9d8b08c7631d7f7a3bff531b1f5870cda85ed3067627a1a426cc90dd5a87e65429a526194c7e323dd949000818d0e31a5a7664075733700ae1218f9e881bd12f '' relay.py
    compare_digest 14a8584718540961cc7a06098f16e63964361a31d8e69db6a638751bc098f17109df9143bb5262fade39937388b1ab16742894bfee32814a03dedce678f69b68 '' requirements-dev.txt
    compare_digest 96f0493dec9a4e10aab36d9083a9ee890da680be27ff99918658bc6f6cb6e489a2cce08c769a4bf70bbda20b51653808279509c4f613f7e17de8c0e88cf7fb07 '' requirements-relay.txt
    compare_digest ea1dce6e28e3426fcf66c8de506934485ff2835ff1139d5f58e6ad3b1413a888c588e9aba6a0457004e9ff7b47cad9c7dab4e5f7b6ff832af34c510146051408 '' requirements-relay-tails.txt
    compare_digest 0704e4a655c0bb270d31edf877d209408959a0d7a457790dfee528e5b35eb505199896edc34d06f1622deaf4db2c367804c56a4cf23a6a7923c06fc2a9123876 '' requirements-pre.txt
    compare_digest 79f8272a2ab122a48c60630c965cd9d000dcafabf5ee9d69b1c33c58ec321feb17e4654dbbbf783cc8868ccdfe2777d60c6c3fc9ef16f8264d9fcf43724e83c2 '' tfc.png
    compare_digest 6ec4e2f4422bec2c4dfcb4ec630bfbb332f7a1f6b9d500a26bb7641dd9882f1f7297a0ef2b3f0603d669ec69eed001a5cf1cb1b2e74d5e53a0cefa0fc8ee8c95 '' tfc.py
    compare_digest 62f26d2805570ee70fad3a076579a554008e7d9f2c9ff310f3bb5876d361cc03dbae7ab63b144ac215a35f920ac56d359481352805a356479d622ab00da15f7f '' tfc.yml
    compare_digest 524e2809046cf0d91caa970a6aa7399c86dbf746ab2b5ab1d3002730ee78f02a6e748221511e4fc98f795f19ff8249070ffe11a2eb521dc1f82ede4fad4e4264 '' uninstall.sh

    compare_digest dd2dc76c186e718cd6eb501985f3f8c639d303e44186c5f21ca8e8cf6a25b329c573ca489eda80877be51ccaa6b72b4e763060d0f0f27c0217e8c6b1016d75ca launchers/ terminator-config-local-test
    compare_digest 7685930aef519ea76b093873909596402875bef64b9f1f18d72d77a5089791734080f52b3c25650dda9335b17360d62ce76ad3751ee8cdee50329af23afe75ec launchers/ TFC-Local-test.desktop
    compare_digest 0a4ca9d76912d27cdea4f36b7334ab561eca2b056eef24ff3b1484cb5dd56c5d79e68145402dbf40c87d4a86340cadeeeadf63a8c3774b89921906a1df603c25 launchers/ tfc-qubes-receiver
    compare_digest a8257a49bc5b9c76ab7a228b69d518e7f7ef338cbf4ebe3df64e99d96d7939130b9005b35c962542e5427ae00c1f2623c06a357614a3122d0a3b161e5d59bb0b launchers/ tfc-qubes-relay
    compare_digest b8a7b0614924e000495c1a4f380c5fd772e85ed93b58b8762c1b1f54381730ef3ec1fd7c7bc0541ef6ce9d857402f2153c8abb9c4b05ee2e57630fcf53ef3c35 launchers/ tfc-qubes-transmitter
    compare_digest 2042803172de9e8f9dfac313ea31de0c6dbe66364f94d8d5458f084efcefc3eb762f7f8cb395b5c5b4dcb39c38d37822185aeaeb91bb8d51e3cdf66252bed305 launchers/ TFC-RP.desktop
    compare_digest 54a9be69c6859b392d51ff5e33f164c41d38d0d06a20697d700f44ddc470d58e4c0d6db23463ca4ad2f3fa47ad7883cb25c8dc4e0350199628d58d5a4de42fc1 launchers/ TFC-RP-Qubes.desktop
    compare_digest 2042803172de9e8f9dfac313ea31de0c6dbe66364f94d8d5458f084efcefc3eb762f7f8cb395b5c5b4dcb39c38d37822185aeaeb91bb8d51e3cdf66252bed305 launchers/ TFC-RP-Tails.desktop
    compare_digest 05489c644799e13632bb79ab0085634ccd36c2d8620b1703ec73990fed753d6df82301e66dd71f59f57795eea6048dc60aaa994d6f7247411c81d575334dd6ce launchers/ TFC-RxP.desktop
    compare_digest 703e94113c7b9c32f767e9546e902e21737707031254a841ab8e71e050383a4bad6c0ec4f46cd28794988a83443873fb6e0e54fab0693e34020be9b2d77cb400 launchers/ TFC-RxP-Qubes.desktop
    compare_digest 0fc83bde92615f2c4b8c542e47b3d01ae96ea5e6aaa0fa5b44ae51d9bff46573b9bc01641d0eb238177e65bcd41dc95416d22a32cd9f8894bac5482869fa1a3d launchers/ TFC-TxP.desktop
    compare_digest cb4cf7f307d0e4b781edf39cb03a3108200ed957b00b7331e01f25eadb253634cb431cfac18e35aa2ddb82a4727801eb81072c0000fdcb6102c74a92ccc52921 launchers/ TFC-TxP-Qubes.desktop

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
    compare_digest 43b2728180899f1e14ce384a1c1f397a77a721819bf3ef144aa97fb39968e16820e8d82200d7f52ab2827f613a482af99f56d234561953efb1803aba91812315 src/common/ statics.py
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
    echo    "  tcb      Install Transmitter/Receiver Program (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.2)"
    echo    "  relay    Install Relay Program                (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.2 / Tails 4.20+)"
    echo -e "  local    Install insecure local testing mode  (Debian 10 / PureOS 9.0+ / *buntu 20.04+ / LMDE 4 / Mint 20.2)\n"
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


function test_installer {
    # Test that the installer's hashes match the files.
    # Note: This function is only used as part of the release pipeline.
    INSTALL_DIR='.'
    verify_tcb_requirements_files
    verify_files
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
    test   ) test_installer;;
    *      ) arg_error;;
esac
