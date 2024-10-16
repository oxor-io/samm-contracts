// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {SAMM, ISAMM} from "../../src/SAMM.sol";
import {SafeProxyFactory} from "../../src/Safe/proxy/SafeProxyFactory.sol";

import {ISafe} from "../../src/Safe/interfaces/ISafe.sol";
import {IMinimalSafeModuleManager} from "../../src/Safe/interfaces/IMinimalSafeModuleManager.sol";
import {ArrHelper} from "../helpers/ArrHelper.sol";

contract Setup is Test {
    //////////////////////
    //    Constants     //
    //////////////////////

    // Safe in mainnet
    address internal constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    SafeProxyFactory internal constant SAFE_PROXY_FACTORY = SafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);

    // Helpers for tests
    uint256 internal constant DEFAULT_ROOT =
        13478250241025044241834632636828135155416924205892387731890373634766567630611; // From 10 default anvil accounts

    uint64 internal constant DEFAULT_THRESHOLD = 1;
    bytes internal constant DEFAULT_CALLDATA = abi.encodeWithSignature("getThreshold()");
    uint256 internal constant DEFAULT_SALT = uint256(keccak256(abi.encode(777)));
    bytes32 internal constant DEFAULT_TX_HASH = 0x09b086d54be973c0cae8f289b9a308969c3a0d336ba3000651cffcde84ce5fb3;

    //////////////////////
    // State Variables  //
    //////////////////////

    // Safe
    ISafe internal safe;

    // SAM
    SAMM internal sam;
    SAMM internal samSingleton;
    SafeProxyFactory internal samProxyFactory;

    //////////////////////
    //    Modifiers     //
    //////////////////////

    modifier fork(string memory env_var) {
        string memory RPC_URL = vm.envString(env_var);
        vm.createSelectFork(RPC_URL);
        _;
    }

    modifier enableModuleForSafe(ISafe safeContract, SAMM module) {
        enableModule(address(safeContract), address(module));
        _;
    }

    //////////////////////
    //  Help functions  //
    //////////////////////

    function setUp() public virtual fork("MAINNET_RPC") {
        safe = createMinimalSafeWallet(ArrHelper._arr(address(this)), DEFAULT_THRESHOLD, DEFAULT_SALT);

        // Create SAM module
        samSingleton = new SAMM();
        samProxyFactory = new SafeProxyFactory();

        bytes memory initializeDataSAM =
            abi.encodeCall(SAMM.setup, (address(safe), DEFAULT_ROOT, DEFAULT_THRESHOLD));

        sam = createSAM(initializeDataSAM, DEFAULT_SALT);
    }

    function createSAM(bytes memory initData, uint256 salt) internal returns (SAMM newSAM) {
        return SAMM(
            address(samProxyFactory.createChainSpecificProxyWithNonce(address(samSingleton), initData, salt))
        );
    }

    // Create Safe wallet with minimal settings
    function createMinimalSafeWallet(address[] memory owners, uint64 threshold, uint256 salt)
        internal
        returns (ISafe newSafeWallet)
    {
        address optionalDelegateCallTo = address(0);
        bytes memory optionalDelegateCallData = "";

        address fallbackHandler = address(0);
        address paymentToken = address(0);
        uint256 payment = 0;
        address payable paymentReceiver = payable(address(0));

        bytes memory initializeDataSafe = abi.encodeCall(
            ISafe.setup,
            (
                owners,
                threshold,
                optionalDelegateCallTo,
                optionalDelegateCallData,
                fallbackHandler,
                paymentToken,
                payment,
                paymentReceiver
            )
        );

        return ISafe(
            address(SAFE_PROXY_FACTORY.createChainSpecificProxyWithNonce(SAFE_SINGLETON, initializeDataSafe, salt))
        );
    }

    error TestRevert_moduleNotEnabled();

    function enableModule(address safeContract, address module) internal {
        bytes memory cd = abi.encodeCall(IMinimalSafeModuleManager.enableModule, (module));
        sendTxToSafe(safeContract, address(this), safeContract, 0, cd, IMinimalSafeModuleManager.Operation.Call, 1e5);

        if (!ISafe(safeContract).isModuleEnabled(module)) {
            revert TestRevert_moduleNotEnabled();
        }
    }

    function sendTxToSafe(
        address safeContract,
        address sender,
        address to,
        uint256 value,
        bytes memory data,
        IMinimalSafeModuleManager.Operation operation,
        uint256 gasForExec
    ) internal returns (bool success) {
        bytes memory sig = encodeSenderSignature(sender);

        vm.prank(sender);
        return ISafe(safeContract).execTransaction{value: value}(
            to, value, data, operation, gasForExec, block.basefee, tx.gasprice, address(0), payable(address(this)), sig
        );
    }

    function encodeSenderSignature(address signer) internal pure returns (bytes memory) {
        bytes memory sig = new bytes(96);

        assembly {
            mstore(add(sig, 0x20), signer) // encode address of approver into r
            mstore(add(sig, 0x60), shl(248, 1)) // v, indicate that it is a approved hash
        }

        return sig;
    }

    // Since after each contract change, its bytecode changes, and thus previous proofs become invalid.
    // In order not to change the proofs in each test, we will make a default proof.
    function defaultCorrectProof() internal pure returns (ISAMM.Proof memory proof) {
        // Proof:
        // Tree constructed from all Anvil addresses
        // From: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (0 Anvil address)
        // Calldata: 0xe75235b8 (getThreshold())
        // Call type: Call
        // Nonce: 0
        // ChainId: 1 (ETH)
        return ISAMM.Proof({
            proof: bytes(hex"00000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000071000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000062a1c0a8fc299869c34bc785fba041d878000000000000000000000000000000000000d6e371325118c5606ceb1821240e000000000000000000000000000000486cc87dde007ccb4a88ea34a495afe97f00000000000000000000000000000000000edb4d470cb12dc125710b82ba4594000000000000000000000000000000d9d35acc05ab827406a91526c2cfed97590000000000000000000000000000000000117ac5225ace8ad73dbb021fdc89020000000000000000000000000000002c2bc8f24a735fd3a178e515b060264048000000000000000000000000000000000016e17a2f928ca68557b9f0f5aa847b000000000000000000000000000000b10921a9773f5b2182efc5f67bfc263166000000000000000000000000000000000029152f76f9bb031096f3cf76ed577f000000000000000000000000000000a2bb96b6371c412ae1d917592ae851396f00000000000000000000000000000000001d0c8e6c9af71d5cc333c6649c6e67000000000000000000000000000000dddd83ea17e357350aa28429bdd43a74a50000000000000000000000000000000000283babcb62b3a3da7df63685bedf58000000000000000000000000000000429724cdc7f790b4a23bf4f9bca0975fe20000000000000000000000000000000000098099a033ae8451211b46275f94870000000000000000000000000000009baa58f79159e8a9366c8169d8ac4b878800000000000000000000000000000000000393876520af22df1e71b8f3f8bcdb0000000000000000000000000000008ebe1ce1bff4a58dced19907e785b23d7400000000000000000000000000000000000ef8ed2967e2b0c7284934aac34fe70000000000000000000000000000006a031b85fd875d6c939baf86f69264896300000000000000000000000000000000000b4b3dd88a706381e9af59ecc512b00000000000000000000000000000004646c5e528d9dd48dd8631aa7e0752a3c6000000000000000000000000000000000029587d38d1025b1bd596187bef6e3c00000000000000000000000000000057a5b19ce31263c15fa47b7540679fe0c300000000000000000000000000000000002a0e772e058352d33e83d2d2845f410000000000000000000000000000007e05f73d0bb723af03859d2e46fc33ccca00000000000000000000000000000000000f090c4f25da2a807147a17cb6d75d00000000000000000000000000000048cc3a930926c40196821e13caaaa3881a0000000000000000000000000000000000295b9dda5fbbd88aba01e8918dccc5000000000000000000000000000000bfd97ec82688e111f5046c4c3a4e5a56300000000000000000000000000000000000291356cbb0c647d00a290ce315ed150a96eb86b636e6612de5d755bedd6af4c8d6230ad2136881830269c77ce49aae25cd62ec2afab9c88a6a6e60c2a3ed685f5dc53da7a6080fc0df8bcc731b6553018a74ee6844d2e55c8ced653efbc39dfd86956fa6e93b604d0c1cccd1590b8c2d6c6e584cb3f81c8cde141962441656e302a886c34501ef87e96337f7200ea7285f98aa429a82939cd638776c54696aea753763d2a3a03cb8aaa73240f7eb391512d7d635bc0e4c71864615533bd68d574b9f1c0a1c18b217a8c25419dd76c70f1bdd010791a2ffed660b393b9ed1d17526f8a47c704ba9b8769e4b9887b2db2031f33be26e19bf777ce74a3e89f46175fcce127c817088b0205e7e9fb2762215d0343c99b258ca16def1a048ddd11e4f2be6b8a1b4764f32b227eff39ce70318b4ed5907b699b23b6af1dd86805236607eb2e482e7667f26062cc7a46d7a620a7d9db5abcbba91834718eeb83f9476337c70714d223e44d32339a82718b252273e17416659605bc2fb7093401580c65ea0c38580ee716944f73484dd8d61c51762ce8f383780519fb76e8d94dbc2d0b514fdf28e30a7426ce7089dcd33e32814ca125e7da279d40cad737d2de783e269e2766834f6495ef9abb36aa2027e140d69e4cc0c09b7db9192b7b5886a849ad2a77058e4f9609e8fa83d457530e160243c45f84b362cab803df021a74ff02d129eb4d3c897bf910e6146a06a700d75140d5b2262aa1eef5e2ec0e95bf045ebefbb870ecca5cd12b7130504f9d2b20b0c8918a44f7245bd5f9834aa5c3e50d3ead8453638eca87ad77b4ec811144f082502afb30cfe323750356d92e5eb2f9ce17916b3a5c4bb3fdcfed1d852da9bc62907a53e76cc0a62c6fa200aa921a838ea2760a32f5d632faff37b2e3ee520e72d55d48ad1ea084040958fcde7698a7297211fb95ac0386d4a105c3ce27f2f7d2330604bbbfea567483ea0ebd4d52c0562b07fabac0af43e899cd35e29ebc75e0e35b24abdff56309467c22df79b9a90197e0d55a7cc90d843c0b0fc31e740312a86d3dbc08365e82c48ff54720bd5a1321ea0b40f6a04e7f7dc2681821563c01ee15da2e0cdf1080d98529b2deecc26a62a9a28860a0e4dbc08731af4ae774e1bb55522b19436b97326fee718c88aab07904ebb714daeece99366ec58bcce1a02d24680989cb161136e3653897413136cef7f462ae1ced19d08307c6d61bf090b0812669b01cc18d1d3638610660653e00f68c57470e99ce6e5814a8ca833320fac96e6ae4d1d1deedf106985b87a116cabe8c931559121b0230f2dfae3b34b038f2c4a200542bbd8d311aa080d76e98f74efed11d754bf1ef5fac248ba6b6d27cab87645eabf535ed6a54c5b3385ebd0ff6aecbdbafc43dae029e20d89b0c712bb71b0cf5c7536bcc903ceaab2a8d1ae067368e27155d125358e8695de8c251d0efe5671fbef9699193e6d86a905d1883011924040cdb60542f25facd43daf1d7dcba791560d5f6133a12c0e17e25d7c6365a53085b719ee4e40b49428c9392889bbf4fed1bd99fa08e51837e40ca2891db0a9877ac5adf5987de192c11c4618bf987e8b09a107a9967ef4f033ebd5d4cb3a1c9bd9a069c4f2f6984cb87dad2cb80681f5faca664f956e185c467f3d7d27fed0a7c9245511558a627496bfa416b2e719995cc94db40ce66855d42f31f8c35e1bd05b08e8ad5213a3d7d7903b1fac2cdfcff30c6fc0f22797d4d886786d531f55b2568e578a73d258cc25301c06370fe9e30930983cef21360276cb9c200c49c9dd5a88b909beb1262e395fb517a87a27e1ddead494fd4bae56f819f934e7f04194e2917f034dc83079ddb4e604129eb87ef878bb484f60278f6add44c2209537b90ad3afd9f2558007bb0b960c78d088957984649bb8fd797dfa321a1c53b2056c4919b01888cee7bdfb7d0002699a3dbefd0efecb95850f7fd094e9a0ce7716e4df633101a76a738725bc5823a208be05ac882085851f098077b9fe08928234d95ee107cd47d77ddfeb6cba1c8889d0ba52009f3e1cfd9a0e0ee97bae8a82f365a203906badc4b6dcda6ca90a36e97d30bd832d8701501619bfb6f52ebf60343895a223ec98f1fec073b0511367f41f78e06dcf5c3322e3d03036ce1ade0d2ed4aed6ae8f5d8dcab644cf53133d7f21fff367a98633ffb5781cedb2859f3ea2408a3e6c90f6fe952d2873571add5ea31b946b5300c3507ef21562bc03526a145851670d77d5b84408aba3ff1848d69806c593b5d14e942469b21e8ede4f1c04392e0b76d3070afb206c478d1404be893d03ff72af0e89edb4cf32da1fea1d714c274001314f8004c1466e941856a8b435b12dc7c3b0ef15bddce2f8e87e4fb3a5a56a67b399a30eb37cf6eb041a6b378af1221cfcde6f5f5db29d2f8cedb23442b671db1f246bd473ed21a72e93ab093e9ed27bf2a0af7d646dd52c345de36eb363d2c089138c2897cbe3c31474e35598c5642ee477443d8d5f556211288be18cc53ca4403d74e2392cb34a2fb743e62d55f77613f7816d6bf83eb0011278085a8c05b7bd59cc72f5f3e6941dacce8705fbad967fee96189036eb288a6cea85289f995ce96d5fd078efc7c005642d39cf3e41c6daae39cafb715df4532b61f2a27845d638c82a6c11a21cb610b592b37bc77522e2d9a89a8990286575c0e469b91649440c9c6100ae9237e32d35e19cd40d6d58e14774567d583b00f53d45114138c67373cf5cc30640b59a04403360e4e9ac8304bfdd5e5ebc32a2344230e951844ae0de6713efcde5b300021e4988c1c0d1d1153e52bef045f18afa96ed332ec6de35058a1190aaa7999c208498e5020d58214b583ae6b3a1e36484aaa6004db9046b07fb142a47050b0f0e76198eeaa62f562902ee9426b94a70d46ef3b07e5dfe73d3815d47e2cdd51425b8f9252099b98d963556cd28028aa5e1544ea60e0ef7482efbd0cda6e16e1f0edbe9d96cc5ea267ef5882d849e0e72ed9e5c222e463f7a8ab9a8d96a747a660fc66a7dfd1fd6bb380eada0f554f0996f0a4aa24e233be396397da1facee8661dbbf50f0961bf9f1ef74d454f27f267f9bcf216bfbe51cbf94cb08d8610e06a189946e391a65e57fbe224fd958ae4274330568b27d0080ecf4cc733e5b322a01f42401be584a76ce6d2b97c2fd9eea4ce70dd343e40a8dc0e1aa4818e34d98a0f3e5ac8ed4fd9e71f3f4463d3e2058e7c76a17075ae21273f3076bba9d077ce1b59afaa28761e89f9f7b3dd36b5987a4c8f88960e8ff163a2bd7e9df1115adf27676e227286718d4f66af67099c74af6ac5f1e57776186d6a0522d613e2f18809855de7b6e901151a39ddc6de59ccef58ce6e6b514421a5740e03920874101d0664981eef14ad4d34a506523429c5d95c3a4cb747b069bf3cf56cc9906e630328b59cf856c912bcd20ea108ce0762ac31486f885736d36446deb96c87bb06e517e731f844689a819805be891d27e2f81372ed0560229300223b187c850bb813240ff396f3088e0fcdbb4b7b8aa2a387f125838bd2c36a32da3c2358bc2ff14d19ee85a2795d1a7d48e9930608dc2393d0a46ae67529402d748402632e6eb8a124237631ed9bd086597e5bae482c62975f8ef2586d795e83bac15be8e8f127c8007f961ef7a27accc6fa974f98eec49e163089bcfa05dcc08234d7c56470588b195eb84e6c0c17c986d37b8507e9ecb212e41dca3af808181d660c283908d87e26b2427a19126ec537db89c593b778e2827089f4203cd0e27a4b33d8291bbc6b0ce51eab3f018989388bb2e1a50ace05fb434f50532343bd231e9ec338d5bb9c25478c853fa8da093196de756fba146170d1ba6909ba9f6e35aa10f78f469b9d2b7d5cddf97bb90d59057eb473040b9949c2151e5aff9853247470b52bd41e0d2857321a462fcf0c2df296cb7d0b63c8127c3065ee7fc30254b2fa252e72434c111388ec9b385ecc15d2d4f053a577a538dd2121495889db4bd3cc336c4d64d50f5259527a057f4ed485aa49939d615f9e61f6657a52c151b64879bec1aedbe527759ce5116cd0abe2c1686c98b8bead7430ec6820f5cd50ab3fc58dca3947692306db58237007aee74eeb1973af57086bd8ce5027b6065f06825d5fcd3bae700dc2819ca0813b0b9f02c71d641a36288748a3844e0b3d1a1225da4c6a2f58cb2d3d3c27c73c10f9e1855e55817684c132643c2ffe6703cfa5a89aa8cdb8e1332ea4fabfcc57ab5ecd895f219e0fd4ce82bf2f0bbfd7dc6c827ccc65747c46b81b38a1ab346ee15ec3465a18eb64db7b02917378e9d8a8e21faa3b43f15e8938148901a9702857216590458d7b8ff13589b9ed02d1a8f67f23f8079228dd44991059399a34ffcc9b9fba37961dae78bc7225f5ce4ad62002c46113f8f02e5cd60f5f1c409834fae2a99347f64e35207c9147e4ee5063cbe0b29b5a858af71bcc048633998b6034b0af015567cbf147f172d73f9719d4ee33e68d09613cb141ec0cadac0ed15cfbf9dd468d4838aa8acc0dbd4f1fa4e95bc1d0d34a506507ae0b1b268e81ccefa73afbf961250ba00ffbc135ac2efa323d9dc181a04c43bf19931b9c251d018ba5965feff342a48244e56dd34f83104ef6d0f598d1d59d749dd00558eb48320d9386402291753fb05e6a1b1892a71372195331ead2d87780a44406e7da8d478d38ec2fe5c1dc2c3b2c11f875182cb677180e4a815ef233a9a29d2df3ae42769c4d1478bf7cfa0bd9367b9036762cf218280bf70612eb779563141929146b55f580c4e7639873f5c381d697e049c68bd47b6792431b8d3830f71702154e0fe0f412d4ba5ea1978f3ce73045ebeb02bffc9e94b9a62ce3ba82415f24bcbf54930570a8e40bd950be103df8edc48744b9a1073c81ca415f54eec4bc2d2cefc9fd80f8e708078aa2ae3695189fb446b2ea0447e36b012f272ef1110f2705c9bcbf270815d3293015b2874df6785356967dbe8d7150738bac5122b93a2216d3701b5ea51c17bb9aef3d74963b2201511bf81b1d98f2af36ee224d50dd231982ce361f7b36f35a64238d5a9cf7b9f61fa50dbee0c4f2305b198c7a21c1120572b62df3f15dec9da771940016e3f7081d5578fbec12c9c04773d2bf325923d7a9977af710cb3e1dc4b32fd7bfbad116c513e1d48766e1a51e8e125c798c01289b6b933f924d411833d4b51c61870110ae03ddb94acfa84e87c5f68a945f04481fb2a94837d3f30b6f7ee8537013199b9241957bdc7a2fab476bf3b3142e1247bd4e259014876110fc03932cf08c6a521fe71bfebaf65205bfcf6a65b7962b78092019f29a55581714bfc58c6c9e42f40463b479c1314c751cc9aea686c324928e3aa9a763bb063d96c318fa4b994b6a99a59cb06e125aa287eb613497940c93e04190724ebe7b612a27bcf8c47869842af97860e6ded2d7c91beb2d88d12b05673da45cbbdbbf20eb0a376d8508d7f8047212d3c0f27444503a8f174d221ea1ee4d0f3aa1d1c3fc028d2daec7d8092aebb2e3955dc1f74c2a6cdbda899e2da03f3a9e42dd8e1486c1710670903565077e399327e4e9600446fa3de33c1119063306c4d2800bb7a5519865962337efb60003c9ce4b42eb91301cd0b158b92e3454b528a9a879599fd3093ebff31ca60384afd1b370ccfbe94eeff194024c303aee20e3e0c6301a4dc7ca04c09d9da0291aa094b51822d52aba1b55e33e731cf3e296252dc8827dda2acd09aed8a9824b5ec4b61577912622b1e3e311932e0943a427ce92ceb7179ae14303fbdf7e701a409f5659aaec94578dfa962835da0470c4f671df521a69af23ec784b4e677180888c3beecb147bb65feaf6eea7d50084cf549efec6f2bb9dab9f60566f68e40835f9a2a145d5ee9acbff7a06a70b2f1f9f23ae21427f367a1e56f5613140908375a6741863171adc1d9dc12772292eb6a7307e41329cafd65ad850c19ad68f0f62952f7d78783a8de5100b83f14c207f08c0c30b3cc702a8894a39b84246b087bb6c159204416da643b8d8027afd1feedf0b63a20eb1253a0841933336c1b53b7e8b36bd4aa7bec8b7321d7ebee7157556f5de92c3084b5ef07a92b2a22e28ac70eda00c3dc0844beae35d7e04332d8bcdeaad4a2f1c6dc9bce3b138eff1179e4b4075e488192c612907c4e876f300b52209646fb810303511646c60ad096a11fa39a49bebdbd950abd0edf04c3e06f2ee86558ec3eea1b8a0946cfeffc918466643499acf75a6996e1bd27262692e0faf85e3347de7518829004a08f5a3bb15ebf3001e852caa8d6bd2148144961d3ab1e11323e8ff479ac85a5998d89fd40c27773e542f67b4b9e0b1531e805719f6eea42f4877ea1a9102b82f0a7d9432b971331d4e21181274f9b1241e4d5c00f370fe0512a3e44d228a29995983a3c72fd6e2bf29bbb5286a86d464a4c4871e0f49cc66d776c6171d97c202790c1db17d59a1abce48c45e579c79925ae95a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001365680efd2897b4d957f21643c60c55c9b33761d91984d1d3a7e9f4a261d0a609560df7ace085549be6765527560e977376afeee4ba1cca84c320efe2f22b282b6fc632811cc2cd9e3b4b9883eb1297a21f1814633a47fe43083f5eb84ff2731608c59cea01de0a94254dbc8f563643e8b26b9759b7ac742d56ebf426d5acfa153d10285b48b4acde5e6a8e2881c77a2f16bb4956986dcc81a6e36cdc344a2a1802bd22a7153acc6740fca31087abdc674c8c3945cf234590d8cf8e8a6934dc00b3311fc34d648504f92763bb22236f6f077b3d4d6cc23f17ba31050d2a753b034c2d933e07b74b64966f6d5fc47d93c7d6789fff2abff9d79ee5c356684f791ab22926dbb5540ed2103793e3a1036c3408cee989d979cf5d06e1b1f7a3671d08eff0b5e58f275e03f303936ebeaa212858c2790e6ed3fec57765f6757309060eba5ca0814edeabe2c145c9d29940f3173d310fd2e991676be4b4a85d9e073d0617868ba5eb4e2d2412812d223b1bc48af020541c0a711d5f8457292565dc140624e9b8b9f70b8a90a620b81934bcb955fc7645e95128baa42b2366bc922f821061c6d15f56b20185ee8c58b533ec40b3c0beab29ad5c5e96176b14fa268d681c3885fba19b0d13cae1035620505f451ebb5583df3060ec68755fa095fe32f40777820e8e7d43e7507350c66361756831c549b484ae3848fe4de409d3ab455930570bdb90e243d209d41038ad26875fa8db45ecbfb23252a1783b20c03dee7e2c98e6ee128a022c65117647c3798e088826e653b88f6615d1d8c01dea74fe221c2fbdcd00320df170299b9a0a238ec49a35bbbc8b6eeccec4990817e0f07d01274e82ea35ca1975dbe68f4a40bd741e1cc6dc2a735762084cc605af33d0b216011e2733bd6771684ce3e38144b8d067289635b029918fded55c4d2fde7aa51a201c8c258da257e55ffe21814c85a17c39e9645e7a86797049c982d74c0c8a5309920e9e7851efaeef179cb70db9302ffafc475b6ec46fbf002a792f64a2fa7e2ec75263fef65ea601f5a8c59d537ba436e03266834e945ce63f82aadbfb35d90754bbfac126ff4a5214d45143dc30d1fa7f06b40e8c1795c64bde4d63a6bde1226fc4c472b24e5cbc45c8fb78647461b692ab80d47b0e4d3133e75a92c528900d9510963a800e9f50e09bbdd9f69de8423983cb7538e7e7db6e80ce236b943d24f00d55a440062cecc9b628914657f544a31827e5bc9f7b3641bb784960bbec20d156bfd683eda76d7cdd3d6a7c31f7d44c3b428dc19f6e5b6c109b17d7c82e1e1874294622cff4fc7cfed385f50b00e8daf469472944f76555468ba49e958518b4d7f5dee0c5bf16d07dec5ba3f6e08867b5fdb00028799ef2b8a32b8b28b818d17451ea8401f38cd28f709704e3f24e8e76b0450975b0c955e1a1bf990492160ab076a198654c1f8fa394529a9c961d58600ad5b9ee27b2ebd10d4cadea852bf458d727a14e7e442bee89d23b196d084458ae16cfb49215d54072fa604e2d0a88decb18794715ee3c6c169458f241b7f2543603a050ae33fe469a0d69d7a41a9f718eab15dc900f4d0c47540908fb5837c9c84b376076213cc9faace7ffbd27d5daf1320d9d02c65cd6631f9d9aae0e9d47e7c81d66edc96c70dd9211b9c32c3059cf668a4556210ceacab6a0776671692e1a992c116bb76b3dc7281bb3e017dccefe383c95ebc98da35d815ff68b88da0d185b1f1cd6816ebe91f15e7476144c4749f92167ee8f0b2e2c259b7484cd24a61f0c42419e99301681ad2532bd13a634688737509c5e5149c8e81da5dc8f5df9dbf8e0c5590beb6f29241d5f3411bfa60535fa112d015a663fccf27b5412894a6542033d389a9b6905a72e90bc164d4692dbdc7feba57b1bc3d7f88dfc07f1fb84074b06e614e47d3100b971b12e16872e5ea0efadd84725d4ffe846c95629cfad75a2a0c30a18140238e37e8e"),
            commit: 0x0d3703c4cc8e88dc9aba3f2c34d00101f580d572b9c09bf27530bbee06d62831
        });
    }
}
