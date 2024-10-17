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
    string internal constant DEFAULT_RELAYER = "ad@oxor.io";
    bytes internal constant DEFAULT_CALLDATA = abi.encodeWithSignature("getThreshold()");
    uint256 internal constant DEFAULT_DEADLINE = 4884818384; // Tue Oct 17 2124 05:59:44
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
            abi.encodeCall(SAMM.setup, (address(safe), DEFAULT_ROOT, DEFAULT_THRESHOLD, DEFAULT_RELAYER));

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
            proof: bytes(hex"0000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000007100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000004a31d5fdbc8f9c937c2aa6a02d1951ef030000000000000000000000000000000000269d36fbb5c160efe5b4275705b0c0000000000000000000000000000000d8f86bd1198a6486137bfcb38a6fce465400000000000000000000000000000000002fc7caa51b389a895b554dde9a2dd3000000000000000000000000000000679e5258f886a558c9c3b747791d569432000000000000000000000000000000000024c3ed530c24813dead1ea0898dd1d00000000000000000000000000000029e86f59c238b116eaec808348afa4720f0000000000000000000000000000000000091392caadd91271ef14a0eeebdec9000000000000000000000000000000fba5f9e37f4b25da1ba31a4744e1626e89000000000000000000000000000000000009b2854fe8fbe0d5f0467336e09ed400000000000000000000000000000047bcf9803ff083994518868c61a71adcb70000000000000000000000000000000000188a740cc40e5636906ff29ffe84fa0000000000000000000000000000008b3d556bb4875f311c7062d0c03756b6d500000000000000000000000000000000002bd3c4a255de3323738a32e41c24f000000000000000000000000000000054528cac89f04987d859abc234032e87690000000000000000000000000000000000029e2193f8a328cbb5cbf4e4c3d3dc000000000000000000000000000000bf986d1b80f03025c93ba75d801ced263400000000000000000000000000000000000c6f269bd74f4574be68e608c77bbf00000000000000000000000000000000abb97a8ff10c1518b9cfb0abfb56afa700000000000000000000000000000000001d0e9553af1fae772ca7a2d36e0f300000000000000000000000000000000ae07cb6d314853b910be9079f92a125360000000000000000000000000000000000234ae55157ab5f4b0e14d7807aba2200000000000000000000000000000074540d62437ecf3a5303853e1d622033d400000000000000000000000000000000001bb155f97f01233e5170e6c70426140000000000000000000000000000007c5ec57d3f000131b555da451e70885afd000000000000000000000000000000000002caece177cc0d2622fa7e06cc6976000000000000000000000000000000b90213c0ae737df692390ee1172c94b92d00000000000000000000000000000000001b822845af549d4828d7efc4bd9a490000000000000000000000000000003443b796cee3c5c1a2a393010321435917000000000000000000000000000000000015f747855042907ae928450a8695ef000000000000000000000000000000fc74ca0665c5ddf619d0c6f530f1df35990000000000000000000000000000000000164847f6d1e03f2743fd6ad8d6976207bb51a0f6b40abf98f747c1134780160ffeca93993ed9ab225daa8db89412b128a8fcd1ea7d956a1f58fdf56e39d84718351db4e07a96e621844b06376bed502bc2472c2237312bd39926e6db85ae7a953abef7553060f330cf42a29d47fc62256f88f395618507e194d3b702df2e32bcd339ec7b4f2e7bc0eb828d00b687a52f734743c8eda444e12801466299a3e539e10e7a828002cffdf994083a895f62079092c0f4bcb6c9f7a8ee1544635296a35e866c161d80032abb0608261d803d28209844282d4cf02ac1f44896367c0e3c82518b86a65a0bc3acac2f11b6aafe2df33af3520ec66913c60e36c5d4ffb9129ebbebabf1a1f3d6fe2b7abaf821dc0321ae716a94fb411d57d559a6cf4ead386f7ca9b8103a6827604de8bcef8f7b3035f2f30b6f19e9d568e5e85af8cc181850b720480dfc86c815d61c2845eb5e18f6a44e46e334b2b0fb3f57fb6043286ab9cd74f984395eff416138f5acaf7c126649605d0df8c2c47d485c664e0201e910e8243fe82ca2a4eb613892a312a90a8a7bf946fce5c15fd7b9c73eaa4d907f470f269b9f88c555ecca0659f9cf112fa4e8c5895bada3ad5a5484404e019ceb240bbb287c055bfb360c61de768dcd00db8556124a0adb3ad19ef41569d52ac3116ce4696e8312eff928b59ccc6c2c0efec17f71e945e3cdd847a9bbe3a01f75d83ba36f698681b335c1f2675783d90b211f933ee7f4bb3aedfefa35887a9ad74903357f27a005d4dae658b821eba7090ce9bd2e7ddb9c15792bfee4c963baf0e0348f16e84e4ad0a2e939307e39131236c8ec6dd08fc720a8ecd1de15a8f20ca2083e2dffe5bba170fe76dfc37d822b960429fd4cc72e5813ec89ffcb9a2fd9f3a7837c9c70faf376c77334cf88601ab993497cfb24df71de40422f2d95700812d04cd8f44a75b429464f7fb81e6d1af8253f8cb4789d8a7f0f24d0c02d897675367ad22a00e7da3b0d88f4525769215d8abb37c5b93aa06a31d1bd1e4914dabdd13431c85399a847369dd66c66cb1c3ab8a3efc99689a3f7210be5e66f6604a85ccce692dc6f72c5f948afc03c7328c15e328a95992bd903ad02b6f5bca02c64b5c13aa2ce5cacaf922a523f380a05f141c14facbe84bd26c8a3bbf28f1493805ddc9ab77a61e1b9c49526eefccd1451339146635eeb4d3b3c0395b59bf9026a46986f841badd84f3d23f2f3d5b70b16aab77f98970b61b9aec19ee1de9f48c3f2374b5d0386082581f19cebf0601a0a95a4d141d6ab0127bd2af817e89dd844ce50c91cfffdad26b8ed7f67e71d2d2c506d9b14ecffd3e7047f76826633da6f02d5801042daf5be281e96b4665b0b609e787f229efd321ba2fe944bf91e477229c0e93890180705ae7ef717437c09718db33de1637430b4d6350fe80e3d1ce551bc98abd87d4ed4de4aa09701511380812122630d4bdd35a3867fca52d8b9f4cce825c3e5910d06f837f09446092bce619c160bced568ace32ba9473dea7c4aba9d53d0ba24e497332ee901042427b5908bf0f7dd5054712e8a6ccd9d18c749951ab557e88c8f186880cc6229bc23fcbd1e0fc3f33fc2f05a5143f462ae4d41036ce972dacf26bdfeb0939b88f80e2d3cb9f459166858b65667ee74f19f817f51a910e5d5cf5c0b0bc7b93b843d238b2a179b9312fd20b5edcc0ecbd1403eeb3b5dd0d599195ed6b66bf1459246116073953dfa7bd3c7d868eec55a3f0f6577d11d1bd89252edc82b12644721d32b93a93ef2c1b6a679e65331f7663fe41238c7970c4217a1fc7845afbd85b9362120e04ba57ae76116191d685092bceb2ae085f0bc887bf9ea8caf2e38f5fa581455cfe05a66b7b052ffd4fac966f5a67d6943d44797c14fe1e312b384521acf2a2ce0bce8acc48468f16d6f7de21a252ab918d8aef58e1bb2e85605bfe6f86c0059749706e3628a0e57321cf790c6e606423921f6d537b2cba6b0c36e1dddb42cf9b1d3b48a6373d955f8c38da59ef82c8fd70065beccb0bf7a42d17d6d60031572d072862a5b536afeead37365194830ec51e53bae4fbc1734034fbbe989ce0b974fb2b7b26bdebf534b0250fbfca507cc476af854a7f228233f79f7dfd8720937ec9f5f8809c56e9c9fcc7cb32e3a1a048e664a7b21b812265e2f479c01d11aa088df4cb5b2df207da88176fa0e40ecb726ec9d8b87aee04a37be7af4321d05f2527a8114c4109dfb6069602b7fac065a33a6a84bed01aed1f78839edb5431eb1638cbe114cf3bed90f42a7c0acab44e32cc6b00300f2e2f4a1c306b50cf7253c165f923eb1fb07368265a99e3dd7e2b51779873a77bb72059e5f85f121811de3810d2f990294681af9056b5e1119febef1d4b521bf78981e7377826f296229cbf3d286a7f99bbf2640734bf69411440e4272b2e95e42aa2bdfa87b689577050260b3464a185cbab33af839f5a813cdecb3b2e61832a7c3072aac4184c0032cb0071457ad55fdf4f42f9f62533eb92198da9ac2a21e6b4224d8d7bbce5d002c7912f374fc7cc729629c39702fb6e6d07377f27f2abeca8e736aa7398060c518c484a1f56f4e24123128c996ee9df815cea89b35a3a5c0ac30fffe1188da52139519e07e5e8a85c6619f62d73b0d10987b2d3b98804f166df150e6b22bc3fe2b2e1689ce6c48d9043267e4e6b42f52c3505b3786c45666e7981f02e0c268ff2cbd3b0861b308371238052a7d26be1dc4f66d856e95ea290827ce253f0a1ada03a606ae7655cf78abb988aa5de5731f182ca2f642c4125210f5415a7e4feb521219a53565087828061cc25dec36d5f8290f332bce64fb011d32c5cd0689b09f193e10f0d588292897e39032c6d61f22f624bce977d7549222bfd48aa774c5372da1d2c37d2310aa48bc303321ecfe2178cc57d01ea9edfac0a02ee7da92a7e12b4442d199835fbbe5d534ceaf26b5a6a000317c7dbf5ce4dcc2043a8d8376e42006937f0507b4ab196f4e02a22a92d0cf52ab2142f0bbc67659e69290fdc1002423f0c53768f114d9b359532a3695cc86162ef32f30760b3139014dfa77d3b41f121e6534273543fa06d1aa25a8a2c495bbb982c9e4cd12c7e121cce59730732a126d8a5919a5144993281808a015333537a6425b3c6396ce97da3121a3613a190ecea884b64dfbfa936c1c9e0782f039fd94d387f168acbba2c734e6a1332e25883979cc8f1f8a5f4cbf5df5cb0fd3f832d0785f9013db62fdba5866cbad2f21b5239347ab80ece3a7cbbdbc354880fdad74e0fb11fb2b521e3e139452ca0f1de20483baec94c4ba381649d9268bfa70d9a2184d3f56b19a328a4cdf396a6b0036cb717b1c1e6dfa6b535c100e63f3121325ffc8131c1d40ed2bd5fab53458270e6cbc9efbd96e70bd6339991a0c5413b3ad664886bd91d8949ea34b3926af044e0dab3ef8c91a40529c946617e340495d5f7fb030407ce6cac6e79ae526721ef396947e9850646fd8b5cc7dd001adc729b4480e51087109939a804ec78b822c5617af13f2b8906179315f4026d528aa884cfb8b884f4e4359b02cfded4a3b0f6a06b016abd408bbf6b770f553667850541785fab3f636d163793c0ac79ee019a9228d2bf0aef02309a41070c06503f0aa809c2b4f30fb9e7975fee3907c7112c409156197dac4f5e30a6a40ed6291e9805e13e5bf59abc079daee6aef351321f0a61e72aa4ed3e0333aa97d597af108b79258942b1bcf2a7d6ab0765be2220df1ee4ceac9673b954e6d7c6ec151065453c162e72eb226dff7cd506f6b9e8d0d44f2e6f2b4b198406de4dc4d734ace69a78baf8ea06e5d0ba614e7515b06250d94c8323a1b3c13095e3b30ff120bacf95e7d422287f5f7c8135daf7bfb073f092bedd369d545c161b788cb984881e7d210962b0d4c2f517c7d0e150ecad8101b1af15779d70e51a530b15dccb7cf34042ec144fd6e0bc574f194b9101b0da82dbd3d6b106792f00570657f4c267708072ce0145e024824a5a2bb46dceff56f29eb9de0f34e913074c9dc965b6e73f28d0a6debb5df05f30cec967c72c8a6281ba01b0f124555be52fb3f28ac4aa02be8b07736b37efe03ad940dbf9cf1ab7023d52b89e62bcba17479d215b336101e43a1d4f20eafc35ee888456ecac8320b2012cd970f0eeb6a8b688b1b444ad335c1aa8a4f163aca663475f83c349a04bf2618629a5721fbb4bd6d409e5149abcd66272cf8d20375e791542b360d71e6f409ae9d0c6b557fa12555284b0294bf4422fd246babc21781b0d4a4cc6904af4d29eb9dbbe54905df13b8c0d16a58d22203cbcd53cb5b3e2b9c106a0a29d2c5f511ffbfbeb8f6a9c22c03fc3fb274f0d21afbf4763b75f8a99c7450c679aa79f0100416d9ed352ef116b61b753c0dcef798e0f810c5725c9dc4b491eb87366d712bdf4e65ab04e7a745e2597f6c77b9ae772b1ea552e8e89f24ad49b11970e9c10a40b7b7fc9aa7b6b4ef83c33a7a49de3d65a86cdcdb2da1fbb7b7f05d8245061057e5a81e2c80019b318be2b6375be48cc72bda881b3573d51d64104483c3da034058eaafc347b205dff35d24c16830d3a01b09102b1df2e07d5f9f37e5c60801bc5ab07241fb757348bd099d2560f0d418b766e8b23099a3f75c785b37cf2b11b6ed0c07db4072c40cf277f7adecd8871cf8a7689055520425df3ab627094d1811ccb9ea73546e5bf0064757baccad1bd2e07991cc2188d671fa9fe299329808c561520ffb90119f6b1a7c28b6ba483addcd13bab64f9f303815eb40d1b6cd1ef0e78c8458def58d3c850f250a6e922955f78d8cfbda480406e88149388c9d1dbd4f2b073e9658ca915326c7f3ff62dcc4ba0c2498ad2d6e8e5f51ff1bab0f264ea15b3c20348bdfb1776862a4813771d114bc5fc9e4ceb4c66c6d2ec56f460a53ce32f49d350d67158b79bd5f4cf696eb16d4b55bf5e0d4aa006ca0225cf11cfc87cb35d5af5968f5ed95a27d002a875790f980b62298c8797ea6f6daccaa2bff56acd2dabae5c54515c4ae0363da95eaef4940d76048516a7a46c648f36305b2f3ec93d60ec01f5bcc501f8f46e32624d508ac4d00da8fcd0bb2f963fe5a1208696f3b2da142ac7ba9d9f7a478f64e1cdadc2a981792b101cf15048bead12c0327f0d7bbc74d5941deeeac70f88506e1352762b8d692586bf9457c33696a18bae7500024091138b15bae8ef25e2e2b00aa80e0fa11e321c877e521bb52791e0234f50790cdf81cd0f69daad75531c380d057aa2564a680ec42b03cc76f0c28128426cb5cd1c7b22b7a7108db81abea245ea057fc6dec056e2c77fa10c31719d171cc7545a1a5cd55938ebfec33b8c8a94533e77877412bf7a010fa1bc0be20f512dc31948d96739911543927455856475419c8b9495991f775abe45ba39c19ab13fb4a6f72e5c32a368d10790ff3fb831880737ec73b0d03b6c7ac012c7f0beaedfa4e065e05537ab34be0942f1e04aed803cc54763c48bd6d61d2a87a080eb29d262518613f3e1c5c0f1585b4c29f44bfa9430fedae4e3ffbbc3ad951122f9e467c321245782929a5efc166676d507700ef98a2e26a722f86b0f33e016b28033515077c059dd1b5bb67c479ae46c5e0424a348f9b5b5c6b835a0c6e050f13467d2e15f18660e2296083089ecaf7e702edfb2e6e766cea0611ad8529c9a9284c25a8c32f1d65beae7bd7758de48a399dbd0d21da1f26029884ad9997c29b0e350b443c98e20b62fde358d93977b97faf1647bcbe2e9c0b6f6a8e462c8c702d66a5686693b8afa0f58f430830eb45809d3a0c418fe86b1fbb12a988980ab5206c223382bf3ba3d4b72cc998cb078010e318a6d140081a9e5b0b607296baf92997c3820be72ca69f86e6061878b95c187b6d1293f210b8cac60dcbc6e0e868182e6dd0c965249fc4ef4651deee0a22bec0804735796d174cf9891a6cf6fbc22d7db7f48015a549b3e839e442d064174862ea1e0678f30b2e79d464ec6252ef0c0aebeed7c727362fd107d42f27e3e392b733af824a36b3c2bf8fa0bbc355b001ba0d10b1ad86ca8a0b50454ce87dd8356e3221506932750873ffb6ec043c7f0c1c7fea8bb94e490c1d5649bb463e7e4ca3b926a08c51879047818e865be137207699fe6d538e90780484b59b9a18e68e2e30f2886127e3db4298190e724fc92437a556f5183efa30e2bd6da9a24de28ba5f74f2658ea3f42acd7c2721e11410cccaa07a802505acb06409ae00522b2b63048219a6ed23d3f84cbe28fdde6972df7e6ce5bdf5f6b2c3bebbfc2873d437f09a05616fb0ee459f8c3f7d702a45e07916e9b1eb20069830dc2db2b11730fc0a40585f206dabee7134b5758c3eb2603c1eeba300be059f2aa0d55632caa939fb114cc1cc2dd200a6d33f26f91c44a2085a5dda36c0811c6ba99cb6729fb42728756151b8b930619b4f1bf53dc42511e9c88c9643231bfa2d46a7dc39283af1f4b463fc971eb568ddbed8b9a761837000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001470e468f15a2d0998fb5390dfefcc90f66345bd14a13e8f27ec293e4f86da042968b32b64bc16b45b0e3ed2c8e36fa974e05728a775484bd1439db5a8f11caf1e13e21e99d71ba67f9b3bde114837887c413b912a1ef6a20ef87492edb4e3e61a954d511da7b0f5dcaf802b78dbe52b115a6c738f9faf599634c430f5dc53ec2587a81118a2decf5ba308a1bd6bb711ba56e881986e84e2d7027dbde1a698d3049cbd50cb3e201d05374fcc463f2be9a5c8b15106c192ee46a0039fe99d809b00a38a9069145fa488ba46440117b0fad6c2acef86c631cd0ac7e307a38554b2293fafa823362abf4878bfccc6f069c99033f10efe7b4053cc696c69d1c65ff72f151feb5712693b50889a8a21672e52824d026e0ebd025822f4cc9c97edfdc504fd2e88948d6c231ebf0a0cf0b44e030aef4ce629e8ada12e0c9c25d92681a70117f78b58c5a1260dad382049c03ddecba3400f9957b8f015a270f3b412857012c974713660641ad96879aa878cd80358be4286c60338d499c38deb8b282f132b7862154bc9bd54c3e537145e67e80d42ffb0848fa514f1665272c4f03f3607018e43878b0ab156a2a4ce27f72e8e04fcb6fdc49d02d2a27a5bcfa3b2b75c570d34cbf546870ce6c390308750aa65065d2b130f6a5625db8017f95e9a8da12e241f2e58fad35d20d7beb6971046d0821b2eb228834ddd7c3974aa4885b786f419a4e941b4abb2adad4560eae6727f4fc2e85d5e7df79d1183778c25d4a3ed2e0e5b068a305ad25666c91f800bab109de224823f4bed1f68e64111ae03f864cb1ac11c51d75a498c098a464fc987d13a7e78dd0a8fa584504720cd9cfecd9505118067354c8a2a4a042a65c559b1ca0b520f864aa09ad414434e32eeef682689077eb124d52ee764be442cf442995504fabd8a1aecc56f3ebafeecaa700fd542100d16f9afed883e0224833007daab6275a7d891a466a76d07063749f780889714c708b18d1e6bcffea2e23b7b778ca31748ca0ab45765f01998941907d808411090ddb484782e4921f870eed7e2c96db3c0cb4bb3e7b0f61e6c5fea6a07b16f23bb356af37337e48992d883439c5d2344fe6e1943a1e7263c9da35f118311dd0fbb5ea025e6a301a111c1cd06ebf1f7be3b4bfe036033d6ffbfc6d69aa6e2051a2ced0be50b6ce18c660b3e6a08adc7a305850807d435592f3463d3ffb8865f28a5b161f13b6ffbdda6fe621c83343fb33f43d4ab0fb784a62e788ca2b6af2129c71b8bd7527078b09c2a1f883118780c8cb9bd7ab82a6351310af629194a8b0abb5aaefdfbc2b8771c050a30af4334876cae6e81e774c21c74422b27c1d60c1022ed86bcf1359631881a59139ff4b27697ee65038bd3eafba57de2615da76705a98bfcd0b622372f673d694efae78db5ba636aace22300ac114bd89026c3e729957221eb34b6d8e82da0b22df570eee802c407b0ee9966dfd4531337b8ea1c18f74e57fce4a2826c552edd24893ebb82807b54ab63f30af2e235b44ce6b16c00af62e1a2da88216cb6e7a1885368ecfb057d032748525fac323e2db780dd5428b1d9558ece6a25c298f230640910896b7e70e9493bab8a60ae1c5d126af9600b3943e120763bde7ae0e15263c2b001f6628432585ef9d06156e6aafa3050b8262fc31b5b17b1d1562046e9d4d37c1a263f51a8dc52dcd179649848d535e0311bb5f3130654b921c73ec805adc633fae96d8e0c78e637387b7707971227a83b1347a7fc0085493462809a4ad8ea6fac17d3540b08d46524002382745a441ce50cc58821fde3cb6809082cea4dfa9ab9305e74aab04798d93b380ad3b472b57d076e41ef94bacf225b86f6a5652d43d6c9aa71dfcc30e1119706deb81569f1a029e60daefe7b6f9d60a0df7c1026f63b9f3d1b6316f827dd9d10cff25a7f164e0653852c99c4593f2b0fb9d5c046b99df62421779eee9ca0242dfe60e1d505a9"),
            commit: 0x0d3703c4cc8e88dc9aba3f2c34d00101f580d572b9c09bf27530bbee06d62831
        });
    }
}
