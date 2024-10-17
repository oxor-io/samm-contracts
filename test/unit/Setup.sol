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
            proof: bytes(hex"000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000ddc2cf378d031cadaaf07d6601e2d2a09c00000000000000000000000000000000002e371e02bfb9544bf0eb71a49ca1b40000000000000000000000000000003b1c4764835b4b2e8aea88cad68b702f1700000000000000000000000000000000002b8efb4203c638ca1ea4f16f9f0ad4000000000000000000000000000000400b41520e501461a2ac06d98d7c8d1ffc00000000000000000000000000000000000e7f37d7004b813be390308c6673e8000000000000000000000000000000d0f9f1da0625c8352a7b3ef2503ba169df00000000000000000000000000000000001a75618de75dc80e29c26250dc9e0e000000000000000000000000000000ededb81432c91432dd038f7d5ed88bfe78000000000000000000000000000000000017d539e35e11dc332f2fa84fce37cc00000000000000000000000000000090b348f6c5186919782a3a3e71bdc1c9050000000000000000000000000000000000282d32cc8b69c33d7f7ed12f9922eb0000000000000000000000000000008b3d556bb4875f311c7062d0c03756b6d500000000000000000000000000000000002bd3c4a255de3323738a32e41c24f000000000000000000000000000000054528cac89f04987d859abc234032e87690000000000000000000000000000000000029e2193f8a328cbb5cbf4e4c3d3dc000000000000000000000000000000bf986d1b80f03025c93ba75d801ced263400000000000000000000000000000000000c6f269bd74f4574be68e608c77bbf00000000000000000000000000000000abb97a8ff10c1518b9cfb0abfb56afa700000000000000000000000000000000001d0e9553af1fae772ca7a2d36e0f30000000000000000000000000000000fd278da24262ee07855cafdb9db199b956000000000000000000000000000000000027a511070e3a5fa992c5a8fcd9324c0000000000000000000000000000002c37a7940467f88c6646b7dec6634e87e00000000000000000000000000000000000030308073beeccfbde589f155d7418000000000000000000000000000000306173ce1fb3c96dc935d5ad77f1fe09bb0000000000000000000000000000000000169dcbbcfcd7c41f8426864e1d7422000000000000000000000000000000ff61676f02daf9fd05d4073d56cede2b4d000000000000000000000000000000000011822b779227c198c5d7996acc612c000000000000000000000000000000e9068d2311ac96ec17846d8f5619e1794300000000000000000000000000000000002148fc272c88b0f20f568e7e302182000000000000000000000000000000ff8789b739d6d8226b6d03ad0790cdb62700000000000000000000000000000000000f7b24025675d68520a0f616dbd5052cbc51f0e39350c4eab0cca18798cdcfadbdaff74df8316e6c24d5054d4031b803a7fc81fd9e4f64cd9f7914f9e88a8d7a7638512bc13f22d7bd208ea2bfce4913dca8fe1973d6a036aa8f42a9d782073154cddb27138b9330a72573b035852209d061eba786ab0fc6a502d4a32b59ba247cefe15f29f2b008eae3b5fb17a5f4065a243df57bf76a6bb09224be36a464f965731d19d9578a9a7c4bdb8a4f9e9c2742388483e800345e37f0e34efc976f033cb2c3b0af2614741ad36e2563e9ba20bdd364227ba0054c2a4c9df0ed0835aba3c3ffa3976c3e5235f6c0f1fc652a0a2fd40b19cc4d600459cd6d7840c36edaf81d86ab632dddbb2269740fc1106526df27a1b00d3487c229da1175268e5497b3b8259f4352ca2dbadda5193be92f08b3041ab8382a46969352d8aa776b9eda66a71c1b98540c3a52d589aa979e0b180cf8171d2b397140bfe209c320db0407288b97c9c2fe9c57131c330b5c7abd0dc7ab59ea905c8c0d708dfce758147a2df3558edeca49be24c9e03dcb9b6fad0005e77cfdf09af09acce227995d8ce03c81e8d181d0e464f362100d3aaa91360bd9d2d209f839fcbafb6133ec76f69ee1d5eaec8b1720cc46edea298c7ece591ea74d4f1b4ca4727a117cf22dad6ffded724ad94d9e9fae2ae5d6e097bda320206f6c8537294a871b995c26c65b66842a3b734367b9843cdb25d7b1f1354ccb0af5956d027ee2c2d31fe66623aa4f437117b626b053df7eea0a2c2da3ddaf980343eb2c80c3a64478b3079afc68046576fe7e149f2713c41b9d8ae1074ec56a1f45123b5c1121164f8014d1996f56bfba8512fb826d491bb24d02e5177aea3b01eff950908394b341f691629c85dc14c5a22174721604ef856c085c1c92ba9e0d7215fec6a28a10657a6cc99dadfb84b547bf51a366bebbddc254d4cb2f205e174205ba8bb769d71d064e22bad55d3daac599398c227ac7c0efda1710915d0a0bc3e4d91798fe766126932a58f2c36e372d1e5d92f61d2e5b737047306ad63723ecb1bbb8b590a2b84e051fbbea07baeabece7654603a4553d88e370a2928ac15f992fb58cb6c66e58cd3cc650db7f472a03249034ca72de52a4c6f4ff3ba56025beccba0f4403cc4db6c5b64233111282465dc73ed70fd7fd04832dde9ba3a1e71610967f5ae943222e29c7db5cfd207c375394bffb83e13e8ce9955e8fdde13dde5a39e74100ad4bd75b94d87fbe3b738245558890fabf0af33bfeab3f5511c2ba2df3b0815f21bc321f75525d9f4b4e42fd80d64092612135b9f8ce920372e48b87d51c5d623e1e81384f641d64cceae49bf5496c136a0499ab9a5c903012cb7390ae30e20bc604959012c8a7b672ba36c39d530112868807f243752865d00c307e7ed3744b849437b5af4aa8ac877d6e48fb2228198402c444d33a80d83061b408644d6b47fc28e8c978e711d578f81bcede296f40619bc10c20a610d1f11ee65ecb13f0edf92197dd2020fd596e9e7735bc473fd976b7a86c3214c021415b2c6a6689f21a2c9083beea63cd2fee904bd2d15706b6ad4fb0d3abd6d88a015e942c377a6f5123e71cb2d26cb1cc2aef90b7f474fc0f1cc6689ae39af1c3600deed8a0d713a85ec3e20c6a9142b23cd73a96fcc4d8469e7b7fa28e8144eed25243229185e22450969ef0f91c3a4eb2d2f5e1359b63d76d8ee0e16ce23bb14055920e81dc57a2db503867b8f0bb1c13f10a0aff4da87490eddeac1093b2ea30719c8d2a829068eb2cef6b2ea90ce1103dfde75a41c7ce31effdf085ab7a53b0deed9ee7fb7a3fe67ce45d7fc3fb65c62ff10dffdccedb9cf05aef64fa6c3e429469f945f92a92dd0247509c7e5687b51b1be40defbf142e098777fd44ed857277e4cded9ccb2cae39510962a0f9bda09436e2d8565d1d88649775bef1020bf04828718146d7962c70b64416ec08b5581aea6f5d30633b74e895a7a886faeec1d4949e0bfeab6c577d54c23bcf1d80fced8f15978a1bd27b0eabffd34f0acca23174771e6e1e2e402d132e1983f64a2de7fa6517b2d5e29589c49967758c0e91351e8b55c7c10545fec48c55ef2ef41decee40e48bdc504df355a6bd567788003bb88302450b152687389e00aafab0f67df757d3d727efc8731f7eedb67b7711521ae5ab1a90b1799ad308c4fd82a805d8a75b397159780970cc5532458f3a502ff00dca098e5f1891b55e98d8e3aee903f97f5ff6a762fe52b4437d4fbb52e0eb1cb0caa10e7d4ad4eee14caf1c228a9ac6938fc43923975a871cd04c8dd39152c91a14917205ced7d3ccc399aed9a21399ee130aee4d6e1e67c516ecede0f1c0cf89e8dd3f8cd3026150fec9707bc67d878f13f858f4bac43514fc95c52d92991aac2297c23817e3bb6d729d0a75093b759bbc9ebc35685cea0cc2924fd9a225c6683e7fdf2b2664c5e268f680ea050ef590d725daca00440140f11a19d002c42ee3a662346c851b54fb5cba2c6e6c4886be308f3f65f60bb7c16c428fa3408af0986882a464429e9852f2a33439893d28d4f014d5919eb9e0c278390aa782318f620f8d6fe34982d2c2ee1653d6c5eed7ca7f58bdc234a0e2d809bd8079203de0f6ef750b8f1e5b3503fc254f8e8e3cd88aa9d252f17acdfb0813c10fa0d19f14007d223fd8e6904914203c70a65a7649283197bef9e2418e4a4ddc57cf92b4e478fe34ae4514a8d29b23260c4864bd70b05cb6c54099afa087e5624574a01cd7f1e76cddc6b9ab0af479d5723a8b66feca76fce0d87b42bb99436012c010862fc32cc346009ee6650defd0651044ef037356e75665f4ffd838966d1fb582795ee585586ea93544c48583df9c676880762f0383b247512565b5af2f4ecd90e97c1416d07b3cddadda3b959c9c473588a2320884495bec77edd008a5411211f9a81ee4b97a6eff1f917b62e0e8ae217ff63edd0dc18fc9d4b89fc571ace952a3d7e5ca01e3f18c687d32559912cd13c6922b0ae7ca06419e47c1d749e091924712955631a0bb55b749b45fe0feda06af7b72e868968c6848ed5d70216ee4904ba16ce2bf3f875c2075fb4c200379ec4250cc8bae507a59e93db935ae47267265840378e231b56d7fb79159f3a646cdef609958af7c1e87c53f6e7f7cccc7f3036c5afa5b07674a1030b9b02fb8f4c132154ba56193a63e3bb0db6ff70b0072ae8696d32a66ad8f874ac4a7b4e720e6062cc0b56008a419943bf5a3d42a4bb094feda59a6383c0232dc2ac9725aa4bc790d265f8bcbf24e98c16693b12a3e613599effaf7f0b8a4b3311bd79f4566828544fa17c1381c099202b32fbd8f679063ea7f5b3f15f4d885699cd848dfb843012b9e28a0d67d63acd2d941f4849f814a6d69d5a325aac9c80773f2fc3d17cb1b7e295b169605b376683a16c53a6d91a5e12035e4fedef6b95204f2147188cb338b7d69bc09d393d26da66d51356ff2e8c1224d23fd6664b8db395d99c1299ebd0488d84ca5bff23a16c26db8907071eaba07b2af28d0515f9a45fa0bf4f26919b75a9f8fe613966ec55ac01ac5f7d2e9c74ada11f712ec522ab40d631630073df248c36c14dc759e85921a379ba7a2061be02bfd04db388933534813f178693aafaae9ff46e7b5bfe4cf27b1ed75724da371e8c225ced3151be5ab9d93a279d743cc4171a3aabd8cfec72929bd78c01bc5bbee309842cbf06bd4333aace75f6badf7152be4885dfa02fed980a75a625a2e7adbe4584b65dc0b7ea4a7324fbb19b45292778cb754b3165e03ee2d25c2a7d1706e20ac896e90c4094db194c4ac519a160ba2fa04271c1e9adf43bb2ed094e2d18aaa8026669f9046d05eb4d4beb9c0e00633f6e4cd18b02e274efe7161985f5b3dc372d333d8d7fb0c8739a56276fe7460254e658ba75bd7ff14d38080801bfa87fbaf797b2275b566d67aa432fe082780847b529c4a94b13ada320b925d482a80271575d89e88cc0f8c37a7880e1e5a860feac5a54935902b3e240e914d9f8a3e3cfa39a3b718edfecfa58d59512bbf1e438257700f5a2b7c458a8ce1a9df5a412229e48d9d7afb03ecd085742ff0b1ec1f5c85d31cae3c6e7aa32191d830c6c74ef0eadbb13170a34b34c33918136edb9936cd5125ae0187a3cf38e01743944277a02020d8b515f8175071d345b49457b4c5bab2a513a4a0d32fb4e07278bff1fadd202bec5c8cae2a207ceea60788ee33cdb926f92528b0f1e281725c26fa0d8adb60ebb9d8a055e3d3a50e933d88ac401df189aa79afc3129649e22fe7e9a27326231d904f65cea7601a01b3df30b649eceb0ca17d036a744b3322cbf6942268cbde906d13e49c30a3c3c89c6d372b4ac99255c0ecca43a299b660b2f3f7a3bd6115f2e354184cf7da8a5383eb2b2aa04b642c8845841d9fff1ed1eb6d395726a95c8df130791610bedb7da1f2fdd2b192e402a27e85fbb2b67701b61c8fb35d63e6a985247b3e75cc8b859f616ca7a6f22ecdb9138acd97117aa2f4985f52e001f371a087c9883367690261411c1eb42e383137d60eb4eb1f62005a068fea44d51a2de7cfec6f2db88f80e6f23d48ba900102416c98f6829a1ca2059dc951fd5a7e2732044c51286b08fe4aac72ae3dbfab868c2b38fa63bcd582c8de6fae8baed911a34a885a20898b24465d96c8f8a04ad9f300da0e43a02482f57879d18a01b5655aa9968fb64ffdb73ad5f961b0de7111e50db18ae907e6404ec783db14a38e46de2141874909f5d5655759df8519d0e34f084b7f02c418203af07d7b06b2729bc8a7f4b3977890e84c0893bb800af77d99cfcd8301179a20861ca0aa1fda93ad09600c2abede55bd161e5680776c436ce6857588970e36e0fc7deeee4f086eb8b6603ad82018a599a4010fdcc84efb79c3044cc893116330ab21501ac02ac0bf5b60ac850510d21f5374deb61c09d024bfd825e2d0d56490d588699b3f27f8032b706c7e5899ede62cf59c478f95a6cb00184311c27d23612619685a686d063619f9cbe43aea07efd35e296efa7ac9ddf3ab427305a5f140381f0debe73f8aae884312571c931c882b7e76049c1bab4c2d86944933af4da0cf37fb78d06751cdc789f288e982ca3c1d682de3b5d9fa5d0cec0ffc239a477071da4cacdb7040d654910e42b803dd1e266d6c2752daea303ea576b6efc2afe1ec4b6a65c4bf433a155fefd8e3e06947c517bbb00102701a1bdd7382a28b14c0a076b6343080a3e2e850f6eaf7526a7d5898e84af19186728c5c5b2ebfcf3822a78e11e238cd0288482020a6b287c1b0abb0bc02793f37d8365337dd5b5004e006d7a92bb5fc0ac179d812fe20da1095a35ffeaeeabbf6e81ebf7f32f9daa61068b92caa1cfcb5e5523fa65269ad38d5ca967f38b1f897e0b57e547e9a3b33c09a0dc05e161e2cb33cc401c700c0623f32b35eeceab0c4737451110723a03ef2ae324fa2789754778c23fc4980f19fba2c844f3eb9a13615a945f9c19e9f767011f6dbd48113ad5deab7f6529efffef222a0d7670e19e57a5db9147bc94acc416f4caacf159c5a33126c25dc617fe6938d7ffec07ba201dcc309f801227c5751b5fe2acba1b8711db59fe8f01d9f1fe613ef7db473cd15614c310a9706b5eed0bc5242ed9f007c0688ba1efd8497cac033278172d8cff97bf788783c9c92d051cb2fc363b9b46aeeb4beae381431d2e8f39d0691f5ca0a6b638964b31edf78129a42e111ec4ae12f68524dd44e0bdb2a47fe950a19d5c9ffe990a3dbc636690031a3ec17daa57d98effd04f86b11bba2b5450acd20dc92c048ba14597b4a0290ae11c5b51dec577a00ed9a5f9f78f7ad2241e6844667613f680e3f6ffb528bc186a07a6c93c361882c49472e301b49e32753f53a841d0fc66bce094aea9fffe2513ce59d7eb55462923d127ab6573fb24819b69f7a37115910005102ff054320db8a7a21459c89bbf4e5e7cc008b83c9f01f1d833f90c4b49a1cd9c1cc6d71b2a11b55683fb78dd71de8387125dc95bf2615a657974e6140aa7905e8815ca2b0c1dd915ef50a7ceeb6fc95e4fee702bf21b8dab45303dfd6b886f1783a8e0b723f73285c71cc427d187e8065ba0373aee17494adbc0f9c198b21c7596ae969d045ffbb9b90b79f8d5704ef106cb8ca80df4297ade08029ff1fbc99d8316066829d095eb7432cb7e7f1bdb03fc40b6473658c444c89da5f141679a4d78d3d2ec1de677e07c0f04290a0bb6e80ecfbf45ae88191d9fcf47dd6353e1f8544fa0fd17b81d67adcdbe4481d028fb7cec2a98f86d2f61a1532822b9698115639df82322c547a39eca5876fe8f117c9f67e2e6c30273883d57d4612b370aba8dbfe624124a7549d1fca7088fdd2592d8ab5fc08c653593559551e741e16c01bb89b2851f84a237a4046d4c5c611337998fd25ce397f4855a0b92d6041ef1a54668a9cb0fcdaa55497a25b7250ffe6b6b2f4d46c794914b27c696fab4a826ca7af33b6c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d85b94ccf90ad92cba2e05db8c7c5af838686bb83c8c2f77575d5b2ce8894103e6c4ff4ca92ec8844490231f9cf67182dbc376c3c5d4b767eb74b33aa1108818cd481af85a06fdd29dcabda5ddac932acc33f0ad77c649619ca57a106a3da22cafc11966ce04cb207287964b1f6f52533bef60ec69c4197d0458be67aa1ca12a40934f233b8f0254adfdbbff4415affd5e5b37a70731f2faede9d58fb42f351f6b279a1c7c71233eaa6cb28d3f7200e22432db82070ece0d6a429fbba4ce001b8c7256bac87d9ed3611f93f3eeaf3a24713baaf913043436cd398198f3af2e12b468b04d6169a4011721a8df354e50da3c5e20d4866664c881caaec8d234421fdae975f3b16286e67eadd41e6d06cd84389e7c3c075ea245a51f22037f9f3f13ad6b53e58df7cdb6036af366fe25e5dc5e4c2526d7d6ae7ecd861114345ab819b639d2d75508da1aef8cc96c7499f8c41fdea0bb6ba985c97b0893dd32394b09458694b7edc2c74462579d652298c74f26b6832c7dc91df385fb2e809659c911ac39a46fa2a6082f0af40f77989757421fb800de0d8dec29edcfbcdfbe0c2c005dd46a50f7459429d98e857361e6676902d4052099407d62e438a762a8302d149951c8331415cf98992173424b67782d386c721b9b3430c50d4359d38ff86511035f9f748d6e915091c4e9d8a1d6ac3796f9cabe130032c7288e814258e86706081407cae516f5951a7fee96a33030c8008a2e292c1025e2afff08d3dc4c1515607499b84e18bce7ba4f5ab78b9fe67ce71ad7d6cc05c67b5d82115a1842da07a18f06a249d27bf324c69c0e7ea0af67351781739a903fbb61437967a6a4ce15b0cc30548f82d36ae4782f82a7f97789bacb8f133c9b91153f2a874e47e3861cbc669bbf2d6392b4dd566fef2f56d4363bf33b61ac1ca394a9e82c71f299ce15561c791427921d74bfe76dd2d72b1cca857de1f92cc181172f9a9a01ae22ac25456e161ab1b23486d36fbb06dc8c21bbcb03fd4e211ef5c40867d944ba5f6a2da154324726e033ba2457cd4f8d8189d868c9d4432a04cd504567ebb03d4de416c84b6e4e2f4ffa2c3ef703cc4b737eea696064ab764e42ab28fd4e34f31e3d0b04595f9ecdd049b749e046a6af20440bb8f4aea86471f8f6221bef69a37d2c2cc5a83807f9240e987a94983672823d6cf8483cd48df600bdba2ccfa8b3f1a005ecf3fdac2e83e2915ece2196941094d88fe5345a8440051b3808d7302815093048914066157691e9cfcde079e59ec80b257483c5a92368eba7ab757054d77214e87b7ff14961e61fdf8a8ca842017f61c6f4baa0ccfd3763560fb526197bfd3030a07b1083959157f7464e4799f9cdf7491743974aec250cf163f7b36505c41f65ef157b5fa1643e458a4e38143ef15bbd499cf50f7110d7470b9f8a4153e60ea25338d1440a54d8f414f57d515fe2bab5dc7880ed2a2ab8360bedfeef33732053f30ad4ee7c8abb20a91816419256ef24abc42568fa9b49578ca3c6e85a6215e3677a207673813df8cde4f40f548f3e1b0a1be0f0bfb48d6be468dab0def7010229c2661e37a70d70264f156e80868ff344816bc88643a88f054a19e6380b2ac27649be0d285dcd932b216f0ece7f069dcc47cbbaa053a06ab94a4612fb3c2cc4ed5e6493fd429aef5a4f350da7deb42a36310b879d57e87553c33141f4db0b51b6966120afb40907e0f67eff2cde7849f509c17f288fb68b55a0f7d671a00f3483d851bc40503f0ef475a541f0e7ebcb0034aa85d98a75dad04f58fdaf4d1f24c246667897c3958b93449e8b36b51aa963ae847242755b661c9b80a3547d10a653dc5cecd7af5072d98a06fff97f0adf668a7adc1938011ce9aebf6b5ba70a8a9447f0901de04f444c080be82c9ce4866d367d474a5b05d47edf7fe2772c0e945a3a815efbf7a45c6f9c0d3fcb2157592c4bc67132d94cc68892c61289c7"),
            commit: 0x187175d306a0820c82a4ebacd968d50463e6c839b49cabba317c422c7740315f
        });
    }
}
