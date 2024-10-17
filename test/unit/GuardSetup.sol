// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {ModuleGuard} from "../../src/ModuleGuard.sol";
import {SafeProxyFactory} from "../../src/Safe/proxy/SafeProxyFactory.sol";
import {ISafe} from "../../src/Safe/interfaces/ISafe.sol";

contract GuardSetup is Test {
    //////////////////////
    //    Constants     //
    //////////////////////

    // Safe in mainnet
    address internal constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    SafeProxyFactory internal constant SAFE_PROXY_FACTORY = SafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);

    // Helpers for tests
    uint64 internal constant DEFAULT_THRESHOLD = 1;
    uint256 internal constant DEFAULT_SALT = uint256(keccak256(abi.encode(777)));

    //////////////////////
    // State Variables  //
    //////////////////////

    // Safe
    ISafe internal safe;

    // Guard
    ModuleGuard internal guard;
    ModuleGuard internal guardSingleton;
    SafeProxyFactory internal guardProxyFactory;

    //////////////////////
    //    Modifiers     //
    //////////////////////

    modifier fork(string memory env_var) {
        string memory RPC_URL = vm.envString(env_var);
        vm.createSelectFork(RPC_URL);
        _;
    }

    //////////////////////
    //  Help functions  //
    //////////////////////

    function setUp() public virtual fork("MAINNET_RPC") {
        address[] memory arr = new address[](1);
        arr[0] = address(this);
        safe = createMinimalSafeWallet(arr, DEFAULT_THRESHOLD, DEFAULT_SALT);

        // Create SAM module
        guardSingleton = new ModuleGuard();
        guardProxyFactory = new SafeProxyFactory();

        bytes memory initializeDataGuard = abi.encodeCall(ModuleGuard.setup, (address(safe)));
        guard = createGuard(initializeDataGuard, DEFAULT_SALT);
    }

    function createGuard(bytes memory initData, uint256 salt) internal returns (ModuleGuard newGuard) {
        return ModuleGuard(
            address(guardProxyFactory.createChainSpecificProxyWithNonce(address(guardSingleton), initData, salt))
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
}