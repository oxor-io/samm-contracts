// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.23;

import {GuardSetup, Test, ModuleGuard} from "./GuardSetup.sol";

contract GuardTest is Test, GuardSetup {
    function test_singletonSetupWillRevert() external {
        vm.expectRevert(ModuleGuard.ModuleGuard__alreadyInitialized.selector);
        guardSingleton.setup(address(123));
    }

    // Simply check that setup was ok
    function test_safeIsInitializedCorrectly() external {
        assertEq(guard.getSafe(), address(safe), "GuardSetup failed! Safe address does not match the default one");
    }
}