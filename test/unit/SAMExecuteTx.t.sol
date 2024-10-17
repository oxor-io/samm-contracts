// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.23;

import {Setup, Test, IMinimalSafeModuleManager, SAMM, ISafe, ArrHelper} from "./Setup.sol";
import {ISAMMErrors, ISAMM} from "../../src/interfaces/ISAMM.sol";

import {SumcheckFailed} from "../../src/utils/Verifier2048.sol";

import {SimpleContract} from "../helpers/SimpleContract.sol";
import {SimpleContractDelegateCall} from "../helpers/SimpleContractDelegateCall.sol";

import {console} from "forge-std/console.sol";

contract SAMExecuteTxTest is Test, Setup {
    // Correct proof must be verified and tx getThreshold executed.
    // Call must be successful and returned data correct
    function test_correctProofCanBeVerifiedAndTxExecutedReturnData() external enableModuleForSafe(safe, sam) {
        ISAMM.Proof memory proof = defaultCorrectProof();

        (bool result, bytes memory returnData) = sam.executeTransactionReturnData(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(proof),
            DEFAULT_DEADLINE
        );

        assertTrue(result);
        assertEq(abi.decode(returnData, (uint256)), DEFAULT_THRESHOLD);
    }

    // Same with the test above, but with another function.
    // Call must be successful.
    function test_correctProofCanBeVerifiedAndTxExecuted() external enableModuleForSafe(safe, sam) {
        ISAMM.Proof memory proof = defaultCorrectProof();

        (bool result) = sam.executeTransaction(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(proof),
            DEFAULT_DEADLINE
        );

        assertTrue(result);
    }

    // Invalid proof must fail the verification process, tx must be reverted
    function test_incorrectProofWillRevert() external enableModuleForSafe(safe, sam) {
        ISAMM.Proof memory proof = defaultCorrectProof();
        proof.proof[300] = 0x11; // Invalidate the proof

        vm.expectRevert(SumcheckFailed.selector);
        sam.executeTransactionReturnData(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(proof),
            DEFAULT_DEADLINE
        );
    }

    // If the module enabled and has not passed the setup process it must not execute transaction via wallet.
    function test_moduleWithoutSetupCantCallTheWallet() external {
        SAMM newSAM = createSAM("", DEFAULT_SALT); // Empty init calldata -> no setup
        enableModule(address(safe), address(newSAM));

        ISAMM.Proof memory proof = defaultCorrectProof();

        vm.expectRevert(ISAMMErrors.SAMM__rootIsZero.selector);
        newSAM.executeTransactionReturnData(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(proof),
            DEFAULT_DEADLINE
        );
    }

    // This test must not be removed.
    // Same proof can not be used in the same transaction.
    function test_sameProofCantBeUsedTwiceInSameTx() external enableModuleForSafe(safe, sam) {
        ISAMM.Proof memory proof = defaultCorrectProof();

        vm.expectRevert(abi.encodeWithSelector(ISAMMErrors.SAMM__commitAlreadyUsed.selector, 1));
        sam.executeTransactionReturnData(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(proof, proof),
            DEFAULT_DEADLINE
        );
    }

    // If executor provides amount of proofs less than threshold tx must be reverted.
    function test_notEnoughProofsWillRevert() external enableModuleForSafe(safe, sam) {
        vm.expectRevert(abi.encodeWithSelector(ISAMMErrors.SAMM__notEnoughProofs.selector, 0, 1));
        sam.executeTransactionReturnData(
            address(sam),
            0,
            DEFAULT_CALLDATA,
            IMinimalSafeModuleManager.Operation.Call,
            ArrHelper._proofArr(),
            DEFAULT_DEADLINE
        );
    }

    // Setter can not be called not from {self} account
    function test_setterWillRevertIfNotSafe() external {
        vm.expectRevert(ISAMMErrors.SAMM__notSafe.selector);
        sam.setThreshold(1);
        vm.expectRevert(ISAMMErrors.SAMM__notSafe.selector);
        sam.setRelayer("abc");
        vm.expectRevert(ISAMMErrors.SAMM__notSafe.selector);
        sam.setDKIMRegistry(address(this));
        vm.expectRevert(ISAMMErrors.SAMM__notSafe.selector);
        sam.setMembersRoot(1);
    }

    // Safe Wallet can directly set parameters in SAM.
    function test_walletCanSetParamsDirectly() external enableModuleForSafe(safe, sam) {
        uint256 newValue = 999;

        // Try to set threshold
        bytes memory cd = abi.encodeCall(SAMM.setThreshold, uint64(newValue));

        sendTxToSafe(address(safe), address(this), address(sam), 0, cd, IMinimalSafeModuleManager.Operation.Call, 1e5);
        assertEq(sam.getThreshold(), newValue);

        // Try to set root
        cd = abi.encodeCall(SAMM.setMembersRoot, (newValue));

        sendTxToSafe(address(safe), address(this), address(sam), 0, cd, IMinimalSafeModuleManager.Operation.Call, 1e5);
        assertEq(sam.getMembersRoot(), newValue);
    }
}
