// SPDX-License-Identifier: GPL-3
/**
 *     Safe Anonymization Mail Module
 *     Copyright (C) 2024 OXORIO-FZCO
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.23;

// Contracts
import {Singleton} from "./Safe/common/Singleton.sol";
import {HonkVerifier as Verifier1024} from "./utils/Verifier1024.sol";
import {HonkVerifier as Verifier2048} from "./utils/Verifier2048.sol";

// Libs
import {PubSignalsConstructor} from "./libraries/PubSignalsConstructor.sol";

// Interfaces
import {ISAMM} from "./interfaces/ISAMM.sol";
import {ISafe} from "./Safe/interfaces/ISafe.sol";
import {IDKIMRegistry} from "./interfaces/IDKIMRegistry.sol";

/// @title Safe Anonymization Mail Module
/// @author Vladimir Kumalagov (@KumaCrypto, @dry914)
/// @notice This contract is a module for Safe Wallet (Gnosis Safe), aiming to provide anonymity for users.
/// It allows users to execute transactions for a specified Safe without revealing the addresses of the members who voted to execute the transaction.
/// @dev This contract should be used as a singleton. And proxy contracts must use delegatecall to use the contract logic.
contract SAMM is Singleton, ISAMM {
    ///////////////////////
    //Immutable Variables//
    ///////////////////////

    // Verifier from repository: https://github.com/oxor-io/samm-circuits
    Verifier1024 private immutable VERIFIER1024 = new Verifier1024();
    Verifier2048 private immutable VERIFIER2048 = new Verifier2048();

    //////////////////////
    // State Variables  //
    //////////////////////
    ISafe private s_safe;
    // The value of type(uint64).max is large enough to hold the maximum possible amount of proofs.
    uint64 private s_threshold;
    // Relayer email address
    string private s_relayer;
    // The root of the Merkle tree from the addresses of all SAM members (using Poseidon)
    uint256 private s_membersRoot;
    uint256 private s_nonce;
    IDKIMRegistry private s_dkimRegistry;

    //////////////////////////////
    // Functions - Constructor  //
    //////////////////////////////
    constructor() {
        // To lock the singleton contract so no one can call setup.
        s_threshold = 1;
    }

    ///////////////////////////
    // Functions - External  //
    ///////////////////////////

    /**
     * @notice Initializes the contract.
     * @dev This method can only be called once.
     * If a proxy was created without setting up, anyone can call setup and claim the proxy.
     * Revert in case:
     *  - The contract has already been initialized.
     *  - One of the passed parameters is 0.
     * @param safe The address of the Safe.
     * @param membersRoot The Merkle root of participant addresses.
     * @param threshold The minimum number of proofs required to execute a transaction.
     */
    function setup(address safe, uint256 membersRoot, uint64 threshold, string calldata relayer, address dkimRegistry)
        external
    {
        if (s_threshold != 0) {
            revert SAMM__alreadyInitialized();
        }

        // Parameters validation block
        {
            if (safe == address(0)) {
                revert SAMM__safeIsZero();
            }

            if (membersRoot == 0) {
                revert SAMM__rootIsZero();
            }

            if (threshold == 0) {
                revert SAMM__thresholdIsZero();
            }

            if (bytes(relayer).length == 0) {
                revert SAMM__emptyRelayer();
            }

            if (dkimRegistry == address(0)) {
                revert SAMM__dkimRegistryIsZero();
            }
        }

        s_safe = ISafe(safe);
        s_membersRoot = membersRoot;
        s_threshold = threshold;
        s_relayer = relayer;
        s_dkimRegistry = IDKIMRegistry(dkimRegistry);

        emit Setup(msg.sender, safe, membersRoot, threshold, relayer, dkimRegistry);
    }

    /**
     * @notice Executes a transaction with zk proofs without returning data.
     * @dev Revert in case:
     *          - Not enough proofs provided (threshold > hash approval amount + amount of provided proofs).
     *          - Contract not initialized.
     *          - One of the proof commits has already been used.
     *          - One of the proof is invalid.
     * @param to The target address to be called by safe.
     * @param value The value in wei to be sent.
     * @param data The data payload of the transaction.
     * @param operation The type of operation (CALL, DELEGATECALL).
     * @param proofs An array of zk proofs.
     * @return success A boolean indicating whether the transaction was successful.
     */
    function executeTransaction(
        address to,
        uint256 value,
        bytes memory data,
        ISafe.Operation operation,
        Proof[] calldata proofs,
        uint256 deadline
    ) external returns (bool success) {
        (success,) = _executeTransaction(to, value, data, operation, proofs, deadline);
    }

    /**
     * @notice Executes a transaction with zk proofs and returns the returned by the transaction execution.
     * @dev Revert in case:
     *          - Not enough proofs provided (threshold > hash approval amount + amount of provided proofs).
     *          - Contract not initialized.
     *          - One of the proof commits has already been used.
     *          - One of the proof is invalid.
     * @param to The target address to be called by safe.
     * @param value The value in wei to be sent.
     * @param data The data payload of the transaction.
     * @param operation The type of operation (CALL, DELEGATECALL).
     * @param proofs An array of zk proofs.
     * @return success A boolean indicating whether the transaction was successful.
     * @return returnData The data returned by the transaction execution.
     */
    function executeTransactionReturnData(
        address to,
        uint256 value,
        bytes memory data,
        ISafe.Operation operation,
        Proof[] calldata proofs,
        uint256 deadline
    ) external returns (bool success, bytes memory returnData) {
        (success, returnData) = _executeTransaction(to, value, data, operation, proofs, deadline);
    }

    /// @notice Updates threshold parameter.
    function setThreshold(uint64 threshold) external {
        if (msg.sender != address(s_safe)) {
            revert SAMM__notSafe();
        }

        if (threshold == 0) {
            revert SAMM__thresholdIsZero();
        }

        s_threshold = threshold;

        emit ThresholdIsChanged(threshold);
    }

    /// @notice Updates members root parameter.
    function setMembersRoot(uint256 membersRoot) external {
        if (msg.sender != address(s_safe)) {
            revert SAMM__notSafe();
        }

        if (membersRoot == 0) {
            revert SAMM__rootIsZero();
        }

        s_membersRoot = membersRoot;

        emit MembersRootIsChanged(membersRoot);
    }

    /// @notice Updates DKIM registry parameter.
    function setDKIMRegistry(address dkimRegistry) external {
        if (msg.sender != address(s_safe)) {
            revert SAMM__notSafe();
        }

        if (dkimRegistry == address(0)) {
            revert SAMM__dkimRegistryIsZero();
        }

        s_dkimRegistry = IDKIMRegistry(dkimRegistry);

        emit DKIMRegistryIsChanged(dkimRegistry);
    }

    /// @notice Updates relayer email address parameter.
    function setRelayer(string calldata relayer) external {
        if (msg.sender != address(s_safe)) {
            revert SAMM__notSafe();
        }

        if (bytes(relayer).length == 0) {
            revert SAMM__emptyRelayer();
        }

        s_relayer = relayer;

        emit RelayerIsChanged(relayer);
    }

    //////////////////////////////
    // Functions  -   View      //
    //////////////////////////////

    /// @notice Retrieves the address of the Safe associated with this module.
    /// @return safe The address of the associated Safe.
    function getSafe() external view returns (address safe) {
        return address(s_safe);
    }

    /// @notice Retrieves the current members root.
    /// @return root The Merkle root of participant addresses.
    function getMembersRoot() external view returns (uint256 root) {
        return s_membersRoot;
    }

    /// @notice Retrieves the threshold number of proofs required for transaction execution.
    /// @return threshold The current threshold value.
    function getThreshold() external view returns (uint64 threshold) {
        return s_threshold;
    }

    /// @notice Retrieves the relayer email address.
    /// @return relayer The current relayer email address.
    function getRelayer() external view returns (string memory relayer) {
        return s_relayer;
    }

    /// @notice Retrieves the address of DKIMRegistry.
    /// @return dkimRegistry The current DKIMRegistry address.
    function getDKIMRegistry() external view returns (address dkimRegistry) {
        return address(s_dkimRegistry);
    }

    /// @notice Retrieves the current nonce value.
    /// @return nonce The current nonce.
    function getNonce() external view returns (uint256 nonce) {
        return s_nonce;
    }

    /**
     * @notice Generates a message hash based on transaction parameters.
     * @param to The target address to be called by safe.
     * @param value The value in wei of the transaction.
     * @param data The data payload of the transaction.
     * @param operation The type of operation (CALL, DELEGATECALL).
     * @param nonce The nonce to be used for the transaction.
     * @return msgHash The resulting message hash.
     */
    function getMessageHash(
        address to,
        uint256 value,
        bytes memory data,
        ISafe.Operation operation,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32 msgHash) {
        return PubSignalsConstructor.getMsgHash(to, value, data, operation, nonce, deadline);
    }

    //////////////////////////////
    //   Functions - Private    //
    //////////////////////////////
    function _executeTransaction(
        address to,
        uint256 value,
        bytes memory data,
        ISafe.Operation operation,
        Proof[] calldata proofs,
        uint256 deadline
    ) private returns (bool success, bytes memory returnData) {
        uint256 root = s_membersRoot;

        // Check root to prevent calls when contract is not initialized.
        if (root == 0) {
            revert SAMM__rootIsZero();
        }

        // Check execution deadline.
        if (block.timestamp > deadline) {
            revert SAMM__deadlineIsPast();
        }

        // pubSignals = [root, relayer, relayer_len, msg_hash, pubkey_mod, redc_params]
        bytes32[] memory pubSignals =
            PubSignalsConstructor.getPubSignals(root, s_relayer, to, value, data, operation, s_nonce++, deadline);

        if (s_threshold > proofs.length) {
            revert SAMM__notEnoughProofs(proofs.length, s_threshold);
        }

        _checkNProofs(proofs, pubSignals);

        return s_safe.execTransactionFromModuleReturnData(to, value, data, operation);
    }

    function _checkNProofs(Proof[] calldata proofs, bytes32[] memory pubSignals) private {
        uint256 proofsLength = proofs.length;

        for (uint256 i; i < proofsLength; i++) {
            Proof memory currentProof = proofs[i];

            // check DKIM public key
            bool isValid = s_dkimRegistry.isDKIMPublicKeyHashValid(currentProof.domain, currentProof.pubkeyHash);
            if (!isValid) {
                revert SAMM__DKIMPublicKeyVerificationFailed(i);
            }

            // Commit must be uniq, because it is a hash(userEmail, msgHash)
            for (uint256 j; j < i; j++) {
                if (proofs[i].commit == currentProof.commit) {
                    revert SAMM__commitAlreadyUsed(i);
                }
            }

            pubSignals[77] = bytes32(currentProof.commit);
            pubSignals[78] = currentProof.pubkeyHash;
            bool result;
            if (currentProof.is2048sig) {
                result = VERIFIER2048.verify({proof: currentProof.proof, publicInputs: pubSignals});
            } else {
                result = VERIFIER1024.verify({proof: currentProof.proof, publicInputs: pubSignals});
            }

            if (!result) {
                revert SAMM__proofVerificationFailed(i);
            }
        }
    }
}
