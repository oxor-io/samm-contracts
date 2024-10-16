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

import {ISafe} from "../Safe/interfaces/ISafe.sol";

library PubSignalsConstructor {
    // Chosen specifically because it is the most convenient representation of numbers at the moment.
    uint256 private constant CHUNK_SIZE = 64;
    uint256 private constant CHUNK_AMOUNT = 4;
    uint256 private constant PUB_SIGNALS_AMOUNT = CHUNK_AMOUNT + 2; // 2 => commit + root
    uint256 private constant ROOT_INDEX_IN_PUB_SIGNALS = 1;
    uint256 private constant MASK = (1 << CHUNK_SIZE) - 1;

    function getMsgHash(address to, uint256 value, bytes memory data, ISafe.Operation operation, uint256 nonce)
        internal
        view
        returns (bytes32 msgHash)
    {
        bytes32 calldataHash = keccak256(data);
        msgHash = keccak256(abi.encode(to, value, calldataHash, operation, nonce, address(this), block.chainid));
    }

    function getPubSignals(
        uint256 participantsRoot,
        string memory relayer,
        address to,
        uint256 value,
        bytes memory data,
        ISafe.Operation operation,
        uint256 nonce
    ) internal view returns (bytes32[] memory pubSignals) {
        // public signals order: root, relayer, relayer_len, msg_hash, pubkey_mod, redc_params
        pubSignals = new bytes32[](113);

        // root
        pubSignals[0] = bytes32(participantsRoot);

        // relayer
        bytes32 relayerBytes32 = bytes32(bytes(relayer));
        for (uint256 i = 0; i < 31; i++) {
            pubSignals[1+i] = bytes32(uint256(uint8(relayerBytes32[i])));
        }
        pubSignals[32] = bytes32(uint256(bytes(relayer).length));

        // msgHash - TODO
        uint8[44] memory msgHash = [119, 70, 50, 115, 90, 68, 120, 52, 109, 99, 75, 54, 65, 115, 74, 88, 84, 74, 77, 82, 103, 83, 111, 99, 115, 67, 112, 50, 50, 87, 87, 102, 90, 119, 120, 120, 119, 82, 72, 106, 103, 112, 48, 61];
        for (uint256 i = 0; i < 44; i++) {
            pubSignals[33+i] = bytes32(uint256(msgHash[i]));
        }

        // pubkey - TODO
        bytes32[18] memory pubkey_modulus_limbs = [
            bytes32(hex"0000000000000000000000000000000000e5cf995b5ef59ce9943d1f4209b6ab"), 
            bytes32(hex"0000000000000000000000000000000000e0caf03235e91a2db27e9ed214bcc6"), 
            bytes32(hex"0000000000000000000000000000000000afe1309f87414bd36ed296dacfade2"), 
            bytes32(hex"0000000000000000000000000000000000beff3f19046a43adce46c932514988"), 
            bytes32(hex"0000000000000000000000000000000000324041af8736e87de4358860fff057"), 
            bytes32(hex"0000000000000000000000000000000000adcc6669dfa346f322717851a8c22a"), 
            bytes32(hex"00000000000000000000000000000000008b2a193089e6bf951c553b5a6f71aa"), 
            bytes32(hex"00000000000000000000000000000000000a570fe582918c4f731a0002068df2"), 
            bytes32(hex"000000000000000000000000000000000039419a433d6bfdd1978356cbca4b60"), 
            bytes32(hex"0000000000000000000000000000000000550d695a514d38b45c862320a00ea5"), 
            bytes32(hex"00000000000000000000000000000000001c56ac1dfbf1beea31e8a613c2a51f"), 
            bytes32(hex"00000000000000000000000000000000006a30c9f22d2e5cb6934263d0838809"), 
            bytes32(hex"00000000000000000000000000000000000a281f268a44b21a4f77a91a52f960"), 
            bytes32(hex"00000000000000000000000000000000005134dc3966c8e91402669a47cc8597"), 
            bytes32(hex"000000000000000000000000000000000071590781df114ec072e641cdc5d224"), 
            bytes32(hex"0000000000000000000000000000000000a1bc0f0937489c806c1944fd029dc9"), 
            bytes32(hex"0000000000000000000000000000000000911f6e47f84db3b64c3648ebb5a127"), 
            bytes32(hex"00000000000000000000000000000000000000000000000000000000000000d5")
        ];
        for (uint256 i = 0; i < 18; i++) {
            pubSignals[77+i] = pubkey_modulus_limbs[i];
        }
        bytes32[18] memory redc_params_limbs = [
            bytes32(hex"0000000000000000000000000000000000a48a824e4ebc7e0f1059f3ecfa57c4"), 
            bytes32(hex"000000000000000000000000000000000005c1db23f3c7d47ad7e7d7cfda5189"), 
            bytes32(hex"000000000000000000000000000000000079bb6bbbd8facf011f022fa9051aec"), 
            bytes32(hex"000000000000000000000000000000000024faa4cef474bed639362ea71f7a21"), 
            bytes32(hex"00000000000000000000000000000000001503aa50b77e24b030841a7d061581"), 
            bytes32(hex"00000000000000000000000000000000005bbf4e62805e1860a904c0f66a5fad"), 
            bytes32(hex"00000000000000000000000000000000005cbd24b72442d2ce647dd7d0a44368"), 
            bytes32(hex"0000000000000000000000000000000000074a8839a4460c169dce7138efdaef"), 
            bytes32(hex"00000000000000000000000000000000000f06e09e3191b995b08e5b45182f65"), 
            bytes32(hex"000000000000000000000000000000000051fad4a89f8369fe10e5d4b6e149a1"), 
            bytes32(hex"0000000000000000000000000000000000dc778b15982d11ebf7fe23b4e15f10"), 
            bytes32(hex"0000000000000000000000000000000000a09ff3a4567077510c474e4ac0a21a"), 
            bytes32(hex"0000000000000000000000000000000000b37e69e5dbb77167b73065e4c5ad6a"), 
            bytes32(hex"0000000000000000000000000000000000ecf4774e22e7fe3a38642186f7ae74"), 
            bytes32(hex"000000000000000000000000000000000016e72b5eb4c813a3b37998083aab81"), 
            bytes32(hex"0000000000000000000000000000000000a48e7050aa8abedce5a45c16985376"), 
            bytes32(hex"0000000000000000000000000000000000dd3285e53b322b221f7bcf4f8f8ad8"), 
            bytes32(hex"0000000000000000000000000000000000000000000000000000000000000132")
        ];
        for (uint256 i = 0; i < 18; i++) {
            pubSignals[95+i] = redc_params_limbs[i];
        }
    }

    // function splitValueByChunks(uint256 value) private pure returns (uint256[CHUNK_AMOUNT] memory chunks) {
    //     for (uint256 i; i < CHUNK_AMOUNT; i++) {
    //         chunks[i] = value & MASK;
    //         value >>= CHUNK_SIZE;
    //     }
    // }
}
