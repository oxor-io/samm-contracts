// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {IERC165} from "./interfaces/IERC165.sol";
import {Enum} from "./libraries/Enum.sol";
import {IModuleGuard} from "./interfaces/IModuleGuard.sol";

import {ISafe} from "./../safe/interfaces/ISafe.sol";
import {Singleton} from "./../safe/common/Singleton.sol";

abstract contract BaseModuleGuard is IModuleGuard {
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return
            interfaceId == type(IModuleGuard).interfaceId || // 0x58401ed8
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }
}

contract ModuleGuard is Singleton, BaseModuleGuard {
    // solhint-disable-next-line payable-fallback
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    event Setup(address indexed initiator, address indexed safe);
    event AlowanceChanged(address indexed to, uint256 amount);
    event TxAllowanceChanged(address indexed to, bytes4 indexed selector, bool isAllowed);
    event ModuleTransactionDetails(bytes32 indexed txHash, address to, uint256 value, bytes data, Enum.Operation operation, address module);

    error ModuleGuard__alreadyInitialized();
    error ModuleGuard__txIsNotAllowed();
    error ModuleGuard__allowanceIsNotEnough();
    error ModuleGuard__safeIsZero();

    //////////////////////
    // State Variables  //
    //////////////////////

    // TODO: is the safe address need for the guard module?
    ISafe private safe;

    // A whitelist of contract addresses and function signatures
    // with which the SAMM module can interact on behalf of the Safe multisig
    mapping(address to => mapping(bytes4 selector => bool)) public isTxAllowed;

    // A limit on the amount of ETH that can be transferred
    // to a single address in the whitelist.
    mapping(address to => uint256) public allowance;

    //////////////////////////////
    // Functions - Constructor  //
    //////////////////////////////
    constructor() {
        // To lock the singleton contract so no one can call setup.
        safe = ISafe(address(1));
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
     * @param _safe The address of the Safe.
     */
    function setup(address _safe) external {
        if (safe != ISafe(address(0))) {
            revert ModuleGuard__alreadyInitialized();
        }

        if (_safe == address(0)) {
            revert ModuleGuard__safeIsZero();
        }

        safe = ISafe(_safe);
        emit Setup(msg.sender, _safe);
    }

    function setTxAllowed(address to, bytes4 selector, bool isAllowed) external {
        // TODO: validation
        isTxAllowed[to][selector] = isAllowed;
        emit TxAllowanceChanged(to, selector, isAllowed);
    }

    function setAllowance(address to, uint256 amount) external {
        // TODO: validation
        allowance[to] = amount;
        emit AlowanceChanged(to, amount);
    }

    /**
     * @notice Called by the Safe contract before a transaction is executed via a module.
     * @param to Destination address of Safe transaction.
     * @param value Ether value of Safe transaction.
     * @param data Data payload of Safe transaction.
     * @param operation Operation type of Safe transaction.
     * @param module Account executing the transaction.
     * @return moduleTxHash Hash of the module transaction.
     */
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        address module
    ) external override returns (bytes32 moduleTxHash) {
        // TODO: check operation: call/delegateCall?
        bytes4 selector = _getABISig(data);
        if (isTxAllowed[to][selector]) {
            revert ModuleGuard__txIsNotAllowed();
        }
        if (allowance[to] >= value) {
            revert ModuleGuard__allowanceIsNotEnough();
        }

        moduleTxHash = keccak256(abi.encodePacked(to, value, data, operation, module));
        emit ModuleTransactionDetails(moduleTxHash, to, value, data, operation, module);
    }

    /**
     * @notice Called by the Safe contract after a module transaction is executed.
     * @dev No-op.
     */
    function checkAfterModuleExecution(bytes32 txHash, bool success) external override {}

    //////////////////////////////
    // Functions  -   View      //
    //////////////////////////////

    /// @notice Retrieves the address of the Safe associated with this module.
    /// @return _safe The address of the associated Safe.
    function getSafe() external view returns (address _safe) {
        return address(safe);
    }

    //////////////////////////////
    //   Functions - Private    //
    //////////////////////////////
    function _getABISig(bytes memory data) private pure returns(bytes4 sig){
        assembly {
            sig := mload(add(data, 0x20))
        }
    }
}
