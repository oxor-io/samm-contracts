// SPDX-License-Identifier: LGPL-3.0-only
/* solhint-disable one-contract-per-file */
pragma solidity >=0.7.0 <0.9.0;
import {IERC165} from "./IERC165.sol";
import {Enum} from "./../libraries/Enum.sol";
import {IModuleGuardErrors} from "./IModuleGuardErrors.sol";
import {IModuleGuardEvents} from "./IModuleGuardEvents.sol";
import {IModuleGuardGetters} from "./IModuleGuardGetters.sol";


/**
 * @title IModuleGuard Interface
 */
interface IModuleGuard is
    IERC165,
    IModuleGuardEvents,
    IModuleGuardErrors,
    IModuleGuardGetters
{

    function setup(address _safe) external;
    function setTxAllowed(address module, address to, bytes4 selector, bool isAllowed) external;
    function setAllowance(address module, address to, uint256 amount) external;

    /**
     * @notice Checks the module transaction details.
     * @dev The function needs to implement module transaction validation logic.
     * @param to The address to which the transaction is intended.
     * @param value The value of the transaction in Wei.
     * @param data The transaction data.
     * @param operation The type of operation of the module transaction.
     * @param module The module involved in the transaction.
     * @return moduleTxHash The hash of the module transaction.
     */
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        address module
    ) external returns (bytes32 moduleTxHash);

    /**
     * @notice Checks after execution of module transaction.
     * @dev The function needs to implement a check after the execution of the module transaction.
     * @param txHash The hash of the module transaction.
     * @param success The status of the module transaction execution.
     */
    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}
