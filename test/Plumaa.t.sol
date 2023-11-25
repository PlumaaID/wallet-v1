// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BaseTest} from "./base/Base.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SafeMock} from "./mocks/Mocks.sol";
import {console2} from "forge-std/console2.sol";
import {Plumaa} from "~/Plumaa.sol";

contract PlumaaTest is BaseTest {
    /// @notice Tests that a transaction can be executed only if the signature is valid.
    function testExecuteTransaction(bytes calldata data) external asCaller {
        vm.expectEmit(true, true, true, true);
        emit SafeMock.ExecutedWith(
            address(receiver),
            0,
            data,
            Enum.Operation.Call
        );
        bool success = plumaa.executeTransaction(
            payable(address(wallet)),
            _forgeRequestData(
                address(receiver),
                0,
                Enum.Operation.Call,
                uint48(block.timestamp + 100),
                data,
                0
            )
        );
        assertTrue(success, "Plumaa: transaction failed");
    }
}
