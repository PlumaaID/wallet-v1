// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BaseTest} from "./base/Base.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";

contract PlumaaTest is BaseTest {
    function testExecuteTransaction() external asCaller {
        bool success = plumaa.executeTransaction(
            payable(address(wallet)),
            _forgeRequestData(
                address(receiver),
                0,
                Enum.Operation.Call,
                uint48(block.timestamp + 100),
                hex"00",
                0
            )
        );
        assertEq(success, true, "Plumaa: transaction failed");
    }
}
