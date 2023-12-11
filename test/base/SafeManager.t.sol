// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BaseTest} from "../Base.t.sol";
import {SafeManagerMock} from "./mocks/SafeManager.m.sol";
import {SafeManager} from "~/base/SafeManager.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";

contract SafeManagerTests is BaseTest {
    SafeManagerMock internal manager;

    function setUp() public override {
        super.setUp();

        // Enable SafeManager Module
        address implementation = Clones.clone(address(new SafeManagerMock()));
        manager = SafeManagerMock(implementation);

        manager.initialize(safe);
    }

    /// @notice it sets the initial safe because it is the first safe
    function test_WhenInitialized() external {
        assertEq(address(manager.safe()), address(safe));
    }

    modifier whenCallingAnOnlySafeMethod() {
        _;
    }

    /// @notice it calls the method on the safe because the safe is authorized
    function test_GivenACallFromTheSafe() external whenCallingAnOnlySafeMethod {
        _forceEnableModule(address(this));
        safe.execTransactionFromModule(
            address(manager), 0, abi.encodeWithSelector(manager.onlySafeFn.selector), Enum.Operation.Call
        );
    }

    /// @notice it throws an error because only the safe is authorized
    function test_GivenACallFromOtherThanTheSafe(address anyone) external whenCallingAnOnlySafeMethod {
        vm.assume(anyone != address(safe));

        vm.prank(anyone);
        vm.expectRevert(abi.encodeWithSelector(SafeManager.SafeManagerUnauthorizedAccount.selector, anyone));
        manager.onlySafeFn();
    }
}
