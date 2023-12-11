// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {SafeManager} from "~/base/SafeManager.sol";

contract SafeManagerMock is SafeManager {
    function initialize(Safe safe_) external initializer {
        __SafeManager_init(safe_);
    }

    function onlySafeFn() external onlySafe {}
}
