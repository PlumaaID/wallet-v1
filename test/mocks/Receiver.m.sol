// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract ReceiverMock {
    event Received(address sender, uint256 value, bytes data);

    fallback() external payable {
        emit Received(msg.sender, msg.value, msg.data);
    }
}
