// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Enum} from "@safe/contracts/common/Enum.sol";
import {Plumaa} from "../../src/Plumaa.sol";

struct TransactionRequest {
    address to;
    uint256 value;
    Enum.Operation operation;
    uint48 deadline;
    bytes data;
    uint256 nonce;
}

contract PlumaaMock is Plumaa {
    function structHash(
        TransactionRequest calldata request
    ) external view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        _TRANSACTION_REQUEST_TYPEHASH,
                        request.to,
                        request.value,
                        request.operation,
                        request.deadline,
                        keccak256(request.data),
                        request.nonce
                    )
                )
            );
    }
}

contract SafeMock {
    event ExecutedWith(
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation
    );

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public virtual returns (bool success) {
        emit ExecutedWith(to, value, data, operation);
        return true;
    }
}

contract Receiver {
    event Received(address sender, uint256 value, bytes data);

    fallback() external payable {
        emit Received(msg.sender, msg.value, msg.data);
    }
}
