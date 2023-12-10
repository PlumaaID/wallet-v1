// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Plumaa} from "~/Plumaa.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";

struct TransactionRequest {
    address to;
    uint256 value;
    Enum.Operation operation;
    uint48 deadline;
    bytes data;
    uint32 nonce;
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

    /// @notice Unsafely overrides the nonce
    function unsafeSetNonce(uint32 newNonce) external {
        _storage().nonce = newNonce;
    }

    /// @notice Get EIP-7201 storage
    function _storage()
        private
        pure
        returns (RSAOwnerManagerStorage storage $)
    {
        assembly {
            $.slot := RSAOwnerManagerStorageLocation
        }
    }
}
