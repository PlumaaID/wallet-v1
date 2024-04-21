// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Plumaa} from "~/Plumaa.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";

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

    function recoverStructHash(
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) external view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        _RECOVERY_REQUEST_TYPEHASH,
                        publicKey.exponent,
                        publicKey.modulus
                    )
                )
            );
    }

    /// @notice Unsafely overrides the nonce
    function unsafeSetNonce(uint32 newNonce) external {
        _RSAOwnerManagerStorage().nonce = newNonce;
    }

    /// @notice Unsafely overrides the threshold
    function unsafeSetThreshold(uint256 newThreshold) external {
        _changeThreshold(newThreshold);
    }

    /// @notice Unsafely authorizes a recoverer
    function unsafeAuthorizeRecoverer(address recoverer) external {
        _authorizeRecoverer(recoverer, threshold());
    }

    /// @notice Get RSAOwnerManager EIP-7201 storage
    function _RSAOwnerManagerStorage()
        private
        pure
        returns (RSAOwnerManagerStorage storage $)
    {
        assembly {
            $.slot := RSA_OWNER_MANAGER_STORAGE_LOCATION
        }
    }
}
