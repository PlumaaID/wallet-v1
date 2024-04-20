// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";

contract RSAOwnerManagerMock is RSAOwnerManager {
    function initialize(bytes memory exponent, bytes memory modulus) external initializer {
        __RSAOwnerManager_init(exponent, modulus);
    }

    function $_setOwner(bytes memory exponent, bytes memory modulus) external {
        _setOwner(exponent, modulus);
    }

    function $_verifyRSAOwner(bytes memory message, bytes memory signature, bytes memory exponent, bytes memory modulus)
        external
        view
        returns (bool)
    {
        return _verifyRSAOwner(message, signature, exponent, modulus);
    }

    function $_useOwnerNonce() external {
        _useOwnerNonce();
    }

    /// @notice Unsafely overrides the nonce
    function unsafeSetNonce(uint32 newNonce) external {
        _storage().nonce = newNonce;
    }

    /// @notice Get EIP-7201 storage
    function _storage() private pure returns (RSAOwnerManagerStorage storage $) {
        assembly {
            $.slot := RSA_OWNER_MANAGER_STORAGE_LOCATION
        }
    }
}
