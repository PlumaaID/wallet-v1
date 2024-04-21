// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";

contract RSAOwnerManagerMock is RSAOwnerManager {
    function initialize(
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) external initializer {
        __RSAOwnerManager_init(publicKey);
    }

    function $_setOwner(
        RSAOwnerManager.RSAPublicKey memory publicKey
    ) external {
        _setOwner(publicKey);
    }

    function $_verifyRSAOwner(
        bytes memory message,
        bytes memory signature,
        RSAOwnerManager.RSAPublicKey memory publicKey
    ) external view returns (bool) {
        return _verifyRSAOwner(message, signature, publicKey);
    }

    function $_useOwnerNonce() external {
        _useOwnerNonce();
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
            $.slot := RSA_OWNER_MANAGER_STORAGE_LOCATION
        }
    }
}
