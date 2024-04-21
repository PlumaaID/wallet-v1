// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {RecoveryManager} from "~/base/RecoveryManager.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";

contract RecoveryManagerMock is RecoveryManager {
    function structHash(
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

    function initialize(
        uint256 initialThreshold,
        address[] calldata initialRecoverers
    ) external initializer {
        __RecoveryManager_init(initialThreshold, initialRecoverers);
    }

    function $_authorizeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) external {
        _authorizeRecoverer(recoverer, newThreshold);
    }

    function $_revokeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) external {
        _revokeRecoverer(recoverer, newThreshold);
    }

    function $_swapRecoverer(
        address oldRecoverer,
        address newRecoverer
    ) external {
        _swapRecoverer(oldRecoverer, newRecoverer);
    }

    function $_changeThreshold(uint256 newThreshold) external {
        _changeThreshold(newThreshold);
    }

    function $_validateRecovery(
        address[] calldata signers,
        bytes[] calldata signatures,
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) external {
        _validateRecovery(signers, signatures, publicKey);
    }

    function recover(
        address[] calldata signers,
        bytes[] calldata signatures,
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) public virtual override {}

    /// @notice Get EIP-7201 storage
    function _storage()
        private
        pure
        returns (RecoveryManagerStorage storage $)
    {
        assembly ("memory-safe") {
            $.slot := RECOVERY_MANAGER_STORAGE_LOCATION
        }
    }
}
