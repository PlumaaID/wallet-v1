// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Safe} from "@safe/contracts/Safe.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {RSAOwnerManager} from "./RSAOwnerManager.sol";
import {StorageSlot} from "../unreleased/StorageSlot.sol";
import {SlotDerivation} from "../unreleased/SlotDerivation.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title Recovery Manager for Plumaa.
///
/// Allows setting up recoverer accounts with a threshold to recover access to the Safe{Wallet} Smart Account.
///
/// NOTE: The RecoveryManager is designed for users loosing their RSA private key. The security model does not
/// consider cases where a stolen RSA private key is used to access Plumaa.
abstract contract RecoveryManager is Initializable, EIP712Upgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using SlotDerivation for bytes32;
    using StorageSlot for bytes32;
    using StorageSlot for StorageSlot.BooleanSlotType;
    using SignatureChecker for address;

    bytes32 internal constant _RECOVERY_REQUEST_TYPEHASH =
        keccak256("RecoveryRequest(bytes exponent, bytes modulus)");

    event RecovererAuthorized(address recoverer);
    event RecovererRevoked(address recoverer);
    event RecovererSwapped(address oldRecoverer, address newRecoverer);
    event ThresholdChanged(uint256 newThreshold);

    /// @dev The recovery threshold specified is invalid
    error RecoveryManagerInvalidThreshold(
        uint256 threshold,
        uint256 maxThreshold
    );

    /// @dev The recoverer is not authorized to recover the Safe{Wallet} Smart Account.
    error RecoveryManagerUnauthorizedRecoverer(address recoverer);

    /// @dev The threshold is not met for the recovery of the Safe{Wallet} Smart Account.
    error RecoveryManagerUnmetThreshold(uint256 threshold, uint256 met);

    // keccak256(abi.encode(uint256(keccak256("plumaa.storage.RecoveryManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant RECOVERY_MANAGER_STORAGE_LOCATION =
        0xaea9d69d7ee786fdbe7231abf0638150c26502253abb8647238d8da7bb87f100;

    struct RecoveryManagerStorage {
        EnumerableSet.AddressSet recoverers;
        uint256 threshold;
    }

    /// @notice Sets the initial storage of the contract.
    function __RecoveryManager_init(
        uint256 initialThreshold,
        address[] calldata initialRecoverers
    ) internal onlyInitializing {
        RecoveryManagerStorage storage $ = _getRecoveryManagerStorage();
        for (uint256 i = 0; i < initialRecoverers.length; i++) {
            $.recoverers.add(initialRecoverers[i]);
            emit RecovererAuthorized(initialRecoverers[i]);
        }
        _changeThreshold(initialThreshold);
    }

    /// @notice Returns the threshold of the recovery manager.
    function threshold() public view returns (uint256) {
        return _getRecoveryManagerStorage().threshold;
    }

    /// @notice Checks if the recoverer is an authorized recoverer.
    function isAuthorizedRecoverer(
        address recoverer
    ) public view returns (bool) {
        return _getRecoveryManagerStorage().recoverers.contains(recoverer);
    }

    /// @dev Return the entire set of recoverers in an array
    ///
    /// WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
    /// to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
    /// this function has an unbounded cost, and using it as part of a state-changing function may render the function
    /// uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
    function recoverers() public view returns (address[] memory) {
        return _getRecoveryManagerStorage().recoverers.values();
    }

    /// @notice Returns the number of recoverers.
    function recoverersLength() public view returns (uint256) {
        return _getRecoveryManagerStorage().recoverers.length();
    }

    /// @notice Authorizes a recoverer to sign for the recovery of the Safe{Wallet} Smart Account.
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers after the recoverer is added
    function _authorizeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) internal {
        _getRecoveryManagerStorage().recoverers.add(recoverer);
        emit RecovererAuthorized(recoverer);
        _changeThreshold(newThreshold); // Is important this is called after the recoverer is added
    }

    /// @notice Revokes the authorization of a recoverer to sign for the recovery of the Safe{Wallet} Smart Account.
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers after the recoverer is removed
    function _revokeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) internal {
        _getRecoveryManagerStorage().recoverers.remove(recoverer);
        emit RecovererRevoked(recoverer);
        _changeThreshold(newThreshold); // Is important this is called after the recoverer is removed
    }

    /// @notice Swaps the recoverer address.
    function _swapRecoverer(
        address oldRecoverer,
        address newRecoverer
    ) internal {
        RecoveryManagerStorage storage $ = _getRecoveryManagerStorage();
        $.recoverers.remove(oldRecoverer);
        $.recoverers.add(newRecoverer);
        emit RecovererSwapped(oldRecoverer, newRecoverer);
    }

    /// @notice Changes the threshold of the recovery manager.
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers
    function _changeThreshold(uint256 newThreshold) internal {
        RecoveryManagerStorage storage $ = _getRecoveryManagerStorage();
        _validateNewThreshold(newThreshold, $.recoverers.length());
        $.threshold = newThreshold;
        emit ThresholdChanged(newThreshold);
    }

    /// @notice Validates the recovery EIP-712 signatures from authorized recoverers.
    /// @param signers The recoverers that signed the recovery request.
    /// @param signatures The signatures to validate.
    /// @param publicKey The new owner RSA public key.
    ///
    /// Requirements:
    /// - The signatures must come from authorized recoverers.
    /// - The number of signatures must be greater than or equal to the threshold.
    /// - The signatures must be from different recoverers.
    /// - Recoverers and signatures must have a one-to-one correspondence.
    function _validateRecovery(
        address[] calldata signers,
        bytes[] calldata signatures,
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) internal {
        bytes32 typehash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _RECOVERY_REQUEST_TYPEHASH,
                    publicKey.exponent,
                    publicKey.modulus
                )
            )
        );

        if (signatures.length < threshold()) {
            revert RecoveryManagerUnmetThreshold(
                threshold(),
                signatures.length
            );
        }

        // Transient storage slot to keep track of the recoverers that have already signed
        bytes32 tRecovererAlreadySigned = RECOVERY_MANAGER_STORAGE_LOCATION;

        // Loop around signatures.
        // Prodiving mising recoverers will panic when accessing out of bounds.
        // Providing extra recoverers will ignore the extra ones.
        for (uint256 i = 0; i < signatures.length; i++) {
            address recoverer = signers[i];

            bool isValidSignature = recoverer.isValidSignatureNow(
                typehash,
                signatures[i]
            );

            StorageSlot.BooleanSlotType recovererAlreadySigned = tRecovererAlreadySigned
                    .deriveMapping(recoverer)
                    .asBoolean();

            if (
                !isValidSignature ||
                !isAuthorizedRecoverer(recoverer) ||
                recovererAlreadySigned.tload()
            ) {
                revert RecoveryManagerUnauthorizedRecoverer(recoverer);
            }

            recovererAlreadySigned.tstore(true);
        }
    }

    /// @notice Validates the threshold.
    /// Threshold can't be 0 or greater than the total recoverers.
    function _validateNewThreshold(
        uint256 newThreshold,
        uint256 totalRecoverers
    ) private pure {
        if (newThreshold == 0 || newThreshold > totalRecoverers) {
            revert RecoveryManagerInvalidThreshold(
                newThreshold,
                totalRecoverers
            );
        }
    }

    function recover(
        address[] calldata signers,
        bytes[] calldata signatures,
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) public virtual;

    /// @notice Get EIP-7201 storage
    function _getRecoveryManagerStorage()
        private
        pure
        returns (RecoveryManagerStorage storage $)
    {
        assembly ("memory-safe") {
            $.slot := RECOVERY_MANAGER_STORAGE_LOCATION
        }
    }
}
