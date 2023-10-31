// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import {SelfAuthorized} from "@safe/contracts/common/SelfAuthorized.sol";
import {RsaVerify} from "SolRsaVerify/RsaVerify.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/**
 * @title Modified version of Safe's OwnerManager for bytes32 that includes EIP7201 support.
 * (https://github.com/safe-global/safe-contracts/blob/main/contracts/base/OwnerManager.solF)
 *
 * An RSA Owner is a public key identified by a `keccak(modulus, exponent)`.
 * @notice This version uses bytes32 instead of address for owners
 */
abstract contract RSAOwnerManager is SelfAuthorized, EIP712Upgradeable {
    using RsaVerify for bytes32;

    event AddedRSAOwner(bytes32 indexed owner);
    event RemovedRSAOwner(bytes32 indexed owner);
    event ChangedRSAThreshold(uint256 threshold);

    // keccak256(abi.encode(uint256(keccak256("plumaa.storage.RSAOwnerManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant RSAOwnerManagerStorageLocation =
        0xd2cca958b80dbad5ce6e876a8c46f66173a169ce6aba515198c38d288b5cc600;

    struct RSAOwnerManagerStorage {
        bytes32 owner;
        uint32 nonce;
    }

    /// @notice Sets the initial storage of the contract.
    function __RSAOwnerManager_init() internal onlyInitializing {
        __EIP712_init_unchained("RSAOwner", "1");
    }

    /// @notice Sets a new authorized public key bytes32 id. See {toPublicKeyId}.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function setOwner(
        bytes memory exponent,
        bytes memory modulus
    ) external authorized {
        _setOwner(modulus, exponent);
    }

    /// @notice Internal version of {setOwner} without access control.
    function _setOwner(bytes memory exponent, bytes memory modulus) internal {
        _getRSAOwnerManagerStorage().owner = toPublicKeyId(modulus, exponent);
    }

    /// @notice On the absense of a proper public key, we identify each RSA owner by a keccak256(modulus, exponent).
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function toPublicKeyId(
        bytes memory exponent,
        bytes memory modulus
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(exponent, modulus));
    }

    /// @notice Returns true if the provided signature is valid for the dignest and public key.
    /// @param message The message to verify.
    /// @param signature The signature to verify.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function verifyRSAOwner(
        bytes memory message,
        bytes memory signature,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bool) {
        return
            isRSAOwner(exponent, modulus) &&
            verifyRSAOwner(sha256(message), signature, exponent, modulus);
    }

    /// @notice Returns true if the provided signature is valid for the dignest and public key.
    /// @param sha256Digest The digest of the message to verify.
    /// @param signature The signature to verify.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function verifyRSAOwner(
        bytes32 sha256Digest,
        bytes memory signature,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bool) {
        return
            isRSAOwner(exponent, modulus) &&
            sha256Digest.pkcs1Sha256(signature, exponent, modulus);
    }

    /// @notice Returns true if the provided public key is an owner of the Safe.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function isRSAOwner(
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bool) {
        return
            _getRSAOwnerManagerStorage().owner ==
            toPublicKeyId(exponent, modulus);
    }

    /// @notice Consumes a nonce.
    /// Returns the current value and increments nonce.
    function useOwnerNonce() internal virtual returns (uint256) {
        unchecked {
            // It is important to do x++ and not ++x here.
            return _getRSAOwnerManagerStorage().nonce++;
        }
    }

    /// @notice Get EIP-7201 storage
    function _getRSAOwnerManagerStorage()
        private
        pure
        returns (RSAOwnerManagerStorage storage $)
    {
        assembly {
            $.slot := RSAOwnerManagerStorageLocation
        }
    }
}
