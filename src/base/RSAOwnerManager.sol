// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import {RsaVerify} from "../utils/RsaVerify.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title Modified version of Safe's OwnerManager for bytes32 that includes EIP7201 support.
 * [Safe's implementation](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/OwnerManager.sol)
 *
 * An RSA Owner is a public key identified by a `keccak(modulus, exponent)`.
 * @notice This version uses bytes32 instead of address for owners
 */
abstract contract RSAOwnerManager is Initializable {
    using RsaVerify for bytes32;

    /// @notice Emitted when the owner is changed.
    event OwnershipTransferred(
        bytes32 indexed previousOwner,
        bytes32 indexed newOwner
    );

    // keccak256(abi.encode(uint256(keccak256("plumaa.storage.RSAOwnerManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant RSA_OWNER_MANAGER_STORAGE_LOCATION =
        0xd2cca958b80dbad5ce6e876a8c46f66173a169ce6aba515198c38d288b5cc600;

    struct RSAOwnerManagerStorage {
        bytes32 owner;
        uint32 nonce;
    }

    /// @notice Sets the initial storage of the contract.
    function __RSAOwnerManager_init(
        bytes memory exponent,
        bytes memory modulus
    ) internal onlyInitializing {
        _setOwner(exponent, modulus);
    }

    /// @notice Returns the current owner of the Plumaa. See {_toPublicKeyId}.
    function owner() public view returns (bytes32) {
        return _getRSAOwnerManagerStorage().owner;
    }

    /// @notice Returns the current nonce of the Plumaa.
    function nonce() public view returns (uint32) {
        return _getRSAOwnerManagerStorage().nonce;
    }

    /// @notice Sets a new authorized public key bytes32 id. See {_toPublicKeyId}.
    /// Beware this internal version doesn't require access control.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function _setOwner(bytes memory exponent, bytes memory modulus) internal {
        bytes32 newOwner = _toPublicKeyId(exponent, modulus);
        bytes32 previousOwner = _getRSAOwnerManagerStorage().owner;
        _getRSAOwnerManagerStorage().owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Returns true if the provided signature is valid for the digest and public key.
    /// @param message The message to verify.
    /// @param signature The signature to verify.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function _verifyRSAOwner(
        bytes memory message,
        bytes memory signature,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bool) {
        return _verifyRSAOwner(sha256(message), signature, exponent, modulus);
    }

    /// @notice Returns true if the provided signature is valid for the digest and public key.
    /// @param sha256Digest The digest of the message to verify.
    /// @param signature The signature to verify.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function _verifyRSAOwner(
        bytes32 sha256Digest,
        bytes memory signature,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bool) {
        return
            _isRSAOwner(exponent, modulus) &&
            sha256Digest.pkcs1Sha256(signature, exponent, modulus);
    }

    /// @notice Consumes a nonce.
    /// Returns the current value and increments nonce.
    function _useOwnerNonce() internal virtual returns (uint32) {
        unchecked {
            // It is important to do x++ and not ++x here.
            return _getRSAOwnerManagerStorage().nonce++;
        }
    }

    /// @notice Returns true if the provided public key is an owner of the Plumaa.
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function _isRSAOwner(
        bytes memory exponent,
        bytes memory modulus
    ) private view returns (bool) {
        return
            _getRSAOwnerManagerStorage().owner ==
            _toPublicKeyId(exponent, modulus);
    }

    /// @notice On the absense of a proper public key, we identify each RSA owner by a keccak256(modulus, exponent).
    /// @param exponent The exponent of the RSA public key.
    /// @param modulus The modulus of the RSA public key.
    function _toPublicKeyId(
        bytes memory exponent,
        bytes memory modulus
    ) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(exponent, modulus));
    }

    /// @notice Get EIP-7201 storage
    function _getRSAOwnerManagerStorage()
        private
        pure
        returns (RSAOwnerManagerStorage storage $)
    {
        assembly {
            $.slot := RSA_OWNER_MANAGER_STORAGE_LOCATION
        }
    }
}
