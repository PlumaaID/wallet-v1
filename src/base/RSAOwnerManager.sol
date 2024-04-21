// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import {RsaVerify} from "../utils/RsaVerify.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title Modified version of Safe's OwnerManager for RSA Public Keys that includes EIP7201 support.
 * [Safe's implementation](https://github.com/safe-global/safe-contracts/blob/main/contracts/base/OwnerManager.sol)
 */
abstract contract RSAOwnerManager is Initializable {
    using RsaVerify for bytes32;

    /// @notice Emitted when the owner is changed.
    event OwnershipTransferred(
        RSAPublicKey indexed previousOwner,
        RSAPublicKey indexed newOwner
    );

    // keccak256(abi.encode(uint256(keccak256("plumaa.storage.RSAOwnerManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant RSA_OWNER_MANAGER_STORAGE_LOCATION =
        0xd2cca958b80dbad5ce6e876a8c46f66173a169ce6aba515198c38d288b5cc600;

    struct RSAPublicKey {
        bytes exponent;
        bytes modulus;
    }

    struct RSAOwnerManagerStorage {
        RSAPublicKey owner;
        uint32 nonce;
    }

    /// @notice Sets the initial storage of the contract.
    function __RSAOwnerManager_init(
        RSAPublicKey calldata initialOwner
    ) internal onlyInitializing {
        _setOwner(initialOwner);
    }

    /// @notice Returns the current owner of the Plumaa.
    function owner() public view returns (RSAPublicKey memory) {
        return _getRSAOwnerManagerStorage().owner;
    }

    /// @notice Returns the current nonce of the Plumaa.
    function nonce() public view returns (uint32) {
        return _getRSAOwnerManagerStorage().nonce;
    }

    /// @notice Sets a new authorized public key as owner.
    /// Beware this internal version doesn't require access control.
    function _setOwner(RSAPublicKey memory newOwner) internal {
        RSAPublicKey memory previousOwner = _getRSAOwnerManagerStorage().owner;
        _getRSAOwnerManagerStorage().owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Returns true if the provided signature is valid for the digest and public key.
    /// @param message The message to verify.
    /// @param signature The signature to verify.
    /// @param publicKey The RSA public key to verify against.
    function _verifyRSAOwner(
        bytes memory message,
        bytes memory signature,
        RSAPublicKey memory publicKey
    ) internal view returns (bool) {
        return _verifyRSAOwner(sha256(message), signature, publicKey);
    }

    /// @notice Returns true if the provided signature is valid for the digest and public key.
    /// @param sha256Digest The digest of the message to verify.
    /// @param signature The signature to verify.
    /// @param publicKey The RSA public key to verify against.
    function _verifyRSAOwner(
        bytes32 sha256Digest,
        bytes memory signature,
        RSAPublicKey memory publicKey
    ) internal view returns (bool) {
        return
            _isRSAOwner(publicKey) &&
            sha256Digest.pkcs1Sha256(
                signature,
                publicKey.exponent,
                publicKey.modulus
            );
    }

    /// @notice Consumes a nonce.
    /// Returns the current value and increments nonce.
    function _useOwnerNonce() internal virtual returns (uint32) {
        unchecked {
            // It is important to do x++ and not ++x here.
            return _getRSAOwnerManagerStorage().nonce++;
        }
    }

    /// @notice Returns true if the provided public key is the owner of the Plumaa.
    function _isRSAOwner(
        RSAPublicKey memory publicKey
    ) private view returns (bool) {
        return
            _toRSAPublicKeyId(_getRSAOwnerManagerStorage().owner) ==
            _toRSAPublicKeyId(publicKey);
    }

    /// @notice For comparison purposes, returns the keccak256 hash of the public key components.
    function _toRSAPublicKeyId(
        RSAPublicKey memory publicKey
    ) private pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(publicKey.exponent, publicKey.modulus));
    }

    /// @notice Get EIP-7201 storage
    function _getRSAOwnerManagerStorage()
        private
        pure
        returns (RSAOwnerManagerStorage storage $)
    {
        assembly ("memory-safe") {
            $.slot := RSA_OWNER_MANAGER_STORAGE_LOCATION
        }
    }
}
