// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Enum} from "@safe/contracts/common/Enum.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {RSAOwnerManager} from "./base/RSAOwnerManager.sol";
import {SafeManager} from "./base/SafeManager.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/// @title Plumaa - An RSA SHA256 PKCS1.5 enabler module for Safe{Wallet} Smart Accounts
contract Plumaa is RSAOwnerManager, SafeManager, EIP712Upgradeable {
    /// @notice A transaction signed with the Bytes32 owner's private key was executed
    event ExecutedRSATransaction(
        address indexed safe,
        bytes32 indexed sha256Digest,
        uint32 nonce,
        bool success
    );

    /// @notice The provided message SHA256 digest doesn't match signature for exponent and modulus
    error InvalidRSASignature(
        bytes32 digest,
        bytes signature,
        bytes exponent,
        bytes modulus
    );

    /// @dev The request `deadline` has expired.
    error ExpiredRSATransaction(uint48 deadline);

    /// @param to The destination address of the transaction
    /// @param value The amount of ETH to transfer
    /// @param data The data of the transaction
    /// @param operation The operation of the transaction
    /// @param deadline The deadline of the transaction
    struct TransactionRequestData {
        address to;
        uint256 value;
        Enum.Operation operation;
        uint48 deadline;
        bytes data;
        bytes signature;
        bytes exponent;
        bytes modulus;
    }

    bytes32 internal constant _TRANSACTION_REQUEST_TYPEHASH =
        keccak256(
            "TransactionRequest(address to,uint256 value,uint8 operation,uint48 deadline,bytes data,uint32 nonce)"
        );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with an RSA owner
    /// @param exponent The exponent of the RSA public key
    /// @param modulus The modulus of the RSA public key
    /// @param safe_ The address of the Safe{Wallet} Smart Account
    function setupPlumaa(
        bytes memory exponent,
        bytes memory modulus,
        Safe safe_
    ) public initializer {
        __EIP712_init("RSAOwnerManager", "1");
        __RSAOwnerManager_init(exponent, modulus);
        __SafeManager_init(safe_);
    }

    /// @notice Executes a transaction from the associated Safe{Wallet} Smart Account using an RSA PKCS1.5 signature
    /// @param request The transaction request
    function executeTransaction(
        TransactionRequestData calldata request
    ) public payable virtual returns (bool) {
        if (block.timestamp >= request.deadline) {
            revert ExpiredRSATransaction(request.deadline);
        }

        uint32 currentNonce = _useOwnerNonce();

        (bool valid, bytes32 sha256Digest) = verifyRSAOwnerTransactionRequest(
            request,
            currentNonce
        );

        if (!valid) {
            revert InvalidRSASignature(
                sha256Digest,
                request.signature,
                request.exponent,
                request.modulus
            );
        }

        Safe _safe = safe();

        bool success = _safe.execTransactionFromModule(
            request.to,
            request.value,
            request.data,
            request.operation
        );

        emit ExecutedRSATransaction(
            address(_safe),
            sha256Digest,
            currentNonce,
            success
        );

        return success;
    }

    /// @notice Checks if the SHA256 digest of a transaction request {_hashTypedDataV4} value is signed by the RSA owner.
    /// @param request The transaction request
    /// @param currentNonce The nonce of the RSA owner
    /// @return valid True if the transaction request is signed by the RSA owner
    /// @return digest The transaction request digest
    function verifyRSAOwnerTransactionRequest(
        TransactionRequestData calldata request,
        uint32 currentNonce
    ) public view virtual returns (bool valid, bytes32 digest) {
        bytes32 typehash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    _TRANSACTION_REQUEST_TYPEHASH,
                    request.to,
                    request.value,
                    request.operation,
                    request.deadline,
                    keccak256(request.data),
                    currentNonce
                )
            )
        );

        // Hashing again is required to be PKCS8 compliant
        bytes32 sha256Digest = sha256(abi.encodePacked(typehash));

        return (
            _verifyRSAOwner(
                sha256Digest,
                request.signature,
                request.exponent,
                request.modulus
            ),
            sha256Digest
        );
    }

    /// @notice Sets the RSA Owner
    /// @param exponent The exponent of the RSA public key
    /// @param modulus The modulus of the RSA public key
    function setOwner(
        bytes memory exponent,
        bytes memory modulus
    ) public onlySafe {
        _setOwner(exponent, modulus);
    }
}
