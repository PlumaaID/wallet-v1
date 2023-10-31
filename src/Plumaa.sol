// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Enum} from "@safe/contracts/common/Enum.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {RSAOwnerManager} from "./base/RSAOwnerManager.sol";

/// @title Plumaa - An RSA SHA256 PKCS1.5 enabler module for Safe{Wallet} Smart Accounts
contract Plumaa is RSAOwnerManager {
    /// @notice A transaction signed with the Bytes32 owner's private key was executed
    event ExecutedRSATransaction(
        address indexed wallet,
        bytes32 indexed sha256Digest,
        uint256 nonce,
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

    bytes32 internal constant TRANSACTION_REQUEST_TYPEHASH =
        keccak256(
            "TransactionRequest(address to,uint256 value,uint8 operation,uint48 deadline,bytes data,uint256 nonce)"
        );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with an RSA owner
    function setupPlumaa(
        bytes memory exponent,
        bytes memory modulus
    ) public initializer {
        __RSAOwnerManager_init();
        _setOwner(exponent, modulus);
    }

    /// @notice Executes a transaction from a Safe{Wallet} Smart Account using an RSA PKCS1.5 signature
    /// @param wallet The Safe{Wallet} Smart Account address
    /// @param request The transaction request
    function executeTransaction(
        address payable wallet,
        TransactionRequestData calldata request
    ) public payable virtual returns (bool) {
        if (block.timestamp >= request.deadline) {
            revert ExpiredRSATransaction(request.deadline);
        }

        uint256 nonce = useOwnerNonce();

        (bytes32 sha256Digest, bool valid) = verifyRSAOwnerRequest(
            request,
            nonce
        );

        if (!valid) {
            revert InvalidRSASignature(
                sha256Digest,
                request.signature,
                request.exponent,
                request.modulus
            );
        }

        bool success = Safe(wallet).execTransactionFromModule(
            request.to,
            request.value,
            request.data,
            request.operation
        );

        emit ExecutedRSATransaction(wallet, sha256Digest, nonce, success);

        return success;
    }

    /// @notice Checks if the SHA256 digest of a transaction request {_hashTypedDataV4} value is signed by the RSA owner.
    /// @param request The transaction request
    /// @return digest The transaction request digest
    /// @return valid True if the transaction request is signed by the RSA owner
    function verifyRSAOwnerRequest(
        TransactionRequestData calldata request,
        uint256 nonce
    ) internal view virtual returns (bytes32 digest, bool valid) {
        bytes32 typehash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    TRANSACTION_REQUEST_TYPEHASH,
                    request.to,
                    request.value,
                    request.operation,
                    request.deadline,
                    keccak256(request.data),
                    nonce
                )
            )
        );

        // Hashing again is required to be PKCS8 compliant
        bytes32 sha256Digest = sha256(abi.encodePacked(typehash));

        return (
            sha256Digest,
            verifyRSAOwner(
                sha256Digest,
                request.signature,
                request.exponent,
                request.modulus
            )
        );
    }
}