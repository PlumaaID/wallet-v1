// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Enum} from "@safe/contracts/common/Enum.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {RSAOwnerManager} from "./base/RSAOwnerManager.sol";
import {SafeManager} from "./base/SafeManager.sol";
import {RecoveryManager} from "./base/RecoveryManager.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title Plumaa - An RSA SHA256 PKCS1.5 enabler module for Safe{Wallet} Smart Accounts
///
/// It allows the Safe{Wallet} Smart Account to execute transactions signed with an RSA PKCS1.5 signature.
/// A notable example of RSA signatures in real-world applications are the government-issued digital certificates.
contract Plumaa is
    RSAOwnerManager,
    SafeManager,
    EIP712Upgradeable,
    RecoveryManager,
    IERC1271
{
    /// @notice A transaction signed with the Bytes32 owner's private key was executed
    event ExecutedRSATransaction(
        address indexed safe,
        bytes32 indexed sha256Digest,
        uint32 nonce,
        bool success
    );

    /// @notice The provided message SHA256 digest doesn't match signature for owner's public key
    error InvalidRSASignature(bytes32 digest, bytes signature);

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
    /// @param initialOwner The RSA public key of the owner
    /// @param safe_ The address of the Safe{Wallet} Smart Account
    /// @param recoveryThreshold The threshold for the recovery manager
    /// @param authorizedRecoverers The initial authorized recoverers
    function setupPlumaa(
        RSAOwnerManager.RSAPublicKey calldata initialOwner,
        Safe safe_,
        uint256 recoveryThreshold,
        address[] calldata authorizedRecoverers
    ) public initializer {
        __EIP712_init("RSAOwnerManager", "1");
        __RSAOwnerManager_init(initialOwner);
        __SafeManager_init(safe_);
        __RecoveryManager_init(recoveryThreshold, authorizedRecoverers);
    }

    /// @notice Checks if the provided signature is valid for the keccak256 hash.
    function isValidSignature(
        bytes32 keccak256Hash,
        bytes memory signature
    ) external view returns (bytes4) {
        // Most signers don't accept custom digests since it's not a good practice to deal with them directly.
        // Therefore, this contract expects sha256 hashes of keccak256 hashes (most likely EVM-produced). This
        // is secure assuming sha256 is a good cryptographic hash function.
        bytes32 sha256Digest = sha256(abi.encodePacked(keccak256Hash));
        return
            _verifyRSAOwner(sha256Digest, signature, owner())
                ? this.isValidSignature.selector
                : bytes4(0);
    }

    /// ===== Execution =====

    /// @notice Executes a transaction from the associated Safe{Wallet} Smart Account sing an RSA PKCS1.5 signature
    /// @param request The transaction request
    function executeTransaction(
        TransactionRequestData calldata request
    ) public virtual returns (bool) {
        if (block.timestamp >= request.deadline) {
            revert ExpiredRSATransaction(request.deadline);
        }

        uint32 currentNonce = _useOwnerNonce();

        (bool valid, bytes32 sha256Digest) = verifyRSAOwnerTransactionRequest(
            request,
            currentNonce
        );

        if (!valid) {
            revert InvalidRSASignature(sha256Digest, request.signature);
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
    /// @return digest The transaction request sha256 digest
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

        // EIP-712 defines typehash as a keccak256. However, PKCS1.5 requires a SHA256 digest.
        // Assuming SHA256 is a good hash function, the user would sign the sha256(keccak256(typehash)).
        bytes32 sha256Digest = sha256(abi.encodePacked(typehash));

        return (
            _verifyRSAOwner(sha256Digest, request.signature, owner()),
            sha256Digest
        );
    }

    /// ===== Recovery =====

    /// @notice Sets a new RSA Public Key Owner
    function setOwner(
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) public onlySafe {
        _setOwner(publicKey);
    }

    /// @notice Authorizes a recoverer to sign for the recovery of the Safe{Wallet} Smart Account
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers after the recoverer is added
    function authorizeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) public onlySafe {
        _authorizeRecoverer(recoverer, newThreshold);
    }

    /// @notice Revokes the authorization of a recoverer to sign for the recovery of the Safe{Wallet} Smart Account.
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers after the recoverer is removed
    function revokeRecoverer(
        address recoverer,
        uint256 newThreshold
    ) public onlySafe {
        _revokeRecoverer(recoverer, newThreshold);
    }

    /// @notice Swaps an authorized recoverer address.
    function swapRecoverer(
        address oldRecoverer,
        address newRecoverer
    ) public onlySafe {
        _swapRecoverer(oldRecoverer, newRecoverer);
    }

    /// @notice Changes the threshold of the recovery manager.
    ///
    /// Requirements:
    /// - The new threshold must be greater than 0
    /// - The new threshold must be less than or equal to the total number of recoverers
    function changeThreshold(uint256 newThreshold) public onlySafe {
        _changeThreshold(newThreshold);
    }

    /// @notice Changes the owner of the Plumaa module controlling the Safe{Wallet} Smart Account
    /// @param signers The authorized recovers that produced the signatures
    /// @param signatures The signatures of the authorized recoverers
    /// @param publicKey The new owner RSA public key
    ///
    /// Requirements:
    /// - The signatures must come from authorized recoverers.
    /// - The number of signatures must be greater than or equal to the threshold.
    /// - The signatures must be from different recoverers.
    /// - Recoverers and signatures must have a one-to-one correspondence.
    function recover(
        address[] calldata signers,
        bytes[] calldata signatures,
        RSAOwnerManager.RSAPublicKey calldata publicKey
    ) public override {
        _validateRecovery(signers, signatures, publicKey);
        _setOwner(publicKey);
    }
}
