// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BaseTest} from "./Base.t.sol";
import {RSASigner} from "./utils/RSASigner.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SafeMock} from "./mocks/Safe.m.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";
import {console2} from "forge-std/console2.sol";
import {Plumaa} from "~/Plumaa.sol";
import {SafeManager} from "~/base/SafeManager.sol";

/// @title Plumaa tests
contract PlumaaTest is BaseTest {
    // Default request arguments
    address private _defaultTo;
    uint256 private _defaultValue;
    Enum.Operation private _defaultOperation;
    uint48 private _defaultDeadline;
    bytes private _defaultData;
    uint32 private _defaultNonce;

    /// @notice Set default values for request arguments
    function setUp() public override {
        super.setUp();
        _defaultTo = address(receiver);
        _defaultValue = 0;
        _defaultOperation = Enum.Operation.Call;
        _defaultDeadline = uint48(block.timestamp) + 1;
        _defaultData = "";
        _defaultNonce = 0;
    }

    modifier whenSettingOwner() {
        _;
    }

    /// @notice it reverts because the sender is not the owner
    function test_GivenANonSafeOwner(
        address anyone,
        bytes memory exponent,
        bytes memory modulus
    ) external whenSettingOwner {
        vm.assume(anyone != address(safe));
        vm.assume(anyone != proxyAdmin);

        vm.prank(anyone);
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeManager.SafeManagerUnauthorizedAccount.selector,
                anyone
            )
        );
        plumaa.setOwner(exponent, modulus);
    }

    /// @notice it sets the owner because the sender is the owner
    function test_GivenTheSafeOwner(
        bytes memory exponent,
        bytes memory modulus
    ) external whenSettingOwner {
        bytes32 publicKeyId = keccak256(abi.encodePacked(exponent, modulus));
        vm.expectEmit(true, true, false, false);
        emit RSAOwnerManager.OwnershipTransferred(plumaa.owner(), publicKeyId);
        _forceEnableModule(address(this));
        safe.execTransactionFromModule(
            address(plumaa),
            0,
            abi.encodeWithSelector(plumaa.setOwner.selector, exponent, modulus),
            Enum.Operation.Call
        );
        assertEq(plumaa.owner(), publicKeyId);
    }

    /// @notice it should be initialized
    function test_WhenInitialized() external {
        RSASigner.PublicKey memory ownerPublicKey = owner.publicKey();
        bytes32 publicKeyId = keccak256(
            abi.encodePacked(ownerPublicKey.exponent, ownerPublicKey.modulus)
        );
        assertEq(plumaa.owner(), publicKeyId);
        assertEq(plumaa.nonce(), 0);
    }

    modifier whenCallingVerifyRSAOwnerTransactionRequest() {
        _;
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingTo(
        address to
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        vm.assume(to != _defaultTo);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.to = to;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingValue(
        uint256 value
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        vm.assume(value != _defaultValue);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.value = value;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingOperation()
        external
        whenCallingVerifyRSAOwnerTransactionRequest
    {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        // _defaultOperation == Enum.Operation.Call;
        request.operation = Enum.Operation.DelegateCall;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingDeadline(
        uint48 deadline
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        vm.assume(deadline != _defaultDeadline);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.deadline = deadline;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingData(
        bytes memory data
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        // Copy default data to memory
        bytes memory defaultData = _defaultData;

        // Assume default data is not the default data because the
        // used signature is product of the default data
        vm.assume(keccak256(data) != keccak256(defaultData));

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.data = data;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidVerifyingNonce(
        uint32 nonce
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        vm.assume(nonce != _defaultNonce);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            nonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the signature doesn't correspond to a valid owner
    function test_GivenATamperedVerifyingSignature(
        bytes memory signature
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.signature = signature;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidVerifyingOwner(
        address to,
        uint256 value,
        uint48 deadline,
        uint8 operation,
        bytes memory data,
        uint32 nonce
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        operation = uint8(bound(operation, 0, uint8(type(Enum.Operation).max)));

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeRequestData(
                other,
                to,
                value,
                Enum.Operation(operation),
                deadline,
                data,
                nonce
            );

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            nonce
        );

        assertFalse(valid);
        assertEq(digest, _toDigest(structHash));
    }

    /// @notice it should return true because the calculated digest matches the signed struct hash
    function test_GivenAValidVerifyingOwner(
        address to,
        uint256 value,
        uint48 deadline,
        uint8 operation,
        bytes memory data,
        uint32 nonce
    ) external whenCallingVerifyRSAOwnerTransactionRequest {
        operation = uint8(bound(operation, 0, uint8(type(Enum.Operation).max)));

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeRequestData(
                owner,
                to,
                value,
                Enum.Operation(operation),
                deadline,
                data,
                nonce
            );

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerTransactionRequest(
            request,
            nonce
        );

        assertTrue(valid);
        assertEq(digest, _toDigest(structHash));
    }

    modifier whenCallingExecuteTransaction() {
        _;
    }

    /// @notice it should revert because the request is no longer valid
    function test_GivenAExpiredRequest(
        uint48 afterDeadline
    ) external whenCallingExecuteTransaction {
        // _defaultDeadline is exactly before the deadline
        vm.assume(afterDeadline > 0);

        // Avoid deadline overflow
        vm.assume(afterDeadline <= _defaultDeadline);

        uint48 deadline = uint48(_defaultDeadline - afterDeadline);

        (Plumaa.TransactionRequestData memory request, ) = _forgeRequestData(
            owner,
            _defaultTo,
            _defaultValue,
            _defaultOperation,
            deadline,
            _defaultData,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.ExpiredRSATransaction.selector,
                deadline
            )
        );
        plumaa.executeTransaction(request);
    }

    modifier givenAValidRequest() {
        _;
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingTo(
        address to
    ) external whenCallingExecuteTransaction givenAValidRequest {
        vm.assume(to != _defaultTo);

        (
            Plumaa.TransactionRequestData memory request,

        ) = _forgeDefaultRequestData(owner);

        request.to = to;

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingValue(
        uint256 value
    ) external whenCallingExecuteTransaction givenAValidRequest {
        vm.assume(value != _defaultValue);

        (
            Plumaa.TransactionRequestData memory request,

        ) = _forgeDefaultRequestData(owner);

        request.value = value;

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingOperation()
        external
        whenCallingExecuteTransaction
        givenAValidRequest
    {
        (
            Plumaa.TransactionRequestData memory request,

        ) = _forgeDefaultRequestData(owner);

        // _defaultOperation == Enum.Operation.Call;
        request.operation = Enum.Operation.DelegateCall;

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingDeadline(
        uint48 deadline
    ) external whenCallingExecuteTransaction givenAValidRequest {
        // Not expired and not equal to the default deadline
        vm.assume(deadline > _defaultDeadline);

        (
            Plumaa.TransactionRequestData memory request,

        ) = _forgeDefaultRequestData(owner);

        request.deadline = deadline;

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingData(
        bytes memory data
    ) external whenCallingExecuteTransaction givenAValidRequest {
        // Copy default data to memory
        bytes memory defaultData = _defaultData;

        // Assume default data is not the default data because the
        // used signature is product of the default data
        vm.assume(keccak256(data) != keccak256(defaultData));

        (
            Plumaa.TransactionRequestData memory request,

        ) = _forgeDefaultRequestData(owner);

        request.data = data;

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidExecutingNonce(
        uint32 nonce
    ) external whenCallingExecuteTransaction givenAValidRequest {
        vm.assume(nonce != _defaultNonce);

        (Plumaa.TransactionRequestData memory request, ) = _forgeRequestData(
            owner,
            _defaultTo,
            _defaultValue,
            _defaultOperation,
            _defaultDeadline,
            _defaultData,
            nonce
        );

        bytes32 structHash = _requestStructHash(
            request.to,
            request.value,
            request.operation,
            request.deadline,
            request.data,
            _defaultNonce
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedExecutingSignature(
        bytes memory signature
    ) external whenCallingExecuteTransaction givenAValidRequest {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.signature = signature;

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidExecutingOwner()
        external
        whenCallingExecuteTransaction
        givenAValidRequest
    {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(other);

        vm.expectRevert(
            abi.encodeWithSelector(
                Plumaa.InvalidRSASignature.selector,
                _toDigest(structHash),
                request.signature,
                request.exponent,
                request.modulus
            )
        );
        plumaa.executeTransaction(request);
    }

    /// @notice Tests that a transaction can be executed only if the signature is valid.
    function test_GivenAValidExecutingOwner(
        uint256 value,
        bytes calldata data,
        uint48 expiresAfter,
        uint32 currentNonce
    ) external whenCallingExecuteTransaction givenAValidRequest {
        currentNonce = uint32(bound(currentNonce, 0, type(uint32).max - 1));

        // Not expired already
        vm.assume(expiresAfter > 0);

        // Avoid deadline overflow
        vm.assume(block.timestamp + expiresAfter <= type(uint48).max);

        plumaa.unsafeSetNonce(currentNonce);

        (
            Plumaa.TransactionRequestData memory requestData,
            bytes32 structHash
        ) = _forgeRequestData(
                owner,
                address(receiver),
                value,
                Enum.Operation.Call,
                uint48(block.timestamp) + expiresAfter,
                data,
                currentNonce
            );

        vm.expectEmit(true, true, true, true);
        emit SafeMock.ExecutedWith(
            address(receiver),
            value,
            data,
            Enum.Operation.Call
        );
        vm.expectEmit(true, true, true, true);
        emit Plumaa.ExecutedRSATransaction(
            address(safe),
            _toDigest(structHash),
            currentNonce,
            true
        );
        vm.deal(address(safe), value);
        bool success = plumaa.executeTransaction(requestData);
        assertTrue(success, "Plumaa: transaction failed");
        assertEq(currentNonce + 1, plumaa.nonce());
    }

    /// @notice Returns the default request data.
    function _forgeDefaultRequestData(
        RSASigner signer
    )
        private
        returns (
            Plumaa.TransactionRequestData memory requestData,
            bytes32 digest
        )
    {
        return
            _forgeRequestData(
                signer,
                _defaultTo,
                _defaultValue,
                _defaultOperation,
                _defaultDeadline,
                _defaultData,
                _defaultNonce
            );
    }

    /// @notice Applies sha256 to `structHash` so the digest is PKCS8 compliant
    function _toDigest(bytes32 structHash) private pure returns (bytes32) {
        return sha256(abi.encodePacked(structHash));
    }
}
