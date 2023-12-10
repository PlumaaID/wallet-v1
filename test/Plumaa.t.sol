// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BaseTest} from "./Base.sol";
import {RSASigner} from "./utils/RSASigner.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SafeMock} from "./mocks/Mocks.sol";
import {console2} from "forge-std/console2.sol";
import {Plumaa} from "~/Plumaa.sol";

/// @title Plumaa tests
contract PlumaaTest is BaseTest {
    // Default request arguments
    address private _defaultTo;
    uint256 private _defaultValue;
    Enum.Operation private _defaultOperation;
    uint48 private _defaultDeadline;
    bytes private _defaultData;
    uint256 private _defaultNonce;

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

    modifier whenCallingVerifyRSAOwnerRequest() {
        _;
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingTo(
        address to
    ) external whenCallingVerifyRSAOwnerRequest {
        vm.assume(to != _defaultTo);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.to = to;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingValue(
        uint256 value
    ) external whenCallingVerifyRSAOwnerRequest {
        vm.assume(value != _defaultValue);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.value = value;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingOperation()
        external
        whenCallingVerifyRSAOwnerRequest
    {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        // _defaultOperation == Enum.Operation.Call;
        request.operation = Enum.Operation.DelegateCall;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingDeadline(
        uint48 deadline
    ) external whenCallingVerifyRSAOwnerRequest {
        vm.assume(deadline != _defaultDeadline);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.deadline = deadline;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenATamperedVerifyingData(
        bytes memory data
    ) external whenCallingVerifyRSAOwnerRequest {
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

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            _defaultNonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidVerifyingNonce(
        uint256 nonce
    ) external whenCallingVerifyRSAOwnerRequest {
        vm.assume(nonce != _defaultNonce);

        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
            request,
            nonce
        );

        assertFalse(valid);
        assertNotEq(digest, _toDigest(structHash));
    }

    /// @notice it should return false because the signature doesn't correspond to a valid owner
    function test_GivenATamperedVerifyingSignature(
        bytes memory signature
    ) external whenCallingVerifyRSAOwnerRequest {
        (
            Plumaa.TransactionRequestData memory request,
            bytes32 structHash
        ) = _forgeDefaultRequestData(owner);

        request.signature = signature;

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
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
        uint256 nonce
    ) external whenCallingVerifyRSAOwnerRequest {
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

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
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
        uint256 nonce
    ) external whenCallingVerifyRSAOwnerRequest {
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

        (bool valid, bytes32 digest) = plumaa.verifyRSAOwnerRequest(
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
    }

    /// @notice it should revert because the calculated digest doesn't match the signed struct hash
    function test_GivenAnInvalidExecutingNonce(
        uint256 nonce
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
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
        plumaa.executeTransaction(payable(address(wallet)), request);
    }

    /// @notice Tests that a transaction can be executed only if the signature is valid.
    function test_GivenAValidExecutingOwner(
        uint256 value,
        bytes calldata data,
        uint48 expiresAfter
    ) external whenCallingExecuteTransaction givenAValidRequest {
        // Not expired already
        vm.assume(expiresAfter > 0);

        // Avoid deadline overflow
        vm.assume(block.timestamp + expiresAfter <= type(uint48).max);

        (
            Plumaa.TransactionRequestData memory requestData,

        ) = _forgeRequestData(
                owner,
                address(receiver),
                value,
                Enum.Operation.Call,
                uint48(block.timestamp) + expiresAfter,
                data,
                0
            );

        vm.expectEmit(true, true, true, true);
        emit SafeMock.ExecutedWith(
            address(receiver),
            value,
            data,
            Enum.Operation.Call
        );
        bool success = plumaa.executeTransaction(
            payable(address(wallet)),
            requestData
        );
        assertTrue(success, "Plumaa: transaction failed");
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

    function _toDigest(bytes32 structHash) private pure returns (bytes32) {
        return sha256(abi.encodePacked(structHash));
    }
}
