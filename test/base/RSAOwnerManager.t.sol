// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {ModuleManager} from "@safe/contracts/base/ModuleManager.sol";
import {SafeProxyFactory} from "@safe/contracts/proxies/SafeProxyFactory.sol";
import {BaseTest} from "../Base.t.sol";
import {RSAOwnerManagerMock} from "./mocks/RSAOwnerManager.m.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";
import {SafeManager} from "~/base/SafeManager.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {RSASigner} from "../utils/RSASigner.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";

contract RSAOwnerManagerTest is BaseTest {
    RSAOwnerManagerMock internal manager;

    function setUp() public override {
        super.setUp();
        // Enable RSAOwnerModule
        address implementation = Clones.clone(
            address(new RSAOwnerManagerMock())
        );
        manager = RSAOwnerManagerMock(implementation);

        RSASigner.PublicKey memory publicKey = owner.publicKey();
        manager.initialize(publicKey.exponent, publicKey.modulus);
    }

    function test_WhenInitialized() external {
        RSASigner.PublicKey memory ownerPublicKey = owner.publicKey();
        bytes32 publicKeyId = keccak256(
            abi.encodePacked(ownerPublicKey.exponent, ownerPublicKey.modulus)
        );
        assertEq(manager.owner(), publicKeyId);
        assertEq(manager.nonce(), 0);
    }

    /// @notice it sets the owner because internal function has no access control
    function test_WhenCalling_setOwner(
        bytes memory exponent,
        bytes memory modulus,
        address anyone
    ) external {
        vm.prank(anyone);
        manager.$_setOwner(exponent, modulus);
        assertEq(
            manager.owner(),
            keccak256(abi.encodePacked(exponent, modulus))
        );
    }

    modifier whenCalling_verifyRSAOwnerWithRawData() {
        _;
    }

    modifier givenAValidSignature() {
        _;
    }

    /// @notice it returns true because is self authorized
    function test_GivenASignatureFromTheOwner(
        bytes memory message
    ) external whenCalling_verifyRSAOwnerWithRawData givenAValidSignature {
        RSASigner.PublicKey memory publicKey = owner.publicKey();

        bytes memory signature = owner.sign(message);
        bool result = manager.$_verifyRSAOwner(
            message,
            signature,
            publicKey.exponent,
            publicKey.modulus
        );

        assertTrue(result);
    }

    /// @notice it returns false because is not authorized
    function test_GivenASignatureFromANonOwner(
        bytes memory message
    ) external whenCalling_verifyRSAOwnerWithRawData givenAValidSignature {
        RSASigner.PublicKey memory publicKey = other.publicKey();

        bytes memory signature = other.sign(message);
        bool result = manager.$_verifyRSAOwner(
            message,
            signature,
            publicKey.exponent,
            publicKey.modulus
        );

        assertFalse(result);
    }

    /// @notice it returns false because is not authorized
    function test_GivenAnInvalidSignature(
        bytes memory signature
    ) external whenCalling_verifyRSAOwnerWithRawData {
        RSASigner.PublicKey memory publicKey = owner.publicKey();

        bool result = manager.$_verifyRSAOwner(
            bytes("message"),
            signature,
            publicKey.exponent,
            publicKey.modulus
        );

        assertFalse(result);
    }

    /// @notice it increments the nonce
    function test_WhenCalling_useOwnerNonce(
        uint32 currentNonce
    ) external whenCalling_verifyRSAOwnerWithRawData {
        // Avoid nonce overflow
        vm.assume(currentNonce != type(uint32).max);

        manager.unsafeSetNonce(currentNonce);
        manager.$_useOwnerNonce();
        assertEq(manager.nonce(), currentNonce + 1);
    }
}
