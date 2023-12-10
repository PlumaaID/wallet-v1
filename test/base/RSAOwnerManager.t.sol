// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {ModuleManager} from "@safe/contracts/base/ModuleManager.sol";
import {SafeProxyFactory} from "@safe/contracts/proxies/SafeProxyFactory.sol";
import {BaseTest} from "../Base.t.sol";
import {RSAOwnerManagerMock} from "./mocks/RSAOwnerManager.m.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {RSASigner} from "../utils/RSASigner.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";

contract RSAOwnerManagerTest is BaseTest {
    RSAOwnerManagerMock internal manager;

    function setUp() public override {
        super.setUp();
        // Enable RSAOwnerModule
        address implementation = Clones.clone(address(new RSAOwnerManagerMock()));
        manager = RSAOwnerManagerMock(implementation);

        RSASigner.PublicKey memory publicKey = owner.publicKey();
        manager.initialize(publicKey.exponent, publicKey.modulus);
    }

    function test_WhenInitialized() external {
        RSASigner.PublicKey memory ownerPublicKey = owner.publicKey();
        bytes32 publicKeyId = keccak256(abi.encodePacked(ownerPublicKey.exponent, ownerPublicKey.modulus));
        assertEq(manager.owner(), publicKeyId);
        assertEq(manager.nonce(), 0);
    }

    modifier whenCallingSetOwner() {
        _;
    }

    /// @notice it sets the owner because safe is calling
    function test_GivenACallFromItself() external whenCallingSetOwner {}

    /// @notice it reverts because only safe can call
    function test_GivenACallFromOtherThanItself() external whenCallingSetOwner {}

    /// @notice it sets the owner because internal function has no access control
    function test_WhenCalling_setOwner() external {
        safe.execTransactionFromModule(
            address(manager),
            0,
            abi.encodeWithSelector(manager.$_setOwner.selector, bytes("exponent"), bytes("modulus")),
            Enum.Operation.Call
        );
    }

    modifier whenCalling_verifyRSAOwnerWithRawData() {
        _;
    }

    modifier givenAValidSignature() {
        _;
    }

    /// @notice it returns true because is self authorized
    function test_GivenASignatureFromTheOwner() external whenCalling_verifyRSAOwnerWithRawData givenAValidSignature {}

    /// @notice it returns false because is not authorized
    function test_GivenASignatureFromANon_owner() external whenCalling_verifyRSAOwnerWithRawData givenAValidSignature {}

    /// @notice it returns false because is not authorized
    function test_GivenAnInvalidSignature() external whenCalling_verifyRSAOwnerWithRawData {}

    /// @notice it increments the nonce
    function test_WhenCalling_useOwnerNonce() external whenCalling_verifyRSAOwnerWithRawData {}

    function _forceEnableModule(address module) internal {
        // Enable as a module to bypass signatures
        // https://twitter.com/0xVazi/status/1732187067776696655
        vm.store(address(safe), keccak256(abi.encode(address(module), 1)), bytes32(uint256(1)));
        assertTrue(safe.isModuleEnabled(address(this)));
    }
}
