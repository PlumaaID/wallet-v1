// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {RecoveryManagerMock, RecoveryManager} from "./mocks/RecoveryManager.m.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {BaseTest} from "../Base.t.sol";

contract RecoveryManagerTest is BaseTest {
    RecoveryManagerMock internal manager;

    function setUp() public override {
        super.setUp();

        // Enable RecoveryManager
        address implementation = Clones.clone(
            address(new RecoveryManagerMock())
        );
        manager = RecoveryManagerMock(implementation);
        address[] memory recoverers = new address[](1);
        recoverers[0] = address(this);
        manager.initialize(1, recoverers);
    }

    RecoveryManagerMock internal uninitializedManager;

    modifier whenInitialized() {
        address implementation = Clones.clone(
            address(new RecoveryManagerMock())
        );
        uninitializedManager = RecoveryManagerMock(implementation);
        _;
    }

    mapping(address => bool) test_GivenAThresholdSmallerThanTheRecoverersLengthAndNon_zeroSeen;

    /// @notice it sets the initial threshold and signers because the threshold is valid
    function test_GivenAThresholdSmallerThanTheRecoverersLengthAndNon_zero(
        uint256 initialThreshold,
        address[] memory initialRecoverers
    ) external whenInitialized {
        vm.assume(initialRecoverers.length > 0);

        uint256 duplicated;

        for (uint256 i = 0; i < initialRecoverers.length; i++) {
            if (
                test_GivenAThresholdSmallerThanTheRecoverersLengthAndNon_zeroSeen[
                    initialRecoverers[i]
                ]
            ) {
                duplicated++;
            }
            test_GivenAThresholdSmallerThanTheRecoverersLengthAndNon_zeroSeen[
                initialRecoverers[i]
            ] = true;
        }

        initialThreshold = bound(
            initialThreshold,
            1,
            initialRecoverers.length - duplicated
        );
        uninitializedManager.initialize(initialThreshold, initialRecoverers);
        assertEq(uninitializedManager.threshold(), initialThreshold);
        address[] memory recoverers = uninitializedManager.recoverers();

        assertEq(recoverers.length, initialRecoverers.length - duplicated);

        // All initial recoverers must be authorized
        for (uint256 i = 0; i < initialRecoverers.length; i++) {
            assertTrue(
                uninitializedManager.isAuthorizedRecoverer(initialRecoverers[i])
            );
        }
    }

    mapping(address => bool) test_GivenAThresholdHigherThanRecoverersLengthSeen;

    /// @notice it reverts because the threshold is invalid
    function test_GivenAThresholdHigherThanRecoverersLength(
        uint256 initialThreshold,
        address[] memory initialRecoverers
    ) external whenInitialized {
        uint256 duplicated;

        for (uint256 i = 0; i < initialRecoverers.length; i++) {
            if (
                test_GivenAThresholdHigherThanRecoverersLengthSeen[
                    initialRecoverers[i]
                ]
            ) {
                duplicated++;
            }
            test_GivenAThresholdHigherThanRecoverersLengthSeen[
                initialRecoverers[i]
            ] = true;
        }

        vm.assume(initialThreshold > initialRecoverers.length - duplicated);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                initialThreshold,
                initialRecoverers.length - duplicated
            )
        );
        uninitializedManager.initialize(initialThreshold, initialRecoverers);
    }

    mapping(address => bool) internal test_GivenAZeroThresholdSeen;

    /// @notice it reverts because the threshold is invalid
    function test_GivenAZeroThreshold(
        address[] memory initialRecoverers
    ) external whenInitialized {
        uint256 duplicated;

        for (uint256 i = 0; i < initialRecoverers.length; i++) {
            if (test_GivenAZeroThresholdSeen[initialRecoverers[i]]) {
                duplicated++;
            }
            test_GivenAZeroThresholdSeen[initialRecoverers[i]] = true;
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                0,
                initialRecoverers.length - duplicated
            )
        );
        uninitializedManager.initialize(0, initialRecoverers);
    }

    modifier whenCalling_authorizeRecoverer(
        address[] memory initialRecoverers
    ) {
        uint256 length = bound(initialRecoverers.length, 0, 10); // To avoid gas exhaustion
        for (uint256 i = 0; i < length; i++) {
            manager.$_authorizeRecoverer(initialRecoverers[i], 1);
        }
        _;
    }

    /// @notice it sets the new threshold and authorizes the recoverer because the threshold is valid
    function test_GivenAValidNewThresholdAfterAuthorization(
        address recoverer,
        uint256 newThreshold,
        address[] memory initialRecoverers
    ) external whenCalling_authorizeRecoverer(initialRecoverers) {
        uint256 increment = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(0)
            : uint256(1);
        vm.assume(!manager.isAuthorizedRecoverer(recoverer));
        newThreshold = bound(
            newThreshold,
            1,
            manager.recoverersLength() + increment
        );
        manager.$_authorizeRecoverer(recoverer, newThreshold);
        assertEq(manager.threshold(), newThreshold);
        assertTrue(manager.isAuthorizedRecoverer(recoverer));
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdHigherThanTheRecoverersLengthAfterAuthorization(
        address recoverer,
        uint256 newThreshold,
        address[] memory initialRecoverers
    ) external whenCalling_authorizeRecoverer(initialRecoverers) {
        uint256 increment = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(0)
            : uint256(1);
        vm.assume(newThreshold > manager.recoverersLength() + increment);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                newThreshold,
                manager.recoverersLength() + increment
            )
        );
        manager.$_authorizeRecoverer(recoverer, newThreshold);
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdEqualToZeroAfterAuthorization(
        address recoverer,
        address[] memory initialRecoverers
    ) external whenCalling_authorizeRecoverer(initialRecoverers) {
        uint256 increment = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(0)
            : uint256(1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                0,
                manager.recoverersLength() + increment
            )
        );
        manager.$_authorizeRecoverer(recoverer, 0);
    }

    modifier whenCalling_revokeRecoverer(address[] memory initialRecoverers) {
        uint256 length = bound(initialRecoverers.length, 0, 10); // To avoid gas exhaustion
        for (uint256 i = 0; i < length; i++) {
            manager.$_authorizeRecoverer(initialRecoverers[i], 1);
        }
        _;
    }

    /// @notice it sets the new threshold and revokes the recoverer because the threshold is valid
    function test_GivenAValidNewThresholdAfterRevoking(
        uint256 newThreshold,
        address recoverer,
        address[] memory initialRecoverers
    ) external whenCalling_revokeRecoverer(initialRecoverers) {
        uint256 decrement = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(1)
            : uint256(0);
        newThreshold = bound(
            newThreshold,
            1,
            manager.recoverersLength() - decrement
        );
        manager.$_revokeRecoverer(recoverer, newThreshold);
        assertEq(manager.threshold(), newThreshold);
        assertFalse(manager.isAuthorizedRecoverer(recoverer));
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdHigherThanTheRecoverersLengthAfterRevoking(
        address recoverer,
        uint256 newThreshold,
        address[] memory initialRecoverers
    ) external whenCalling_revokeRecoverer(initialRecoverers) {
        uint256 decrement = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(1)
            : uint256(0);
        vm.assume(newThreshold > manager.recoverersLength());
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                newThreshold,
                manager.recoverersLength() - decrement
            )
        );
        manager.$_revokeRecoverer(recoverer, newThreshold);
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdEqualToZeroAfterRevoking(
        address recoverer,
        address[] memory initialRecoverers
    ) external whenCalling_revokeRecoverer(initialRecoverers) {
        uint256 decrement = manager.isAuthorizedRecoverer(recoverer)
            ? uint256(1)
            : uint256(0);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                0,
                manager.recoverersLength() - decrement
            )
        );
        manager.$_revokeRecoverer(recoverer, 0);
    }

    /// @notice it swaps the recoverers because the new recoverer is valid
    function test_WhenCalling_swapRecoverer(
        address recoverer,
        address newRecoverer
    ) external {
        manager.$_authorizeRecoverer(recoverer, 1);

        manager.$_swapRecoverer(recoverer, newRecoverer);
        assertFalse(manager.isAuthorizedRecoverer(recoverer));
        assertTrue(manager.isAuthorizedRecoverer(newRecoverer));
    }

    modifier whenCalling_changeThreshold(address[] memory initialRecoverers) {
        uint256 length = bound(initialRecoverers.length, 0, 10); // To avoid gas exhaustion
        for (uint256 i = 0; i < length; i++) {
            manager.$_authorizeRecoverer(initialRecoverers[i], 1);
        }
        _;
    }

    /// @notice it sets the new threshold because the threshold is valid
    function test_GivenAValidNewThreshold(
        uint256 newThreshold,
        address[] memory initialRecoverers
    ) external whenCalling_changeThreshold(initialRecoverers) {
        vm.assume(initialRecoverers.length > 1);
        newThreshold = bound(newThreshold, 1, manager.recoverersLength());
        manager.$_changeThreshold(newThreshold);
        assertEq(manager.threshold(), newThreshold);
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdHigherThanTheRecoverersLength(
        uint256 newThreshold,
        address[] memory initialRecoverers
    ) external whenCalling_changeThreshold(initialRecoverers) {
        vm.assume(newThreshold > manager.recoverersLength());
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                newThreshold,
                manager.recoverersLength()
            )
        );
        manager.$_changeThreshold(newThreshold);
    }

    /// @notice it reverts because the new threshold is invalid
    function test_GivenANewThresholdEqualToZero(
        address[] memory initialRecoverers
    ) external whenCalling_changeThreshold(initialRecoverers) {
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerInvalidThreshold.selector,
                0,
                manager.recoverersLength()
            )
        );
        manager.$_changeThreshold(0);
    }

    struct RecoveryEOASigner {
        address signer;
        uint256 privateKey;
        bytes recoverySignature;
    }

    RecoveryEOASigner[] internal signers;

    modifier whenCalling_validateRecovery(
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    ) {
        vm.assume(signerNames.length > 1);
        uint256 signersLength = bound(signerNames.length, 2, 10); // To avoid gas exhaustion
        bytes32 typehash = manager.structHash(publicKey);

        for (uint256 i = 0; i < signersLength; i++) {
            (address signer, uint256 privateKey) = makeAddrAndKey(
                string(abi.encodePacked(signerNames[i], i))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, typehash);
            bytes memory signature = abi.encodePacked(r, s, v);
            RecoveryEOASigner memory eoaSigner = RecoveryEOASigner({
                signer: signer,
                privateKey: privateKey,
                recoverySignature: signature
            });
            signers.push(eoaSigner);
            manager.$_authorizeRecoverer(signer, 1);
        }
        _;
    }

    /// @notice it reverts because the threshold is not met
    function test_GivenSignaturesLengthSmallerThanTheThreshold(
        uint256 threshold,
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    ) external whenCalling_validateRecovery(signerNames, publicKey) {
        threshold = bound(threshold, 1, signers.length);
        manager.$_changeThreshold(threshold);

        uint256 unmetThreshold = threshold - 1;

        address[] memory _signers = new address[](unmetThreshold);
        for (uint256 i = 0; i < unmetThreshold; i++) {
            _signers[i] = signers[i].signer;
        }
        bytes[] memory _signatures = new bytes[](unmetThreshold);
        for (uint256 i = 0; i < unmetThreshold; i++) {
            _signatures[i] = signers[i].recoverySignature;
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerUnmetThreshold.selector,
                manager.threshold(),
                _signatures.length
            )
        );
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }

    /// @notice it reverts because there are no valid signatures
    function test_GivenNoSignatures(
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    ) external whenCalling_validateRecovery(signerNames, publicKey) {
        address[] memory _signers = new address[](0);
        bytes[] memory _signatures = new bytes[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerUnmetThreshold.selector,
                manager.threshold(),
                0
            )
        );
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }

    modifier givenAValidAmountOfSignatures() {
        _;
    }

    /// @notice it returns true because the threshold is met
    function test_GivenValidSignatures(
        uint256 threshold,
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    )
        external
        whenCalling_validateRecovery(signerNames, publicKey)
        givenAValidAmountOfSignatures
    {
        threshold = bound(threshold, 1, signers.length);
        manager.$_changeThreshold(threshold);

        address[] memory _signers = new address[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signers[i] = signers[i].signer;
        }
        bytes[] memory _signatures = new bytes[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signatures[i] = signers[i].recoverySignature;
        }
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }

    /// @notice it reverts because there is at least one invalid signature
    function test_GivenInvalidSignatures(
        uint256 threshold,
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    )
        external
        whenCalling_validateRecovery(signerNames, publicKey)
        givenAValidAmountOfSignatures
    {
        threshold = bound(threshold, 1, signers.length);
        manager.$_changeThreshold(threshold);

        address[] memory _signers = new address[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signers[i] = signers[i].signer;
        }
        bytes[] memory _signatures = new bytes[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signatures[i] = signers[i].recoverySignature;
        }
        // Tamper with the first signature
        _signatures[0][0] ^= 0x01;
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerUnauthorizedRecoverer.selector,
                _signers[0]
            )
        );
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }

    /// @notice it reverts because there is at least one duplicated signature
    function test_GivenDuplicatedSignatures(
        uint256 threshold,
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    )
        external
        whenCalling_validateRecovery(signerNames, publicKey)
        givenAValidAmountOfSignatures
    {
        threshold = bound(threshold, 2, signers.length);
        manager.$_changeThreshold(threshold);

        address[] memory _signers = new address[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signers[i] = signers[i].signer;
        }
        bytes[] memory _signatures = new bytes[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signatures[i] = signers[i].recoverySignature;
        }
        // Duplicate the first signature
        _signatures[threshold - 1] = _signatures[0];
        _signers[threshold - 1] = _signers[0];
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerUnauthorizedRecoverer.selector,
                _signers[threshold - 1]
            )
        );
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }

    /// @notice it reverts because there is at least one unauthorized signature
    function test_GivenUnauthorizedSignatures(
        uint256 threshold,
        string[] memory signerNames,
        RSAOwnerManager.RSAPublicKey memory publicKey
    )
        external
        whenCalling_validateRecovery(signerNames, publicKey)
        givenAValidAmountOfSignatures
    {
        threshold = bound(threshold, 1, signers.length);
        manager.$_changeThreshold(threshold);

        address[] memory _signers = new address[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signers[i] = signers[i].signer;
        }
        bytes[] memory _signatures = new bytes[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            _signatures[i] = signers[i].recoverySignature;
        }
        // Remove the first signer
        manager.$_revokeRecoverer(_signers[0], 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                RecoveryManager.RecoveryManagerUnauthorizedRecoverer.selector,
                _signers[0]
            )
        );
        manager.$_validateRecovery(_signers, _signatures, publicKey);
    }
}
