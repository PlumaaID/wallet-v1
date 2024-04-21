// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ModuleManager} from "@safe/contracts/base/ModuleManager.sol";
import {TransactionRequest} from "./mocks/Plumaa.m.sol";
import {PlumaaFactory} from "~/PlumaaFactory.sol";
import {PlumaaMock} from "./mocks/Plumaa.m.sol";
import {Safe, SafeMock} from "./mocks/Safe.m.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SafeProxyFactory} from "@safe/contracts/proxies/SafeProxyFactory.sol";
import {Plumaa, RSAOwnerManager} from "~/Plumaa.sol";
import {console2} from "forge-std/console2.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import {RSASigner} from "./utils/RSASigner.sol";

contract BaseTest is Test {
    // Signers
    RSASigner internal owner;
    RSASigner internal other;

    /// Factories
    PlumaaFactory plumaaFactory;
    SafeProxyFactory safeProxyFactory;

    // Mocks
    PlumaaMock internal plumaa;
    SafeMock internal safe;
    address internal receiver = address(0x1234);

    function setUp() public virtual {
        owner = new RSASigner("owner");
        other = new RSASigner("other");

        plumaaFactory = new PlumaaFactory();
        safeProxyFactory = new SafeProxyFactory();

        address plumaaBeacon = Upgrades.deployBeacon(
            "Plumaa.m.sol:PlumaaMock",
            address(this)
        );
        (safe, plumaa) = _deployMocks(address(new SafeMock()), plumaaBeacon);
    }

    function _forgeRequestData(
        RSASigner signer,
        address to,
        uint256 value,
        Enum.Operation operation,
        uint48 deadline,
        bytes memory data,
        uint32 nonce
    )
        internal
        returns (Plumaa.TransactionRequestData memory, bytes32 structHash)
    {
        structHash = _requestStructHash(
            to,
            value,
            operation,
            deadline,
            data,
            nonce
        );
        bytes memory signature = signer.sign(abi.encodePacked(structHash));

        return (
            Plumaa.TransactionRequestData({
                to: to,
                value: value,
                operation: operation,
                deadline: deadline,
                data: data,
                signature: signature
            }),
            structHash
        );
    }

    function _requestStructHash(
        address to,
        uint256 value,
        Enum.Operation operation,
        uint48 deadline,
        bytes memory data,
        uint32 nonce
    ) internal view returns (bytes32 digest) {
        TransactionRequest memory request = TransactionRequest({
            to: to,
            value: value,
            operation: operation,
            deadline: deadline,
            data: data,
            nonce: nonce
        });

        return plumaa.structHash(request);
    }

    function _deployMocks(
        address safeSingleton,
        address plumaaBeacon
    ) private returns (SafeMock, PlumaaMock) {
        bytes32 salt = keccak256("salt");

        uint256 recoveryThreshold = 1;
        address[] memory authorizedRecoverers = new address[](1);

        RSAOwnerManager.RSAPublicKey memory publicKey = owner.publicKey();
        address payable safeProxy = payable(
            safeProxyFactory.createProxyWithNonce(
                safeSingleton,
                _buildDeploySafeMockData(
                    plumaaBeacon,
                    salt,
                    publicKey,
                    recoveryThreshold,
                    authorizedRecoverers
                ),
                uint256(salt)
            )
        );

        address plumaaAddress = plumaaFactory.predictDeterministicAddress(
            plumaaBeacon,
            salt,
            publicKey,
            Safe(safeProxy),
            recoveryThreshold,
            authorizedRecoverers
        );

        return (SafeMock(safeProxy), PlumaaMock(plumaaAddress));
    }

    function _buildDeploySafeMockData(
        address plumaaBeacon,
        bytes32 salt,
        RSAOwnerManager.RSAPublicKey memory publicKey,
        uint256 recoveryThreshold,
        address[] memory authorizedRecoverers
    ) private view returns (bytes memory) {
        address[] memory owners = new address[](1);
        owners[0] = address(this);

        return
            abi.encodeCall(
                Safe.setup,
                (
                    owners,
                    1,
                    address(plumaaFactory),
                    abi.encodeCall(
                        PlumaaFactory.safeSetup,
                        (
                            plumaaBeacon,
                            salt,
                            publicKey,
                            recoveryThreshold,
                            authorizedRecoverers
                        )
                    ),
                    address(0),
                    address(0),
                    0,
                    payable(0)
                )
            );
    }

    function _forceEnableModule(address module) internal {
        // Enable as a module to bypass signatures
        // https://twitter.com/0xVazi/status/1732187067776696655
        vm.store(
            address(safe),
            keccak256(abi.encode(address(module), 1)),
            bytes32(uint256(1))
        );
        assertTrue(safe.isModuleEnabled(address(module)));
    }
}
