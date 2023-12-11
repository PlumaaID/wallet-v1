// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TransactionRequest} from "./mocks/Plumaa.m.sol";
import {PlumaaMock} from "./mocks/Plumaa.m.sol";
import {Safe, SafeMock} from "./mocks/Safe.m.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SafeProxyFactory} from "@safe/contracts/proxies/SafeProxyFactory.sol";
import {Plumaa} from "~/Plumaa.sol";
import {console2} from "forge-std/console2.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import {RSASigner} from "./utils/RSASigner.sol";

contract BaseTest is Test {
    RSASigner internal owner;
    RSASigner internal other;

    PlumaaMock internal plumaa;
    SafeMock internal safe;
    address internal receiver = address(0x1234);
    address proxyAdmin;

    uint256 internal callerPrivateKey;
    address internal caller;

    modifier asCaller() {
        vm.startPrank(caller);
        _;
        vm.stopPrank();
    }

    function setUp() public virtual {
        owner = new RSASigner("owner");
        other = new RSASigner("other");

        RSASigner.PublicKey memory publicKey = owner.publicKey();

        safe = _deploySafeMock();
        address _proxy = Upgrades.deployTransparentProxy(
            "Plumaa.m.sol:PlumaaMock",
            address(this),
            abi.encodeCall(Plumaa.setupPlumaa, (publicKey.exponent, publicKey.modulus, safe))
        );
        plumaa = PlumaaMock(_proxy);
        _forceEnableModule(address(plumaa));
        proxyAdmin = computeCreateAddress(address(_proxy), 1);

        callerPrivateKey = 0xA11CE;
        caller = vm.addr(callerPrivateKey);
    }

    function _forgeRequestData(
        RSASigner signer,
        address to,
        uint256 value,
        Enum.Operation operation,
        uint48 deadline,
        bytes memory data,
        uint32 nonce
    ) internal returns (Plumaa.TransactionRequestData memory, bytes32 structHash) {
        structHash = _requestStructHash(to, value, operation, deadline, data, nonce);
        bytes memory signature = signer.sign(abi.encodePacked(structHash));

        RSASigner.PublicKey memory publicKey = signer.publicKey();

        return (
            Plumaa.TransactionRequestData({
                to: to,
                value: value,
                operation: operation,
                deadline: deadline,
                data: data,
                signature: signature,
                exponent: publicKey.exponent,
                modulus: publicKey.modulus
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

    function _deploySafeMock() private returns (SafeMock) {
        SafeProxyFactory factory = new SafeProxyFactory();
        bytes32 salt = keccak256("salt");
        address singleton = address(new SafeMock());
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        bytes memory data =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));

        return SafeMock(payable(address(factory.createProxyWithNonce(singleton, data, uint256(salt)))));
    }

    function _forceEnableModule(address module) internal {
        // Enable as a module to bypass signatures
        // https://twitter.com/0xVazi/status/1732187067776696655
        vm.store(address(safe), keccak256(abi.encode(address(module), 1)), bytes32(uint256(1)));
        assertTrue(safe.isModuleEnabled(address(module)));
    }
}
