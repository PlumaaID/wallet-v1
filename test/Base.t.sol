// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {TransactionRequest, PlumaaMock, SafeMock, Receiver} from "./mocks/Mocks.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {Plumaa} from "~/Plumaa.sol";
import {console2} from "forge-std/console2.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import {RSASigner} from "./utils/RSASigner.sol";

contract BaseTest is Test {
    RSASigner internal owner;
    RSASigner internal other;

    PlumaaMock internal plumaa;
    SafeMock internal wallet;
    Receiver internal receiver;

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

        address _proxy = Upgrades.deployTransparentProxy(
            "Mocks.sol:PlumaaMock",
            address(this),
            abi.encodeCall(
                Plumaa.setupPlumaa,
                (publicKey.exponent, publicKey.modulus)
            )
        );
        plumaa = PlumaaMock(_proxy);
        wallet = new SafeMock();
        receiver = new Receiver();

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
}
