// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {TransactionRequest, PlumaaMock, SafeMock, Receiver} from "../mocks/Mocks.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {Plumaa} from "../../src/Plumaa.sol";
import {console2} from "forge-std/console2.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";

contract BaseTest is Test {
    PlumaaMock internal plumaa;
    SafeMock internal wallet;
    Receiver internal receiver;

    uint256 internal callerPrivateKey;
    address internal caller;

    bytes exponent =
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000010001";

    bytes modulus =
        hex"a37197156db6b567c232dd266c7c55fa4385a831fc92c10df6d739e650d3a01b"
        hex"83debaffeea2fa3903401ac7bd67ee5ef7a44eefd68889a3d966aea880e44098"
        hex"0fa06b29cb3b3ce7808610e2b3d85c24e453e3888dfe4da23b63fe4dbb625e2e"
        hex"be139ea619869bb8e2ca8289c9f06c69266857d6376563eab8b3727efd763e5f";

    struct PublicKey {
        bytes exponent;
        bytes modulus;
    }

    PublicKey public publicKey = PublicKey(exponent, modulus);

    modifier asCaller() {
        vm.startPrank(caller);
        _;
        vm.stopPrank();
    }

    function setUp() public virtual {
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
        address to,
        uint256 value,
        Enum.Operation operation,
        uint48 deadline,
        bytes memory data,
        uint256 nonce
    ) internal returns (Plumaa.TransactionRequestData memory) {
        TransactionRequest memory request = TransactionRequest({
            to: to,
            value: value,
            operation: operation,
            deadline: deadline,
            data: data,
            nonce: nonce
        });

        string[] memory inputBuilder = new string[](255);
        uint8 i = 0;

        string memory digest = Strings.toHexString(
            uint256(plumaa.structHash(request))
        );

        inputBuilder[i++] = "bash";
        inputBuilder[i++] = "scripts/sign.sh";
        inputBuilder[i++] = digest;

        string[] memory inputs = new string[](i);
        for (uint8 j = 0; j < i; j++) {
            inputs[j] = inputBuilder[j];
        }

        bytes memory signature = vm.ffi(inputs);

        return
            Plumaa.TransactionRequestData({
                to: to,
                value: value,
                operation: operation,
                deadline: deadline,
                data: data,
                signature: signature,
                exponent: publicKey.exponent,
                modulus: publicKey.modulus
            });
    }
}
