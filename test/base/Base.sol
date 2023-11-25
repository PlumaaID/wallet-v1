// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {TransactionRequest, PlumaaMock, SafeMock, Receiver} from "../mocks/Mocks.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {Plumaa} from "~/Plumaa.sol";
import {console2} from "forge-std/console2.sol";
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
        hex"D1B9284C60D59E73B47CE5EC49F6B834BAB37DD127A6CD6C5DFBB4D18C727B77"
        hex"EC82296C1969026CC42208C5E00CF37FEC8308F8E342ADCD7F3269743F568CB0"
        hex"92BDBADFED9C999B8CCA17E253B26480D157449C6DA15D75781957BF8A479970"
        hex"FE33968398723D02C00A16717225B97CC1CF906C62E1516958A252D229C71FC4"
        hex"B8274F3E8476708697022E4B0B4053F7BDBAC7931624CF2DA985E905EBDB27A6"
        hex"65B5DCB83A289A5D2E1AC78B08CED9F3796CC79C0AABC50C90CF5549746F8FB7"
        hex"3666AC5C80AB3692FB83DCDC1ACEDCE6B40E627AFDB28AD8A62F5D5D6B5F4EDB"
        hex"123E1C0586CAF5270ED6B0971D85E9B9DD9E95B992FF55878AAB55178FF67CD3";

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

        bytes32 digest = plumaa.structHash(request);

        string[] memory inputBuilder = new string[](255);
        uint8 i = 0;
        inputBuilder[i++] = "bash";
        inputBuilder[i++] = "scripts/sign.sh";
        inputBuilder[i++] = vm.toString(digest);

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
