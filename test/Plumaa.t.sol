// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Upgrades} from "@openzeppelin/foundry-upgrades/Upgrades.sol";

import {Plumaa} from "../src/Plumaa.sol";

contract FooTest is Test {
    address private _proxy;

    bytes exponent =
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"0000000000000000000000000000000000000000000000000000000000010001";

    bytes modulus =
        hex"a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a"
        hex"afbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080"
        hex"ede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941"
        hex"ada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5";

    struct PublicKey {
        bytes exponent;
        bytes modulus;
    }

    function setUp() public virtual {
        PublicKey memory publicKey = PublicKey({
            exponent: exponent,
            modulus: modulus
        });
        _proxy = Upgrades.deployTransparentProxy(
            "Plumaa.sol:Plumaa",
            address(this),
            abi.encodeCall(
                Plumaa.setupPlumaa,
                (publicKey.exponent, publicKey.modulus)
            )
        );
    }

    function test_Example() external {
        console2.log("Hello World");
    }
}
