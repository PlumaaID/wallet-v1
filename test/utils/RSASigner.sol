// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {TransactionRequest} from "../mocks/Plumaa.m.sol";
import {Vm} from "forge-std/Vm.sol";
import {RSAOwnerManager} from "~/base/RSAOwnerManager.sol";

contract RSASigner {
    address constant CHEATCODE_ADDRESS =
        0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
    Vm private vm = Vm(CHEATCODE_ADDRESS);

    RSAOwnerManager.RSAPublicKey private _publicKey;

    string private _name;

    /// @notice Creates a new RSA signer. Takes the signer's public key and
    constructor(string memory name) {
        _name = name;
        _publicKey = RSAOwnerManager.RSAPublicKey(
            hex"010001",
            _extractModulus(name)
        );
    }

    /// @notice Returns the RSA public key
    function publicKey() public view returns (RSAOwnerManager.RSAPublicKey memory) {
        return _publicKey;
    }

    /// @notice Signs a message with the RSA private key
    function sign(bytes memory data) public returns (bytes memory) {
        string[] memory inputBuilder = new string[](255);
        uint8 i = 0;
        inputBuilder[i++] = "bash";
        inputBuilder[i++] = "scripts/sign.sh";
        inputBuilder[i++] = vm.toString(data);
        inputBuilder[i++] = _name;

        string[] memory inputs = new string[](i);
        for (uint8 j = 0; j < i; j++) {
            inputs[j] = inputBuilder[j];
        }

        return vm.ffi(inputs);
    }

    /// @notice Reads the modulus from the signer's public key
    function _extractModulus(
        string memory signer
    ) private returns (bytes memory) {
        string[] memory inputBuilder = new string[](255);
        uint8 i = 0;
        inputBuilder[i++] = "bash";
        inputBuilder[i++] = "scripts/modulus.sh";
        inputBuilder[i++] = signer;

        string[] memory inputs = new string[](i);
        for (uint8 j = 0; j < i; j++) {
            inputs[j] = inputBuilder[j];
        }

        return vm.ffi(inputs);
    }
}
