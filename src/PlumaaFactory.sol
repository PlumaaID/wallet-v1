// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Plumaa} from "./Plumaa.sol";

contract PlumaaFactory {
    using Address for address;
    using Clones for address;

    address immutable singletonProxy;

    /// @notice Creates a new PlumaaFactory contract.
    constructor(address _singletonProxy) {
        singletonProxy = _singletonProxy;
    }

    /// @notice Creates a new Plumaa contract.
    function create(bytes memory exponent, bytes memory modulus) public returns (address) {
        address clone = Clones.clone(singletonProxy);
        Plumaa(clone).setupPlumaa(exponent, modulus, Safe(payable(msg.sender)));
        return clone;
    }

    /// @notice Creates a new Plumaa contract in a deterministic way
    function createDeterministic(bytes32 salt, bytes memory exponent, bytes memory modulus) public returns (address) {
        address clone = Clones.cloneDeterministic(singletonProxy, _toSafeSalt(salt));
        Plumaa(clone).setupPlumaa(exponent, modulus, Safe(payable(msg.sender)));
        return clone;
    }

    /// @notice Predicts the address of a new Plumaa contract
    function predictDeterministicAddress(bytes32 salt) public view returns (address) {
        return singletonProxy.predictDeterministicAddress(_toSafeSalt(salt), address(this));
    }

    /// @notice Optionally calls target with `data` if larger than a Solidity
    /// selector (4 bytes).
    function _optionalCall(address target, bytes memory data) internal {
        if (data.length >= 4) {
            target.functionCall(data);
        }
    }

    /// @notice Creates a salt scoped to each `msg.sender`.
    function _toSafeSalt(bytes32 salt) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(salt, msg.sender));
    }
}
