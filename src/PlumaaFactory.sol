// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Plumaa} from "./Plumaa.sol";

contract PlumaaFactory {
    using Address for address;

    address immutable proxy;

    /// @notice Creates a new PlumaaFactory contract.
    constructor(address _proxy) {
        proxy = _proxy;
    }

    /// @notice Creates a new Plumaa contract.
    /// Optionally calls the new clone with `data` if larger than a Solidity selector (4 bytes).
    function create(
        bytes memory exponent,
        bytes memory modulus,
        bytes memory data
    ) public returns (address) {
        address clone = Clones.clone(proxy);
        Plumaa(clone).setupPlumaa(exponent, modulus);
        _optionalCall(clone, data);
        return clone;
    }

    /// @notice Creates a new Plumaa contract in a deterministic way
    /// Optionally calls the new clone with `data` if larger than a Solidity selector (4 bytes).
    function createDeterministic(
        bytes32 salt,
        bytes memory exponent,
        bytes memory modulus,
        bytes memory data
    ) public returns (address) {
        address clone = Clones.cloneDeterministic(proxy, salt);
        Plumaa(clone).setupPlumaa(exponent, modulus);
        _optionalCall(clone, data);
        return clone;
    }

    /// @notice Predicts the address of a new Plumaa contract
    function predictDeterministicAddress(
        bytes32 salt
    ) public view returns (address) {
        return Clones.predictDeterministicAddress(proxy, salt);
    }

    /// @notice Optionally calls target with `data` if larger than a Solidity selector (4 bytes).
    function _optionalCall(address target, bytes memory data) internal {
        if (data.length >= 4) {
            target.functionCall(data);
        }
    }
}
