// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {Plumaa} from "./Plumaa.sol";

contract PlumaaFactory {
    address private immutable __self;

    /// @notice Modifier to make a function callable via delegatecall only.
    /// If the function is called via a regular call, it will revert.
    modifier onlyDelegateCall() {
        require(address(this) != __self);
        _;
    }

    constructor() {
        __self = address(this);
    }

    /// @notice Predicts the address of a new Plumaa contract
    function predictDeterministicAddress(
        address beacon,
        bytes32 salt,
        bytes memory exponent,
        bytes memory modulus,
        Safe safe
    ) public pure returns (address) {
        return
            Create2.computeAddress(
                salt,
                keccak256(_proxyCreationCode(beacon, exponent, modulus, safe)),
                address(safe)
            );
    }

    /// @notice Creates a new Plumaa contract and enables it as a module in a Safe.
    /// This method can only be called as a delegatecall from a Safe. This is possible through
    /// the Safe's {setup} method which includes optional delegatecall data.
    function safeSetup(
        address beacon,
        bytes32 salt,
        bytes memory exponent,
        bytes memory modulus
    ) public onlyDelegateCall {
        Safe safe = Safe(payable(address(this)));
        address clone = Create2.deploy(
            0,
            salt,
            _proxyCreationCode(beacon, exponent, modulus, safe)
        );
        safe.enableModule(clone);
    }

    /// @notice Returns the creation code with arguments of a new beacon proxy.
    function _proxyCreationCode(
        address beacon,
        bytes memory exponent,
        bytes memory modulus,
        Safe safe
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                type(BeaconProxy).creationCode,
                abi.encode(
                    beacon,
                    abi.encodeCall(
                        Plumaa.setupPlumaa,
                        (exponent, modulus, safe)
                    )
                )
            );
    }
}
