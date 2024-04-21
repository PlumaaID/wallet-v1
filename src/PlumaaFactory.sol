// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {Plumaa, RSAOwnerManager} from "./Plumaa.sol";

contract PlumaaFactory {
    address private immutable __self;

    /// @dev Reverts if called directly.
    error PlumaaFactoryOnlyDelegateCall();

    /// @notice Modifier to make a function callable via delegatecall only.
    /// If the function is called via a regular call, it will revert.
    modifier onlyDelegateCall() {
        if (msg.sender == __self) revert PlumaaFactoryOnlyDelegateCall();
        _;
    }

    constructor() {
        __self = address(this);
    }

    /// @notice Predicts the address of a new Plumaa contract
    function predictDeterministicAddress(
        address beacon,
        bytes32 salt,
        RSAOwnerManager.RSAPublicKey memory owner,
        Safe safe,
        uint256 recoveryThreshold,
        address[] calldata authorizedRecoverers
    ) public pure returns (address) {
        return
            Create2.computeAddress(
                salt,
                keccak256(
                    _proxyCreationCode(
                        beacon,
                        owner,
                        safe,
                        recoveryThreshold,
                        authorizedRecoverers
                    )
                ),
                address(safe)
            );
    }

    /// @notice Creates a new Plumaa contract and enables it as a module in a Safe.
    /// This method can only be called as a delegatecall from a Safe. This is possible through
    /// the Safe's {setup} method which includes optional delegatecall data.
    function safeSetup(
        address beacon,
        bytes32 salt,
        RSAOwnerManager.RSAPublicKey memory owner,
        uint256 recoveryThreshold,
        address[] calldata authorizedRecoverers
    ) public onlyDelegateCall {
        Safe safe = Safe(payable(address(this)));
        address clone = Create2.deploy(
            0,
            salt,
            _proxyCreationCode(
                beacon,
                owner,
                safe,
                recoveryThreshold,
                authorizedRecoverers
            )
        );
        safe.enableModule(clone);
        // safe.swapOwner(prevOwner, oldOwner, newOwner);
    }

    /// @notice Returns the creation code with arguments of a new beacon proxy.
    function _proxyCreationCode(
        address beacon,
        RSAOwnerManager.RSAPublicKey memory owner,
        Safe safe,
        uint256 recoveryThreshold,
        address[] calldata authorizedRecoverers
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                type(BeaconProxy).creationCode,
                abi.encode(
                    beacon,
                    abi.encodeCall(
                        Plumaa.setupPlumaa,
                        (owner, safe, recoveryThreshold, authorizedRecoverers)
                    )
                )
            );
    }
}
