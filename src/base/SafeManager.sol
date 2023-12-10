// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Safe} from "@safe/contracts/Safe.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Contract to manage the ownership of a Plumaa with EIP7201 support.
contract SafeManager is Initializable {
    /// @dev The caller account is not authorized to perform an operation.
    error SafeManagerUnauthorizedAccount(address account);

    // keccak256(abi.encode(uint256(keccak256("plumaa.storage.SafeManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant SafeManagerStorageLocation =
        0x6465d3aa1a400bf0e2554af5439f7f8a5b30fd78a22df4e95de86b9d82986200;

    struct SafeManagerStorage {
        Safe _safe;
    }

    /// @dev Throws if called by any account other than the safe.
    modifier onlySafe() {
        _checkSafe();
        _;
    }

    /// @notice Sets the initial storage of the contract.
    function __SafeManager_init(Safe safe_) internal onlyInitializing {
        _getSafeManagerStorage()._safe = safe_;
    }

    /// @dev Returns the address of the owner safe.
    function safe() public view virtual returns (Safe) {
        return _getSafeManagerStorage()._safe;
    }

    /// @dev Throws if the sender is not the owner.
    function _checkSafe() internal view virtual {
        if (address(safe()) != msg.sender) {
            revert SafeManagerUnauthorizedAccount(msg.sender);
        }
    }

    /// @notice Get EIP-7201 storage
    function _getSafeManagerStorage()
        private
        pure
        returns (SafeManagerStorage storage $)
    {
        assembly {
            $.slot := SafeManagerStorageLocation
        }
    }
}
