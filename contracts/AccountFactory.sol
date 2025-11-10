// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

interface IERC1155Token {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 id, uint256 amount) external;
}

/**
 * Account:
 * - owner: the user's EOA (the address you pass as `user`)
 * - controller: your backend/admin that signs UserOps and calls mint/burn
 * - entryPoint: accepted to satisfy the factory ABI; not used here, but kept for compatibility
 */
contract Account is IAccount {
    address public owner;       // player EOA
    address public controller;  // backend/admin signer
    address public entryPoint;  // optional (not used in this minimal example)

    constructor(address _user, address _entryPoint, address _ownerAsController) {
        owner      = _user;
        controller = _ownerAsController; // 3rd arg is your admin/controller
        entryPoint = _entryPoint;        // stored for ABI parity (not required here)
    }

    function validateUserOp(
        UserOperation calldata op,
        bytes32 userOpHash,
        uint256
    ) external view override returns (uint256) {
        address signer = ECDSA.recover(
            userOpHash,
            op.signature
        );
        // allow either the user EOA or the controller/admin
        return (signer == owner || signer == controller) ? 0 : 1;
    }

    // controller-only execution surface for your ERC1155
    function mint(address token, address to, uint256 amount) external {
        require(msg.sender == controller, "Only controller");
        IERC1155Token(token).mint(to, amount);
    }

    function burn(address token, address from, uint256 id, uint256 amount) external {
        require(msg.sender == controller, "Only controller");
        IERC1155Token(token).burn(from, id, amount);
    }
}

/**
 * Factory (ABI-compatible):
 * createAccount(address user, address entryPoint, address owner)
 * - user        => Account.owner (player EOA)
 * - entryPoint  => stored on Account (optional)
 * - owner       => Account.controller (your admin/backend signer)
 *
 * Address is counterfactual via CREATE2 salt = bytes32(uint160(user)).
 */
contract AccountFactory {
    function createAccount(address user, address entryPoint, address owner) external returns (address) {
        bytes32 salt = bytes32(uint256(uint160(user)));
        bytes memory creationCode = abi.encodePacked(
            type(Account).creationCode,
            abi.encode(user, entryPoint, owner)
        );

        address addr = Create2.computeAddress(salt, keccak256(creationCode));
        if (addr.code.length == 0) {
            assembly {
                addr := create2(0, add(creationCode, 0x20), mload(creationCode), salt)
            }
        }
        return addr;
    }
}
