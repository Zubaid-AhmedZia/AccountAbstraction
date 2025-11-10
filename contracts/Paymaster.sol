// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@account-abstraction/contracts/core/EntryPoint.sol";

/**
 * Guard rails:
 * - Only allows ops with initCode from your factory (if creating).
 * - Only allows calling Account.mint/burn.
 * - Enforces the first arg `token` == your ERC1155 address.
 *///
contract Paymaster is IPaymaster {
    EntryPoint public immutable entryPoint;
    address   public immutable factory;
    address   public immutable erc1155Token;

    // selectors for Account.mint(address,address,uint256) and Account.burn(address,address,uint256,uint256)
    bytes4 private constant MINT_SEL = bytes4(keccak256("mint(address,address,uint256)"));
    bytes4 private constant BURN_SEL = bytes4(keccak256("burn(address,address,uint256,uint256)"));

    constructor(address payable _entryPoint, address _factory, address _erc1155Token) {
        entryPoint   = EntryPoint(_entryPoint);
        factory      = _factory;
        erc1155Token = _erc1155Token;
    }

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32,
        uint256
    ) external view override returns (bytes memory, uint256) {
        require(msg.sender == address(entryPoint), "Paymaster: not EP");

        // If deploying, enforce our factory (initCode = abi.encodePacked(factory, createAccount calldata))
        bytes calldata ic = userOp.initCode;
        if (ic.length != 0) {
            address fac;
            assembly {
                let p := add(ic.offset, 32)       // skip length
                fac := shr(96, calldataload(p))   // first 20 bytes of data is the factory address
            }
            require(fac == factory, "Paymaster: bad factory");
        }

        // Grab selector from callData (first 4 bytes of the data after the 32-byte length)
        bytes calldata cd = userOp.callData;
        bytes4 sel;
        assembly {
            let p := add(cd.offset, 32)           // skip length word
            sel := shr(224, calldataload(p))      // top 4 bytes = selector
        }
        require(sel == MINT_SEL || sel == BURN_SEL, "Paymaster: bad selector");

        // Read the first argument (address token) located right after the 4-byte selector
        address token;
        assembly {
            let p := add(add(cd.offset, 32), 4)   // skip length + selector (4)
            let word := calldataload(p)           // first argument word
            token := shr(96, word)                // address = last 20 bytes
        }
        require(token == erc1155Token, "Paymaster: invalid token");

        return ("", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256) external override {}
}
