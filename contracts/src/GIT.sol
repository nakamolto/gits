// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {IGIT} from "./interfaces/IGIT.sol";

/// @title GIT — GITS Reward Token
/// @notice Minimal immutable ERC-20 reward token. Minting restricted to RewardsManager.
contract GIT is ERC20, IGIT {
    error NotMinter();

    /// @notice RewardsManager contract address. Set immutably at deployment.
    address public immutable minter;

    constructor(string memory name_, string memory symbol_, address minter_) ERC20(name_, symbol_) {
        minter = minter_;
    }

    /// @inheritdoc IGIT
    function mint(address to, uint256 amount) external override {
        if (msg.sender != minter) revert NotMinter();
        _mint(to, amount);
    }
}
