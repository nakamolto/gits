// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "forge-std/interfaces/IERC20.sol";

/// @title IGIT — GIT Token Interface
/// @notice Minimal normative interface for the GITS reward token (Section 13.3).
/// @dev GIT is ERC-20 with decimals=18. No burn, no pause, no upgrade, no owner.
///      The adaptive sink is implemented as mint reduction (RewardsManager mints only R_net).
///      Slashed bond amounts are hard assets (not GIT) burned via protocol burn address.
interface IGIT is IERC20 {
    /// @notice Mint new GIT tokens. Callable ONLY by minter() (RewardsManager).
    /// @param to Recipient address.
    /// @param amount Amount to mint (in base units, 18 decimals).
    function mint(address to, uint256 amount) external;

    /// @notice Returns the RewardsManager contract address (set immutably at construction).
    function minter() external view returns (address);
}
