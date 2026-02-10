// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {GIT} from "../src/GIT.sol";

contract GITTest is Test {
    address internal constant MINTER = address(0xBEEF);

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant SPENDER = address(0x5EED);

    GIT internal token;

    function setUp() public {
        token = new GIT("GITS Reward Token", "GIT", MINTER);
    }

    function test_decimals_returns18() public {
        assertEq(token.decimals(), 18);
    }

    function test_minterGetter_returnsConstructorMinter() public {
        assertEq(token.minter(), MINTER);
    }

    function test_mint_byMinter_succeeds() public {
        uint256 amount = 123e18;

        vm.prank(MINTER);
        token.mint(ALICE, amount);

        assertEq(token.totalSupply(), amount);
        assertEq(token.balanceOf(ALICE), amount);
    }

    function test_mint_byNonMinter_reverts() public {
        vm.expectRevert(GIT.NotMinter.selector);
        token.mint(ALICE, 1e18);
    }

    function test_erc20_transfer_approve_transferFrom() public {
        vm.prank(MINTER);
        token.mint(ALICE, 100e18);

        // transfer (no fees, exact deltas)
        vm.prank(ALICE);
        token.transfer(BOB, 40e18);

        assertEq(token.balanceOf(ALICE), 60e18);
        assertEq(token.balanceOf(BOB), 40e18);

        // approve + transferFrom
        vm.prank(ALICE);
        token.approve(SPENDER, 50e18);
        assertEq(token.allowance(ALICE, SPENDER), 50e18);

        vm.prank(SPENDER);
        token.transferFrom(ALICE, BOB, 10e18);

        assertEq(token.balanceOf(ALICE), 50e18);
        assertEq(token.balanceOf(BOB), 50e18);
        assertEq(token.allowance(ALICE, SPENDER), 40e18);
    }

    function test_noOwnerOrAdminFunctions_exist() public {
        _assertMissing(abi.encodeWithSignature("owner()"));
        _assertMissing(abi.encodeWithSignature("transferOwnership(address)", address(1)));
        _assertMissing(abi.encodeWithSignature("renounceOwnership()"));

        _assertMissing(abi.encodeWithSignature("pause()"));
        _assertMissing(abi.encodeWithSignature("unpause()"));

        _assertMissing(abi.encodeWithSignature("burn(uint256)", uint256(1)));

        _assertMissing(abi.encodeWithSignature("grantRole(bytes32,address)", bytes32(0), address(1)));
        _assertMissing(abi.encodeWithSignature("revokeRole(bytes32,address)", bytes32(0), address(1)));
    }

    function _assertMissing(bytes memory data) internal {
        (bool ok,) = address(token).call(data);
        assertFalse(ok);
    }
}
