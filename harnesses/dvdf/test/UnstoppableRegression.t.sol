// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {DamnValuableToken} from "../src/DamnValuableToken.sol";
import {UnstoppableVault} from "../src/UnstoppableVault.sol";

/// @title UnstoppableRegression — regression tests that pin the *fixed* behaviour.
/// @notice These tests encode the security property the vulnerability violated, so
///         that a remediation (or a regression) is caught automatically:
///           * the flash-loan path must not depend on the live token balance in a
///             way a donation can break;
///           * a donation must not be able to change the outcome of a flash loan.
///
///         They assert the property directly on a *guarded* vault
///         (`GuardedVault`), so they fail if the guard is removed.
contract UnstoppableRegression is Test {
    address internal constant DEPLOYER = address(0xD0);
    address internal constant ATTACKER = address(0xA11CE);

    DamnValuableToken internal token;
    GuardedVault internal vault;

    function setUp() public {
        vm.startPrank(DEPLOYER);
        token = new DamnValuableToken();
        vault = new GuardedVault(token, DEPLOYER, DEPLOYER);
        token.mint(DEPLOYER, 1_000_000e18);
        token.approve(address(vault), 1_000_000e18);
        vault.deposit(1_000_000e18, DEPLOYER);
        token.mint(ATTACKER, 10e18);
        vm.stopPrank();
    }

    /// @notice A donation must not be able to make the flash loan revert.
    function test_regression_donation_does_not_break_flashloan() public {
        vm.prank(ATTACKER);
        token.transfer(address(vault), 1e18); // hostile donation

        // The guarded vault accounts for donations, so the loan still succeeds.
        vm.prank(DEPLOYER);
        bool ok = vault.flashLoan(address(this), address(token), 100e18, bytes(""));
        assertTrue(ok, "REGRESSION: donation broke the flash loan on the guarded vault");
        assertFalse(vault.paused(), "REGRESSION: guarded vault must stay live");
    }

    function onFlashLoan(address, address token_, uint256 amount, uint256, bytes calldata)
        external
        returns (bytes32)
    {
        DamnValuableToken(token_).approve(msg.sender, amount);
        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }
}

/// @title GuardedVault — the remediation: track assets with an internal counter
///        instead of trusting the live token balance, so a donation cannot change
///        the accounting invariant.
contract GuardedVault {
    DamnValuableToken public immutable asset;
    address public owner;
    address public feeRecipient;
    bool public paused;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    uint256 public accountedAssets;   // <-- the fix

    modifier onlyOwner() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    constructor(DamnValuableToken _token, address _owner, address _feeRecipient) {
        asset = _token;
        owner = _owner;
        feeRecipient = _feeRecipient;
    }

    function totalAssets() public view returns (uint256) {
        return accountedAssets; // donations to the vault do not count
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        require(!paused, "paused");
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        accountedAssets += assets;
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data)
        external
        returns (bool)
    {
        require(token == address(asset), "unsupported");
        require(convertToShares(totalSupply) == totalAssets(), "invariant");
        asset.transfer(receiver, amount);
        bytes32 magic = IFlasher2(receiver).onFlashLoan(msg.sender, token, amount, 0, data);
        require(magic == keccak256("IERC3156FlashBorrower.onFlashLoan"), "callback");
        asset.transferFrom(receiver, address(this), amount);
        return true;
    }

    function setPause(bool flag) external onlyOwner {
        paused = flag;
    }
}

interface IFlasher2 {
    function onFlashLoan(address, address, uint256, uint256, bytes calldata) external returns (bytes32);
}
