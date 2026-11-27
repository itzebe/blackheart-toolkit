// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {DamnValuableToken} from "./DamnValuableToken.sol";

/// @title UnstoppableVault — a tokenized vault offering free flash loans during a
///        grace period, modelled on Damn Vulnerable DeFi's "Unstoppable" challenge.
/// @notice DELIBERATELY VULNERABLE (local training fixture, no real value).
///
/// Vulnerability: `totalAssets()` trusts the vault's *live* token balance, and the
/// flash-loan path asserts `convertToShares(totalSupply) == totalAssets()`. Any
/// actor can transfer tokens directly to the vault (a donation that mints no
/// shares), which breaks that equality. The next flash loan then reverts with
/// `InvalidBalance`, and an on-chain monitor that treats a failing flash loan as a
/// liveness fault will pause the vault and seize ownership — a permanent denial of
/// service triggered with a single token transfer.
contract UnstoppableVault {
    DamnValuableToken public immutable asset;
    address public owner;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint64 public immutable end;
    uint64 public constant GRACE_PERIOD = 30 days;
    uint256 public constant FEE_FACTOR = 0.05 ether;

    address public feeRecipient;
    bool public paused;

    error InvalidAmount(uint256 amount);
    error InvalidBalance();
    error CallbackFailed();
    error UnsupportedCurrency();
    error Unauthorized();

    event Paused(bool status);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(DamnValuableToken _token, address _owner, address _feeRecipient) {
        asset = _token;
        owner = _owner;
        feeRecipient = _feeRecipient;
        end = uint64(block.timestamp) + GRACE_PERIOD;
    }

    /// @dev Trusts the live token balance — this is the flaw.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply;
    }

    function deposit(uint256 assets, address receiver) external whenNotPaused returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = convertToShares(assets);
        require(shares > 0, "no shares");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function withdraw(uint256 shares, address receiver) external returns (uint256 assets) {
        require(shares > 0, "zero");
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
    }

    function maxFlashLoan(address token) public view returns (uint256) {
        if (token != address(asset)) return 0;
        return totalAssets();
    }

    function flashFee(address token, uint256 amount) public view returns (uint256) {
        if (token != address(asset)) revert UnsupportedCurrency();
        if (block.timestamp < end && amount < maxFlashLoan(token)) return 0;
        return (amount * FEE_FACTOR) / 1 ether;
    }

    /// @notice Free flash loan during the grace period; enforces an accounting
    ///         invariant that a donation can break.
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data)
        external
        returns (bool)
    {
        if (amount == 0) revert InvalidAmount(0);
        if (token != address(asset)) revert UnsupportedCurrency();
        uint256 balanceBefore = totalAssets();
        // ERC4626 requirement the challenge authors added as a safety check.
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();

        asset.transfer(receiver, amount);

        uint256 fee = flashFee(token, amount);
        bytes32 magic = IFlasher(receiver).onFlashLoan(msg.sender, token, amount, fee, data);
        if (magic != keccak256("IERC3156FlashBorrower.onFlashLoan")) revert CallbackFailed();

        asset.transferFrom(receiver, address(this), amount + fee);
        asset.transfer(feeRecipient, fee);
        return true;
    }

    function setPause(bool flag) external onlyOwner {
        paused = flag;
        emit Paused(flag);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

interface IFlasher {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external
        returns (bytes32);
}
