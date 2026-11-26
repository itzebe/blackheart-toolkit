// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AdversarialERC20
/// @notice A real, working ERC20 that can be *switched* into hostile behaviours.
/// @dev This is a controlled instrument for exploit development, not a token for
///      production. Every hostile behaviour is off by default, so the same
///      contract doubles as an honest reference in a negative-control test.
///      Behaviours are toggled per-instance, which makes the differential
///      (hostile vs. honest) comparison exact: the only variable is the flag.
contract AdversarialERC20 {
    string public name = "Adversarial Token";
    string public symbol = "ADV";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ---- hostile switches (all default off) ---------------------------------

    /// @notice When true, `transfer`/`transferFrom` credit the recipient nothing
    ///         while still debiting the sender (a fee-on-transfer / lossy token).
    bool public skimsOnTransfer;
    /// @notice Fraction (in basis points, 1e4 = 100%) removed on each transfer.
    uint256 public skimBps;
    /// @notice When true, `transferFrom` ignores the allowance entirely.
    bool public ignoreAllowance;
    /// @notice When true, `balanceOf` is a view of attacker-controlled storage,
    ///         not of the real ledger (a lying token used for oracle/solvency games).
    bool public liesAboutBalances;
    mapping(address => uint256) public reportedBalance;
    /// @notice When true, re-enter `onTransferHook` on the configured target.
    bool public reentersOnTransfer;
    address public reentryTarget;
    bytes public reentryData;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error InsufficientBalance();
    error InsufficientAllowance();

    constructor(uint256 initialSupply) {
        _mint(msg.sender, initialSupply);
    }

    // ---- hostile configuration ----------------------------------------------

    function setSkim(bool on, uint256 bps) external {
        skimsOnTransfer = on;
        skimBps = bps;
    }

    function setIgnoreAllowance(bool on) external {
        ignoreAllowance = on;
    }

    function setLiesAboutBalances(bool on) external {
        liesAboutBalances = on;
    }

    function setReportedBalance(address who, uint256 amount) external {
        reportedBalance[who] = amount;
    }

    function setReentry(address target, bytes calldata data) external {
        reentersOnTransfer = true;
        reentryTarget = target;
        reentryData = data;
    }

    function disableReentry() external {
        reentersOnTransfer = false;
    }

    // ---- ERC20 --------------------------------------------------------------

    function reportedOrReal(address who) public view returns (uint256) {
        return liesAboutBalances ? reportedBalance[who] : balanceOf[who];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (!ignoreAllowance) {
            uint256 allowed = allowance[from][msg.sender];
            if (allowed != type(uint256).max) {
                if (allowed < amount) revert InsufficientAllowance();
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 bal = balanceOf[from];
        if (bal < amount) revert InsufficientBalance();
        balanceOf[from] = bal - amount;

        uint256 credited = amount;
        if (skimsOnTransfer && skimBps > 0) {
            uint256 fee = (amount * skimBps) / 10_000;
            credited = amount - fee;
            // The fee vanishes: totalSupply is not reduced and no one is credited.
        }
        balanceOf[to] += credited;
        emit Transfer(from, to, credited);

        if (reentersOnTransfer && reentryTarget != address(0)) {
            (bool ok,) = reentryTarget.call(reentryData);
            ok; // a hostile token may ignore the outcome of the callback
        }
    }
}
