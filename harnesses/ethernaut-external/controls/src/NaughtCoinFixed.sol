// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NaughtCoinFixed -- differential control for Ethernaut "NaughtCoin"
/// @notice The minimal fix for the NaughtCoin flaw: the time-lock is applied to
///         *every* transfer path, including the inherited `transferFrom`. In the
///         challenge only `transfer` carried the `lockTokens` modifier, so a
///         spender could move the player's locked balance through `transferFrom`.
///         Interface-compatible with the level: same constructor, `transfer`,
///         `transferFrom`, `approve`, `allowance`, `balanceOf`, `totalSupply`,
///         `timeLock`, `INITIAL_SUPPLY` and `player`.
contract NaughtCoinFixed {
    string public constant name = "NaughtCoin";
    string public constant symbol = "0x0";
    uint8 public constant decimals = 18;

    uint256 public timeLock = block.timestamp + 10 * 365 days;
    uint256 public INITIAL_SUPPLY;
    address public player;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address _player) {
        player = _player;
        INITIAL_SUPPLY = 1000000 * (10 ** uint256(decimals));
        _mint(player, INITIAL_SUPPLY);
    }

    modifier lockTokens() {
        if (msg.sender == player) {
            require(block.timestamp > timeLock, "locked");
            _;
        } else {
            _;
        }
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address _to, uint256 _value) public lockTokens returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    // The fix: the time-lock follows the *owner of the funds*, not the caller, so
    // a spender cannot move the player's locked balance through the delegated path.
    function transferFrom(address _from, address _to, uint256 _value)
        public
        returns (bool)
    {
        if (_from == player) {
            require(block.timestamp > timeLock, "locked");
        }
        uint256 allowed = _allowances[_from][msg.sender];
        require(allowed >= _value, "allowance");
        if (allowed != type(uint256).max) {
            _allowances[_from][msg.sender] = allowed - _value;
        }
        _transfer(_from, _to, _value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) private {
        require(_balances[from] >= value, "balance");
        _balances[from] -= value;
        _balances[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 amount) private {
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
