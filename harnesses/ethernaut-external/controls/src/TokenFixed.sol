// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TokenFixed -- differential control for Ethernaut "Token"
/// @notice The minimal fix for the Token flaw: the balance subtraction is checked,
///         so transferring more than the sender holds reverts instead of wrapping
///         around. Interface-compatible with the challenge: `transfer`,
///         `balanceOf`, `totalSupply`, and the `Token(uint256)` constructor.
contract TokenFixed {
    mapping(address => uint256) private balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value, "insufficient balance");
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
