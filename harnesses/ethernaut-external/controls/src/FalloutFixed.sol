// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FalloutFixed -- differential control for Ethernaut "Fallout"
/// @notice The minimal fix for the Fallout flaw: the function that was *meant* to
///         be the constructor (`Fal1out`) no longer grants ownership. Ownership is
///         set once, in the real constructor, to the deployer. `Fal1out()` is kept
///         only so the case's operation list still dispatches (an interface
///         requirement), but it is inert.
///
///         Interface-compatible with the challenge: `owner()`, `allocate()`,
///         `sendAllocation(address)`, `collectAllocations()`,
///         `allocatorBalance(address)`, and `Fal1out()`.
contract FalloutFixed {
    mapping(address => uint256) private allocations;
    address payable public owner;

    constructor() {
        owner = payable(msg.sender);
    }

    /// @dev Inert: the historical bug was that this set `owner`. Now it does not.
    function Fal1out() public payable {}

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function allocate() public payable {
        allocations[msg.sender] += msg.value;
    }

    function sendAllocation(address payable allocator) public {
        require(allocations[allocator] > 0);
        allocator.transfer(allocations[allocator]);
    }

    function collectAllocations() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    function allocatorBalance(address allocator) public view returns (uint256) {
        return allocations[allocator];
    }
}
