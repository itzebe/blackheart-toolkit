// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "forge-std/Test.sol";

import "@uma/common/implementation/FixedPoint.sol";
import "@uma/data-verification-mechanism/implementation/Finder.sol";
import "@uma/data-verification-mechanism/implementation/Registry.sol";
import "@uma/data-verification-mechanism/implementation/Store.sol";
import "@uma/data-verification-mechanism/implementation/IdentifierWhitelist.sol";
import "@uma/data-verification-mechanism/implementation/VotingToken.sol";
import "@uma/data-verification-mechanism/implementation/VotingV2.sol";
import "@uma/data-verification-mechanism/implementation/FixedSlashSlashingLibrary.sol";
import "@uma/data-verification-mechanism/implementation/Constants.sol";

/// @notice Standalone fixture for the deployed UMA DVM (VotingV2 + Staker + Registry + token).
/// Mirrors the mainnet deployment topology.
abstract contract VotingV2Fixture is Test {
    VotingToken public votingToken;
    Finder public finder;
    Registry public registry;
    Store public store;
    IdentifierWhitelist public identifierWhitelist;
    FixedSlashSlashingLibrary public slashingLibrary;
    VotingV2 public votingV2;

    // Mainnet deploy parameters (packages/core/deploy/053_deploy_votingV2.js).
    uint64 internal constant PHASE_LENGTH = 86400; // 1 day per phase -> 2 days per round.
    uint128 internal constant EMISSION_RATE = 0.18e18; // 0.18 UMA per second.
    uint64 internal constant UNSTAKE_COOLDOWN = 7 days;
    uint32 internal constant MAX_ROLLS = 4;
    uint32 internal constant MAX_REQUESTS_PER_ROUND = 1000;
    uint128 internal constant GAT = 100e18; // smaller than mainnet so the fixture can exceed it.
    uint64 internal constant SPAT = 0.5e18; // 50% agreement.
    uint256 internal constant BASE_SLASH = 0.16e18; // 16% slash per wrong/no vote.

    bytes32 internal constant IDENTIFIER = "TEST_IDENTIFIER";

    // Owner of the DVM + token + registry in the fixture.
    address internal constant OWNER = address(0xA11CE);

    function _deployDvm() internal {
        vm.startPrank(OWNER);
        votingToken = new VotingToken();
        finder = new Finder();
        registry = new Registry();
        store = new Store(FixedPoint.fromUnscaledUint(0), FixedPoint.fromUnscaledUint(0), address(0));
        identifierWhitelist = new IdentifierWhitelist();
        slashingLibrary = new FixedSlashSlashingLibrary(BASE_SLASH, 0.16e18);

        identifierWhitelist.addSupportedIdentifier(IDENTIFIER);

        finder.changeImplementationAddress(OracleInterfaces.Registry, address(registry));
        finder.changeImplementationAddress(OracleInterfaces.Store, address(store));
        finder.changeImplementationAddress(OracleInterfaces.IdentifierWhitelist, address(identifierWhitelist));

        // VotingV2's constructor calls setGatAndSpat which requires gat < totalSupply(). Mirror the
        // deploy script: mint a temporary supply, then burn it after deployment.
        votingToken.addMember(uint256(1), OWNER); // Minter (held by the fixture owner)
        votingToken.mint(OWNER, uint256(GAT) + 1e18);

        votingV2 = new VotingV2(
            EMISSION_RATE,
            UNSTAKE_COOLDOWN,
            PHASE_LENGTH,
            MAX_ROLLS,
            MAX_REQUESTS_PER_ROUND,
            GAT,
            SPAT,
            address(votingToken),
            address(finder),
            address(slashingLibrary),
            address(0)
        );

        // Wire roles: VotingV2 must be a Minter (rewards) and Burner (slashing).
        votingToken.addMember(uint256(1), address(votingV2)); // Minter
        votingToken.addMember(uint256(2), address(votingV2)); // Burner

        // The fixture is a Registry contract creator so tests can register a requester contract.
        registry.addMember(uint256(1), address(this)); // ContractCreator role id == 1.
        vm.stopPrank();
    }

    /// @notice Mints tokens to `voter` and stakes `amount` on their behalf.
    function _mintAndStake(address voter, uint128 amount) internal {
        vm.prank(OWNER);
        votingToken.mint(voter, amount);
        vm.startPrank(voter);
        votingToken.approve(address(votingV2), amount);
        votingV2.stake(amount);
        vm.stopPrank();
    }

    /// @notice Registers a contract address in the Registry so it may request prices.
    function _registerRequester(address requester) internal {
        // The test contract is the Registry ContractCreator (set in _deployDvm).
        address[] memory parties = new address[](0);
        registry.registerContract(parties, requester);
    }

    function _commit(
        address voter,
        uint256 time,
        int256 price,
        int256 salt,
        uint32 roundId
    ) internal {
        bytes32 hash = keccak256(abi.encodePacked(price, salt, voter, time, bytes(""), uint256(roundId), IDENTIFIER));
        vm.prank(voter);
        votingV2.commitVote(IDENTIFIER, time, bytes(""), hash);
    }

    function _reveal(
        address voter,
        uint256 time,
        int256 price,
        int256 salt
    ) internal {
        vm.prank(voter);
        votingV2.revealVote(IDENTIFIER, time, price, bytes(""), salt);
    }
}
