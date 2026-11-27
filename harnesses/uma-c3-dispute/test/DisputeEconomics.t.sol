// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OptimisticOracleV2} from "uma/optimistic-oracle-v2/implementation/OptimisticOracleV2.sol";
import {Finder} from "uma/data-verification-mechanism/implementation/Finder.sol";
import {Store} from "uma/data-verification-mechanism/implementation/Store.sol";
import {AddressWhitelist} from "uma/common/implementation/AddressWhitelist.sol";
import {IdentifierWhitelist} from "uma/data-verification-mechanism/implementation/IdentifierWhitelist.sol";
import {FixedPoint} from "uma/common/implementation/FixedPoint.sol";

contract MockERC20 {
    string public name = "Mock USDC";
    string public symbol = "mUSDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address a, uint256 v) external {
        balanceOf[a] += v;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v;
        balanceOf[f] -= v;
        balanceOf[to] += v;
        return true;
    }
}

/// @dev External dependency only: stands in for the DVM's price feed.
contract MockOracle {
    mapping(bytes32 => int256) public prices;
    mapping(bytes32 => bool) public has;

    function _k(bytes32 id, uint256 ts, bytes calldata anc) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, ts, anc));
    }

    function setPrice(bytes32 id, uint256 ts, bytes calldata anc, int256 p) external {
        prices[_k(id, ts, anc)] = p;
        has[_k(id, ts, anc)] = true;
    }

    function requestPrice(bytes32, uint256, bytes calldata) external {}

    function hasPrice(bytes32 id, uint256 ts, bytes calldata anc) external view returns (bool) {
        return has[_k(id, ts, anc)];
    }

    function getPrice(bytes32 id, uint256 ts, bytes calldata anc) external view returns (int256) {
        require(has[_k(id, ts, anc)], "no price");
        return prices[_k(id, ts, anc)];
    }
}

/// @notice Measures the exact fund flows of an UMA Optimistic Oracle v2 dispute against the
///         unmodified implementation. Values mirror the live Polymarket reporter configuration
///         decoded on-chain: bond 250, finalFee 250, reward 0.80 (USDC.e, 6 decimals).
contract DisputeEconomics is Test {
    uint256 constant BOND = 250e6;
    uint256 constant FINAL_FEE = 250e6;
    uint256 constant REWARD = 0.8e6;
    uint256 constant LIVENESS = 7200; // 2h, live default
    bytes32 constant IDENT = "YES_OR_NO_QUERY";

    Finder finder;
    Store store;
    AddressWhitelist collateralWhitelist;
    IdentifierWhitelist identifierWhitelist;
    MockOracle oracle;
    MockERC20 currency;
    OptimisticOracleV2 oo;

    address requester = address(0x1111);
    address proposer = address(0x2222);
    address disputer = address(0x3333);

    uint256 ts;

    function setUp() public {
        vm.warp(1_800_000_000);

        finder = new Finder();
        store = new Store(FixedPoint.Unsigned(0), FixedPoint.Unsigned(0), address(0));
        collateralWhitelist = new AddressWhitelist();
        identifierWhitelist = new IdentifierWhitelist();
        oracle = new MockOracle();
        currency = new MockERC20();

        finder.changeImplementationAddress(bytes32("Store"), address(store));
        finder.changeImplementationAddress(bytes32("CollateralWhitelist"), address(collateralWhitelist));
        finder.changeImplementationAddress(bytes32("IdentifierWhitelist"), address(identifierWhitelist));
        finder.changeImplementationAddress(bytes32("Oracle"), address(oracle));

        collateralWhitelist.addToWhitelist(address(currency));
        identifierWhitelist.addSupportedIdentifier(IDENT);
        store.setFinalFee(address(currency), FixedPoint.Unsigned(FINAL_FEE));

        oo = new OptimisticOracleV2(LIVENESS, address(finder), address(0));

        currency.mint(requester, 1000e6);
        currency.mint(proposer, 1000e6);
        currency.mint(disputer, 1000e6);
        vm.prank(requester);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(proposer);
        currency.approve(address(oo), type(uint256).max);
        vm.prank(disputer);
        currency.approve(address(oo), type(uint256).max);

        ts = block.timestamp;
        vm.prank(requester);
        oo.requestPrice(IDENT, ts, "", IERC20(address(currency)), REWARD);
        vm.prank(requester);
        oo.setBond(IDENT, ts, "", BOND);
        vm.prank(requester);
        oo.setCustomLiveness(IDENT, ts, "", uint64(LIVENESS));
    }

    function _propose(int256 price) internal {
        vm.prank(proposer);
        oo.proposePrice(requester, IDENT, ts, "", price);
    }

    function _dispute() internal {
        vm.prank(disputer);
        oo.disputePrice(requester, IDENT, ts, "");
    }

    /* ------------------- Test 1: normal settlement ------------------- */

    function test_1_normal_settlement() public {
        _propose(1e18);
        assertEq(uint256(oo.getState(requester, IDENT, ts, "")), uint256(2), "Proposed"); // State.Proposed == 2

        vm.warp(block.timestamp + LIVENESS + 1);
        uint256 payout = oo.settle(requester, IDENT, ts, "");

        assertEq(payout, BOND + FINAL_FEE + REWARD, "undisputed payout");
        assertEq(currency.balanceOf(proposer), 1000e6 - BOND - FINAL_FEE + payout, "proposer net");
        assertEq(currency.balanceOf(proposer), 1000e6 + REWARD, "proposer gains only the reward");
        assertEq(currency.balanceOf(address(store)), 0, "store untouched without a dispute");
        assertEq(currency.balanceOf(address(oo)), 0, "oo drained");
    }

    /* ------------------ Test 2: disputed settlement ------------------ */

    function test_2_disputed_settlement_proposer_wins() public {
        _propose(1e18);
        _dispute();

        assertEq(uint256(oo.getState(requester, IDENT, ts, "")), uint256(4), "Disputed");
        assertEq(currency.balanceOf(disputer), 1000e6 - BOND - FINAL_FEE, "disputer paid 500");
        assertEq(currency.balanceOf(address(store)), BOND / 2 + FINAL_FEE, "store took 125 + 250 = 375");
        assertEq(currency.balanceOf(address(oo)), BOND + BOND + FINAL_FEE + FINAL_FEE + REWARD - (BOND / 2 + FINAL_FEE), "oo holds the rest");

        // No DVM answer: the request stays Disputed indefinitely.
        vm.warp(block.timestamp + 30 days);
        assertEq(uint256(oo.getState(requester, IDENT, ts, "")), uint256(4), "still Disputed after 30 days");
        vm.expectRevert();
        oo.settle(requester, IDENT, ts, "");

        // DVM answers in the proposer's favour.
        oracle.setPrice(IDENT, ts, oo.stampAncillaryData("", requester), 1e18);
        uint256 payout = oo.settle(requester, IDENT, ts, "");

        assertEq(payout, BOND + (BOND - BOND / 2) + FINAL_FEE + REWARD, "winner payout 625.80");
        assertEq(currency.balanceOf(proposer), 1000e6 - BOND - FINAL_FEE + payout, "proposer net +125.80");
        assertEq(currency.balanceOf(proposer), 1000e6 + 125.8e6, "proposer profit");
        assertEq(currency.balanceOf(disputer), 500e6, "disputer lost 500");
        assertEq(currency.balanceOf(address(oo)), 0, "oo drained");
    }

    /* -------------------- Test 3: attacker economics ------------------ */

    function test_3_attacker_cost_of_a_failed_dispute() public {
        uint256 d0 = currency.balanceOf(disputer);
        uint256 p0 = currency.balanceOf(proposer);
        uint256 s0 = currency.balanceOf(address(store));

        _propose(1e18);
        _dispute();
        oracle.setPrice(IDENT, ts, oo.stampAncillaryData("", requester), 1e18);
        oo.settle(requester, IDENT, ts, "");

        uint256 disputerLoss = d0 - currency.balanceOf(disputer);
        uint256 proposerGain = currency.balanceOf(proposer) - p0;
        uint256 burned = currency.balanceOf(address(store)) - s0;

        assertEq(disputerLoss, 500e6, "attacker loses bond + final fee");
        assertEq(burned, 375e6, "irreversibly burned (half bond + final fee)");
        assertEq(proposerGain, 125.8e6, "attacker's other 125 goes to the proposer, plus the reward");
        assertEq(disputerLoss, burned + 125e6, "every unit of the loss is accounted for");
    }

    /* ------------------ Test 4: successful dispute ------------------- */

    function test_4_successful_dispute_pays_the_disputer() public {
        _propose(1e18);
        _dispute();
        oracle.setPrice(IDENT, ts, oo.stampAncillaryData("", requester), 0); // proposer was wrong
        uint256 payout = oo.settle(requester, IDENT, ts, "");

        assertEq(payout, 625.8e6, "winner payout");
        assertEq(currency.balanceOf(disputer), 500e6 + payout, "disputer net");
        assertEq(currency.balanceOf(disputer), 1125.8e6, "disputer profit 125.80");
        assertEq(currency.balanceOf(proposer), 500e6, "proposer lost 500");
    }

    /* ------------------- Test 5: no double dispute ------------------- */

    function test_5_cannot_dispute_the_same_request_twice() public {
        _propose(1e18);
        _dispute();
        vm.prank(disputer);
        vm.expectRevert();
        oo.disputePrice(requester, IDENT, ts, "");
    }

    /* ---------------------- Test 6: control case --------------------- */

    function test_6_control_no_dispute_no_delay() public {
        _propose(1e18);
        vm.warp(block.timestamp + LIVENESS + 1);
        uint256 payout = oo.settle(requester, IDENT, ts, "");
        assertEq(payout, 500.8e6);
        assertEq(currency.balanceOf(address(store)), 0);
        assertEq(currency.balanceOf(disputer), 1000e6, "no cost to a non-participant");
    }

    /* ----------------- Test 7: funds locked, not lost ---------------- */

    function test_7_dispute_locks_bonds_but_not_market_funds() public {
        _propose(1e18);
        _dispute();
        // The OO holds exactly the two bonds, two final fees and the reward. It never holds the
        // market's own collateral: that lives in the CTF / exchange.
        assertEq(currency.balanceOf(address(oo)), 2 * BOND + 2 * FINAL_FEE + REWARD - (BOND / 2 + FINAL_FEE), "locked");
        assertEq(currency.balanceOf(requester), 1000e6 - REWARD, "requester's market funds untouched");
    }
}
