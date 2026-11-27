// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.16;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../../src/data-verification-mechanism/interfaces/FinderInterface.sol";
import "../../src/data-verification-mechanism/interfaces/StoreInterface.sol";
import "../../src/data-verification-mechanism/interfaces/IdentifierWhitelistInterface.sol";
import "../../src/common/implementation/FixedPoint.sol";

contract TestERC20 is ERC20 {
    constructor(string memory n, string memory s) ERC20(n, s) {}

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

contract MockFinder is FinderInterface {
    mapping(bytes32 => address) public impls;

    function changeImplementationAddress(bytes32 interfaceName, address implementationAddress) external override {
        impls[interfaceName] = implementationAddress;
    }

    function getImplementationAddress(bytes32 interfaceName) external view override returns (address) {
        return impls[interfaceName];
    }
}

contract MockStore is StoreInterface {
    mapping(address => uint256) public finalFees;

    function setFinalFee(address currency, uint256 fee) external {
        finalFees[currency] = fee;
    }

    function payOracleFees() external payable override {}

    function payOracleFeesErc20(address, FixedPoint.Unsigned calldata) external override {}

    function computeRegularFee(
        uint256,
        uint256,
        FixedPoint.Unsigned calldata
    ) external pure override returns (FixedPoint.Unsigned memory, FixedPoint.Unsigned memory) {
        return (FixedPoint.Unsigned(0), FixedPoint.Unsigned(0));
    }

    function computeFinalFee(address currency) external view override returns (FixedPoint.Unsigned memory) {
        return FixedPoint.Unsigned(finalFees[currency]);
    }
}

contract MockIdentifierWhitelist is IdentifierWhitelistInterface {
    mapping(bytes32 => bool) public supported;

    function setSupported(bytes32 id, bool v) external {
        supported[id] = v;
    }

    function addSupportedIdentifier(bytes32 identifier) external override {
        supported[identifier] = true;
    }

    function removeSupportedIdentifier(bytes32 identifier) external override {
        supported[identifier] = false;
    }

    function isIdentifierSupported(bytes32 identifier) external view override returns (bool) {
        return supported[identifier];
    }
}

// Minimal DVM-compatible oracle: records requests and returns a settable price.
contract MockOracle {
    struct Request {
        bool requested;
        bool resolved;
        int256 price;
    }

    mapping(bytes32 => Request) public requests;
    bytes public lastAncillaryData;
    uint256 public requestCount;

    function requestPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external {
        bytes32 id = keccak256(abi.encode(identifier, time, ancillaryData));
        if (!requests[id].requested) {
            requests[id].requested = true;
            requestCount++;
            lastAncillaryData = ancillaryData;
        }
    }

    function hasPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external view returns (bool) {
        return requests[keccak256(abi.encode(identifier, time, ancillaryData))].resolved;
    }

    function getPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external view returns (int256) {
        Request memory r = requests[keccak256(abi.encode(identifier, time, ancillaryData))];
        require(r.resolved, "Price not resolved");
        return r.price;
    }

    function pushPrice(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData,
        int256 price
    ) external {
        bytes32 id = keccak256(abi.encode(identifier, time, ancillaryData));
        requests[id].requested = true;
        requests[id].resolved = true;
        requests[id].price = price;
    }

    function getRequestId(
        bytes32 identifier,
        uint256 time,
        bytes memory ancillaryData
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(identifier, time, ancillaryData));
    }
}

// Records callbacks from OOv3.
contract MockCallbackRecipient {
    uint256 public resolvedCount;
    uint256 public disputedCount;
    bool public lastResolution;
    bytes32 public lastAssertionId;
    bool public revertOnResolve;

    function setRevertOnResolve(bool v) external {
        revertOnResolve = v;
    }

    function assertionResolvedCallback(bytes32 assertionId, bool assertedTruthfully) external {
        if (revertOnResolve) revert("callback revert");
        resolvedCount++;
        lastResolution = assertedTruthfully;
        lastAssertionId = assertionId;
    }

    function assertionDisputedCallback(bytes32 assertionId) external {
        disputedCount++;
        lastAssertionId = assertionId;
    }
}
