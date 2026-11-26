// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {Bridge2Medusa} from "./Bridge2Medusa.t.sol";

// ---------------------------------------------------------------------------
// Echidna property harness for the real Hyperliquid bridge (Bridge2.sol).
//
// A third, independent fuzzing engine over the same protocol paths. It inherits
// the Medusa harness (same actions, same setup, same attacker model) and simply
// re-exposes each property under Echidna's `echidna_` naming convention, which
// must return true while the property holds.
//
//   echidna . --contract Bridge2Echidna --config test/echidna.yaml
// ---------------------------------------------------------------------------

contract Bridge2Echidna is Bridge2Medusa {
  function echidna_funds_conserved() public view returns (bool) {
    return property_funds_conserved();
  }

  function echidna_broken_quorum_never_registered() public view returns (bool) {
    return property_broken_quorum_never_registered();
  }

  function echidna_no_double_payout() public view returns (bool) {
    return property_no_double_payout();
  }

  function echidna_invalidated_never_finalized() public view returns (bool) {
    return property_invalidated_never_finalized();
  }
}
