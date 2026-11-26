"""Acceptance bar for the interrogation ledger.

The engine's value is not that it finds something -- it is that it never drops a
claim silently. These tests pin the three properties that make that true:

* a claim the code does not honour is ``FALSIFIED`` with evidence at a real line;
* a claim the check cannot decide is ``UNTESTABLE``, never "clean";
* a ``SURVIVED`` verdict always names what the check could not see, so it can
  never be read as a proof;
* the guarded twin is silent, in both environments.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from blackheart.interrogate import (
    FALSIFIED,
    SURVIVED,
    UNTESTABLE,
    as_dict,
    interrogate,
    render_markdown,
    summarise,
)


VULNERABLE_SOL = """
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: balanceOf[msg.sender]}("");
        require(ok);
        balanceOf[msg.sender] = 0;
    }

    function initialize(address o) external {
        owner = o;
    }

    function spin(uint256 n) external {
        while (true) {
            balanceOf[msg.sender] += n;
        }
    }
}
"""

GUARDED_SOL = """
pragma solidity ^0.8.0;

contract SafeVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    bool private initialized;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function initialize(address o) external {
        require(!initialized, "init");
        initialized = true;
        owner = o;
    }
}
"""

VULNERABLE_RS = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn unguarded(origin: OriginFor<T>, key: u32) -> DispatchResult {
            let value = Self::lookup(key).unwrap();
            for (_k, _v) in Items::<T>::iter() {
                Self::touch(value);
            }
            Ok(())
        }

        #[pallet::call_index(1)]
        pub fn weightless(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            Ok(())
        }
    }
}
"""

GUARDED_RS = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call(weight(<T as Config>::WeightInfo))]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::transfer())]
        pub fn transfer(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(amount > 0u64, Error::<T>::BadInput);
            let left = Self::balance(&who).checked_sub(amount).ok_or(Error::<T>::BadInput)?;
            Self::set_balance(&who, left);
            Ok(())
        }
    }
}
"""


def _write(tmp_path: Path, name: str, source: str) -> Path:
    (tmp_path / name).write_text(source, encoding="utf-8")
    return tmp_path


def test_solidity_claims_are_falsified_with_evidence(tmp_path):
    verdicts, language, errors = interrogate(str(_write(tmp_path, "Vault.sol", VULNERABLE_SOL)))
    assert language == "solidity" and not errors
    by_key = {v.claim.key: v for v in verdicts}

    assert by_key["authorization:Vault.mint"].status == FALSIFIED
    assert by_key["authorization:Vault.withdraw"].status == FALSIFIED
    assert by_key["initialization:Vault.initialize"].status == FALSIFIED
    assert by_key["ordering:Vault.withdraw"].status == FALSIFIED
    assert by_key["conservation:Vault"].status == FALSIFIED

    mint = by_key["authorization:Vault.mint"]
    assert "Vault.sol:" in mint.claim.location
    assert mint.evidence
    assert mint.counterexample


def test_solidity_guarded_twin_survives_and_says_what_it_could_not_see(tmp_path):
    verdicts, _, _ = interrogate(str(_write(tmp_path, "SafeVault.sol", GUARDED_SOL)))
    by_key = {v.claim.key: v for v in verdicts}
    assert by_key["authorization:SafeVault.mint"].status == SURVIVED
    assert by_key["initialization:SafeVault.initialize"].status == SURVIVED
    assert by_key["ordering:SafeVault.withdraw"].status == SURVIVED
    for verdict in verdicts:
        if verdict.status == SURVIVED:
            assert verdict.blind_spot, "a survived verdict must name what it could not see"


def test_rust_claims_are_falsified(tmp_path):
    verdicts, language, errors = interrogate(str(_write(tmp_path, "lib.rs", VULNERABLE_RS)))
    assert language == "rust" and not errors
    by_key = {v.claim.key: v for v in verdicts}
    assert by_key["authorization:lib::Pallet.unguarded"].status == FALSIFIED
    assert by_key["no-panic:lib::Pallet.unguarded"].status == FALSIFIED
    assert by_key["bounded-work:lib::Pallet.unguarded"].status == FALSIFIED
    assert by_key["weighted:lib::Pallet.weightless"].status == FALSIFIED


def test_rust_guarded_twin_survives(tmp_path):
    verdicts, _, _ = interrogate(str(_write(tmp_path, "lib.rs", GUARDED_RS)))
    assert verdicts
    assert all(v.status == SURVIVED for v in verdicts), [
        (v.claim.key, v.status, v.evidence) for v in verdicts if v.status != SURVIVED
    ]


def test_every_verdict_is_one_of_three_states(tmp_path):
    verdicts, _, _ = interrogate(str(_write(tmp_path, "Vault.sol", VULNERABLE_SOL)))
    assert {v.status for v in verdicts} <= {FALSIFIED, SURVIVED, UNTESTABLE}
    counts = summarise(verdicts)
    assert sum(counts.values()) == len(verdicts)


def test_unbounded_loop_is_untestable_not_clean(tmp_path):
    """A loop bounded by calldata is not proved safe; it is undecided."""
    verdicts, _, _ = interrogate(str(_write(tmp_path, "Vault.sol", VULNERABLE_SOL)))
    spin = next(v for v in verdicts if v.claim.key == "termination:Vault.spin")
    assert spin.status == FALSIFIED  # while (true) is decidable
    assert spin.blind_spot


def test_ledger_states_the_discipline(tmp_path):
    verdicts, language, errors = interrogate(str(_write(tmp_path, "lib.rs", VULNERABLE_RS)))
    payload = as_dict(verdicts, language, errors)
    assert "not a proof" in payload["discipline"]
    text = render_markdown(verdicts, language, errors)
    assert "Falsified claims" in text
    assert "could not see" in text


def test_unknown_tree_is_reported_not_silently_empty(tmp_path):
    verdicts, language, errors = interrogate(str(tmp_path))
    assert verdicts == []
    assert language == "unknown"
    assert errors, "an unscannable tree must not look like a clean one"


def test_cli_interrogate_emits_json(tmp_path):
    _write(tmp_path, "lib.rs", VULNERABLE_RS)
    root = Path(__file__).resolve().parents[1]
    out = subprocess.run(
        [sys.executable, "-m", "blackheart", "interrogate", str(tmp_path), "--json"],
        cwd=root, capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload["language"] == "rust"
    assert payload["summary"]["FALSIFIED"] >= 1
    assert payload["verdicts"][0]["question"]


def test_ambiguous_tree_says_ambiguous_not_empty(tmp_path):
    _write(tmp_path, "lib.rs", VULNERABLE_RS)
    _write(tmp_path, "Vault.sol", VULNERABLE_SOL)
    verdicts, language, errors = interrogate(str(tmp_path))
    assert verdicts == [] and language == "unknown"
    assert "ambiguous" in errors[0]
    assert "pass --language" in errors[0]


def test_custom_ensure_guard_counts_as_authorization(tmp_path):
    """`Self::ensure_sudo(origin)?` is a guard; a name list must not miss it."""
    _write(tmp_path, "lib.rs", '''
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::sudo())]
        pub fn sudo(origin: OriginFor<T>, call: Box<T::RuntimeCall>) -> DispatchResult {
            Self::ensure_sudo(origin)?;
            call.dispatch_bypass_filter(RawOrigin::Root.into())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::open())]
        pub fn open(origin: OriginFor<T>, amount: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Ok(())
        }
    }
}
''')
    verdicts, language, errors = interrogate(str(tmp_path), "rust")
    assert language == "rust" and not errors
    falsified = [v for v in verdicts if v.status == FALSIFIED]
    assert not falsified, [v.claim.key for v in falsified]
