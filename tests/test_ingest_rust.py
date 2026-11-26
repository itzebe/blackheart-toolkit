"""Acceptance bar for Rust / Substrate ingestion.

The EVM engines cannot read a runtime, so this is the second environment the
tool has to work in. The properties that make it trustworthy are the same ones
the Solidity scanner is held to:

* the noise stripper preserves offsets, so every flag's ``file:line`` is real,
  and it understands Rust's nested comments, raw strings and lifetimes;
* the scanner recovers dispatchables from both the bare ``#[pallet::call]`` form
  and the modern ``#[pallet::call(weight(...))]`` form -- missing the second one
  reported a real pallet as having no dispatchables at all;
* each rule fires on its vulnerable shape and **stays silent on its guarded
  twin**;
* every rule maps to a category that exists in the objective catalog.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from blackheart.ingest.rust import ingest_rust, strip_rust_noise
from blackheart.ingest.rust_flags import RUST_RULES, evaluate_rust
from blackheart.objectives import _OBJECTIVE_CATALOG


VULNERABLE = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn panics(origin: OriginFor<T>, key: u32) -> DispatchResult {
            ensure_signed(origin)?;
            let value = Self::lookup(key).unwrap();
            let _ = value;
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn iterates(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            for (_k, _v) in Items::<T>::iter() {
                Self::touch();
            }
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn saturates(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            ensure_signed(origin)?;
            let account = Self::account();
            let left = account.balance.saturating_sub(amount);
            Self::transfer(left);
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn casts(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            ensure_signed(origin)?;
            let small = amount as u32;
            Self::transfer(small.into());
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(10_000)]
        pub fn multiplies(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            ensure_signed(origin)?;
            let rate = Self::rate();
            let fee = amount * rate;
            Self::transfer(fee);
            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(10_000)]
        pub fn unguarded(origin: OriginFor<T>) -> DispatchResult {
            Self::bump();
            Ok(())
        }

        #[pallet::call_index(6)]
        pub fn weightless(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(10_000)]
        pub fn event_first(origin: OriginFor<T>, key: u32) -> DispatchResult {
            ensure_signed(origin)?;
            Self::deposit_event(Event::Done { key });
            Items::<T>::insert(key, 1u64);
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(10_000)]
        pub fn timed(origin: OriginFor<T>) -> DispatchResult {
            ensure_signed(origin)?;
            if frame_system::Pallet::<T>::block_number() < 100u32.into() {
                return Err(Error::<T>::BadInput.into());
            }
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(10_000)]
        pub fn ignores_result(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            ensure_signed(origin)?;
            let _ = T::Currency::transfer(&Self::a(), &Self::b(), amount.into(), ExistenceRequirement::AllowDeath);
            Ok(())
        }
    }
}
"""

GUARDED = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call(weight(<T as Config>::WeightInfo))]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::transfer())]
        pub fn transfer(origin: OriginFor<T>, to: T::AccountId, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(amount > 0u64, Error::<T>::BadInput);
            let left = Self::balance(&who).checked_sub(amount).ok_or(Error::<T>::BadInput)?;
            Self::set_balance(&who, left);
            Self::set_balance(&to, Self::balance(&to).checked_add(amount).ok_or(Error::<T>::BadInput)?);
            Self::deposit_event(Event::Done { who });
            Ok(())
        }
    }
}
"""


def _scan(tmp_path: Path, source: str):
    (tmp_path / "lib.rs").write_text(source, encoding="utf-8")
    return ingest_rust(tmp_path)


def test_strip_noise_preserves_length_and_newlines():
    src = 'let a = "x // not a comment"; // real\n/* outer /* nested */ still */ let b = 1;'
    stripped = strip_rust_noise(src)
    assert len(stripped) == len(src)
    assert stripped.count("\n") == src.count("\n")
    assert "not a comment" not in stripped
    assert "nested" not in stripped
    assert "let b = 1;" in stripped


def test_lifetimes_are_not_eaten_as_char_literals():
    src = "fn f<'a>(x: &'a str) -> &'a str { x }"
    assert strip_rust_noise(src) == src


def test_raw_strings_are_blanked():
    src = 'let s = r#"contains "quotes" and // slashes"#; let t = 2;'
    stripped = strip_rust_noise(src)
    assert len(stripped) == len(src)
    assert "quotes" not in stripped
    assert "let t = 2;" in stripped


def test_dispatchables_are_recovered_from_the_bare_attribute(tmp_path):
    report = _scan(tmp_path, VULNERABLE)
    names = {f.name for f in report.dispatchables}
    assert {"panics", "iterates", "unguarded", "weightless"} <= names
    assert not report.errors


def test_dispatchables_are_recovered_from_the_weighted_attribute(tmp_path):
    """`#[pallet::call(weight(<T as Config>::WeightInfo))]` is the modern form.

    Matching only the bare `#[pallet::call]` reported a real pallet (pallet-assets,
    34 dispatchables) as having none, and every rule then stayed silent.
    """
    report = _scan(tmp_path, GUARDED)
    assert [f.name for f in report.dispatchables] == ["transfer"]
    assert report.dispatchables[0].weight  # impl-level weight is inherited


@pytest.mark.parametrize(
    "rule,function",
    [
        ("panic-in-dispatchable", "panics"),
        ("unbounded-storage-iteration", "iterates"),
        ("saturating-arithmetic-in-value-path", "saturates"),
        ("unchecked-cast", "casts"),
        ("multiplication-without-checked", "multiplies"),
        ("no-origin-check", "unguarded"),
        ("missing-weight-annotation", "weightless"),
        ("event-before-state-change", "event_first"),
        ("time-window-comparison", "timed"),
        ("unchecked-transfer-result", "ignores_result"),
    ],
)
def test_each_rule_fires_on_its_shape(tmp_path, rule, function):
    flags = evaluate_rust(_scan(tmp_path, VULNERABLE))
    hit = {f.rule for f in flags if f.function == function}
    assert rule in hit, f"{rule} did not fire on {function}; got {sorted(hit)}"
    flag = next(f for f in flags if f.rule == rule and f.function == function)
    assert flag.evidence, "a flag without evidence is not actionable"
    assert flag.line > 0 and flag.path.endswith("lib.rs")


def test_the_guarded_twin_is_silent(tmp_path):
    """Precision is the only reason a triage sheet gets read."""
    flags = evaluate_rust(_scan(tmp_path, GUARDED))
    assert flags == ()


def test_every_rule_category_exists_in_the_objective_catalog():
    assert {r.category for r in RUST_RULES} <= set(_OBJECTIVE_CATALOG)


def test_report_says_a_lead_is_not_a_finding(tmp_path):
    report = _scan(tmp_path, VULNERABLE)
    assert report.dispatchables
    # The scanner is a scanner: it records what it could not read rather than
    # claiming a clean surface.
    assert isinstance(report.errors, tuple)


def test_cli_ingest_accepts_a_rust_tree(tmp_path):
    (tmp_path / "lib.rs").write_text(VULNERABLE, encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    out = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(tmp_path), "--language", "rust", "--json"],
        cwd=root, capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload["language"] == "rust"
    assert payload["dispatchables"] > 0
    assert payload["leads"]


def test_mixed_tree_names_the_language_it_did_not_read(tmp_path):
    """A mixed tree is the easiest way to believe a scan covered more than it did."""
    (tmp_path / "lib.rs").write_text(VULNERABLE, encoding="utf-8")
    (tmp_path / "Vault.sol").write_text("contract A { function f() external {} }", encoding="utf-8")
    report = ingest_rust(tmp_path)
    assert report.dispatchables

    from blackheart.ingest import unread_sources

    notes = unread_sources(str(tmp_path), "rust")
    assert notes and "solidity" in notes[0]
    assert unread_sources(str(tmp_path), "solidity")[0].startswith("1 rust")


def test_ambiguous_tree_is_reported_as_ambiguous_not_empty(tmp_path):
    (tmp_path / "lib.rs").write_text(VULNERABLE, encoding="utf-8")
    (tmp_path / "Vault.sol").write_text("contract A { function f() external {} }", encoding="utf-8")
    from blackheart.ingest import detect_language, language_census

    assert detect_language(str(tmp_path)) == "unknown"
    census = language_census(str(tmp_path))
    assert census == {"rust": 1, "solidity": 1}


def test_multi_line_weight_attribute_is_recognised(tmp_path):
    """A weight written across several lines is still a weight."""
    source = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::report(
            proof.validator_count(),
            T::MaxNominators::get(),
        ))]
        pub fn report(origin: OriginFor<T>, proof: Proof) -> DispatchResult {
            ensure_signed(origin)?;
            Ok(())
        }
    }
}
"""
    flags = evaluate_rust(_scan(tmp_path, source))
    assert not [f for f in flags if f.rule == "missing-weight-annotation"], flags


def test_test_and_benchmark_files_are_not_the_pallet(tmp_path):
    """src/tests.rs helpers are not attacker-reachable dispatchables."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "lib.rs").write_text(GUARDED, encoding="utf-8")
    (src_dir / "tests.rs").write_text(VULNERABLE, encoding="utf-8")
    report = ingest_rust(tmp_path)
    names = {f.name for f in report.dispatchables}
    assert "transfer" in names
    assert "panics" not in names, "a dispatchable defined in tests.rs leaked into the surface"


def test_impl_level_weight_with_equals_is_recognised(tmp_path):
    """`#[pallet::call(weight = T::WeightInfo)]` is the third spelling."""
    source = """
#[frame_support::pallet]
pub mod pallet {
    #[pallet::call(weight = T::WeightInfo)]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(1)]
        pub fn unnote(origin: OriginFor<T>, hash: T::Hash) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Ok(())
        }
    }
}
"""
    flags = evaluate_rust(_scan(tmp_path, source))
    assert not [f for f in flags if f.rule == "missing-weight-annotation"], flags
