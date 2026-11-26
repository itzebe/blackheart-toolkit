"""Acceptance bar for ``blackheart explore`` (shell + --query)."""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

from blackheart.explore import Session, repl

ROOT = Path(__file__).resolve().parent.parent

SOURCE = """\
pragma solidity ^0.8.0;

contract Demo {
    address public owner;

    function setOwner(address next) external {
        owner = next;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function peek(address who) external view returns (uint256) {
        return balances[who];
    }

    mapping(address => uint256) public balances;
}
"""


def _session(tmp_path: Path) -> Session:
    (tmp_path / "Demo.sol").write_text(SOURCE, encoding="utf-8")
    return Session(str(tmp_path))


def test_contracts_and_functions(tmp_path: Path) -> None:
    session = _session(tmp_path)
    assert session.blocked is False
    assert "Demo" in session.dispatch("contracts")
    functions = session.dispatch("functions")
    assert "setOwner" in functions and "withdraw" in functions


def test_explain_shows_leads_and_claims(tmp_path: Path) -> None:
    out = _session(tmp_path).dispatch("explain setOwner")
    assert "setOwner" in out
    assert "unguarded-state-changer" in out
    assert "Claims" in out


def test_leads_claims_help(tmp_path: Path) -> None:
    session = _session(tmp_path)
    assert "medium" in session.dispatch("leads")
    assert "FALSIFIED" in session.dispatch("claims")
    assert "functions" in session.dispatch("help")
    assert "unknown command" in session.dispatch("frobnicate")


def test_repl_from_piped_stdin(tmp_path: Path) -> None:
    session = _session(tmp_path)
    out = io.StringIO()
    code = repl(session, stdin=io.StringIO("functions\nquit\n"), stdout=out)
    assert code == 0
    assert "Functions" in out.getvalue()


def test_cli_query(tmp_path: Path) -> None:
    (tmp_path / "Demo.sol").write_text(SOURCE, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "blackheart", "explore", str(tmp_path), "--query", "functions"],
        cwd=ROOT, capture_output=True, text=True, timeout=240,
    )
    assert result.returncode == 0, result.stderr
    assert "setOwner" in result.stdout

RUST_SOURCE = '''
#![allow(unused)]
use frame_support::pallet_prelude::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Admins<T: Config> =
        StorageMap<_, Blake2_128Concat, <T as frame_system::Config>::AccountId, (), OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        pub fn set_admin(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            let _ = who;
            Admins::<T>::insert(who, ());
            Ok(())
        }
    }
}
'''


def test_rust_functions_and_explain(tmp_path: Path) -> None:
    (tmp_path / "lib.rs").write_text(RUST_SOURCE, encoding="utf-8")
    session = Session(str(tmp_path))
    functions = session.dispatch("functions")
    assert "set_admin" in functions
    assert "dispatchable" in functions
    explained = session.dispatch("explain set_admin")
    assert "set_admin" in explained
    assert "Leads" in explained
    assert "Claims" in explained

