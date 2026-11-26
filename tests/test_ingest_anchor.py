"""Acceptance bar for Solana / Anchor ingestion.

The Rust scanner began as a Substrate scanner: it looked for
``#[pallet::call]`` dispatchables and judged FRAME weights and ``ensure!``
origins. That is blind to a Solana program, where the reachable surface is an
Anchor instruction and the authorization lives in the ``#[derive(Accounts)]``
struct. Pointing it at a real Anchor program therefore reported thousands of
functions and **zero** dispatchables -- a false "clean".

These tests pin the properties that make the Anchor path trustworthy:

* a ``#[program]`` handler and any ``Context<T>`` function are dispatchables,
  and the ``Accounts`` struct is recovered with its per-field constraints,
  including multi-line ``#[account(...)]`` attributes;
* a raw writable ``UncheckedAccount``/``AccountInfo`` with no
  address/owner/seeds/has_one/constraint is a lead, while each guarded twin
  (``has_one``, ``seeds``, ``address``) stays silent;
* an unchecked CPI is a lead, while a program-id check clears it;
* FRAME-only rules (origin, weight) do not fire on Anchor;
* every rule maps to a category in the objective catalog.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from blackheart.ingest.rust import ingest_rust
from blackheart.ingest.rust_flags import RUST_RULES, evaluate_rust
from blackheart.objectives import _OBJECTIVE_CATALOG


VULNERABLE = """
use anchor_lang::prelude::*;

#[program]
pub mod demo {
    use super::*;
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::withdraw(ctx, amount)
    }
}

pub mod instructions {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let _ = (ctx, amount);
        Ok(())
    }

    pub fn cpi_unsafe(ctx: Context<Guard>) -> Result<()> {
        let ix = 0;
        invoke(&ix, &[])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Guard<'info> {
    pub authority: Signer<'info>,
}
"""


GUARDED = """
use anchor_lang::prelude::*;

#[program]
pub mod demo {
    use super::*;
    pub fn withdraw(ctx: Context<Guarded>) -> Result<()> {
        instructions::withdraw(ctx)
    }
    pub fn withdraw_safe(ctx: Context<GuardedConstraint>) -> Result<()> {
        instructions::withdraw_safe(ctx)
    }
    pub fn withdraw_pda(ctx: Context<GuardedPda>) -> Result<()> {
        instructions::withdraw_pda(ctx)
    }
    pub fn withdraw_fixed(ctx: Context<GuardedAddress>) -> Result<()> {
        instructions::withdraw_fixed(ctx)
    }
    pub fn cpi_safe(ctx: Context<Guarded>) -> Result<()> {
        instructions::cpi_safe(ctx)
    }
    pub fn cross_bound(ctx: Context<CrossBound>) -> Result<()> {
        instructions::cross_bound(ctx)
    }
}

pub mod instructions {
    use super::*;

    pub fn withdraw(ctx: Context<Guarded>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    pub fn withdraw_safe(ctx: Context<GuardedConstraint>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    pub fn withdraw_pda(ctx: Context<GuardedPda>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    pub fn withdraw_fixed(ctx: Context<GuardedAddress>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    pub fn cpi_safe(ctx: Context<Guarded>) -> Result<()> {
        check!(ctx.accounts.authority.key() == expected)?;
        let ix = 0;
        invoke(&ix, &[])?;
        Ok(())
    }

    pub fn cross_bound(ctx: Context<CrossBound>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Guarded<'info> {
    #[account(
        mut,
        has_one = authority @ ErrorCode::Unauthorized,
    )]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct GuardedConstraint<'info> {
    #[account(
        mut,
        constraint = vault.key() == expected,
    )]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct GuardedPda<'info> {
    #[account(mut, seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct GuardedAddress<'info> {
    #[account(mut, address = crate::ID)]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CrossBound<'info> {
    #[account(
        has_one = integration_acc_3 @ ErrorCode::InvalidUser,
    )]
    pub bank: AccountLoader<'info, Bank>,
    #[account(mut)]
    pub integration_acc_3: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
"""


def _scan(tmp_path: Path, source: str):
    (tmp_path / "lib.rs").write_text(source, encoding="utf-8")
    return ingest_rust(tmp_path)


def test_anchor_handlers_are_dispatchables_with_their_accounts(tmp_path):
    report = _scan(tmp_path, VULNERABLE)
    module = report.modules[0]
    assert module.anchor is True

    instructions = {f.name for f in report.dispatchables}
    assert {"withdraw", "cpi_unsafe"} <= instructions

    withdraw = next(f for f in report.dispatchables if f.name == "withdraw")
    assert withdraw.accounts_struct == "Withdraw"
    struct = module.accounts_for("Withdraw")
    assert struct is not None
    assert [f.name for f in struct.fields] == ["vault", "authority"]
    assert "UncheckedAccount" in struct.field("vault").type


def test_multiline_account_attributes_are_joined(tmp_path):
    report = _scan(tmp_path, GUARDED)
    module = report.modules[0]
    has_one = module.accounts_for("Guarded").field("vault")
    assert "has_one = authority" in has_one.attrs
    constraint = module.accounts_for("GuardedConstraint").field("vault")
    assert "constraint = vault.key() == expected" in constraint.attrs


def test_unchecked_writable_account_is_a_lead(tmp_path):
    flags = evaluate_rust(_scan(tmp_path, VULNERABLE))
    leads = [f for f in flags if f.rule == "anchor-unchecked-writable-account"]
    assert leads, "a raw writable UncheckedAccount with no binding must be a lead"
    assert all("vault: UncheckedAccount" in f.evidence for f in leads)
    assert {f.function for f in leads} >= {"withdraw"}
    assert all(f.path == "lib.rs" and f.line > 0 for f in leads)


def test_each_guarded_account_is_silent(tmp_path):
    flags = evaluate_rust(_scan(tmp_path, GUARDED))
    assert not [f for f in flags if f.rule == "anchor-unchecked-writable-account"]
    assert not [f for f in flags if f.rule == "anchor-unchecked-cpi"]


def test_cross_field_has_one_binds_the_raw_account(tmp_path):
    flags = evaluate_rust(_scan(tmp_path, GUARDED))
    assert not [
        f
        for f in flags
        if f.rule == "anchor-unchecked-writable-account" and "integration_acc_3" in f.evidence
    ]


def test_unchecked_cpi_is_a_lead(tmp_path):
    flags = evaluate_rust(_scan(tmp_path, VULNERABLE))
    leads = [f for f in flags if f.rule == "anchor-unchecked-cpi"]
    assert [f.function for f in leads] == ["cpi_unsafe"]


def test_frame_only_rules_do_not_fire_on_anchor(tmp_path):
    flags = evaluate_rust(_scan(tmp_path, VULNERABLE))
    rules = {f.rule for f in flags}
    assert "no-origin-check" not in rules
    assert "missing-weight-annotation" not in rules


def test_every_rule_category_exists_in_the_objective_catalog():
    for rule in RUST_RULES:
        assert rule.category in _OBJECTIVE_CATALOG, rule.category


def test_cli_ingest_reports_anchor_dispatchables_and_leads(tmp_path):
    (tmp_path / "lib.rs").write_text(VULNERABLE, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "ingest", str(tmp_path), "--language", "rust", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["dispatchables"] >= 2
    assert payload["leads"] >= 2


def _authorization_verdicts(tmp_path: Path, source: str):
    from blackheart.interrogate import interrogate

    (tmp_path / "lib.rs").write_text(source, encoding="utf-8")
    verdicts, language, errors = interrogate(str(tmp_path), "rust")
    assert language == "rust"
    assert errors == ()
    return [v for v in verdicts if v.claim.key.startswith("authorization:")]


def test_anchor_authorization_is_judged_by_the_accounts_struct(tmp_path):
    verdicts = _authorization_verdicts(tmp_path, VULNERABLE)
    withdraw = [v for v in verdicts if v.claim.subject.endswith(".withdraw")]
    assert withdraw
    for v in withdraw:
        assert v.status == "FALSIFIED"
        assert "unbound writable account" in v.method
        assert "no origin check in the dispatchable body" not in v.counterexample
        assert "Accounts struct" in v.claim.statement


def test_guarded_anchor_accounts_never_produce_a_false_authorization_claim(tmp_path):
    verdicts = _authorization_verdicts(tmp_path, GUARDED)
    assert verdicts, "the guarded fixture has dispatchables"
    assert not [v for v in verdicts if v.status == "FALSIFIED"]
    assert {v.status for v in verdicts} <= {"SURVIVED", "UNTESTABLE"}


def test_anchor_has_no_frame_weight_claim(tmp_path):
    from blackheart.interrogate import interrogate

    (tmp_path / "lib.rs").write_text(VULNERABLE, encoding="utf-8")
    verdicts, _, _ = interrogate(str(tmp_path), "rust")
    assert not [v for v in verdicts if v.claim.key.startswith("weighted:")]
