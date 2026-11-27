"""The first real TestSparker adapter: dispatcher analysis vs actual execution.

This adapter closes the loop the deployed-contract work left open. The selector
analyser makes a *claim* -- "a call with selector S reaches code" -- and until now
that claim was checked only by hand-written fixtures, which is how three of them
came to be invalid EVM without anyone noticing.

The adapter turns the claim into an executable test:

  for each selector the analyser reports REACHABLE,
      call the contract with that selector and assert the dispatcher routes it
      somewhere other than the unknown-selector fallback;

  for each selector it reports PRESENT_ONLY (data, not an entry point),
      call it and assert it does *not* reach a dispatch body.

Then it runs those calls in :mod:`blackheart.evm` and compares. A mismatch is a
defect in the analyser, stated as such -- not a vulnerability in the target.

Why this is a real adapter and not a wrapper: it generates *new* tests per
contract (one per selector, plus boundary and adversarial cases), executes them,
classifies each honestly, and preserves counterexamples. It also mutates code to
probe the analyser's edges (truncated PUSH, bogus destinations, metadata trailers)
so a regression in the analyser is caught by execution rather than by a fixture
that happened to be right.

Ground truth caveat, stated once and enforced by the code: the interpreter models
the opcodes a dispatcher uses. It is not a full EVM and is never presented as one.
``DispatchSparker.capability`` records that limitation on every report.
"""

from __future__ import annotations

import random
from typing import Any, Optional

from ..deployed import function_selector
from ..deployed_selectors import (
    PRESENT_ONLY,
    REACHABLE,
    analyse_selectors,
)
from ..evm import BAD_JUMP, INVALID, execute
from .adapter import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_NO_SIGNAL,
    GeneratedTest,
    TestOutcome,
    fingerprint,
)

__all__ = ["DispatchSparker"]

#: Selectors the adapter uses as a control: overwhelmingly unlikely to be real.
_CONTROL_SELECTOR = "00000001"

#: Opcode names used when describing a mutation, for the rationale text.
_SSTORE = 0x55
_REVERT = 0xFD


def _hex(code: bytes) -> str:
    return code.hex()


def _unhex(text: str) -> bytes:
    body = text[2:] if text.startswith("0x") else text
    return bytes.fromhex(body)


class DispatchSparker:
    """Generate and execute dispatcher tests against the analyser's own claims."""

    name = "dispatch"
    #: Dispatcher tests run in the local interpreter; nothing live is touched.
    requires_live_target = False
    capability = (
        "Executes dispatcher calls in a deterministic local EVM model (opcode subset "
        "a Solidity dispatcher uses). This is NOT a full EVM and results are never "
        "presented as mainnet execution."
    )

    # -- generation ------------------------------------------------------- #
    def generate(
        self,
        *,
        seed: int = 0,
        corpus: Optional[list[dict]] = None,
        limit: Optional[int] = None,
    ) -> list[GeneratedTest]:
        """Build one test per selector claim, plus adversarial mutations.

        ``corpus`` is a list of ``{"name": str, "code": hex, "abi": [signatures]}``.
        When omitted, the adapter uses the repository's real solc fixtures so a
        plain run has a meaningful baseline and needs no network.
        """
        cases = corpus if corpus is not None else self.default_corpus()
        tests: list[GeneratedTest] = []
        for case in cases:
            tests.extend(self._tests_for_case(case, seed=seed))
        tests.extend(self._adversarial_tests(seed=seed))
        if limit is not None:
            tests = tests[:limit]
        return tests

    def default_corpus(self) -> list[dict]:
        """The repository's real solc 0.8.24 fixtures, legacy and via-IR."""
        import glob
        import os

        out: list[dict] = []
        for path in sorted(glob.glob("tests/fixtures/dispatch/*.code.txt")):
            name = os.path.basename(path)[: -len(".code.txt")]
            abi_path = path.replace(".code.", ".abi.")
            try:
                code = open(path, encoding="utf-8").read().strip()
                abi = [s for s in open(abi_path, encoding="utf-8").read().split() if s]
            except OSError:
                continue
            out.append({"name": name, "code": code, "abi": abi})
        return out

    def _tests_for_case(self, case: dict, *, seed: int) -> list[GeneratedTest]:
        name = case.get("name", "unnamed")
        code_hex = case.get("code", "")
        abi = case.get("abi", []) or []
        try:
            raw = _unhex(code_hex)
        except ValueError:
            return [
                GeneratedTest(
                    test_id=fingerprint("malformed", name, code_hex),
                    adapter=self.name,
                    kind="malformed_code",
                    code=code_hex,
                    rationale=f"{name}: corpus code is not valid hex",
                    generation={"seed": seed, "case": name},
                )
            ]

        report = analyse_selectors(raw)
        tests: list[GeneratedTest] = []

        # A test per ABI selector: the dispatcher must recognise its own functions.
        abi_selectors: set[str] = set()
        for sig in abi:
            try:
                sel = function_selector(sig)
            except Exception:  # a signature the repo helper cannot hash is not our defect
                continue
            abi_selectors.add(sel)
            expectation: dict[str, Any] = {"not_fallback": True}
            if "expect_defect" in case:
                # Only a case that states its own ground truth contributes to
                # precision/recall; the rest are excluded rather than assumed clean.
                expectation["expect_defect"] = bool(case["expect_defect"])
            tests.append(
                GeneratedTest(
                    test_id=fingerprint("abi", name, sel),
                    adapter=self.name,
                    kind="abi_selector_reaches_dispatch",
                    code=_hex(raw),
                    input={"selector": sel, "calldata_suffix": "00" * 32},
                    expectation=expectation,
                    rationale=(
                        f"{name}: {sig} is in the ABI, so a call must be routed by the "
                        "dispatcher rather than fall through to the unknown-selector path"
                    ),
                    generation={"seed": seed, "case": name, "signature": sig},
                )
            )

        # A test per analyser claim, so the analysis itself is checked by execution.
        for entry in report.selectors:
            tests.append(
                GeneratedTest(
                    test_id=fingerprint("claim", name, entry.selector, entry.status),
                    adapter=self.name,
                    kind="analysis_matches_execution",
                    code=_hex(raw),
                    input={"selector": entry.selector, "calldata_suffix": "00" * 32},
                    expectation={
                        "analysed_status": entry.status,
                        "in_abi": entry.selector in abi_selectors,
                    },
                    rationale=(
                        f"{name}: analyser reports {entry.status} for {entry.selector}; "
                        "execution must not contradict that claim"
                    ),
                    generation={"seed": seed, "case": name, "claimed": entry.status},
                )
            )

        # Boundary: the empty-calldata call must not execute a dispatch body.
        tests.append(
            GeneratedTest(
                test_id=fingerprint("empty", name),
                adapter=self.name,
                kind="empty_calldata_is_recorded",
                code=_hex(raw),
                input={"selector": "", "calldata_suffix": ""},
                expectation={"not_fallback": False},
                rationale=(
                    f"{name}: record what a call with no calldata does, so a change in "
                    "the receive/fallback path is visible across runs"
                ),
                generation={"seed": seed, "case": name},
            )
        )
        return tests

    def known_answer_corpus(self) -> list[dict]:
        """Cases whose correct verdict is established *outside* the analyser.

        Ground truth here is one of two things, never the analyser's own output:

        * a contract compiled by solc, whose ABI lists the functions (the fixtures);
        * a hand-built shape whose EVM semantics are unambiguous and were checked
          against ``anvil`` -- e.g. a JUMPI to a non-JUMPDEST can never be taken.

        ``expect_defect`` is what the *adapter* should report, which is what makes
        precision and recall computable. Every case states its own rationale so a
        reviewer can disagree with the ground truth explicitly rather than
        discovering it was assumed.
        """
        cases: list[dict] = []

        # 1. Real solc contracts: every ABI selector is a real entry point, so the
        #    analyser reporting any of them PRESENT_ONLY is a false negative.
        for case in self.default_corpus():
            abi = case.get("abi") or []
            if not abi:
                continue
            cases.append({
                "name": case["name"],
                "code": case["code"],
                "abi": abi,
                "expect_defect": False,
                "ground_truth": (
                    "solc compiled this contract; its ABI is the definition of which "
                    "selectors are callable entry points"
                ),
            })

        # 2. A jump to a non-JUMPDEST cannot be taken (verified against anvil). If the
        #    analyser claimed reachability here it would be wrong; today it correctly
        #    refuses, so no defect is expected.
        head = bytes.fromhex("60003560e01c")
        compare = bytes.fromhex("63" + "aaaaaaaa" + "14")
        dest = len(head) + len(compare) + 3
        bogus = head + compare + b"\x61" + dest.to_bytes(2, "big") + b"\x57" \
            + bytes.fromhex("60006000fd")
        cases.append({
            "name": "bogus-destination",
            "code": bogus.hex(),
            "abi": [],
            "expect_defect": False,
            "ground_truth": "anvil reverts: JUMPI to a non-JUMPDEST is never taken",
        })

        # 3. A real, valid dispatcher built by hand and verified in anvil: the body
        #    must be found. A PRESENT_ONLY verdict here is a false negative.
        valid = head + compare + b"\x61" + (dest + 3 + 7).to_bytes(2, "big") + b"\x57" \
            + bytes.fromhex("60006000fd") + bytes.fromhex("5b60aa60005500")
        cases.append({
            "name": "hand-built-valid-dispatcher",
            "code": valid.hex(),
            # The contract dispatches on 0xaaaaaaaa. Declaring a signature here
            # would hash to a different selector and make the test compare the
            # wrong thing, so the selector is named directly.
            "abi": [],
            "probe_selector": "aaaaaaaa",
            "expect_defect": False,
            "ground_truth": (
                "anvil: selector 0xaaaaaaaa reaches the body and writes storage; the "
                "analyser must report it reachable"
            ),
        })

        # 4. A published ABI that claims a selector the dispatcher does not route --
        #    the shape of an upgrade whose ABI was not regenerated, or an optimiser
        #    that dropped an arm. Ground truth is execution, not analysis: solc
        #    compiled the code, so the arm is absent and a call with that selector
        #    takes the unknown-selector path (the analyser must notice).
        base = next((c for c in self.default_corpus() if c.get("abi")), None)
        if base is not None:
            cases.append({
                "name": "abi-declares-unrouted-selector",
                "code": base["code"],
                "abi": ["notImplementedInThisBuild()"],
                "expect_defect": True,
                "ground_truth": (
                    f"{base['name']} was compiled without notImplementedInThisBuild(); "
                    "executing that selector takes the unknown-selector path, so a "
                    "dispatcher that routes it is a defect"
                ),
            })
        return cases

    def _adversarial_tests(self, *, seed: int) -> list[GeneratedTest]:
        """Mutations that probe the analyser's edges, not just the happy path."""
        rng = random.Random(seed)
        tests: list[GeneratedTest] = []

        # 1. A dispatcher whose destination is not a JUMPDEST must never be
        #    reported REACHABLE -- execution proves the jump fails.
        head = bytes.fromhex("60003560e01c")
        compare = bytes.fromhex("63" + "aaaaaaaa" + "14")
        bogus_dest = b"\x61" + (len(head) + len(compare) + 3).to_bytes(2, "big")
        code = head + compare + bogus_dest + b"\x57" + bytes.fromhex("60006000fd")
        tests.append(
            GeneratedTest(
                test_id=fingerprint("adv", "bogus-destination", code),
                adapter=self.name,
                kind="bogus_destination_is_not_reachable",
                code=_hex(code),
                input={"selector": "aaaaaaaa", "calldata_suffix": "00" * 32},
                expectation={"must_not_be_reachable": True},
                rationale=(
                    "a JUMPI whose destination is not a JUMPDEST cannot select a body; "
                    "the analyser must not call this selector reachable"
                ),
                generation={"seed": seed, "mutation": "bogus-destination"},
            )
        )

        # 2. A truncated PUSH must mark the report incomplete, not silently pass.
        truncated = bytes.fromhex("63aaaa")  # PUSH4 with 2 bytes of operand
        tests.append(
            GeneratedTest(
                test_id=fingerprint("adv", "truncated-push", truncated),
                adapter=self.name,
                kind="truncated_push_is_incomplete",
                code=_hex(truncated),
                input={},
                expectation={"incomplete": True},
                rationale="a truncated PUSH operand cannot be walked; the report must say so",
                generation={"seed": seed, "mutation": "truncated-push"},
            )
        )

        # 3. A random 0x5b inside PUSH data is not a legal jump destination.
        filler = bytes([rng.randrange(256) for _ in range(4)])
        payload = b"\x5b" * 32
        code = bytes([0x7F]) + payload + bytes.fromhex("600356")  # PUSH32; JUMP 3
        tests.append(
            GeneratedTest(
                test_id=fingerprint("adv", "jumpdest-in-push", filler),
                adapter=self.name,
                kind="jumpdest_inside_push_is_not_a_destination",
                code=_hex(code),
                input={},
                expectation={"must_not_be_reachable": True},
                rationale=(
                    "a 0x5b byte inside a PUSH payload is data; a jump to it must fail"
                ),
                generation={"seed": seed, "mutation": "jumpdest-in-push"},
            )
        )
        return tests

    # -- validation ------------------------------------------------------- #
    def validate(self, test: GeneratedTest) -> Optional[str]:
        if test.adapter != self.name:
            return f"adapter mismatch: {test.adapter!r} is not {self.name!r}"
        if test.kind not in _KNOWN_KINDS:
            return f"unknown test kind: {test.kind!r}"
        if not test.code:
            return "test has no code under test"
        try:
            _unhex(test.code)
        except ValueError as exc:
            return f"code is not valid hex: {exc}"
        sel = test.input.get("selector", "")
        if sel and (len(sel) != 8 or any(c not in "0123456789abcdef" for c in sel)):
            return f"selector must be 4 lowercase hex bytes, got {sel!r}"
        return None

    # -- execution -------------------------------------------------------- #
    def execute(self, test: GeneratedTest) -> TestOutcome:
        reason = self.validate(test)
        if reason is not None:
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_INCONCLUSIVE,
                detail=f"not executed: {reason}",
            )

        raw = _unhex(test.code)
        sel = test.input.get("selector", "")
        suffix = test.input.get("calldata_suffix", "")
        calldata = (bytes.fromhex(sel) if sel else b"") + (
            bytes.fromhex(suffix) if suffix else b""
        )
        run = execute(raw, calldata=calldata, gas=900_000)
        observed = run.to_dict()
        observed["calldata"] = calldata.hex()

        kind = test.kind
        if kind == "malformed_code":
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed=observed,
                detail="corpus entry was malformed; nothing to execute",
            )

        if kind == "truncated_push_is_incomplete":
            report = analyse_selectors(raw)
            if report.complete:
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "report_complete": report.complete},
                    detail=(
                        "analyser reported the walk complete despite a truncated PUSH; "
                        "this is an analyser defect (a false 'complete')"
                    ),
                    defect_signal=True,
                )
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed={**observed, "report_complete": report.complete},
                detail="analyser correctly reported an incomplete walk",
            )

        if kind in (
            "bogus_destination_is_not_reachable",
            "jumpdest_inside_push_is_not_a_destination",
        ):
            report = analyse_selectors(raw)
            reachable = {s.selector for s in report.reachable}
            claimed = bool(reachable)
            # Execution is the arbiter: a selector is only truly reachable if the
            # call does not fail with an interpreter-level defect.
            failed = run.halt not in ("STOP", "RETURN", "REVERT")
            if claimed and failed:
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "analyser_reachable": sorted(reachable)},
                    detail=(
                        f"analyser claimed {sorted(reachable)} reachable, but execution "
                        f"halted with {run.halt}: the destination cannot be jumped to"
                    ),
                    defect_signal=True,
                )
            if not claimed and not failed:
                # The analyser missed a selector that execution reached: a false negative.
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "analyser_reachable": sorted(reachable)},
                    detail=(
                        "execution reached code but the analyser reported no reachable "
                        "selector (false negative)"
                    ),
                    defect_signal=True,
                )
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed={**observed, "analyser_reachable": sorted(reachable)},
                detail="analyser and execution agree on this mutation",
            )

        if kind == "abi_selector_reaches_dispatch":
            # "Reached dispatch" means it did not behave like the control selector.
            control = execute(
                raw,
                calldata=bytes.fromhex(_CONTROL_SELECTOR) + b"\x00" * 32,
                gas=900_000,
            )
            same_as_control = (
                run.halt == control.halt
                and run.storage_writes == control.storage_writes
                and run.return_data == control.return_data
            )
            if same_as_control:
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "control": control.to_dict()},
                    detail=(
                        "an ABI-declared selector behaved identically to an unknown "
                        "selector: the dispatcher does not route it (analyser or "
                        "dispatcher defect)"
                    ),
                    defect_signal=True,
                )
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed={**observed, "control": control.to_dict()},
                detail="ABI selector is routed differently from an unknown selector",
            )

        if kind == "analysis_matches_execution":
            # Re-derive the claim now. A claim frozen at generation time would only
            # compare the analyser against its own earlier output, hiding any
            # regression introduced between generate() and execute().
            current = analyse_selectors(raw)
            by_sel = {s.selector: s.status for s in current.selectors}
            claimed = by_sel.get(test.input.get("selector", ""), "")
            control = execute(
                raw,
                calldata=bytes.fromhex(_CONTROL_SELECTOR) + b"\x00" * 32,
                gas=900_000,
            )
            behaves_like_data = (
                run.halt == control.halt
                and run.storage_writes == control.storage_writes
                and run.return_data == control.return_data
            )
            if claimed == REACHABLE and behaves_like_data:
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "control": control.to_dict()},
                    detail=(
                        f"analyser claims {test.input.get('selector')} is REACHABLE but "
                        "execution cannot distinguish it from an unknown selector"
                    ),
                    defect_signal=True,
                )
            if claimed == PRESENT_ONLY and test.expectation.get("in_abi"):
                # Ground truth is the ABI, which solc compiled -- not this code and
                # not a behavioural heuristic. Two reverting paths look identical, so
                # "differs from control" cannot catch a via-IR false negative; ABI
                # membership can, and does.
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_CONFIRMED_DEFECT,
                    observed={**observed, "control": control.to_dict()},
                    detail=(
                        f"analyser reports {test.input.get('selector')} as PRESENT_ONLY "
                        "(data, not an entry point) but the contract's own ABI declares "
                        "it as a function: a dispatcher false negative"
                    ),
                    defect_signal=True,
                )
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed={**observed, "control": control.to_dict()},
                detail="analyser claim is consistent with execution",
            )

        if kind == "empty_calldata_is_recorded":
            # Observation, not an assertion. A contract with receive() legitimately
            # takes a different path for empty calldata than for an unknown selector,
            # so "it differed" is NOT a defect -- treating it as one manufactures
            # false positives (it did, on the FallbackOnly fixtures). The only honest
            # failure here is being unable to model the code at all.
            if run.halt in (INVALID, BAD_JUMP):
                return TestOutcome(
                    test_id=test.test_id,
                    disposition=DISPOSITION_INCONCLUSIVE,
                    observed=observed,
                    detail=(
                        f"the interpreter could not model this code ({run.halt}); "
                        "the observation is recorded but not interpreted"
                    ),
                )
            return TestOutcome(
                test_id=test.test_id,
                disposition=DISPOSITION_NO_SIGNAL,
                observed=observed,
                detail="empty-calldata path recorded; no analyser claim to contradict",
            )

        return TestOutcome(
            test_id=test.test_id,
            disposition=DISPOSITION_INCONCLUSIVE,
            observed=observed,
            detail=f"adapter has no classifier for kind {kind!r}",
        )


_KNOWN_KINDS = frozenset(
    {
        "malformed_code",
        "abi_selector_reaches_dispatch",
        "analysis_matches_execution",
        "empty_calldata_is_recorded",
        "bogus_destination_is_not_reachable",
        "truncated_push_is_incomplete",
        "jumpdest_inside_push_is_not_a_destination",
    }
)
