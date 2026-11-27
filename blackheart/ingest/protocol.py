"""Compose several contract models into one protocol target.

A single-contract model cannot express the path that matters most in DeFi: a
call into contract A that moves state in contract B. This module keeps each
contract's own ``SynthesizedTarget`` (and therefore its own honest unmodelled
surface) and adds explicit, named cross-contract links.

A link is declared or compiler-derived, never guessed: ``Link(caller="Vault",
caller_op="deposit", callee="Token", callee_op="mint")``. A link can map caller
parameters to differently named callee parameters, and callee return values back
into caller fields. A call that cannot be resolved, modelled, or mapped is
``UNMODELLED``: the step aborts and the gap is named. It is never silently
treated as success, and a missing parameter is never fabricated as zero.

State is namespaced per contract, and each contract's invariants are evaluated
against its own sub-state. External calls execute in the callee's sub-state and
a revert restores the whole protocol snapshot atomically.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Optional

from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target
from .callgraph import CallGraph, infer_calls
from .semantics import REVERTED, UNMODELLED, CallResult, returned, reverted, unmodelled
from .solidity import ContractSurface
from .synthesize import SynthesisReport, SynthesizedTarget, _eval, synthesize


@dataclass(frozen=True)
class Link:
    caller: str
    caller_op: str
    callee: str
    callee_op: str
    #: ``((caller_param, callee_param), ...)``. Empty keeps name-sharing, but
    #: every callee parameter must still exist by name.
    param_map: tuple[tuple[str, str], ...] = ()
    #: ``((caller_field, callee_return_field), ...)``. A return is read from the
    #: callee's modelled return expression after the call.
    return_map: tuple[tuple[str, str], ...] = ()
    kind: str = "call"

    def to_dict(self) -> dict:
        return {"caller": self.caller, "caller_op": self.caller_op,
                "callee": self.callee, "callee_op": self.callee_op,
                "param_map": [list(pair) for pair in self.param_map],
                "return_map": [list(pair) for pair in self.return_map],
                "kind": self.kind}


@dataclass
class ProtocolReport:
    contracts: dict[str, SynthesisReport] = field(default_factory=dict)
    links: tuple[Link, ...] = ()
    unmodelled: dict[str, tuple[str, ...]] = field(default_factory=dict)
    notes: tuple[str, ...] = ()
    callgraph: dict = field(default_factory=dict)
    #: Aggregated model-coverage ledger for the composed protocol.
    model_coverage: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "contracts": {k: v.__dict__ for k, v in self.contracts.items()},
            "links": [l.to_dict() for l in self.links],
            "unmodelled": {k: list(v) for k, v in self.unmodelled.items()},
            "notes": list(self.notes),
            "callgraph": dict(self.callgraph),
            "model_coverage": dict(self.model_coverage),
        }


class ProtocolTarget(Target, PureState):
    """A namespaced composition of synthesized contracts with declared links."""

    def __init__(self, targets: dict[str, SynthesizedTarget], links: tuple[Link, ...] = (),
                 name: str = "protocol") -> None:
        self.targets = dict(targets)
        self.links = tuple(links)
        self.name = name
        #: Calls that could not be modelled or mapped. A path that hits one
        #: aborts; the set is the evidence for the gap.
        self.unmodelled_calls: set[str] = set()
        #: COMPLETED | REVERTED | UNMODELLED for the most recent step.
        self.last_outcome = "COMPLETED"
        self._call_stack: tuple[str, ...] = ()
        self._fired: set[tuple[str, str, str, str]] = set()
        self.reentrancy_limit = 3
        #: Filled by :func:`build_protocol`; absent means not recorded.
        self.model_coverage: dict = {}

    def reset(self) -> dict[str, Any]:
        return {name: target.reset() for name, target in self.targets.items()}

    def ops(self) -> list[OpSpec]:
        out: list[OpSpec] = []
        addresses = list(self.targets)
        for contract, target in self.targets.items():
            for op in target.ops():
                domain = {name: list(values) for name, values in op.param_domain.items()}
                for name, values in domain.items():
                    # A composed protocol can pass a contract address (the vault
                    # to a token transfer). The single-contract model cannot.
                    if "attacker" in values:
                        domain[name] = ([c for c in addresses if c not in values]
                                        + values)
                out.append(OpSpec(
                    f"{contract}.{op.name}", list(op.actors), domain,
                    weight=op.weight,
                    description=f"{contract}: {op.description}",
                ))
        return out

    def invariants(self) -> list[InvariantSpec]:
        out: list[InvariantSpec] = []
        for contract, target in self.targets.items():
            for inv in target.invariants():
                out.append(InvariantSpec(
                    f"{contract}:{inv.inv_id}", f"{contract}: {inv.title}",
                    self._scoped(contract, inv), inv.severity_if_broken,
                ))
            if target.op_model("convertToShares") is not None:
                out.append(InvariantSpec(
                    f"{contract}:erc4626:nonzero-shares",
                    f"{contract}: a positive deposit must not mint zero shares",
                    self._nonzero_shares(contract),
                    severity_if_broken="high",
                ))
        return out

    def _nonzero_shares(self, contract: str):
        def predicate(state: dict) -> bool:
            sub = state[contract]
            if int(sub.get("totalSupply", 0) or 0) == 0:
                return True
            shares = self.targets[contract].view_call(
                sub, "convertToShares", "attacker", (1,),
                on_view=lambda receiver, method, args, caller_state:
                    self._resolve_view(state, contract, receiver, method, args),
            )
            return int(shares) > 0
        return predicate

    def _resolve_view(self, state: dict, caller: str, receiver: str,
                      method: str, args: tuple) -> Any:
        args = tuple(caller if a == "this" else a for a in args)
        candidates = self._receiver_candidates(caller, receiver)
        if len(candidates) > 1:
            reason = (f"ambiguous view receiver {receiver}.{method} in {caller}: "
                      f"{', '.join(candidates)}")
            self._record_unmodelled(reason)
            self.last_outcome = UNMODELLED
            raise ValueError(reason)
        callee_name = candidates[0] if candidates else ""
        callee = self.targets.get(callee_name)
        if callee is not None:
            try:
                return callee.view_call(
                    state[callee_name], method, "attacker", tuple(args),
                    on_view=lambda r, m, a, s:
                        self._resolve_view(state, callee_name, r, m, a),
                )
            except (ValueError, TypeError, KeyError):
                pass
        fallback = self._token_view(state.get(callee_name, {}), method, args)
        if fallback is not None:
            return fallback
        raise ValueError(f"no modelled view for {receiver}.{method}")

    @staticmethod
    def _scoped(contract: str, inv: InvariantSpec):
        def predicate(state: dict) -> bool:
            return bool(inv.evaluate(state[contract]))
        return predicate

    def snapshot(self, state: dict) -> dict:
        return {name: self.targets[name].snapshot(state[name]) for name in self.targets}

    def fresh_instance(self) -> "ProtocolTarget":
        fresh = ProtocolTarget(
            {name: target.fresh_instance() for name, target in self.targets.items()},
            self.links, self.name,
        )
        fresh.model_coverage = dict(self.model_coverage)
        return fresh

    def _callee_params(self, contract: str, op_name: str, actor: str,
                       params: dict[str, Any]) -> Optional[dict[str, Any]]:
        target = self.targets[contract]
        model = next((m for m in target.op_models() if m.name == op_name), None)
        if model is None:
            return None
        # A link shares parameters by name. A missing name is not zero: applying
        # transfer(to=0, amount=0) fabricates a state change and can make an
        # invariant fail for a call that never happened.
        if any(name not in params for name in model.params):
            return None
        return {name: params[name] for name in model.params}

    def _receiver_candidates(self, caller: str, receiver: str) -> tuple[str, ...]:
        """Resolve an interface/base-typed receiver to its concrete contract.

        A state variable typed ``IOracle`` names the interface, not the deployed
        implementation. Exactly one concrete contract that implements it is a
        resolution; two or more is ambiguity and stays unresolved. The interface
        itself is not a candidate: a declaration-only surface has no body to run.
        """
        target = self.targets[caller]
        state_types = dict(target.contract.state_types)
        typ = state_types.get(receiver, "")
        if typ:
            # Include the declared type and every concrete derived contract:
            # a base-typed variable may hold any of them, so two candidates are
            # genuinely ambiguous, not a reason to pick the base.
            matches = tuple(
                name for name, candidate in self.targets.items()
                if self._concrete(candidate)
                and (name == typ or typ in candidate.contract.bases)
            )
            if matches:
                return matches
        if receiver in self.targets and self._concrete(self.targets[receiver]):
            return (receiver,)
        return ()

    @staticmethod
    def _concrete(target: SynthesizedTarget) -> bool:
        return any(not func.declaration_only for func in target.contract.functions)

    def _receiver_contract(self, caller: str, receiver: str) -> str:
        candidates = self._receiver_candidates(caller, receiver)
        return candidates[0] if len(candidates) == 1 else ""

    def to_dict(self) -> dict:
        return {"name": self.name, "contracts": sorted(self.targets),
                "links": [l.to_dict() for l in self.links],
                "unmodelled_calls": sorted(self.unmodelled_calls),
                "last_outcome": self.last_outcome}

    def _record_unmodelled(self, message: str) -> None:
        self.unmodelled_calls.add(message)

    def _link_params(self, link: Link, params: dict[str, Any]
                     ) -> Optional[dict[str, Any]]:
        if not link.param_map:
            return self._callee_params(link.callee, link.callee_op, "", params)
        target = self.targets.get(link.callee)
        if target is None:
            return None
        model = target.op_model(link.callee_op)
        if model is None:
            return None
        mapped: dict[str, Any] = {}
        for caller_name, callee_name in link.param_map:
            if caller_name not in params:
                return None
            mapped[callee_name] = params[caller_name]
        if any(name not in mapped for name in model.params):
            return None
        return {name: mapped[name] for name in model.params}

    def _enter_frame(self, contract: str, func: str,
                     model: Any) -> Optional[CallResult]:
        frame = f"{contract}.{func}"
        if frame in self._call_stack:
            if model is not None and getattr(model, "non_reentrant", False):
                return reverted(f"nonReentrant guard at {frame}")
            if len(self._call_stack) >= self.reentrancy_limit:
                reason = f"reentrancy depth limit at {frame}"
                self._record_unmodelled(reason)
                return unmodelled(reason)
        self._call_stack += (frame,)
        return None

    def _pop_frame(self) -> None:
        if self._call_stack:
            self._call_stack = self._call_stack[:-1]

    def _make_on_view(self, contract: str, state: dict, actor: str):
        def on_view(receiver: str, method: str, args: tuple,
                    caller_state: dict) -> Any:
            candidates = self._receiver_candidates(contract, receiver)
            if len(candidates) > 1:
                reason = (f"ambiguous view receiver {receiver}.{method} in "
                          f"{contract}: {', '.join(candidates)}")
                self._record_unmodelled(reason)
                self.last_outcome = UNMODELLED
                raise ValueError(reason)
            callee_name = candidates[0] if candidates else ""
            callee = self.targets.get(callee_name)
            normalized = tuple(contract if a == "this" else a for a in args)
            if callee is not None:
                try:
                    return callee.view_call(
                        state[callee_name], method, actor, normalized,
                        on_view=self._make_on_view(callee_name, state, actor),
                    )
                except (ValueError, TypeError, KeyError):
                    pass
            fallback = self._token_view(state.get(callee_name, {}), method,
                                        normalized)
            if fallback is not None:
                return fallback
            raise ValueError(f"no modelled view for {receiver}.{method}")
        return on_view

    def _execute_callee(self, caller_contract: str, caller_op: str, call,
                        state: dict, actor: str, params: dict,
                        caller_state: dict, call_ctx: dict) -> CallResult:
        candidates = self._receiver_candidates(caller_contract, call.receiver)
        if not candidates:
            reason = (f"unresolved receiver {call.receiver}.{call.op} "
                      f"in {caller_contract}.{caller_op}")
            self._record_unmodelled(reason)
            return unmodelled(reason)
        if len(candidates) > 1:
            reason = (f"ambiguous receiver {call.receiver}.{call.op} in "
                      f"{caller_contract}.{caller_op}: "
                      f"{', '.join(candidates)}")
            self._record_unmodelled(reason)
            return unmodelled(reason)
        callee_name = candidates[0]
        callee = self.targets.get(callee_name)
        if callee is None:
            reason = f"unknown callee contract {callee_name}"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        try:
            args = tuple(
                caller_contract if value == "this" else value
                for value in (_eval(arg, caller_state, actor, params, call_ctx)
                              for arg in call.args)
            )
        except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
            reason = f"cannot evaluate call arguments for {callee_name}.{call.op}: {exc}"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        callee_model = callee.op_model(call.op)
        if callee_model is None or not callee_model.modelled:
            token_result = self._token_call(
                callee_name, state[callee_name], call.op, args, caller_contract)
            if token_result is None:
                reason = (f"callee {callee_name}.{call.op} is not modelled and "
                          "has no structural fallback")
                self._record_unmodelled(reason)
                return unmodelled(reason)
            if not token_result:
                return reverted(f"structural call {callee_name}.{call.op} reverted")
            self._fired.add((caller_contract, caller_op, callee_name, call.op))
            return returned()
        if len(args) != len(callee_model.params):
            reason = (f"callee {callee_name}.{call.op} expects "
                      f"{len(callee_model.params)} argument(s), got {len(args)}")
            self._record_unmodelled(reason)
            return unmodelled(reason)
        callee_params = dict(zip(callee_model.params, args))
        entered = self._enter_frame(callee_name, call.op, callee_model)
        if entered is not None:
            return entered
        try:
            self.last_outcome = "COMPLETED"
            ok = callee.apply_ordered(
                state[callee_name], callee_model, caller_contract, callee_params,
                on_call=self._make_on_call(callee_name, call.op, callee_params,
                                           state, caller_contract),
                on_view=self._make_on_view(callee_name, state, caller_contract),
            )
            if not ok:
                if self.last_outcome == UNMODELLED:
                    return unmodelled(f"nested call in {callee_name}.{call.op} is unmodelled")
                return reverted(f"{callee_name}.{call.op} reverted")
            targets = call.assign_targets or (
                (call.assign_to,) if call.assign_to else ())
            if targets:
                if callee_model.return_expr is None and not callee_model.return_exprs:
                    reason = (f"return value of {callee_name}.{call.op} is not "
                              "modelled")
                    self._record_unmodelled(reason)
                    return unmodelled(reason)
                try:
                    values = callee.view_call_values(
                        state[callee_name], call.op, caller_contract, args,
                        on_view=self._make_on_view(callee_name, state, caller_contract))
                except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
                    reason = (f"cannot evaluate return value of "
                              f"{callee_name}.{call.op}: {exc}")
                    self._record_unmodelled(reason)
                    return unmodelled(reason)
                if len(values) < len(targets):
                    reason = (f"{callee_name}.{call.op} returns {len(values)} "
                              f"value(s), assignment needs {len(targets)}")
                    self._record_unmodelled(reason)
                    return unmodelled(reason)
                self._fired.add((caller_contract, caller_op, callee_name, call.op))
                return returned(*values)
            self._fired.add((caller_contract, caller_op, callee_name, call.op))
            return returned()
        except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
            reason = f"cannot apply {callee_name}.{call.op}: {exc}"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        finally:
            self._pop_frame()

    def _make_on_call(self, caller_contract: str, caller_op: str,
                      params: dict, state: dict, actor: str):
        def on_call(call, caller_state: dict,
                    call_ctx: dict | None = None) -> CallResult:
            call_ctx = call_ctx or {}
            try:
                if call.condition is not None and not _eval(
                        call.condition, caller_state, actor, params, call_ctx):
                    return returned()
                result = self._execute_callee(
                    caller_contract, caller_op, call, state, actor, params,
                    caller_state, call_ctx)
                self.last_outcome = result.status
                return result
            except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
                reason = f"call in {caller_contract}.{caller_op} failed: {exc}"
                self._record_unmodelled(reason)
                self.last_outcome = UNMODELLED
                return unmodelled(reason)
        return on_call

    def _execute_link(self, link: Link, state: dict, actor: str,
                      params: dict) -> CallResult:
        callee = self.targets.get(link.callee)
        if callee is None:
            reason = f"link callee {link.callee} is unknown"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        callee_params = self._link_params(link, params)
        if callee_params is None:
            reason = (f"link {link.caller}.{link.caller_op} -> "
                      f"{link.callee}.{link.callee_op} has no complete parameter map")
            self._record_unmodelled(reason)
            return unmodelled(reason)
        callee_model = callee.op_model(link.callee_op)
        if callee_model is None:
            reason = f"link callee {link.callee}.{link.callee_op} is not modelled"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        entered = self._enter_frame(link.callee, link.callee_op, callee_model)
        if entered is not None:
            return entered
        try:
            self.last_outcome = "COMPLETED"
            if not callee.apply_ordered(
                    state[link.callee], callee_model, actor, callee_params,
                    on_call=self._make_on_call(link.callee, link.callee_op,
                                               callee_params, state, actor),
                    on_view=self._make_on_view(link.callee, state, actor)):
                if self.last_outcome == UNMODELLED:
                    return unmodelled(f"nested call in {link.callee}.{link.callee_op} is unmodelled")
                return reverted(f"{link.callee}.{link.callee_op} reverted")
            args = tuple(callee_params.get(name, 0) for name in callee_model.params)
            values: tuple[Any, ...] | None = None
            for caller_field, callee_field in link.return_map:
                if callee_model.return_expr is None and not callee_model.return_exprs:
                    reason = f"return value of {link.callee}.{link.callee_op} is not modelled"
                    self._record_unmodelled(reason)
                    return unmodelled(reason)
                try:
                    if values is None:
                        values = callee.view_call_values(
                            state[link.callee], link.callee_op, actor, args,
                            on_view=self._make_on_view(link.callee, state, actor))
                    if callee_field in callee_model.return_names:
                        index = callee_model.return_names.index(callee_field)
                    elif len(values) == 1:
                        index = 0
                    else:
                        reason = (f"return value {callee_field!r} of "
                                  f"{link.callee}.{link.callee_op} is not named "
                                  f"among {callee_model.return_names}")
                        self._record_unmodelled(reason)
                        return unmodelled(reason)
                    value = values[index]
                except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
                    reason = f"cannot read return value {callee_field}: {exc}"
                    self._record_unmodelled(reason)
                    return unmodelled(reason)
                state[link.caller][caller_field] = value
            self._fired.add((link.caller, link.caller_op, link.callee, link.callee_op))
            return returned()
        except (ValueError, TypeError, KeyError, ZeroDivisionError) as exc:
            reason = f"cannot apply link {link.caller}.{link.caller_op}: {exc}"
            self._record_unmodelled(reason)
            return unmodelled(reason)
        finally:
            self._pop_frame()

    def step(self, state: dict, op_name: str, actor: str, params: dict[str, Any]) -> None:
        if "." not in op_name:
            self.last_outcome = UNMODELLED
            return
        contract, func = op_name.split(".", 1)
        target = self.targets.get(contract)
        if target is None:
            self.last_outcome = UNMODELLED
            return
        model = target.op_model(func)
        if model is None:
            self.last_outcome = UNMODELLED
            return
        snapshot = copy.deepcopy(state)
        entered = self._enter_frame(contract, func, model)
        if entered is not None:
            self.last_outcome = entered.status
            if entered.unmodelled:
                self._record_unmodelled(entered.reason)
            return
        self._fired = set()
        try:
            if not model.modelled:
                # A direct ERC20 operation can still be applied by the
                # structural token model when its local variable or nested
                # mapping is outside the statement subset.
                args = tuple(params.get(name, 0) for name in model.params)
                token_result = self._token_call(contract, state[contract], func,
                                                args, actor)
                if token_result is None:
                    reason = f"operation {op_name} is unmodelled"
                    self._record_unmodelled(reason)
                    self.last_outcome = UNMODELLED
                    return
                if not token_result:
                    state.clear()
                    state.update(snapshot)
                    self.last_outcome = REVERTED
                    return
            else:
                self.last_outcome = "COMPLETED"
                ok = target.apply_ordered(
                    state[contract], model, actor, params,
                    on_call=self._make_on_call(contract, func, params, state, actor),
                    on_view=self._make_on_view(contract, state, actor),
                )
                if not ok:
                    state.clear()
                    state.update(snapshot)
                    if self.last_outcome != UNMODELLED:
                        self.last_outcome = REVERTED
                    return
            for link in self.links:
                if link.caller != contract or link.caller_op != func:
                    continue
                if (contract, func, link.callee, link.callee_op) in self._fired:
                    continue
                result = self._execute_link(link, state, actor, params)
                if not result.returned:
                    state.clear()
                    state.update(snapshot)
                    self.last_outcome = result.status
                    return
            self.last_outcome = "COMPLETED"
        finally:
            self._pop_frame()

    @staticmethod
    def _token_view(token_state: dict, method: str, args: tuple) -> Any:
        """Read an ERC20-like mapping getter the scanner did not emit as a fn."""
        if method == "balanceOf" and isinstance(token_state.get("balanceOf"), dict):
            return int(token_state["balanceOf"].get(args[0] if args else "attacker", 0) or 0)
        if method == "allowance" and isinstance(token_state.get("allowance"), dict):
            inner = token_state["allowance"].get(args[0] if args else "", {})
            return int((inner or {}).get(args[1] if len(args) > 1 else "", 0) or 0)
        if method == "totalSupply" and "totalSupply" in token_state:
            return int(token_state.get("totalSupply", 0) or 0)
        if method == "decimals":
            return 18
        return None

    @staticmethod
    def _token_call(token_name: str, token_state: dict, op: str,
                    args: tuple, actor: str) -> Optional[bool]:
        """Apply ERC20-like state transitions structurally.

        The scanner recovers mappings but not the local variable in
        ``transferFrom``; this fallback is selected by shape (a ``balanceOf``
        mapping), never by a token name. It returns ``None`` when the callee is
        not token-like, so an unknown call is skipped rather than guessed.
        """
        balances = token_state.get("balanceOf")
        if not isinstance(balances, dict):
            return None

        def bal(key: str) -> int:
            return int(balances.get(key, 0) or 0)

        def set_bal(key: str, value: int) -> None:
            if value < 0:
                raise ValueError("balance underflow")
            balances[key] = value

        if op == "mint":
            to = args[0] if args else actor
            amount = int(args[1] if len(args) > 1 else 0)
            set_bal(to, bal(to) + amount)
            token_state["totalSupply"] = int(token_state.get("totalSupply", 0) or 0) + amount
            return True
        if op == "burn":
            amount = int(args[0] if args else 0)
            if bal(actor) < amount:
                return False
            set_bal(actor, bal(actor) - amount)
            token_state["totalSupply"] = int(token_state.get("totalSupply", 0) or 0) - amount
            return True
        if op == "transfer":
            to = args[0] if args else ""
            amount = int(args[1] if len(args) > 1 else 0)
            if bal(actor) < amount:
                return False
            set_bal(actor, bal(actor) - amount)
            set_bal(to, bal(to) + amount)
            return True
        if op == "transferFrom":
            frm = args[0] if args else ""
            to = args[1] if len(args) > 1 else ""
            amount = int(args[2] if len(args) > 2 else 0)
            allowance = token_state.setdefault("allowance", {})
            if not isinstance(allowance, dict):
                return False
            inner = allowance.setdefault(frm, {})
            allowed = int((inner or {}).get(actor, 0) or 0)
            if allowed < amount or bal(frm) < amount:
                return False
            inner[actor] = allowed - amount
            set_bal(frm, bal(frm) - amount)
            set_bal(to, bal(to) + amount)
            return True
        if op == "approve":
            spender = args[0] if args else ""
            amount = int(args[1] if len(args) > 1 else 0)
            allowance = token_state.setdefault("allowance", {})
            if not isinstance(allowance, dict):
                return False
            allowance.setdefault(actor, {})[spender] = amount
            return True
        return None



def build_protocol(
    contracts: dict[str, ContractSurface],
    *,
    links: tuple[Link, ...] = (),
    name: str = "protocol",
    infer_links: bool = False,
    graph: CallGraph | None = None,
) -> tuple[ProtocolTarget, ProtocolReport]:
    """Synthesize each contract and compose them with explicit and/or inferred links."""
    targets: dict[str, SynthesizedTarget] = {}
    reports: dict[str, SynthesisReport] = {}
    unmodelled: dict[str, tuple[str, ...]] = {}
    for contract_name, surface in contracts.items():
        target, report = synthesize(surface, registry=contracts)
        targets[contract_name] = target
        reports[contract_name] = report
        unmodelled[contract_name] = report.unmodelled_ops
    known = set(targets)
    if graph is None:
        graph = infer_calls(contracts) if infer_links else CallGraph()
    selected: list[Link] = list(links)
    seen = {(l.caller, l.caller_op, l.callee, l.callee_op) for l in selected}
    for edge in graph.edges:
        key = (edge.caller, edge.caller_op, edge.callee, edge.callee_op)
        if key not in seen:
            seen.add(key)
            selected.append(Link(*key))
    notes: list[str] = list(graph.notes)
    for link in selected:
        if link.caller not in known or link.callee not in known:
            notes.append(f"link {link.caller}.{link.caller_op} -> "
                         f"{link.callee}.{link.callee_op} names an unknown contract")
        elif not any(m.name == link.callee_op for m in targets[link.callee].op_models()):
            notes.append(f"link callee {link.callee}.{link.callee_op} is not modelled")
    from .model_coverage import protocol_coverage

    coverage = protocol_coverage(targets, selected, graph)
    protocol = ProtocolTarget(targets, tuple(selected), name)
    protocol.model_coverage = coverage.to_dict()
    report = ProtocolReport(
        reports, tuple(selected), unmodelled, tuple(notes), graph.to_dict(),
        model_coverage=protocol.model_coverage,
    )
    return protocol, report
