"""Synthesise an executable model from an ingested contract surface.

This is the step that turns ``ingest`` from a triage sheet into the front of a
search. It reads a :class:`~blackheart.ingest.solidity.ContractSurface`, builds a
:class:`~blackheart.invariants.engine.Target` whose operations are the contract's
own externally callable functions, and hands it to the existing certifier.

Two rules keep it honest.

1. **It only models what it can read.** A tiny interpreter understands a fixed
   set of statement shapes -- assignment, ``+=``/``-=``, mapping writes, and
   ``require``/``if ... revert`` guards. An operation containing anything else is
   marked *unmodelled* and its effects are not simulated at all. Half-simulating
   a function is how a model lies.

2. **It models only the unprivileged attacker.** The actors are ``attacker`` and
   ``victim``; the owner slot is a sentinel that no actor holds. A guarded
   function is therefore unreachable until an *unguarded* function lets an actor
   take the slot -- which is exactly the bug the search is meant to find.

A violation in this model is a *lead about the source*: it says an unprivileged
actor can drive a state sequence that breaks a declared property, under the
modelled subset. It is confirmed only against the real contract.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from ..invariants.engine import InvariantSpec, OpSpec, PureState, Target
from .semantics import CallResult
from .solidity import ContractSurface, FunctionSurface

ACTORS = ("attacker", "victim")
OWNER_SENTINEL = "admin"
ADDRESS_DOMAIN = ["attacker", "victim", "admin"]
UINT_DOMAIN = [0, 1, 2, 100]
_IGNORED = ("emit", "//", "/*")


# --------------------------------------------------------------------------- #
# A tiny expression language: tokenise, parse, evaluate
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"\s*(\d+|[A-Za-z_]\w*|==|!=|<=|>=|&&|\|\||[-+*/%<>!\[\](),.])")
_CAST_NAMES = frozenset({
    "address", "payable", "uint", "uint8", "uint16", "uint32", "uint64",
    "uint128", "uint256", "int", "int8", "int16", "int32", "int64", "int128",
    "int256", "bool", "bytes", "bytes4", "bytes8", "bytes16", "bytes32",
    "string", "IERC20", "IERC4626",
})


def _tokenize(text: str) -> list[str]:
    text = text.replace("msg.sender", "__sender__").replace("msg.value", "__value__")
    tokens, i = [], 0
    while i < len(text):
        m = _TOKEN_RE.match(text, i)
        if not m:
            if text[i].isspace():
                i += 1
                continue
            raise ValueError(f"cannot tokenise {text[i]!r}")
        tokens.append(m.group(1))
        i = m.end()
    return tokens


class _Parser:
    """Recursive descent with the precedence Solidity expressions need here."""

    def __init__(self, tokens: list[str]) -> None:
        self.t = tokens
        self.i = 0

    def _peek(self) -> Optional[str]:
        return self.t[self.i] if self.i < len(self.t) else None

    def _eat(self, value: Optional[str] = None) -> str:
        tok = self._peek()
        if tok is None or (value is not None and tok != value):
            raise ValueError(f"expected {value!r}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self) -> tuple:
        node = self._or()
        if self.i != len(self.t):
            raise ValueError(f"trailing tokens {self.t[self.i:]}")
        return node

    def _or(self) -> tuple:
        node = self._and()
        while self._peek() == "||":
            self._eat("||")
            node = ("bin", "||", node, self._and())
        return node

    def _and(self) -> tuple:
        node = self._eq()
        while self._peek() == "&&":
            self._eat("&&")
            node = ("bin", "&&", node, self._eq())
        return node

    def _eq(self) -> tuple:
        node = self._cmp()
        while self._peek() in ("==", "!="):
            op = self._eat()
            node = ("bin", op, node, self._cmp())
        return node

    def _cmp(self) -> tuple:
        node = self._add()
        while self._peek() in ("<", "<=", ">", ">="):
            op = self._eat()
            node = ("bin", op, node, self._add())
        return node

    def _add(self) -> tuple:
        node = self._mul()
        while self._peek() in ("+", "-"):
            op = self._eat()
            node = ("bin", op, node, self._mul())
        return node

    def _mul(self) -> tuple:
        node = self._unary()
        while self._peek() in ("*", "/", "%"):
            op = self._eat()
            node = ("bin", op, node, self._unary())
        return node

    def _unary(self) -> tuple:
        if self._peek() == "!":
            self._eat("!")
            return ("not", self._unary())
        if self._peek() == "-":
            self._eat("-")
            return ("neg", self._unary())
        return self._primary()

    def _primary(self) -> tuple:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end")
        if tok == "(":
            self._eat("(")
            node = self._or()
            self._eat(")")
            return node
        if tok.isdigit():
            return ("num", int(self._eat()))
        if re.fullmatch(r"[A-Za-z_]\w*", tok):
            name = self._eat()
            if name == "__sender__":
                node: tuple = ("sender",)
            elif name == "__value__":
                node = ("num", 0)
            elif name in _CAST_NAMES and self._peek() == "(":
                # A type cast is an identity in this model: address(this) is
                # the contract, uint256(x) is x. The cast is not a call.
                self._eat("(")
                node = self._or()
                self._eat(")")
                return node
            else:
                node = ("id", name)
            while True:
                if self._peek() == "[":
                    self._eat("[")
                    idx = self._or()
                    self._eat("]")
                    node = ("index", node, idx)
                elif self._peek() == ".":
                    self._eat(".")
                    field = self._eat()
                    node = ("member", node, field)
                elif self._peek() == "(":
                    self._eat("(")
                    args = self._call_args()
                    self._eat(")")
                    if node[0] == "id":
                        node = ("call", node[1], args)
                    elif node[0] == "member":
                        node = ("mcall", node[1], node[2], args)
                    else:
                        raise ValueError("unsupported call target")
                else:
                    break
            return node
        raise ValueError(f"unexpected token {tok!r}")

    def _call_args(self) -> tuple[tuple, ...]:
        args: list[tuple] = []
        if self._peek() == ")":
            return ()
        while True:
            args.append(self._or())
            if self._peek() != ",":
                break
            self._eat(",")
        return tuple(args)


def parse_expression(text: str) -> tuple:
    return _Parser(_tokenize(text)).parse()


def _eval(node: tuple, state: dict, actor: str, params: dict,
          ctx: Optional[dict] = None) -> Any:
    ctx = ctx or {}
    locals_ = ctx.get("locals", {})
    kind = node[0]
    if kind == "num":
        return node[1]
    if kind == "sender":
        return actor
    if kind == "id":
        name = node[1]
        if name == "this":
            return "this"
        if name in locals_:
            return locals_[name]
        if name in params:
            return params[name]
        if name in state:
            return state[name]
        prefix = name + "."
        fields = {key[len(prefix):]: value for key, value in state.items()
                  if key.startswith(prefix)}
        if fields:
            return fields
        raise ValueError(f"unknown identifier {name!r}")
    if kind == "call":
        name, args = node[1], node[2]
        functions = ctx.get("functions") or {}
        model = functions.get(name)
        if model is None:
            raise ValueError(f"unknown function {name!r}")
        values = tuple(_eval(arg, state, actor, params, ctx) for arg in args)
        bound = dict(zip(model.params, values))
        return _eval_function(model, state, actor, bound, ctx)
    if kind == "mcall":
        receiver_node, method, args = node[1], node[2], node[3]
        if receiver_node[0] == "id":
            receiver = receiver_node[1]
        else:
            receiver = _eval(receiver_node, state, actor, params, ctx)
        resolver = ctx.get("on_view")
        if resolver is None:
            raise ValueError(f"no view resolver for {receiver}.{method}")
        values = tuple(_eval(arg, state, actor, params, ctx) for arg in args)
        return resolver(receiver, method, values, state)
    if kind == "ternary":
        return (_eval(node[2], state, actor, params, ctx)
                if _eval(node[1], state, actor, params, ctx)
                else _eval(node[3], state, actor, params, ctx))
    if kind == "index":
        base = state[node[1]] if isinstance(node[1], str) else _eval(
            node[1], state, actor, params, ctx)
        key = _eval(node[2], state, actor, params, ctx)
        return base.get(key, 0) if isinstance(base, dict) else 0
    if kind == "member":
        base_node, field = node[1], node[2]
        if base_node[0] == "id":
            name = base_node[1]
            flat = f"{name}.{field}"
            if flat in state:
                return state[flat]
            if name in locals_:
                base = locals_[name]
            elif name in state:
                base = state[name]
            else:
                prefix = name + "."
                base = {key[len(prefix):]: value for key, value in state.items()
                        if key.startswith(prefix)}
                if not base:
                    raise ValueError(f"unknown identifier {name!r}")
        else:
            base = _eval(base_node, state, actor, params, ctx)
        if isinstance(base, dict):
            if field in base:
                return base[field]
            if field == "length":
                keys = [int(key) for key in base if isinstance(key, int)]
                return max(keys) + 1 if keys else 0
            return 0
        if field == "length" and isinstance(base, list):
            return len(base)
        raise ValueError(f"cannot read .{field} from {base!r}")
    if kind == "not":
        return not _eval(node[1], state, actor, params, ctx)
    if kind == "neg":
        return -_eval(node[1], state, actor, params, ctx)
    if kind == "bin":
        op = node[1]
        left = _eval(node[2], state, actor, params, ctx)
        right = _eval(node[3], state, actor, params, ctx)
        if op == "&&":
            return bool(left) and bool(right)
        if op == "||":
            return bool(left) or bool(right)
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/":
            if right == 0:
                raise ValueError("division by zero")
            return left // right
        if op == "%":
            if right == 0:
                raise ValueError("modulo by zero")
            return left % right
    raise ValueError(f"cannot evaluate {node!r}")


def _eval_function_values(model: "OpModel", state: dict, actor: str, params: dict,
                          ctx: dict) -> tuple[Any, ...]:
    """Evaluate every modelled return value of a view function, in order."""
    exprs = model.return_exprs or ((model.return_expr,) if model.return_expr else ())
    if not exprs:
        raise ValueError(f"function {model.name!r} has no modelled return")
    stack = ctx.setdefault("stack", set())
    if model.name in stack:
        raise ValueError(f"recursive internal call to {model.name!r}")
    stack.add(model.name)
    try:
        return tuple(_eval(expr, state, actor, params, ctx) for expr in exprs)
    finally:
        stack.discard(model.name)


def _eval_function(model: "OpModel", state: dict, actor: str, params: dict,
                   ctx: dict) -> Any:
    """Evaluate the first modelled return value, for single-value callers."""
    return _eval_function_values(model, state, actor, params, ctx)[0]


# --------------------------------------------------------------------------- #
# Statement interpretation
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Effect:
    kind: str                      # assign | add | sub | mul | div | mod | require
    target: str
    index: Optional[tuple]
    value: tuple
    #: A branch condition. ``None`` means the effect always applies after the
    #: operation's top-level guards; otherwise it applies only when true.
    condition: Optional[tuple] = None
    #: For ``pools[i].amount``: the struct member written inside the mapping
    #: entry. Empty for a scalar or a whole mapping element.
    member: str = ""
    #: A function-local scalar. It lives in the call frame's local map, never in
    #: the contract's persistent state, and it disappears when the frame ends.
    local: bool = False


@dataclass(frozen=True)
class _Call:
    """A statement-level external call, kept separate from local effects."""
    receiver: str
    op: str
    args: tuple[tuple, ...] = ()
    condition: Optional[tuple] = None
    assign_to: str = ""
    #: ``(x, y) = callee()``: one target per returned value, in order.
    assign_targets: tuple[str, ...] = ()


@dataclass
class OpModel:
    name: str
    params: tuple[str, ...]
    param_decls: tuple[str, ...] = ()
    guard_text: tuple[str, ...] = ()
    guards: tuple[tuple, ...] = ()
    effects: tuple[_Effect, ...] = ()
    calls: tuple[_Call, ...] = ()
    #: Local effects and calls in source order. ``effects`` and ``calls`` stay
    #: available for callers that only need one kind; protocol execution uses
    #: this list so a write after a call is not silently moved before it.
    ordered: tuple[_Effect | _Call, ...] = ()
    return_expr: Optional[tuple] = None
    #: Every declared return value, in declaration order. ``return_expr`` is
    #: kept as the first value for callers that only need one result.
    return_exprs: tuple[tuple, ...] = ()
    return_names: tuple[str, ...] = ()
    return_text: str = ""
    #: A ``nonReentrant`` modifier is a real guard in the model. A recursive
    #: entry is refused instead of being silently unfolded.
    non_reentrant: bool = False
    modelled: bool = True
    unmodelled: tuple[str, ...] = ()

    @property
    def has_conditional_effects(self) -> bool:
        return any(effect.condition is not None for effect in self.effects)


_LVALUE = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
#: ``pools[i].amount`` is an array-of-struct element write. Keep the base,
#: index and member separate so the model can write the member without
#: pretending the whole struct is a scalar.
_ASSIGN_RE = re.compile(
    r"^(?P<base>[A-Za-z_]\w*)\s*(?:\[(?P<index>[^\]]+)\])?"
    r"(?:\.(?P<member>[A-Za-z_]\w*))?\s*(?P<op>\+=|-=|\*=|/=|%=|=)\s*(?P<value>.+)$",
    re.S)
_UNARY_RE = re.compile(
    r"^(?:(\+\+|--)\s*(" + _LVALUE + r")|(" + _LVALUE + r")\s*(\+\+|--))$")
_DELETE_RE = re.compile(r"^delete\s+(" + _LVALUE + r")\s*(\[[^\]]+\])?$")
_PUSH_RE = re.compile(r"^(" + _LVALUE + r")\.push\s*\((.*)\)$", re.S)
_CALL_STMT_RE = re.compile(
    r"^([A-Za-z_]\w*)(?:\([^()]*\))?\.([A-Za-z_]\w*)"
    r"\s*(?:\{[^{}]*\})?\s*\((.*)\)$", re.S)
_CALL_ASSIGN_RE = re.compile(
    r"^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)(?:\([^()]*\))?\.([A-Za-z_]\w*)"
    r"\s*(?:\{[^{}]*\})?\s*\((.*)\)$", re.S)
_TUPLE_CALL_ASSIGN_RE = re.compile(
    r"^\(([^()]*)\)\s*=\s*([A-Za-z_]\w*)(?:\([^()]*\))?\.([A-Za-z_]\w*)"
    r"\s*(?:\{[^{}]*\})?\s*\((.*)\)$", re.S)
_INTERNAL_CALL_ASSIGN_RE = re.compile(
    r"^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\((.*)\)$", re.S)
_LOCAL_DECL_RE = re.compile(
    r"^(?P<type>uint\d*|int\d*|address(?:\s+payable)?|bool|bytes\d*|string)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=\s*(?P<value>.+))?$", re.S)
_IGNORED_CALL_RECEIVERS = frozenset({
    "msg", "block", "tx", "abi", "super", "this", "address", "type", "payable",
})
_REQUIRE_RE = re.compile(r"^require\s*\((.*)\)$", re.S)
_ASSERT_RE = re.compile(r"^assert\s*\((.*)\)$", re.S)
_IF_REVERT_RE = re.compile(r"^if\s*\((.*)\)\s*revert\b.*$", re.S)
_REVERT_RE = re.compile(r"^revert\s*(?:\(.*\))?$", re.S)


def _first_arg(text: str) -> str:
    depth = 0
    for i, c in enumerate(text):
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            return text[:i]
    return text


def _split_args(text: str) -> tuple[str, ...]:
    text = text.strip()
    if not text:
        return ()
    parts: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(text):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return tuple(part.strip() for part in parts if part.strip())


def _match_paren(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _match_brace(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _statement_end(text: str, start: int) -> int:
    """Return the index just past one statement, including a nested ``else``."""
    i = _skip_ws(text, start)
    if text.startswith("if", i) and (i + 2 >= len(text)
                                     or not (text[i + 2].isalnum() or text[i + 2] == "_")):
        j = _skip_ws(text, i + 2)
        if j < len(text) and text[j] == "(":
            close = _match_paren(text, j)
            k = _skip_ws(text, close + 1)
            if k < len(text) and text[k] == "{":
                end = _match_brace(text, k) + 1
            else:
                end = _semicolon_end(text, k)
            m = _skip_ws(text, end)
            if text.startswith("else", m):
                return _statement_end(text, m + 4)
            return end
    return _semicolon_end(text, i)


def _semicolon_end(text: str, start: int) -> int:
    depth = 0
    for j in range(start, len(text)):
        if text[j] in "([{":
            depth += 1
        elif text[j] in ")]}":
            depth -= 1
        elif text[j] == ";" and depth == 0:
            return j + 1
    return len(text)


def _parse_statements(text: str) -> list[tuple]:
    """Split a block into simple statements and ``if``/``else`` constructs."""
    out: list[tuple] = []
    i, n = 0, len(text)
    while i < n:
        i = _skip_ws(text, i)
        if i >= n:
            break
        if text.startswith("if", i) and (i + 2 >= n or not (text[i + 2].isalnum() or text[i + 2] == "_")):
            j = _skip_ws(text, i + 2)
            if j < n and text[j] == "(":
                close = _match_paren(text, j)
                condition = text[j + 1:close]
                k = _skip_ws(text, close + 1)
                if k < n and text[k] == "{":
                    end = _match_brace(text, k)
                    then = text[k + 1:end]
                    m = _skip_ws(text, end + 1)
                    otherwise = ""
                    if text.startswith("else", m):
                        e = _skip_ws(text, m + 4)
                        if e < n and text[e] == "{":
                            eend = _match_brace(text, e)
                            otherwise = text[e + 1:eend]
                            i = eend + 1
                        else:
                            eend = _statement_end(text, e)
                            otherwise = text[e:eend]
                            i = eend
                    else:
                        i = end + 1
                    out.append(("if", condition, then, otherwise))
                    continue
                # Single-statement if: ``if (c) return x;``. Without this the
                # whole branch was reported unmodelled even though its only
                # statement is a return the return extractor can read.
                end = _statement_end(text, k)
                then = text[k:end]
                m = _skip_ws(text, end)
                otherwise = ""
                if text.startswith("else", m):
                    e = _skip_ws(text, m + 4)
                    eend = (_match_brace(text, e) + 1 if e < n and text[e] == "{"
                            else _statement_end(text, e))
                    otherwise = text[e:eend]
                    end = eend
                out.append(("if", condition, then, otherwise))
                i = end
                continue
        j, depth = i, 0
        while j < n:
            c = text[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth == 0:
                break
            j += 1
        out.append(("simple", text[i:j]))
        i = j + 1
    return out


def _parse_simple(stmt: str, condition: Optional[tuple],
                  guards: list[tuple], guard_text: list[str],
                  effects: list[_Effect], calls: list[_Call],
                  ordered: list[_Effect | _Call], unmodelled: list[str],
                  *, allow_guard: bool = True, allow_locals: bool = False) -> bool:
    """Interpret one simple statement; return whether it can change state.

    A top-level ``require`` before any state write is a precondition and stays a
    guard. Once a statement can move state, a later ``require`` is emitted as an
    ordered effect: it must read the state produced by the statements before it,
    and a failure must roll the whole call back. That distinction is what makes
    ``x += 1; require(x < 5);`` mean what Solidity means.
    """
    stmt = " ".join(stmt.split())
    if not stmt or stmt.startswith(_IGNORED):
        return False
    if stmt == "return" or stmt.startswith("return "):
        # A view function's return is folded into its value expression. In a
        # state-changing function an early return stops the remaining writes;
        # treating it as a no-op would apply code Solidity never reaches.
        if allow_locals:
            return False
        effect = _Effect("halt", "", None, ("num", 1), condition)
        effects.append(effect)
        ordered.append(effect)
        return True
    m = _LOCAL_DECL_RE.match(stmt)
    if m:
        # A local in a view function is resolved by the return extractor. In a
        # state-changing function it is a real per-call value, not a contract
        # slot: model it in the call frame so later reads and writes see it.
        if allow_locals:
            return False
        name, value_text = m.group("name"), m.group("value")
        try:
            value = (parse_expression(value_text) if value_text is not None
                     else ("num", 0))
        except ValueError:
            unmodelled.append(stmt)
            return False
        effect = _Effect("assign", name, None, value, condition, local=True)
        effects.append(effect)
        ordered.append(effect)
        return True
    if "{" in stmt or "}" in stmt:
        unmodelled.append(stmt)
        return False
    m = _REQUIRE_RE.match(stmt) or _ASSERT_RE.match(stmt)
    if m:
        cond_text = _first_arg(m.group(1))
        try:
            cond = parse_expression(cond_text)
        except ValueError:
            unmodelled.append(stmt)
            return False
        if condition is None and allow_guard:
            keyword = "assert" if stmt.startswith("assert") else "require"
            guards.append(cond)
            guard_text.append(f"{keyword}({cond_text.strip()})")
        else:
            effect = _Effect("require", "", None, cond, condition)
            effects.append(effect)
            ordered.append(effect)
        return True
    if _REVERT_RE.match(stmt):
        effect = _Effect("revert", "", None, ("num", 1), condition)
        effects.append(effect)
        ordered.append(effect)
        return True
    m = _IF_REVERT_RE.match(stmt)
    if m:
        try:
            cond = parse_expression(_first_arg(m.group(1)))
        except ValueError:
            unmodelled.append(stmt)
            return False
        if condition is None and allow_guard:
            guards.append(("not", cond))
            guard_text.append(f"if ({m.group(1).strip()}) revert")
        else:
            effect = _Effect("require", "", None, ("not", cond), condition)
            effects.append(effect)
            ordered.append(effect)
        return True
    m = _TUPLE_CALL_ASSIGN_RE.match(stmt)
    if m:
        targets_text, receiver, op, args_text = m.groups()
        targets = tuple(part.strip() for part in _split_args(targets_text))
        if (not targets or receiver in _IGNORED_CALL_RECEIVERS
                or any(not re.fullmatch(r"[A-Za-z_]\w*", target) for target in targets)):
            unmodelled.append(stmt)
            return False
        try:
            args = tuple(parse_expression(arg) for arg in _split_args(args_text))
        except ValueError:
            unmodelled.append(stmt)
            return False
        call = _Call(receiver, op, args, condition, assign_targets=targets)
        calls.append(call)
        ordered.append(call)
        return True
    m = _INTERNAL_CALL_ASSIGN_RE.match(stmt)
    if m:
        assign_to, op, args_text = m.groups()
        try:
            args = tuple(parse_expression(arg) for arg in _split_args(args_text))
        except ValueError:
            unmodelled.append(stmt)
            return False
        call = _Call("", op, args, condition, assign_to)
        calls.append(call)
        ordered.append(call)
        return True
    m = _CALL_ASSIGN_RE.match(stmt)
    if m:
        assign_to, receiver, op, args_text = m.groups()
        if receiver in _IGNORED_CALL_RECEIVERS:
            unmodelled.append(stmt)
            return False
        try:
            args = tuple(parse_expression(arg) for arg in _split_args(args_text))
        except ValueError:
            unmodelled.append(stmt)
            return False
        call = _Call(receiver, op, args, condition, assign_to)
        calls.append(call)
        ordered.append(call)
        return True
    m = _PUSH_RE.match(stmt)
    if m:
        target, value_text = m.groups()
        try:
            value = parse_expression(_first_arg(value_text))
        except ValueError:
            unmodelled.append(stmt)
            return False
        effect = _Effect("push", target, None, value, condition)
        effects.append(effect)
        ordered.append(effect)
        return True
    m = _CALL_STMT_RE.match(stmt)
    if m:
        receiver, op, args_text = m.groups()
        if receiver in _IGNORED_CALL_RECEIVERS:
            unmodelled.append(stmt)
            return False
        try:
            args = tuple(parse_expression(arg) for arg in _split_args(args_text))
        except ValueError:
            unmodelled.append(stmt)
            return False
        call = _Call(receiver, op, args, condition)
        calls.append(call)
        ordered.append(call)
        return True
    m = _DELETE_RE.match(stmt)
    if m:
        target, index_text = m.groups()
        try:
            index = parse_expression(index_text[1:-1]) if index_text else None
        except ValueError:
            unmodelled.append(stmt)
            return False
        effect = _Effect("assign", target, index, ("num", 0), condition)
        effects.append(effect)
        ordered.append(effect)
        return True
    m = _UNARY_RE.match(stmt)
    if m:
        target = m.group(2) or m.group(3)
        op = m.group(1) or m.group(4)
        kind = "add" if op == "++" else "sub"
        effect = _Effect(kind, target, None, ("num", 1), condition)
        effects.append(effect)
        ordered.append(effect)
        return True
    m = _ASSIGN_RE.match(stmt)
    if m:
        base, index_text, member, op, value_text = m.groups()
        target = base if index_text else (f"{base}.{member}" if member else base)
        try:
            value = parse_expression(value_text)
            index = parse_expression(index_text) if index_text else None
        except ValueError:
            unmodelled.append(stmt)
            return False
        kind = {"=": "assign", "+=": "add", "-=": "sub", "*=": "mul",
                "/=": "div", "%=": "mod"}[op]
        effect = _Effect(kind, target, index, value, condition,
                         member if index_text and member else "")
        effects.append(effect)
        ordered.append(effect)
        return True
    unmodelled.append(stmt)
    return False


def _parse_block(text: str, condition: Optional[tuple],
                 guards: list[tuple], guard_text: list[str],
                 effects: list[_Effect], calls: list[_Call],
                 ordered: list[_Effect | _Call], unmodelled: list[str],
                 *, allow_guards: bool = True, allow_locals: bool = False) -> bool:
    """Parse a block; return whether any statement in it can move state."""
    wrote = False
    for item in _parse_statements(text):
        if item[0] == "simple":
            if _parse_simple(item[1], condition, guards, guard_text, effects,
                             calls, ordered, unmodelled,
                             allow_guard=allow_guards and not wrote,
                             allow_locals=allow_locals):
                wrote = True
            continue
        _kind, cond_text, then, otherwise = item
        try:
            cond = parse_expression(cond_text)
        except ValueError:
            unmodelled.append(f"if ({cond_text})")
            continue
        combined = cond if condition is None else ("bin", "&&", condition, cond)
        if _parse_block(then, combined, guards, guard_text, effects, calls,
                        ordered, unmodelled, allow_guards=False,
                        allow_locals=allow_locals):
            wrote = True
        if otherwise and _parse_block(otherwise, ("not", combined), guards, guard_text,
                                      effects, calls, ordered, unmodelled,
                                      allow_guards=False, allow_locals=allow_locals):
            wrote = True
    return wrote


_LOOP_RE = re.compile(r"(for|while)\s*\(([^)]*)\)\s*\{([^{}]*)\}", re.S)
_LOOP_VAR_RE = re.compile(r"for\s*\(\s*(?:uint\d*|int\d*)?\s*([A-Za-z_]\w*)\s*=")
_BOUND_RE = re.compile(r"<\s*(\d+)")
MAX_UNROLL = 8


def _unroll(body: str) -> tuple[str, bool]:
    """Unroll one bounded, loop-variable-free ``for`` loop, or leave it alone.

    A loop is only unrolled when its bound is a literal within ``MAX_UNROLL`` and
    its body never reads the index. Anything else is left for ``interpret`` to
    mark unmodelled -- a half-unrolled loop would be a wrong model, not a partial
    one.
    """
    match = _LOOP_RE.search(body)
    if not match:
        return body, False
    header, inner = match.group(2), match.group(3)
    variable = _LOOP_VAR_RE.search(f"for ({header})")
    if not variable:
        return body, False
    if re.search(rf"\b{re.escape(variable.group(1))}\b", inner):
        return body, False
    bound = _BOUND_RE.search(header)
    if not bound:
        return body, False
    count = int(bound.group(1))
    if count < 0 or count > MAX_UNROLL:
        return body, False
    repeated = " ".join([inner.strip()] * count)
    return body[:match.start()] + repeated + body[match.end():], True


def _strip_unchecked(text: str) -> str:
    """Remove ``unchecked { ... }`` wrappers; the statements inside still run."""
    while True:
        match = re.search(r"\bunchecked\s*\{", text)
        if not match:
            return text
        opening = match.end() - 1
        closing = _match_brace(text, opening)
        if closing <= opening:
            return text
        text = text[:match.start()] + text[opening + 1:closing] + text[closing + 1:]


def _substitute(node: tuple, locals_: dict[str, tuple]) -> tuple:
    kind = node[0]
    if kind == "id":
        return locals_.get(node[1], node)
    if kind == "index":
        return ("index", _substitute(node[1], locals_), _substitute(node[2], locals_))
    if kind == "member":
        return ("member", _substitute(node[1], locals_), node[2])
    if kind == "call":
        return ("call", node[1], tuple(_substitute(arg, locals_) for arg in node[2]))
    if kind == "mcall":
        return ("mcall", _substitute(node[1], locals_), node[2],
                tuple(_substitute(arg, locals_) for arg in node[3]))
    if kind == "ternary":
        return ("ternary", _substitute(node[1], locals_),
                _substitute(node[2], locals_), _substitute(node[3], locals_))
    if kind in ("not", "neg"):
        return (kind, _substitute(node[1], locals_))
    if kind == "bin":
        return ("bin", node[1], _substitute(node[2], locals_),
                _substitute(node[3], locals_))
    return node


def _return_values(text: str) -> tuple[tuple, ...]:
    """Parse one Solidity return expression, including a tuple return."""
    text = text.strip()
    if not text:
        return ()
    if text.startswith("(") and _match_paren(text, 0) == len(text) - 1:
        text = text[1:-1]
    parts = _split_args(text)
    if not parts:
        return ()
    return tuple(parse_expression(part) for part in parts)


def _return_expressions(body: str) -> tuple[tuple[tuple, ...], str]:
    """Read a function's return paths into one conditional expression per value.

    A view function such as ``convertToShares`` commonly has a local and two
    returns::

        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();

    The model needs the value, not the control flow. Local assignments are
    substituted, each return becomes a condition, and the paths are folded into
    nested ternaries. The same fold is applied per returned component, so a
    ``returns (uint256, uint256)`` function is not silently reduced to its first
    value. Anything that cannot be parsed yields no expressions -- a partial
    return would be a wrong value, not a partial one.
    """
    returns: list[tuple[Optional[tuple], tuple[tuple, ...]]] = []
    locals_: dict[str, tuple] = {}

    def walk(text: str, condition: Optional[tuple]) -> bool:
        for item in _parse_statements(text):
            if item[0] == "simple":
                stmt = " ".join(item[1].split())
                if not stmt:
                    continue
                if stmt == "return":
                    continue
                if stmt.startswith("return "):
                    try:
                        values = _return_values(stmt[len("return "):])
                    except ValueError:
                        return False
                    returns.append((condition, tuple(
                        _substitute(value, locals_) for value in values)))
                    continue
                m = _LOCAL_DECL_RE.match(stmt)
                if m:
                    name = m.group("name")
                    value_text = (m.group("value") or "").strip()
                    if not value_text:
                        locals_[name] = ("num", 0)
                        continue
                else:
                    m = re.match(r"^([A-Za-z_]\w*)\s*=\s*(.+)$", stmt, re.S)
                    if not m:
                        continue
                    name, value_text = m.group(1), m.group(2)
                try:
                    locals_[name] = _substitute(parse_expression(value_text), locals_)
                except ValueError:
                    return False
                continue
            _kind, cond_text, then, otherwise = item
            try:
                cond = _substitute(parse_expression(cond_text), locals_)
            except ValueError:
                return False
            combined = cond if condition is None else ("bin", "&&", condition, cond)
            if not walk(then, combined):
                return False
            if otherwise and not walk(otherwise, ("not", combined)):
                return False
        return True

    if not walk(body, None) or not returns:
        return (), ""
    arity = len(returns[0][1])
    if arity == 0 or any(len(values) != arity for _condition, values in returns):
        return (), ""
    exprs: list[tuple] = []
    for index in range(arity):
        expr = ("num", 0)
        for condition, values in reversed(returns):
            expr = (values[index] if condition is None
                    else ("ternary", condition, values[index], expr))
        exprs.append(expr)
    return tuple(exprs), "conditional return"


def _return_expression(body: str) -> tuple[Optional[tuple], str]:
    """Backward-compatible single-value view of :func:`_return_expressions`."""
    exprs, text = _return_expressions(body)
    return (exprs[0] if exprs else None), text


def interpret(func: FunctionSurface, owner_var: str) -> OpModel:
    """Interpret one function into guards and effects, or mark it unmodelled."""
    guards: list[tuple] = []
    guard_text: list[str] = []
    effects: list[_Effect] = []
    calls: list[_Call] = []
    ordered: list[_Effect | _Call] = []
    unmodelled: list[str] = []

    body = _strip_unchecked(func.body)
    if body != func.body:
        func = replace(func, body=body)
    if "{" in body:
        body, unrolled = _unroll(body)
        if unrolled:
            func = replace(func, body=body)

    for mod in func.modifiers:
        if mod.startswith("only"):
            # A role modifier is a guard on the owner slot; unknown roles are
            # modelled as the same guard and flagged, never silently ignored.
            guards.append(("bin", "==", ("sender",), ("id", owner_var)))
            guard_text.append(f"{mod} -> msg.sender == {owner_var}")

    _parse_block(func.body, None, guards, guard_text, effects, calls, ordered,
                 unmodelled, allow_locals=not func.state_changing)

    return_exprs, return_text = _return_expressions(func.body)

    return OpModel(
        name=func.name,
        params=tuple(_param_name(p) for p in func.params),
        param_decls=tuple(func.params),
        guard_text=tuple(guard_text),
        guards=tuple(guards),
        effects=tuple(effects),
        calls=tuple(calls),
        ordered=tuple(ordered),
        return_expr=return_exprs[0] if return_exprs else None,
        return_exprs=return_exprs,
        return_names=tuple(_param_name(value) for value in func.returns),
        return_text=return_text,
        non_reentrant=any(mod == "nonReentrant" for mod in func.modifiers),
        modelled=not unmodelled,
        unmodelled=tuple(unmodelled),
    )


def _param_name(param: str) -> str:
    parts = param.split()
    return parts[-1] if parts else param


def _param_domain(param: str) -> list[Any]:
    typ = param.split()[0] if param.split() else ""
    if typ.startswith("address"):
        return ADDRESS_DOMAIN
    if typ.startswith("bool"):
        return [True, False]
    if typ.startswith(("uint", "int")):
        return UINT_DOMAIN
    if typ.endswith("]"):
        return [[]]
    return ["0x"]


# --------------------------------------------------------------------------- #
# The synthesised target
# --------------------------------------------------------------------------- #

@dataclass
class SynthesisReport:
    contract: str
    path: str
    modelled_ops: tuple[str, ...]
    unmodelled_ops: tuple[str, ...]
    unmodelled_statements: tuple[str, ...]
    invariants: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)
    external_calls: tuple[str, ...] = ()
    #: The model-coverage ledger (see :mod:`blackheart.ingest.model_coverage`).
    model_coverage: dict = field(default_factory=dict)


class SynthesizedTarget(Target, PureState):
    """A Target whose operations are a contract's own external functions."""

    def __init__(self, contract: ContractSurface, op_models: tuple[OpModel, ...],
                 invariants: tuple[InvariantSpec, ...], owner_var: str,
                 mappings: tuple[str, ...], scalars: tuple[str, ...]) -> None:
        self.contract = contract
        self.name = f"ingest:{contract.name}"
        self._op_models = {m.name: m for m in op_models}
        self._invariants = invariants
        self._owner_var = owner_var
        self._mappings = mappings
        self._scalars = scalars
        #: Filled by :func:`synthesize`; an absent ledger means "not recorded",
        #: never "complete".
        self.model_coverage: dict = {}

    def reset(self) -> dict:
        state: dict[str, Any] = {m: {} for m in self._mappings}
        for var in self._scalars:
            state[var] = OWNER_SENTINEL if var == self._owner_var else 0
        return state

    def ops(self) -> list[OpSpec]:
        specs: list[OpSpec] = []
        for model in self._op_models.values():
            domain = {}
            for name, decl in zip(model.params, model.param_decls or model.params):
                domain[name] = _param_domain(decl)
            specs.append(OpSpec(model.name, list(ACTORS), domain,
                                description="ingested contract function"))
        return specs

    def op_models(self) -> tuple[OpModel, ...]:
        """The interpreted operations, for a symbolic pass over the same model."""
        return tuple(self._op_models.values())

    def op_model(self, name: str) -> Optional[OpModel]:
        return self._op_models.get(name)

    def fresh_instance(self) -> "SynthesizedTarget":
        """A new target with the same surface and no shared mutable state.

        The independent verifier requires a fresh instance, not a reset of the
        instance that produced the witness.
        """
        fresh = type(self)(self.contract, self.op_models(), tuple(self.invariants()),
                           self._owner_var, self._mappings, self._scalars)
        fresh.model_coverage = dict(self.model_coverage)
        return fresh

    def invariants(self) -> list[InvariantSpec]:
        return list(self._invariants)

    def snapshot(self, state: dict) -> dict:
        snap = {}
        for key, value in state.items():
            snap[key] = dict(sorted(value.items())) if isinstance(value, dict) else value
        return snap

    def apply_ordered(self, state: dict, model: Optional[OpModel], actor: str,
                      params: dict[str, Any], *,
                      on_call: Optional[Any] = None,
                      on_view: Optional[Any] = None,
                      _stack: Optional[set[str]] = None) -> bool:
        """Apply guards and source-ordered effects, delegating calls.

        ``on_call(call, caller_state)`` handles an external call; an internal
        call (receiver ``""``) is executed against this target's own state.
        ``on_view(receiver, method, args, caller_state)`` resolves a view call
        inside an expression. With no handler a call is skipped: a single
        contract must not pretend another contract's state moved.
        """
        if model is None or not model.modelled:
            return False
        stack = _stack if _stack is not None else set()
        if model.name in stack:
            return False
        stack.add(model.name)
        ctx = {"functions": self._op_models, "on_view": on_view,
               "locals": {}}
        try:
            for guard in model.guards:
                try:
                    if not _eval(guard, state, actor, params, ctx):
                        return False
                except (ValueError, TypeError, KeyError):
                    return False
            candidate = copy.deepcopy(state)
            items = model.ordered or (tuple(model.effects) + tuple(model.calls))
            for item in items:
                if isinstance(item, _Call):
                    if item.receiver == "":
                        if not self._apply_internal(candidate, item, actor, params,
                                                    ctx, on_call, on_view, stack):
                            return False
                    elif on_call is not None:
                        result = on_call(item, candidate, ctx)
                        if isinstance(result, CallResult):
                            if not result.returned:
                                return False
                            targets = item.assign_targets or (
                                (item.assign_to,) if item.assign_to else ())
                            if targets:
                                if len(result.values) < len(targets):
                                    return False
                                locals_ = ctx.setdefault("locals", {})
                                for target, value in zip(targets, result.values):
                                    if target in locals_:
                                        locals_[target] = value
                                    else:
                                        candidate[target] = value
                        elif not result:
                            return False
                    continue
                try:
                    if item.condition is not None and not _eval(
                            item.condition, candidate, actor, params, ctx):
                        continue
                    if item.kind == "halt":
                        break
                    if item.kind == "revert":
                        return False
                    self._apply(candidate, item, actor, params, ctx)
                except (ValueError, TypeError, KeyError, ZeroDivisionError):
                    return False
            state.clear()
            state.update(candidate)
            return True
        finally:
            stack.discard(model.name)

    def _apply_internal(self, state: dict, call: _Call, actor: str,
                        params: dict, ctx: dict, on_call: Optional[Any],
                        on_view: Optional[Any], stack: set[str]) -> bool:
        model = self._op_models.get(call.op)
        if model is None or not model.modelled:
            return False
        try:
            values = tuple(_eval(arg, state, actor, params, ctx) for arg in call.args)
        except (ValueError, TypeError, KeyError, ZeroDivisionError):
            return False
        bound = dict(zip(model.params, values))
        if model.effects or model.calls:
            if not self.apply_ordered(state, model, actor, bound,
                                      on_call=on_call, on_view=on_view,
                                      _stack=stack):
                return False
        if call.assign_to:
            try:
                ctx.setdefault("locals", {})[call.assign_to] = _eval_function(
                    model, state, actor, bound, ctx)
            except (ValueError, TypeError, KeyError, ZeroDivisionError):
                return False
        return True

    def view_call(self, state: dict, name: str, actor: str,
                  args: tuple[Any, ...], *, on_view: Optional[Any] = None) -> Any:
        """Evaluate the first modelled return value against ``state``."""
        return self.view_call_values(state, name, actor, args, on_view=on_view)[0]

    def view_call_values(self, state: dict, name: str, actor: str,
                         args: tuple[Any, ...], *,
                         on_view: Optional[Any] = None) -> tuple[Any, ...]:
        """Evaluate every modelled return value against ``state``."""
        model = self._op_models.get(name)
        if model is None or (model.return_expr is None and not model.return_exprs):
            raise ValueError(f"{name!r} has no modelled return")
        ctx = {"functions": self._op_models, "on_view": on_view, "locals": {}}
        return _eval_function_values(
            model, state, actor, dict(zip(model.params, args)), ctx)


    def step(self, state: dict, op_name: str, actor: str,
             params: dict[str, Any]) -> bool:
        """Apply one operation; return whether it completed without reverting."""
        return self.apply_ordered(state, self._op_models.get(op_name), actor, params)

    def _apply(self, state: dict, effect: _Effect, actor: str, params: dict,
               ctx: Optional[dict] = None) -> None:
        ctx = ctx or {}
        value = _eval(effect.value, state, actor, params, ctx)
        if effect.kind == "require":
            if not value:
                raise ValueError("require failed")
            return
        if effect.kind == "push":
            container = state.setdefault(effect.target, {})
            keys = [int(key) for key in container if isinstance(key, int)]
            container[max(keys) + 1 if keys else 0] = value
            return
        locals_ = ctx.setdefault("locals", {})
        if effect.local and effect.index is not None:
            raise ValueError("a local array element is not modelled")
        if effect.index is not None:
            key = _eval(effect.index, state, actor, params, ctx)
            container = state.setdefault(effect.target, {})
            if effect.member:
                entry = container.get(key, {})
                current = entry.get(effect.member, 0) if isinstance(entry, dict) else 0
            else:
                current = container.get(key, 0)
        elif effect.local or effect.target in locals_:
            current = locals_.get(effect.target, 0)
        else:
            current = state.get(effect.target, 0)
        if effect.kind == "assign":
            result = value
        elif effect.kind == "add":
            result = current + value
        elif effect.kind == "sub":
            result = current - value
            if result < 0:
                raise ValueError("underflow")
        elif effect.kind == "mul":
            result = current * value
        elif effect.kind == "div":
            if value == 0:
                raise ValueError("division by zero")
            result = current // value
        elif effect.kind == "mod":
            if value == 0:
                raise ValueError("modulo by zero")
            result = current % value
        else:
            raise ValueError(f"unknown effect kind {effect.kind!r}")
        if effect.local or (effect.index is None and effect.target in locals_):
            locals_[effect.target] = result
            return
        if effect.index is not None:
            if effect.member:
                entry = dict(state[effect.target].get(key, {}) or {})
                entry[effect.member] = result
                state[effect.target][key] = entry
            else:
                state[effect.target][key] = result
        else:
            state[effect.target] = result


def _owner_var(contract: ContractSurface) -> str:
    for candidate in ("owner", "admin", "governance", "authority"):
        if candidate in contract.state_vars:
            return candidate
    return "owner"


def _state_shape(contract: ContractSurface) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Flatten struct fields and classify arrays/mappings, without guessing."""
    structs = dict(contract.structs)
    if not contract.state_types:
        mappings = []
        for var in contract.state_vars:
            if any(re.search(rf"\b{re.escape(var)}\s*\[", f.body)
                   for f in contract.functions):
                mappings.append(var)
        return tuple(mappings), tuple(v for v in contract.state_vars if v not in mappings)
    mappings: list[str] = []
    scalars: list[str] = []
    for var, typ in contract.state_types:
        typ = typ.strip()
        if typ.startswith("mapping") or typ.endswith("]"):
            mappings.append(var)
        elif typ in structs:
            for fname, ftype in structs[typ]:
                key = f"{var}.{fname}"
                if ftype.startswith("mapping") or ftype.endswith("]"):
                    mappings.append(key)
                else:
                    scalars.append(key)
        else:
            scalars.append(var)
    return tuple(mappings), tuple(scalars)


def _mappings(contract: ContractSurface) -> tuple[str, ...]:
    return _state_shape(contract)[0]


def _resolve_inheritance(contract: ContractSurface,
                         registry: dict[str, ContractSurface],
                         seen: tuple[str, ...] = ()) -> ContractSurface:
    """Merge inherited functions, state and modifiers; a derived signature wins."""
    if not contract.bases or not registry or contract.name in seen:
        return contract
    functions: dict[str, FunctionSurface] = {}
    state_types: dict[str, str] = {}
    modifiers: list[str] = []
    structs: dict[str, tuple[tuple[str, str], ...]] = {}
    for base_name in contract.bases:
        base = registry.get(base_name)
        if base is None:
            continue
        base = _resolve_inheritance(base, registry, seen + (contract.name,))
        for func in base.functions:
            functions.setdefault(func.signature, func)
        for var, typ in (base.state_types or ()):
            state_types.setdefault(var, typ)
        for var in base.state_vars:
            state_types.setdefault(var, "uint256")
        for mod in base.modifiers_defined:
            if mod not in modifiers:
                modifiers.append(mod)
        for name, fields in base.structs:
            structs.setdefault(name, fields)
    for func in contract.functions:
        functions[func.signature] = func
    for var, typ in contract.state_types:
        state_types[var] = typ
    for var in contract.state_vars:
        state_types.setdefault(var, "uint256")
    for mod in contract.modifiers_defined:
        if mod not in modifiers:
            modifiers.append(mod)
    for name, fields in contract.structs:
        structs[name] = fields
    merged_types = tuple(state_types.items())
    return replace(
        contract,
        functions=tuple(functions.values()),
        state_vars=tuple(var for var, _typ in merged_types),
        state_types=merged_types,
        modifiers_defined=tuple(modifiers),
        structs=tuple(structs.items()),
    )


def _conservation_invariants(target_vars: dict, mappings: tuple[str, ...]) -> list[InvariantSpec]:
    specs: list[InvariantSpec] = []
    totals = [v for v in target_vars if v.lower() in ("totalsupply", "totalshares", "supply")]
    balances = [m for m in mappings if "balance" in m.lower() or "share" in m.lower()]
    for mapping in balances:
        for total in totals:
            specs.append(InvariantSpec(
                f"conservation:{mapping}-{total}",
                f"sum({mapping}) equals {total} after every sequence",
                _make_conservation(mapping, total),
                severity_if_broken="high",
            ))
    return specs


def _authorization_invariants(owner_var: str,
                              scalars: tuple[str, ...]) -> list[InvariantSpec]:
    """The owner slot is a trust root: an unprivileged call must not move it.

    The reset state uses :data:`OWNER_SENTINEL`, which is deliberately not an
    actor. An unguarded write to the owner slot is therefore a real violation,
    while an ``onlyOwner`` path stays unreachable for the unprivileged actors
    the model explores.
    """
    if owner_var not in scalars:
        return []
    return [InvariantSpec(
        f"authorization:{owner_var}",
        f"{owner_var} only changes through an authorized operation",
        lambda state: state.get(owner_var) == OWNER_SENTINEL,
        severity_if_broken="high",
    )]


def _make_conservation(mapping: str, total: str):
    def predicate(state: dict) -> bool:
        return sum(state.get(mapping, {}).values()) == state.get(total, 0)
    return predicate


def synthesize(contract: ContractSurface, *,
               registry: Optional[dict[str, ContractSurface]] = None
               ) -> tuple[SynthesizedTarget, SynthesisReport]:
    contract = _resolve_inheritance(contract, registry or {})
    owner_var = _owner_var(contract)
    mappings, scalars = _state_shape(contract)

    models: list[OpModel] = []
    declarations: list[str] = []
    for func in contract.functions:
        if not func.externally_callable:
            continue
        if func.declaration_only:
            declarations.append(func.name)
            continue
        models.append(interpret(func, owner_var))

    invariants = _conservation_invariants({**{s: 0 for s in scalars}}, mappings)
    invariants.extend(_authorization_invariants(owner_var, scalars))
    target = SynthesizedTarget(contract, tuple(models), tuple(invariants),
                               owner_var, mappings, scalars)

    modelled = tuple(m.name for m in models if m.modelled)
    unmodelled = tuple(m.name for m in models if not m.modelled)
    statements = tuple(s for m in models for s in m.unmodelled)
    notes = []
    if not invariants:
        notes.append("no conservation invariant derived: the contract has no "
                     "balance-like mapping paired with a supply scalar")
    if declarations:
        notes.append(
            f"{len(declarations)} interface declaration(s) have no body and are not "
            f"modelled: {', '.join(declarations)}"
        )
    if unmodelled:
        notes.append(f"{len(unmodelled)} operation(s) are unmodelled and do not move "
                     "state; their reachability is not explored")
    external_calls = tuple(f"{m.name}->{c.receiver}.{c.op}"
                           for m in models for c in m.calls)
    if external_calls:
        notes.append(f"{len(external_calls)} external call(s) recorded; their effects "
                     "are applied only by a protocol composition, never by a "
                     "single-contract step")
    report = SynthesisReport(
        contract=contract.name,
        path=contract.path,
        modelled_ops=modelled,
        unmodelled_ops=unmodelled,
        unmodelled_statements=statements,
        invariants=tuple(i.inv_id for i in invariants),
        notes=tuple(notes),
        external_calls=external_calls,
    )
    # The ledger is part of the report, not an optional extra: a caller that
    # does not see it must not be able to call the result clean.
    from .model_coverage import coverage_for_contract

    coverage = coverage_for_contract(contract, report, target)
    report.model_coverage = coverage.to_dict()
    target.model_coverage = report.model_coverage
    return target, report
