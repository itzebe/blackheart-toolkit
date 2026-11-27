"""A real EVM execution adapter: drive the engine against deployed bytecode.

Every other runtime adapter in this package drives a *Python* application (over
loopback HTTP or a child process). This one drives a **real EVM**: an ephemeral
``anvil`` node, the exact pinned application bytecode deployed to it, and the
engine's operations dispatched as real transactions via JSON-RPC.

Why this exists (mission 03, Phase 4). The historical-rediscovery corpus is a set
of *Python models* of vulnerable logic; the runtime apps are BLACKHEART's own
deliberately-vulnerable fixtures. Neither is "unfamiliar, independently maintained
application source running as real bytecode". To test the engine against real
external source, the engine needs a target whose operations are actual EVM calls
against actual deployed contracts. That is the genuine compatibility gap this
adapter fills -- it adds no new engine, it supplies a new *transport* under the
unchanged ``SequenceTarget`` protocol.

Design and safety:

  * **Local only.** The adapter talks to ``127.0.0.1`` on a port it chose itself,
    via the same :class:`~blackheart.statespace.runtime.authz.LocalScope` gate as
    every other adapter. It cannot reach a remote chain: there is no RPC-URL
    parameter a caller could point elsewhere -- the node is spawned here.
  * **Real bytecode, not a model.** Contracts are deployed from compiled artifact
    bytecode; operations are ABI-encoded calls; state is read back with
    ``eth_call``. A violation is established from the *node's* observed state.
  * **Deterministic and resettable.** Deployment happens once; every sequence runs
    from an ``evm_snapshot`` of that clean state, restored with ``evm_revert``.
  * **No secrets, no funds.** The node is ephemeral and its accounts are the
    standard, publicly-known anvil test accounts; nothing here touches a real
    network or real value.

The adapter is generic: an :class:`EvmCase` declares the contracts to deploy, the
setup calls, the operations (with their actor and parameter domains), the
invariants, and the snapshot to read. A concrete case is *data*, not code.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..model import SystemModel, Actor, Operation
from .authz import LocalScope
from .base import BaseExecutionAdapter
from .evm_coverage import EvmCoverageOracle
from .interface import ExecRecord, ExecutionError, ScopeError


# --------------------------------------------------------------------------- #
# Minimal ABI encoder/decoder (stdlib only)
# --------------------------------------------------------------------------- #
#
# The node speaks raw hex; the engine speaks typed parameters. Only the types the
# corpus actually uses are supported, and each is exercised by a test that checks
# the encoding against ``cast calldata``. An unsupported type is a hard error, not
# a silent best-effort: a mis-encoded call would be a false result.

def _word(n: int) -> bytes:
    if n < 0:
        n += 1 << 256
    return int(n).to_bytes(32, "big")


def _pad(b: bytes) -> bytes:
    rem = len(b) % 32
    return b if rem == 0 else b + b"\x00" * (32 - rem)


def _is_dynamic(t: str) -> bool:
    return t in ("bytes", "string") or t.endswith("]")


def _enc_static(t: str, v: Any) -> bytes:
    if t == "address":
        h = v[2:] if isinstance(v, str) and v.startswith("0x") else str(v)
        return bytes(12) + bytes.fromhex(h.rjust(40, "0")[-40:])
    if t == "bool":
        return _word(1 if v else 0)
    if t.startswith("uint") or t.startswith("int"):
        return _word(int(v))
    if t.startswith("bytes") and t != "bytes":  # bytesN
        n = int(t[5:])
        h = v[2:] if isinstance(v, str) and v.startswith("0x") else bytes(v).hex()
        return bytes.fromhex(h.rjust(n * 2, "0")[: n * 2])
    raise ValueError(f"unsupported ABI static type {t!r}")


def _enc_dynamic(t: str, v: Any) -> bytes:
    if t == "bytes":
        b = bytes.fromhex(v[2:]) if isinstance(v, str) and v.startswith("0x") else bytes(v)
        return _word(len(b)) + _pad(b)
    if t == "string":
        b = v.encode("utf-8")
        return _word(len(b)) + _pad(b)
    if t.endswith("[]"):
        elem = t[:-2]
        items = list(v)
        body = encode_params([elem] * len(items), items)
        return _word(len(items)) + body
    raise ValueError(f"unsupported ABI dynamic type {t!r}")


def encode_params(types: list[str], values: list[Any]) -> bytes:
    """ABI-encode a parameter list (head/tail), per the Solidity ABI spec."""
    if len(types) != len(values):
        raise ValueError(f"{len(types)} types but {len(values)} values")
    static_size = 32 * len(types)
    head = b""
    tail = b""
    for t, v in zip(types, values):
        if _is_dynamic(t):
            head += _word(static_size + len(tail))
            tail += _enc_dynamic(t, v)
        else:
            head += _enc_static(t, v)
    return head + tail


def decode_uints(data: bytes, count: int) -> list[int]:
    """Decode ``count`` leading uint256 words from a return payload."""
    out = []
    for i in range(count):
        chunk = data[i * 32:(i + 1) * 32]
        out.append(int.from_bytes(chunk, "big") if chunk else 0)
    return out


def decode_address(data: bytes) -> str:
    return "0x" + data[12:32].hex()


def decode_bool(data: bytes) -> bool:
    return bool(int.from_bytes(data[:32], "big"))


# --------------------------------------------------------------------------- #
# JSON-RPC client
# --------------------------------------------------------------------------- #

class EthRpc:
    """A tiny, dependency-free JSON-RPC client for the local anvil node."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: Optional[list] = None) -> Any:
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}
        ).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            raise ExecutionError(f"rpc {method} failed: {exc}") from exc
        if "error" in body:
            raise ExecutionError(f"rpc {method} error: {body['error']}")
        return body.get("result")


def _foundry_bin(name: str) -> Optional[str]:
    """Locate a foundry binary on PATH, or in the standard install location.

    The sandbox installs foundry at ``~/.foundry/bin`` which is not always on the
    non-interactive PATH; fall back to it so the adapter works without a shell.
    """
    found = shutil.which(name)
    if found:
        return found
    candidate = Path.home() / ".foundry" / "bin" / name
    return str(candidate) if candidate.exists() else None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AnvilNode:
    """An ephemeral local EVM node. Spawned here; never a caller-supplied URL."""

    #: The standard anvil test accounts (public, deterministic). Account index ->
    #: address. These hold test ether on the ephemeral node only.
    ACCOUNTS = (
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
        "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
    )

    def __init__(self, *, port: Optional[int] = None, timeout: float = 30.0,
                 fork_url: Optional[str] = None,
                 fork_block: Optional[int] = None) -> None:
        anvil = _foundry_bin("anvil")
        if anvil is None:
            raise ExecutionError("anvil not found on PATH; cannot start a local EVM")
        self._anvil = anvil
        self.port = port or _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.timeout = timeout
        #: When set, the node is pinned to a *specific* block of a real chain.
        #: The block is recorded so evidence can name the exact state it ran on.
        self.fork_url = fork_url
        self.fork_block = fork_block
        self._proc: Optional[subprocess.Popen] = None
        self.rpc = EthRpc(self.url, timeout=timeout)

    def start(self) -> None:
        # idempotent: a second start() must not spawn a second node and orphan the
        # first (its Popen handle would be overwritten and the process leaked).
        if self._proc is not None and self._proc.poll() is None:
            return
        argv = [self._anvil, "--port", str(self.port), "--host", "127.0.0.1",
                "--accounts", str(len(self.ACCOUNTS)), "--silent"]
        if self.fork_url:
            argv += ["--fork-url", self.fork_url]
            if self.fork_block is not None:
                # A pinned block is a hard requirement, never a hint: if the
                # upstream cannot serve it the node must fail, not silently fork
                # "latest" and label the run with a block it did not use.
                argv += ["--fork-block-number", str(self.fork_block)]
        self._proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + self.timeout
        last: Optional[Exception] = None
        while time.monotonic() < deadline:
            try:
                self.rpc.call("eth_chainId")
                return
            except ExecutionError as exc:  # not up yet
                last = exc
                time.sleep(0.1)
        self.stop()
        raise ExecutionError(f"anvil did not become ready: {last}")

    def assert_fork_pinned(self) -> dict:
        """Prove the node is on the requested block, or fail loudly.

        Anvil will happily fork "latest" if the upstream refuses the requested
        block. That would silently make a run's recorded block a lie, so the pin
        is verified against the node itself rather than trusted from the argv.
        """
        if not self.fork_url:
            return {"forked": False}
        block = self.rpc.call("eth_getBlockByNumber", ["latest", False])
        number = int(block["number"], 16)
        if self.fork_block is not None and number != self.fork_block:
            raise ExecutionError(
                f"fork landed on block {number}, not the pinned {self.fork_block}; "
                "refusing to label this run with a block it did not execute on"
            )
        return {
            "forked": True,
            "block_number": number,
            "block_hash": block["hash"],
            "chain_id": int(self.rpc.call("eth_chainId"), 16),
        }

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 -- cleanup must never raise
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- #
# Case specification
# --------------------------------------------------------------------------- #

@dataclass
class ContractSpec:
    """One contract to deploy: its artifact, constructor types, and arguments."""

    key: str
    artifact: str                              # path to a forge artifact JSON
    ctor_types: tuple[str, ...] = ()
    ctor_args: tuple[Any, ...] = ()            # may contain Ref("<deployed key>")
    value: int = 0                             # wei sent at construction
    #: resolve this contract's address from a getter after deployment, e.g.
    #: ("exchange", "token()") -> the ERC721 the exchange created.
    resolve_from: Optional[tuple[str, str]] = None


@dataclass
class Ref:
    """A reference to an already-deployed contract's address (constructor arg)."""

    key: str


@dataclass(frozen=True)
class Self:
    """Marker: the address of the account sending the operation (its `msg.sender`)."""


@dataclass
class SetupCall:
    """A call made during deployment to reach the challenge's initial state."""

    actor: str                                 # anvil account index, as a string, or an address
    target: str                                # deployed contract key
    signature: str                             # e.g. "transfer(address,uint256)"
    args: tuple[Any, ...] = ()
    value: int = 0
    #: send from this raw address (e.g. a leaked-key source) via impersonation
    from_address: str = ""


@dataclass(frozen=True)
class Param:
    """A placeholder in an :class:`EvmOp` argument template naming an engine param."""

    name: str


@dataclass
class EvmOp:
    """One engine operation, mapped to a real contract call.

    ``args`` is the full ABI argument template, in order: each element is either a
    :class:`Param` (filled from the engine's params), a :class:`Ref` (a deployed
    contract address), or a literal. The engine's parameter space is exactly the
    ``Param`` names, with the ABI types and candidate domains declared beside them.
    """

    name: str
    actor: str                                 # the engine actor name that sends it
    target: str                                # deployed contract key
    signature: str                             # Solidity function signature
    args: tuple[Any, ...] = ()                 # template: Param | Ref | literal
    param_types: dict[str, str] = field(default_factory=dict)   # param -> ABI type
    domains: dict[str, tuple[Any, ...]] = field(default_factory=dict)  # param -> values
    value_param: str = ""                       # a param carried as msg.value (payable)
    description: str = ""

    def param_names(self) -> list[str]:
        return [a.name for a in self.args if isinstance(a, Param)]


@dataclass
class SnapshotRead:
    """One state read for the snapshot: ``target.signature(args)`` -> value."""

    key: str
    target: str
    signature: str
    args: tuple[Any, ...] = ()
    ret: str = "uint256"


@dataclass
class TransitionSpec:
    """A declared precondition transition the model should reason about.

    A security-relevant step that *enables* another operation (e.g. an approval
    that must precede a delegated transfer). Declaring it puts the operation into
    the explorer's relevant-operation set, so the enumeration considers sequences
    that reach the guarded operation *through* this transition.
    """

    name: str
    guard: str
    guard_roles: tuple[str, ...] = ()
    operation: str = ""
    description: str = ""


@dataclass
class EvmCase:
    """A complete, self-contained EVM evaluation case (data, not code)."""

    name: str
    suite: str                                 # "development" | "blind" | "control"
    description: str
    root: Path                                 # the vendored project root
    contracts: tuple[ContractSpec, ...]
    #: actor name -> anvil account index ("0".."9") or a raw address (impersonated)
    actors: dict[str, str] = field(default_factory=dict)
    setup: tuple[SetupCall, ...] = ()
    ops: tuple[EvmOp, ...] = ()
    snapshot: tuple[SnapshotRead, ...] = ()
    invariants: tuple[tuple[str, str, Callable[[dict], bool]], ...] = ()
    #: declared precondition transitions (put their operation into the relevant set)
    transitions: tuple[TransitionSpec, ...] = ()
    #: operations the model should treat as *sensitive* (mutating a protected
    #: asset), so the explorer's model-guided enumeration includes them
    sensitive: tuple[str, ...] = ()
    #: a plain-language statement of the ground-truth outcome (documented, not
    #: disclosed to the engine), kept beside the case for the report
    ground_truth: str = ""
    reference: str = ""


# --------------------------------------------------------------------------- #
# The adapter
# --------------------------------------------------------------------------- #

class EvmExecutionAdapter(BaseExecutionAdapter):
    """Drive a deployed EVM application as an executable target."""

    transport = "evm"

    def __init__(self, case: EvmCase, scope: LocalScope, *, node: Optional[AnvilNode] = None,
                 budget=None, timeout: float = 30.0) -> None:
        super().__init__(scope, budget=budget, timeout=timeout)
        self.case = case
        self.name = case.name
        self.node = node or AnvilNode()
        self._model: Optional[SystemModel] = None
        self._invariants: list[Any] = []
        self._addresses: dict[str, str] = {}
        self._selectors: dict[str, str] = {}
        self._snapshot_id: Optional[str] = None
        self._impersonated: set[str] = set()
        self._logs: list[str] = []
        #: Real EVM execution coverage (opcode/pc/edge) from the node's transaction
        #: traces. Best-effort: a node without ``debug_traceTransaction`` simply
        #: contributes no EVM features, and the behavioural signal still works.
        self.coverage = EvmCoverageOracle(self.node.rpc)

    # -- lifecycle ------------------------------------------------------- #

    def load(self) -> None:
        # the node is local by construction; the scope gate still applies so a
        # caller cannot run an adapter without an explicit authorization record.
        if self._loaded:
            return
        self._authorize(host="127.0.0.1", port=self.node.port, kind="http")
        self.node.start()
        self._deploy_all()
        self._resolve_post_deploy()
        self._run_setup()
        self._snapshot_id = self.node.rpc.call("evm_snapshot")
        self._loaded = True
        self._loaded_meta = {
            "node": self.node.url,
            "contracts": dict(self._addresses),
            "snapshot_id": self._snapshot_id,
        }

    def close(self) -> None:
        self.node.stop()
        # impersonation lives on the node; a later load() starts a fresh node, so
        # the record must be cleared or re-impersonation would be skipped.
        self._impersonated.clear()
        self._loaded = False

    def _artifact(self, rel: str) -> dict:
        path = Path(rel)
        if not path.is_absolute():
            path = self.case.root / rel
        if not path.exists():
            raise ExecutionError(
                f"artifact not found: {path}; run the harness fetch/build first"
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        # cache the selectors this artifact exposes
        for sig, sel in (data.get("methodIdentifiers") or {}).items():
            self._selectors.setdefault(sig, "0x" + sel)
        return data

    def _resolve(self, v: Any) -> Any:
        if isinstance(v, Ref):
            if v.key not in self._addresses:
                raise ExecutionError(f"reference to undeployed contract {v.key!r}")
            return self._addresses[v.key]
        if isinstance(v, Self):
            raise ExecutionError("Self marker is only valid in an EvmOp argument template")
        return v

    def _resolve_arg(self, v: Any, params: dict[str, Any], sender: str) -> Any:
        if isinstance(v, Param):
            if v.name not in params:
                raise ExecutionError(f"operation param {v.name!r} was not supplied")
            return params[v.name]
        if isinstance(v, Self):
            return sender
        return self._resolve(v)

    def _sender(self, actor: str) -> str:
        """Map an engine actor name to a real sending account.

        The case maps actor names to either an anvil test-account index
        ("0".."9") or a raw address. A raw address is only usable because the
        adapter *impersonates* it (``anvil_impersonateAccount``) -- legitimate
        here because the case is a local, self-contained reproduction of a
        documented compromise (e.g. leaked oracle keys), not a real account.
        """
        target = self.case.actors.get(actor, actor)
        if target.isdigit():
            return AnvilNode.ACCOUNTS[int(target)]
        return target

    def _ensure_impersonated(self, addr: str) -> None:
        if addr in self._impersonated:
            return
        if addr in AnvilNode.ACCOUNTS:
            self._impersonated.add(addr)
            return
        self.node.rpc.call("anvil_impersonateAccount", [addr])
        # fund it so it can pay for gas on the ephemeral node
        self.node.rpc.call("anvil_setBalance", [addr, hex(10 ** 20)])
        self._impersonated.add(addr)

    def _deploy_all(self) -> None:
        for spec in self.case.contracts:
            # A spec with resolve_from is created by another contract (e.g. a
            # proxy a factory/diamond core spawns); it has no bytecode of its own
            # to deploy and its address is read back in _resolve_post_deploy. Its
            # artifact is still loaded so the selectors it exposes are known.
            if spec.resolve_from:
                self._artifact(spec.artifact)
                continue
            data = self._artifact(spec.artifact)
            bytecode = data.get("bytecode", {}).get("object", "")
            if not bytecode or bytecode == "0x":
                raise ExecutionError(f"no bytecode for {spec.key!r} ({spec.artifact})")
            args = [self._resolve(a) for a in spec.ctor_args]
            encoded = encode_params(list(spec.ctor_types), args) if spec.ctor_types else b""
            tx = {
                "from": AnvilNode.ACCOUNTS[1],           # deployer account
                "data": bytecode + encoded.hex(),
            }
            if spec.value:
                tx["value"] = hex(spec.value)
            receipt = self._send_and_wait(tx)
            if not receipt or not receipt.get("contractAddress"):
                raise ExecutionError(f"deployment of {spec.key!r} failed: {receipt}")
            self._addresses[spec.key] = receipt["contractAddress"]

    def _resolve_post_deploy(self) -> None:
        """Resolve addresses a contract created (e.g. the exchange's NFT)."""
        for spec in self.case.contracts:
            if not spec.resolve_from:
                continue
            parent, sig = spec.resolve_from
            addr = self._call(parent, sig, (), "address")
            if not addr or addr == "0x" + "00" * 20:
                raise ExecutionError(f"could not resolve {spec.key!r} from {parent}.{sig}")
            self._addresses[spec.key] = addr

    def _run_setup(self) -> None:
        for call in self.case.setup:
            if call.from_address:
                sender = call.from_address
            elif call.actor:
                sender = self._sender(call.actor)
            else:
                sender = AnvilNode.ACCOUNTS[1]     # the deployer account
            self._ensure_impersonated(sender)
            self._send_function_raw(sender, call.target, call.signature, call.args, call.value)

    # -- transactions ---------------------------------------------------- #

    def _calldata(self, signature: str, args: tuple) -> str:
        sel = self._selectors.get(signature)
        if sel is None:
            raise ExecutionError(f"unknown function selector for {signature!r}")
        if not args:
            return sel
        types = _parse_types(signature)
        return sel + encode_params(types, list(args)).hex()

    def _send_and_wait(self, tx: dict) -> dict:
        tx.setdefault("gas", hex(30_000_000))
        txh = self.node.rpc.call("eth_sendTransaction", [tx])
        # anvil mines instantly; poll the receipt briefly
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            receipt = self.node.rpc.call("eth_getTransactionReceipt", [txh])
            if receipt is not None:
                return receipt
            time.sleep(0.02)
        raise ExecutionError("transaction not mined within timeout")

    def _send_function(self, actor: str, target: str, signature: str, args: tuple,
                       value: int = 0) -> dict:
        sender = self._sender(actor)
        self._ensure_impersonated(sender)
        return self._send_function_raw(sender, target, signature, args, value)

    def _send_function_raw(self, sender: str, target: str, signature: str, args: tuple,
                           value: int = 0) -> dict:
        addr = self._addresses.get(target, target)
        tx = {
            "from": sender,
            "to": addr,
            "data": self._calldata(signature, tuple(self._resolve(a) for a in args)),
        }
        if value:
            tx["value"] = hex(value)
        return self._send_and_wait(tx)

    def _call(self, target: str, signature: str, args: tuple, ret: str) -> Any:
        if ret == "eth_balance":
            addr = self._addresses.get(target, target)
            bal = self.node.rpc.call("eth_getBalance", [addr, "latest"])
            return int(bal, 16) if bal else 0
        addr = self._addresses.get(target, target)
        data = self._calldata(signature, tuple(self._resolve(a) for a in args))
        raw = self.node.rpc.call("eth_call", [{"to": addr, "data": data}, "latest"])
        payload = bytes.fromhex(raw[2:]) if raw and raw.startswith("0x") else b""
        if ret == "address":
            return decode_address(payload)
        if ret == "bool":
            return decode_bool(payload)
        if ret.startswith("uint"):
            return decode_uints(payload, 1)[0]
        return decode_uints(payload, 1)[0]

    # -- declared model -------------------------------------------------- #

    def model(self) -> SystemModel:
        if self._model is None:
            actor_names = sorted({op.actor for op in self.case.ops})
            actors = [Actor(name=a, unprivileged=True,
                            note=f"EVM actor '{a}' -> {self.case.actors.get(a, '?')} (local EVM only)")
                      for a in actor_names]
            sensitive = set(self.case.sensitive)
            ops = [
                Operation(name=op.name, actor_roles=(op.actor,),
                          entry_point=op.signature,
                          effect=op.description or f"calls {op.signature} on {op.target}",
                          sensitive=op.name in sensitive,
                          source=f"external-case:{self.case.name}")
                for op in self.case.ops
            ]
            model = SystemModel(
                target=self.case.name,
                summary=self.case.description,
                actors=actors,
                operations=ops,
                assets=[r.key for r in self.case.snapshot] or ["state"],
            )
            for inv_id, statement, _pred in self.case.invariants:
                model.add_invariant(inv_id, statement)
            for tr in self.case.transitions:
                model.add_transition(tr.name, tr.guard, tr.guard_roles,
                                     operation=tr.operation, description=tr.description)
            self._model = model
        return self._model

    def identities(self) -> list[str]:
        return [a.name for a in self.model().actors]

    def operations(self) -> list[str]:
        return [op.name for op in self.case.ops]

    def invariants(self) -> list[Any]:
        if not self._invariants and self.case.invariants:
            from ...invariants.engine import InvariantSpec

            self._invariants = [
                InvariantSpec(inv_id, title, pred, severity_if_broken="high")
                for inv_id, title, pred in self.case.invariants
            ]
        return self._invariants

    def set_invariants(self, invariants: list[Any]) -> None:
        self._invariants = invariants

    def op_specs(self):
        """Expose the case's operations as engine ``OpSpec``s (name, actor, domain)."""
        from ...invariants.engine import OpSpec

        specs = []
        for op in self.case.ops:
            domain: dict[str, list] = {}
            for name in op.param_names():
                if name in op.domains:
                    domain[name] = list(op.domains[name])
            if op.value_param:
                domain[op.value_param] = list(op.domains.get(op.value_param, (0,)))
            specs.append(OpSpec(op.name, [op.actor], domain, weight=1,
                                description=op.description))
        return specs

    # -- state ----------------------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        if not self._loaded:
            return {}
        out: dict[str, Any] = {}
        for read in self.case.snapshot:
            try:
                out[read.key] = self._call(read.target, read.signature, read.args, read.ret)
            except (ExecutionError, ScopeError):
                out[read.key] = None
        return out

    def reset(self) -> None:
        if self._snapshot_id is not None:
            self.node.rpc.call("evm_revert", [self._snapshot_id])
            self._snapshot_id = self.node.rpc.call("evm_snapshot")
        # A new run starts a new coverage buffer, so the features the caller reads
        # describe only the run just executed.
        self.coverage.begin_run()

    # -- dispatch -------------------------------------------------------- #

    def _dispatch(self, operation: str, actor: str, params: dict[str, Any]) -> ExecRecord:
        op = next((o for o in self.case.ops if o.name == operation), None)
        if op is None:
            raise ExecutionError(f"operation {operation!r} is not in this case")
        sender = self._sender(op.actor)
        self._ensure_impersonated(sender)
        args = tuple(self._resolve_arg(a, params, sender) for a in op.args)
        value = int(params.get(op.value_param, 0)) if op.value_param else 0
        receipt = self._send_function_raw(sender, op.target, op.signature, args, value)
        status = int(receipt.get("status", "0x0"), 16)
        ok = status == 1
        # Real execution coverage: trace the transaction just mined and fold its
        # opcode/pc/edge features into the run's buffer. Best-effort -- a node
        # without the debug API records a note and contributes nothing.
        self.coverage.collect(receipt.get("transactionHash"), label=op.name)
        return ExecRecord(
            index=-1, actor=actor, operation=operation, params=dict(params),
            provenance="executed", transport=self.transport,
            status="ok" if ok else "reverted", accepted=ok,
            http_status=None,
            error="" if ok else "transaction reverted",
            response={"tx": receipt.get("transactionHash"), "gasUsed": receipt.get("gasUsed")},
        )


def _parse_types(signature: str) -> list[str]:
    """Extract the parameter types from a Solidity signature."""
    inner = signature[signature.index("(") + 1: signature.rindex(")")]
    if not inner.strip():
        return []
    types, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "," and depth == 0:
            types.append(cur.strip())
            cur = ""
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        cur += ch
    types.append(cur.strip())
    return types
