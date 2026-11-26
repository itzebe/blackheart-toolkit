"""Authorized research triggers: authenticate, validate, and dispatch to the scheduler.

A *trigger* is an external request to start BLACKHEART research on an asset. It is
the one place where data BLACKHEART did not create decides that work should run,
so it is treated as hostile input from the first line: authenticated, schema-
validated, deduplicated, scope-checked, rate-limited, and recorded -- and only
then turned into a durable scheduler job.

Design in one paragraph. A :class:`TriggerSource` authenticates a raw delivery
into a :class:`TriggerRequest` (or rejects it); a :class:`TriggerLedger` records
every delivery with its disposition and provenance in a tamper-evident chain; a
:class:`TriggerReceiver` applies the policy gates in a fixed order (replay ->
dedupe -> rate limit -> authorization -> job) and, only when all pass, enqueues a
job through the existing :class:`~blackheart.scheduler.engine.Scheduler`. The
receiver never runs research itself and never invents a verdict -- the scheduler
and the engine own that, exactly as they already do.

The security properties, each enforced in code and tested:

  * **Authentication.** The webhook source verifies an HMAC-SHA256 signature over
    ``timestamp.body`` in constant time, and rejects a timestamp outside a skew
    window (a replayed old delivery cannot authenticate).
  * **Replay and duplicate delivery.** A per-delivery nonce is remembered, and a
    content digest dedupes a resend; neither a replay nor a duplicate creates a
    second job.
  * **Payload validation.** A closed schema; unknown keys, wrong types, a missing
    required field, or an oversized body are rejected before anything is built.
  * **Authorization before creation.** The asset must pass the *existing*
    :func:`blackheart.authz.authorize_active_testing` gate, against an
    authorization record the receiver is configured with -- a payload cannot
    supply or override it. The scheduler re-checks the same gate again at claim
    and execution time.
  * **Bounded cost.** A sliding-window rate limit caps accepted work per window;
    a flood is rejected without creating jobs.
  * **Honest states.** A delivery is recorded as RECEIVED, AUTHENTICATED,
    ACCEPTED (job created), DISPATCHED (claimed), EXECUTED, or COMPLETED -- and a
    trigger that only reached the queue is never recorded as executed.
"""

from __future__ import annotations
import os

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..authz import authorize_active_testing
from ..chainedlog import ChainedLog
from ..integrity import IntegrityKey
from ..models import AuthorizationRecord, utcnow

__all__ = [
    "TriggerState",
    "TriggerError",
    "TriggerRequest",
    "TriggerRecord",
    "TriggerPolicy",
    "TriggerSource",
    "WebhookTriggerSource",
    "ManualTriggerSource",
    "RecurringTrigger",
    "TriggerLedger",
    "TriggerReceiver",
    "TriggerDispatch",
    "validate_payload",
    "PAYLOAD_FIELDS",
]


class TriggerState:
    """The lifecycle of one delivery. Distinct on purpose: a queued trigger is not
    an executed one, and the record must never conflate them."""

    RECEIVED = "RECEIVED"            # arrived; not yet authenticated
    AUTHENTICATED = "AUTHENTICATED"  # signature/timestamp/nonce verified
    ACCEPTED = "ACCEPTED"            # a durable job was created
    DISPATCHED = "DISPATCHED"        # the scheduler claimed the job
    EXECUTED = "EXECUTED"            # the engine ran (verdict recorded on the job)
    COMPLETED = "COMPLETED"          # terminal: the job reached a terminal state
    REJECTED = "REJECTED"            # failed a gate; a reason is recorded
    DUPLICATE = "DUPLICATE"          # a known delivery; deduped, no new job


class TriggerError(ValueError):
    """A trigger was refused. The message is safe to show; it never contains a secret."""


# --------------------------------------------------------------------------- #
# The request and its record
# --------------------------------------------------------------------------- #

#: The fields a trigger payload may carry. Anything else is rejected. Note what is
#: *absent*: there is no ``authz`` and no ``scope`` field -- authorization is the
#: receiver's to enforce, never the payload's to assert.
PAYLOAD_FIELDS = {
    "kind",         # "hunt" | "investigate" -- the scheduler executor to run
    "target",       # engine target id (e.g. "access-control")
    "asset",        # the in-scope asset being researched
    "scope_reference",  # free-text reference to the program scope
    "hypothesis",   # required only for kind="investigate"
    "seed",         # optional int, forwarded to the executor
    "priority",     # optional int
    "note",         # optional operator note, stored for provenance
}


@dataclass
class TriggerRequest:
    """A validated, authenticated request to start research. Built by a source."""

    kind: str
    target: str
    asset: str
    source: str                       # which TriggerSource produced it
    scope_reference: str = ""
    hypothesis: dict = field(default_factory=dict)
    seed: int = 0
    priority: int = 0
    note: str = ""
    # Provenance, filled by the receiver.
    delivery_id: str = ""             # unique per delivery (nonce)
    payload_sha256: str = ""          # digest of the canonical payload
    received_at: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "target": self.target, "asset": self.asset,
            "source": self.source, "scope_reference": self.scope_reference,
            "hypothesis": self.hypothesis, "seed": self.seed,
            "priority": self.priority, "note": self.note,
            "delivery_id": self.delivery_id,
            "payload_sha256": self.payload_sha256, "received_at": self.received_at,
        }

    def idempotency_key(self) -> str:
        """Dedupe on the *payload*, so a resend (new nonce, same content) is one job."""
        return f"trigger:{self.payload_sha256}" if self.payload_sha256 else ""


@dataclass
class TriggerRecord:
    """The durable record of one delivery and its disposition."""

    delivery_id: str
    source: str
    state: str = TriggerState.RECEIVED
    reason: str = ""
    payload_sha256: str = ""
    request: dict = field(default_factory=dict)
    job_id: str = ""
    received_at: str = ""
    #: The receiver clock at receipt, as an epoch float. The rate limiter reads
    #: *this* rather than parsing ``received_at`` so it stays deterministic under
    #: an injected clock (a test can advance time; wall clock would not follow).
    received_epoch: float = 0.0
    updated_at: str = ""
    history: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "delivery_id": self.delivery_id, "source": self.source,
            "state": self.state, "reason": self.reason,
            "payload_sha256": self.payload_sha256, "request": self.request,
            "job_id": self.job_id, "received_at": self.received_at,
            "received_epoch": self.received_epoch,
            "updated_at": self.updated_at, "history": self.history,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TriggerRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------- #
# The ledger
# --------------------------------------------------------------------------- #

class TriggerLedger:
    """A tamper-evident record of every delivery, accepted or rejected.

    Rejections are recorded too -- a forged signature, a replay, a flood -- because
    an operator needs to see attempts, not only successes. A rejected record never
    carries the secret or the raw body, only a digest and a safe reason.
    """

    def __init__(self, root: str | os.PathLike, name: str = "triggers",
                 *, key: Optional[IntegrityKey] = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = ChainedLog(self.root / f"{name}.jsonl", key=key)
        self.path = self.log.path
        self.key = key

    def record(self, rec: TriggerRecord) -> TriggerRecord:
        if not rec.updated_at:
            rec.updated_at = utcnow()
        self.log.append(rec.delivery_id, rec.to_dict())
        return rec

    def get(self, delivery_id: str) -> Optional[TriggerRecord]:
        content = self.log.get(delivery_id)
        return TriggerRecord.from_dict(content) if content else None

    def all(self) -> list[TriggerRecord]:
        return [TriggerRecord.from_dict(c) for c in self.log.state().values()]

    def by_payload(self, payload_sha256: str) -> Optional[TriggerRecord]:
        """The first record for a given payload digest -- used to dedupe a resend."""
        for rec in self.all():
            if rec.payload_sha256 == payload_sha256 and rec.job_id:
                return rec
        return None

    def seen_nonce(self, delivery_id: str) -> bool:
        return self.log.get(delivery_id) is not None

    def verify_integrity(self, *, require_signatures: bool = False) -> dict:
        return self.log.verify_integrity(require_signatures=require_signatures)

    def transaction(self):
        """Hold the ledger lock across a read-decide-append sequence.

        The receiver's dedupe and rate-limit gates read the log and then append;
        without one lock over both, two concurrent deliveries both see "no
        duplicate" and each creates a job.
        """
        return self.log.transaction()

    def head(self) -> tuple[int, str]:
        return self.log.head()


# --------------------------------------------------------------------------- #
# Sources: how a raw delivery becomes an authenticated TriggerRequest
# --------------------------------------------------------------------------- #

class TriggerSource:
    """A provider-independent trigger interface.

    A concrete source turns *some* transport (a signed webhook, a manual CLI
    invocation, a recurring schedule) into a :class:`TriggerRequest`, or raises
    :class:`TriggerError`. It is responsible for **authentication only** -- the
    receiver owns authorization, dedupe, rate limiting, and job creation, so a new
    source cannot accidentally skip those gates.
    """

    name = "abstract"

    def authenticate(self, raw: bytes, headers: dict, *,
                     now: Optional[float] = None) -> TriggerRequest:
        raise NotImplementedError


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_payload(payload: dict, *, max_bytes: int = 64 * 1024) -> dict:
    """Validate a trigger payload against the closed schema. Raises on any doubt.

    Returns the payload unchanged (already a dict). Rejects: a non-object, an
    unknown key, a wrong type, a missing required field, an over-long string, or a
    body larger than ``max_bytes``. Every rejection is a :class:`TriggerError`
    with a safe message.
    """
    if not isinstance(payload, dict):
        raise TriggerError("payload must be a JSON object")
    raw = _canonical(payload)
    if len(raw) > max_bytes:
        raise TriggerError(f"payload too large ({len(raw)} > {max_bytes} bytes)")

    unknown = set(payload) - PAYLOAD_FIELDS
    if unknown:
        raise TriggerError(f"unknown payload field(s): {sorted(unknown)}")

    for required in ("kind", "target", "asset"):
        if required not in payload:
            raise TriggerError(f"missing required field: {required}")
    for key in ("kind", "target", "asset", "scope_reference", "note"):
        if key in payload and not isinstance(payload[key], str):
            raise TriggerError(f"field {key!r} must be a string")
        if isinstance(payload.get(key), str) and len(payload[key]) > 512:
            raise TriggerError(f"field {key!r} too long (max 512 chars)")

    kind = payload["kind"]
    if kind not in ("hunt", "investigate"):
        raise TriggerError(f"unknown trigger kind {kind!r}; known: hunt, investigate")
    for key in ("target", "asset"):
        if not payload[key].strip():
            raise TriggerError(f"field {key!r} must not be empty")

    if "seed" in payload and not isinstance(payload["seed"], int):
        raise TriggerError("field 'seed' must be an integer")
    if "priority" in payload and not isinstance(payload["priority"], int):
        raise TriggerError("field 'priority' must be an integer")
    if "hypothesis" in payload and not isinstance(payload["hypothesis"], dict):
        raise TriggerError("field 'hypothesis' must be an object")

    if kind == "investigate" and not payload.get("hypothesis"):
        raise TriggerError("kind 'investigate' requires a 'hypothesis' object")

    return payload


class WebhookTriggerSource(TriggerSource):
    """An HMAC-authenticated webhook (GitHub/Stripe/generic style).

    The signature is ``sha256=<hex>`` over ``<timestamp>.<body>``. Authentication
    checks, in order: a present signature header, a timestamp inside the skew
    window, and a constant-time HMAC comparison. A failure is a
    :class:`TriggerError` that names the failed check but never the secret.
    """

    name = "webhook"

    def __init__(
        self, secret: bytes, *, signature_header: str = "X-Blackheart-Signature",
        timestamp_header: str = "X-Blackheart-Timestamp",
        max_skew_seconds: int = 300, max_bytes: int = 64 * 1024,
    ) -> None:
        if not secret:
            raise ValueError("webhook secret must not be empty")
        self.secret = secret
        self.signature_header = signature_header
        self.timestamp_header = timestamp_header
        self.max_skew_seconds = max_skew_seconds
        self.max_bytes = max_bytes

    def _header(self, headers: dict, name: str) -> str:
        # Headers are case-insensitive on the wire; accept any case.
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v or ""
        return ""

    def expected_signature(self, timestamp: str, body: bytes) -> str:
        msg = timestamp.encode("utf-8") + b"." + body
        return "sha256=" + hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

    def authenticate(self, raw: bytes, headers: dict, *,
                     now: Optional[float] = None) -> TriggerRequest:
        if len(raw) > self.max_bytes:
            raise TriggerError(f"body too large ({len(raw)} > {self.max_bytes} bytes)")

        sig = self._header(headers, self.signature_header)
        if not sig:
            raise TriggerError(f"missing signature header {self.signature_header!r}")
        ts = self._header(headers, self.timestamp_header)
        if not ts:
            raise TriggerError(f"missing timestamp header {self.timestamp_header!r}")
        try:
            ts_val = int(ts)
        except ValueError:
            raise TriggerError("timestamp header is not an integer") from None

        now = time.time() if now is None else now
        if abs(now - ts_val) > self.max_skew_seconds:
            raise TriggerError(
                f"timestamp outside {self.max_skew_seconds}s skew window (replay?)"
            )

        expected = self.expected_signature(ts, raw)
        if not hmac.compare_digest(expected, sig):
            raise TriggerError("signature verification failed")

        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TriggerError(f"body is not valid JSON: {type(exc).__name__}") from None
        payload = validate_payload(payload, max_bytes=self.max_bytes)

        delivery_id = self._header(headers, "X-Blackheart-Delivery")
        if not delivery_id:
            # No delivery id supplied: derive a stable one from the signature so a
            # resend of the same signed body is recognised, while a genuinely new
            # signed body gets a new id.
            delivery_id = "wh-" + hashlib.sha256(
                (ts + "." + sig).encode("utf-8")
            ).hexdigest()[:24]

        return TriggerRequest(
            kind=payload["kind"], target=payload["target"], asset=payload["asset"],
            source=self.name, scope_reference=payload.get("scope_reference", ""),
            hypothesis=payload.get("hypothesis", {}), seed=payload.get("seed", 0),
            priority=payload.get("priority", 0), note=payload.get("note", ""),
            delivery_id=delivery_id,
            payload_sha256=hashlib.sha256(_canonical(payload)).hexdigest(),
            received_at=utcnow(),
        )


class ManualTriggerSource(TriggerSource):
    """An operator-initiated trigger, run locally from the CLI.

    There is no transport signature to verify -- the operator already holds the
    authorization. This source therefore only validates the payload; the receiver
    still applies every gate (dedupe, rate limit, authorization, job creation)
    exactly as for a webhook, so a manual trigger cannot bypass a control.
    """

    name = "manual"

    def authenticate(self, raw: bytes, headers: dict, *,
                     now: Optional[float] = None) -> TriggerRequest:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TriggerError(f"payload is not valid JSON: {type(exc).__name__}") from None
        payload = validate_payload(payload)
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        return TriggerRequest(
            kind=payload["kind"], target=payload["target"], asset=payload["asset"],
            source=self.name, scope_reference=payload.get("scope_reference", ""),
            hypothesis=payload.get("hypothesis", {}), seed=payload.get("seed", 0),
            priority=payload.get("priority", 0), note=payload.get("note", ""),
            delivery_id="manual-" + uuid.uuid4().hex[:12],
            payload_sha256=digest, received_at=utcnow(),
        )


@dataclass
class RecurringTrigger:
    """A schedule entry: the same validated payload fires every ``interval`` seconds.

    The scheduler already has misfire handling for a job whose moment passed while
    nothing ran, so a recurring trigger is just "a trigger whose delivery is due
    every N seconds". :meth:`TriggerReceiver.tick` emits at most one delivery per
    due moment and records the last-fired time, so a restart does not double-fire.
    """

    trigger_id: str
    interval_seconds: int
    payload: dict
    last_fired: float = 0.0

    def due(self, now: float) -> bool:
        return now - self.last_fired >= self.interval_seconds

    def to_dict(self) -> dict:
        return {"trigger_id": self.trigger_id, "interval_seconds": self.interval_seconds,
                "payload": self.payload, "last_fired": self.last_fired}

    @classmethod
    def from_dict(cls, d: dict) -> "RecurringTrigger":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------- #
# Policy and the receiver
# --------------------------------------------------------------------------- #

@dataclass
class TriggerPolicy:
    """The receiver's limits. ``authz`` is the *only* authorization a trigger is
    judged against; a payload can never supply or override it.

    ``authz_provider`` is the *live* source of that record. When set, both the
    receiver and the scheduler read authorization from it at decision time, so a
    scope withdrawal recorded after a job was queued is honoured instead of being
    ignored in favour of the snapshot taken at enqueue. When a provider *is* set it
    is authoritative and fails closed: if it cannot produce a record (the file was
    deleted or became unreadable) the delivery is rejected and the job is blocked --
    the enqueue-time snapshot is never used as a fallback. The CLI wires a provider
    that re-reads the authorization file on every call; leaving it unset keeps the
    previous snapshot semantics for callers that never mutate their record.
    """

    authz: AuthorizationRecord
    max_accepted_per_window: int = 20
    window_seconds: int = 60
    allow_sources: tuple[str, ...] = ("webhook", "manual", "recurring")
    #: ``asset -> AuthorizationRecord | None``. Read at claim and execution time.
    authz_provider: Optional[Callable[[str], Optional[AuthorizationRecord]]] = None

    def resolve_authz(self, asset: str) -> Optional[AuthorizationRecord]:
        """The *current* authorization record for ``asset``.

        Returns the configured snapshot only when **no** live provider is set. When
        a provider is set it is authoritative: a provider that raises or returns
        ``None`` -- the file was deleted, or became unreadable -- yields ``None``,
        and the receiver refuses the delivery. Falling back to the snapshot there
        would accept a delivery against scope that may have been withdrawn.
        """
        if self.authz_provider is None:
            return self.authz
        try:
            return self.authz_provider(asset)
        except Exception:  # noqa: BLE001 -- a broken provider must not authorize
            return None


@dataclass
class TriggerDispatch:
    """The outcome of handling one delivery."""

    delivery_id: str
    state: str
    reason: str = ""
    job_id: str = ""
    created_job: bool = False

    def to_dict(self) -> dict:
        return {"delivery_id": self.delivery_id, "state": self.state,
                "reason": self.reason, "job_id": self.job_id,
                "created_job": self.created_job}


class TriggerReceiver:
    """Applies the trigger gates and, when all pass, enqueues a scheduler job.

    The gate order is deliberate and fixed: **authentication** (done by the source)
    -> **replay/nonce** -> **duplicate payload** -> **rate limit** ->
    **authorization** -> **job creation**. A cheaper or more fundamental check runs
    before an expensive one, and nothing creates a job until every check passes.
    """

    def __init__(
        self, ledger: TriggerLedger, policy: TriggerPolicy, *,
        scheduler=None, clock: Callable[[], float] = time.time,
        max_body_bytes: int = 64 * 1024,
    ) -> None:
        self.ledger = ledger
        self.policy = policy
        self.scheduler = scheduler
        self.clock = clock
        self.max_body_bytes = max_body_bytes

    # -- gate: rate limit ---------------------------------------------- #
    def _recent_accepts(self, now: float) -> int:
        cutoff = now - self.policy.window_seconds
        count = 0
        for rec in self.ledger.all():
            if rec.state in (TriggerState.ACCEPTED, TriggerState.DISPATCHED,
                             TriggerState.EXECUTED, TriggerState.COMPLETED):
                if rec.received_epoch >= cutoff:
                    count += 1
        return count

    # -- the main entry point ------------------------------------------ #
    def handle(self, source: TriggerSource, raw: bytes, headers: dict) -> TriggerDispatch:
        """Authenticate and process one delivery end to end.

        Authentication runs first, outside the ledger lock (it is pure and needs no
        log state). Everything that *decides from the log and then appends* -- the
        replay check, the payload dedupe, the rate-limit count, and the ACCEPTED
        record -- runs inside one :meth:`TriggerLedger.transaction`, so two
        concurrent deliveries of the same payload cannot both observe "no
        duplicate" and both create a job. That was a real defect: without the lock,
        24 concurrent resends produced 3 jobs.
        """
        now = self.clock()

        # 1. Authentication. A source failure is recorded and refused.
        try:
            req = source.authenticate(raw, headers, now=now)
        except TriggerError as exc:
            return self._reject_anonymous(source.name, str(exc))

        # Steps 2-7 are one atomic read-modify-append over the ledger.
        with self.ledger.transaction():
            return self._gated_handle(req, now)

    def _gated_handle(self, req: TriggerRequest, now: float) -> TriggerDispatch:
        # 2. Replay: a delivery id we have already seen is refused outright.
        if self.ledger.seen_nonce(req.delivery_id):
            existing = self.ledger.get(req.delivery_id)
            # Record the *replay attempt* under its own id. Reusing the original
            # delivery id would overwrite the genuine record -- erasing the proof
            # that the first delivery created work -- and the ledger would then
            # report a successful delivery as a duplicate.
            return self._record_replay(req, existing.job_id if existing else "")

        # 3. Duplicate payload: a resend with a new delivery id is the same work.
        dup = self.ledger.by_payload(req.payload_sha256)
        if dup is not None:
            return self._record(req, TriggerState.DUPLICATE,
                                "duplicate: identical payload already accepted",
                                job_id=dup.job_id)

        # 4. Source allow-list.
        if req.source not in self.policy.allow_sources:
            return self._record(req, TriggerState.REJECTED,
                                f"source {req.source!r} not allowed")

        # 5. Rate limit.
        if self._recent_accepts(now) >= self.policy.max_accepted_per_window:
            return self._record(
                req, TriggerState.REJECTED,
                f"rate limit: {self.policy.max_accepted_per_window} accepted in "
                f"{self.policy.window_seconds}s window",
            )

        # 6. Authorization -- against the policy record, never the payload. The
        # policy's live provider is consulted so a withdrawal made since the
        # receiver started is honoured here too, not only at execution time.
        record = self.policy.resolve_authz(req.asset)
        if record is None:
            return self._record(
                req, TriggerState.REJECTED,
                "authorization failed: live authorization record is unavailable",
            )
        decision = authorize_active_testing(record, req.asset)
        if not decision.allowed:
            return self._record(
                req, TriggerState.REJECTED,
                "authorization failed: " + "; ".join(decision.blockers),
            )

        # 7. Job creation. Authentication + authorization both passed.
        if self.scheduler is None:
            return self._record(req, TriggerState.AUTHENTICATED,
                                "no scheduler attached; authenticated but not dispatched")
        job = self._enqueue(req, record)
        return self._record(req, TriggerState.ACCEPTED,
                            "job created", job_id=job.job_id, created_job=True)

    def _enqueue(self, req: TriggerRequest, record: AuthorizationRecord):
        payload = {"source": req.source, "delivery_id": req.delivery_id,
                   "note": req.note, "seed": req.seed}
        if req.hypothesis:
            payload["hypothesis"] = req.hypothesis
        # Snapshot the record authorization was actually granted against, not the
        # policy's possibly-stale configured record: the scheduler may run with no
        # live provider (e.g. recovered by a different process) and would then
        # trust this snapshot.
        return self.scheduler.enqueue(
            kind=req.kind, target=req.target, asset=req.asset,
            authz=record, payload=payload,
            idempotency_key=req.idempotency_key(),
            priority=req.priority, scope_reference=req.scope_reference,
        )

    # -- recording ------------------------------------------------------ #
    def _record(self, req: TriggerRequest, state: str, reason: str = "",
                job_id: str = "", created_job: bool = False) -> TriggerDispatch:
        rec = TriggerRecord(
            delivery_id=req.delivery_id, source=req.source, state=state,
            reason=reason, payload_sha256=req.payload_sha256,
            request=req.to_dict(), job_id=job_id,
            received_at=req.received_at, received_epoch=self.clock(),
            updated_at=utcnow(),
            history=[f"{TriggerState.RECEIVED}: from {req.source}",
                     f"{state}: {reason}" if reason else state],
        )
        self.ledger.record(rec)
        return TriggerDispatch(req.delivery_id, state, reason, job_id, created_job)

    def _record_replay(self, req: TriggerRequest, job_id: str) -> TriggerDispatch:
        """Record a replay attempt under a *fresh* id so the original survives."""
        reason = f"replay: delivery {req.delivery_id} already seen"
        rec = TriggerRecord(
            delivery_id="replay-" + uuid.uuid4().hex[:12], source=req.source,
            state=TriggerState.DUPLICATE, reason=reason,
            payload_sha256=req.payload_sha256, request=req.to_dict(),
            job_id=job_id, received_at=req.received_at,
            received_epoch=self.clock(), updated_at=utcnow(),
            history=[f"REPLAY: original {req.delivery_id} already recorded"],
        )
        self.ledger.record(rec)
        return TriggerDispatch(req.delivery_id, TriggerState.DUPLICATE, reason, job_id)

    def _reject_anonymous(self, source_name: str, reason: str) -> TriggerDispatch:
        """Record a delivery that could not even be authenticated."""
        delivery_id = "rejected-" + uuid.uuid4().hex[:12]
        rec = TriggerRecord(
            delivery_id=delivery_id, source=source_name, state=TriggerState.REJECTED,
            reason=reason, received_at=utcnow(), received_epoch=self.clock(),
            updated_at=utcnow(), history=[f"REJECTED: {reason}"],
        )
        self.ledger.record(rec)
        return TriggerDispatch(delivery_id, TriggerState.REJECTED, reason)

    # -- observability: link a trigger to its job's real outcome -------- #
    def sync_states(self) -> list[TriggerDispatch]:
        """Advance accepted triggers to DISPATCHED/EXECUTED/COMPLETED from the job.

        This is how a trigger record tells the truth about what happened to the
        work: a trigger is only EXECUTED once its job actually ran, and only
        COMPLETED once the job is terminal. Nothing here guesses.
        """
        if self.scheduler is None:
            return []
        updated: list[TriggerDispatch] = []
        for rec in self.ledger.all():
            if rec.state not in (TriggerState.ACCEPTED, TriggerState.DISPATCHED,
                                 TriggerState.EXECUTED):
                continue
            job = self.scheduler.store.get(rec.job_id) if rec.job_id else None
            if job is None:
                continue
            new_state = self._state_for(job)
            if new_state != rec.state:
                rec.state = new_state
                rec.updated_at = utcnow()
                # Carry the job's real outcome into the reason so a `trigger list`
                # never shows a failed run as a bare "COMPLETED".
                rec.reason = f"job {job.job_id} is {job.state}"
                rec.history.append(f"{new_state}: job {job.job_id} is {job.state}")
                self.ledger.record(rec)
                updated.append(TriggerDispatch(rec.delivery_id, new_state,
                                               rec.reason, rec.job_id))
        return updated

    @staticmethod
    def _state_for(job) -> str:
        from ..scheduler.jobs import JobState
        if job.state in (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED):
            return TriggerState.COMPLETED
        if job.state == JobState.LEASED:
            return TriggerState.DISPATCHED
        if job.attempts > 0:
            return TriggerState.EXECUTED
        return TriggerState.ACCEPTED

    # -- recurring triggers -------------------------------------------- #
    def tick(self, recurring: list[RecurringTrigger]) -> list[TriggerDispatch]:
        """Fire every recurring trigger whose interval has elapsed.

        Firing a recurring trigger is a normal delivery: it goes through the same
        gates, so a recurring trigger whose scope was withdrawn stops creating
        jobs. ``last_fired`` advances only after a successful delivery, so a crash
        between fire and record does not lose the moment -- the next tick retries.
        """
        now = self.clock()
        out: list[TriggerDispatch] = []
        manual = ManualTriggerSource()
        for trig in recurring:
            if not trig.due(now):
                continue
            raw = json.dumps(trig.payload).encode("utf-8")
            try:
                req = manual.authenticate(raw, {}, now=now)
            except TriggerError as exc:
                out.append(self._reject_anonymous(f"recurring:{trig.trigger_id}", str(exc)))
                trig.last_fired = now
                continue
            req.source = "recurring"
            req.delivery_id = f"rec-{trig.trigger_id}-{int(now)}"
            # A recurring trigger is a *fresh* run every interval, not a resend of
            # the first: give each fire its own idempotency key so payload dedupe
            # does not turn a recurring trigger into a fire-once trigger. The
            # delivery id (which embeds the fire time) already prevents a replay of
            # the same moment from creating a second job.
            req.payload_sha256 = hashlib.sha256(
                (req.payload_sha256 + req.delivery_id).encode("utf-8")
            ).hexdigest()
            dispatch = self.handle(_PreparedSource(req), raw, {})
            if dispatch.state in (TriggerState.ACCEPTED, TriggerState.DUPLICATE):
                trig.last_fired = now
            out.append(dispatch)
        return out


class _PreparedSource(TriggerSource):
    """Wrap an already-built request so ``tick`` can reuse ``handle`` unchanged."""

    name = "prepared"

    def __init__(self, req: TriggerRequest) -> None:
        self._req = req

    def authenticate(self, raw: bytes, headers: dict, *,
                     now: Optional[float] = None) -> TriggerRequest:
        return self._req
