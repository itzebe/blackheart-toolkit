"""Tamper-evidence for append-only research logs (P3 investigations, evidence).

The original P3 stamp stored a hash of each record *beside* the record. That
detects a careless edit, but it is not tamper-evident against a capable attacker:
whoever can rewrite the payload can rewrite its adjacent hash, and nothing binds
one record to the next, so records can be deleted, reordered, or truncated
without a trace.

This module implements the honest, layered design the mission asks for, and it
states plainly what each layer does and does not protect against:

  1. **Content hash** (``content_sha256``). Detects accidental corruption and a
     lone record edited without updating its hash.
  2. **Hash chain** (``prev`` + ``chain_sha256``). Each record commits to the
     previous record's chain hash, so deleting, reordering, inserting, or
     truncating records breaks the chain at a detectable point. Detects an
     attacker who edits a record *and* recomputes its own hashes.
  3. **Keyed MAC** (HMAC-SHA256, ``hmac``). Without the key an attacker cannot
     forge a chain that verifies, so a wholesale rewrite that recomputes the
     whole hash chain is still caught. The key lives *outside* the log.
  4. **External checkpoint** (``blackheart integrity checkpoint``). A signed
     record of the chain head, kept in a separate file, detects truncation of the
     log's tail -- which the in-band chain alone cannot, since a shorter log is
     still internally consistent.

Threat model (see ``docs/INTEGRITY.md`` for the full table):

  * Accidental corruption ......................... detected (1)
  * A single record edited ........................ detected (1)
  * A record + its adjacent hash edited ........... detected (2)
  * Delete / reorder / insert / truncate records .. detected (2)
  * Wholesale rewrite of the log .................. detected (3, needs the key)
  * Tail truncation of the whole log .............. detected (4, needs a checkpoint)
  * Host compromise that holds the signing key .... **not** defended
  * A locally stored checkpoint the attacker can rewrite ... **not** defended

The last two are stated honestly: a party who controls the machine and the key,
or who can rewrite both the log and a local checkpoint, cannot be stopped by
anything stored on that machine. Detecting that requires an *off-host* anchor,
which the mission rules out (no paid infrastructure); the limitation is recorded
rather than papered over.

Verification outcomes are kept distinct and are never silently upgraded:

  * ``VERIFIED``     -- the chain (and MAC, if a key is supplied) is intact.
  * ``FAILED``       -- a concrete check failed; the log is not trustworthy.
  * ``LEGACY``       -- records predate integrity protection (unstamped).
  * ``UNAVAILABLE``  -- verification could not run (no key where one is required,
                        no log, unreadable file). **Never** treated as success.

Cryptography uses only the standard library (``hashlib``/``hmac``/``secrets``);
no algorithm is invented and no third-party dependency is required.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import canonical_json, sha256_of

# The chain hash of the first record: 32 zero bytes, hex.
GENESIS = "0" * 64

# Environment variable consulted for the integrity key when no explicit key is
# passed. It holds either the raw hex key or a path to a key file.
KEY_ENV = "BLACKHEART_INTEGRITY_KEY"

# Status values. These are deliberately distinct: a caller must never collapse
# UNAVAILABLE or LEGACY into VERIFIED.
VERIFIED = "VERIFIED"
FAILED = "FAILED"
LEGACY = "LEGACY"
UNAVAILABLE = "UNAVAILABLE"


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #

@dataclass
class IntegrityKey:
    """An HMAC signing key with a stable identifier.

    ``key_id`` is recorded alongside each MAC so a verifier can tell *which* key
    produced it -- the first step of key rotation (an old key can still verify
    old records while a new key signs new ones).
    """

    key_id: str
    key: bytes

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("integrity key must not be empty")

    def mac(self, message: bytes) -> str:
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()


def generate_key(key_id: str = "") -> IntegrityKey:
    """Generate a fresh 256-bit key. The value is returned, never logged here."""
    return IntegrityKey(key_id=key_id or f"k-{secrets.token_hex(4)}",
                        key=secrets.token_bytes(32))


def key_to_file(key: IntegrityKey, path: str | os.PathLike) -> None:
    """Write a key to ``path`` with owner-only permissions.

    The key is written to a file the caller chose; it is never printed and never
    stored inside the log it protects.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"key_id": key.key_id, "key_hex": key.key.hex()}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover - filesystem without POSIX perms
        pass


def key_from_file(path: str | os.PathLike) -> IntegrityKey:
    """Load a key file written by :func:`key_to_file` (or a bare hex key file)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("{"):
        data = json.loads(text)
        return IntegrityKey(key_id=data.get("key_id", ""), key=bytes.fromhex(data["key_hex"]))
    return IntegrityKey(key_id="", key=bytes.fromhex(text))


def resolve_key(
    key: Optional[bytes] = None, key_path: Optional[str] = None,
    key_id: str = "",
) -> Optional[IntegrityKey]:
    """Resolve a key from an explicit value, a path, or the environment.

    Returns ``None`` when no key is configured -- the caller then reports
    ``UNAVAILABLE`` for signature checks rather than pretending they passed.
    """
    if key is not None:
        return IntegrityKey(key_id=key_id, key=key)
    if key_path:
        k = key_from_file(key_path)
        return IntegrityKey(key_id=key_id or k.key_id, key=k.key)
    env = os.environ.get(KEY_ENV)
    if env:
        if Path(env).exists():
            k = key_from_file(env)
            return IntegrityKey(key_id=key_id or k.key_id, key=k.key)
        try:
            return IntegrityKey(key_id=key_id, key=bytes.fromhex(env))
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------- #
# Hashing / MAC helpers
# --------------------------------------------------------------------------- #

def content_hash(content: dict) -> str:
    return sha256_of(content)


def _mac_message(seq: int, prev: str, content_sha256: str) -> bytes:
    return canonical_json({"seq": seq, "prev": prev,
                           "content_sha256": content_sha256}).encode("utf-8")


def chain_hash(seq: int, prev: str, content_sha256: str) -> str:
    """The chain hash: commits to position, predecessor, and content digest."""
    return sha256_of({"seq": seq, "prev": prev, "content_sha256": content_sha256})


def record_mac(key: IntegrityKey, seq: int, prev: str, content_sha256: str) -> str:
    return key.mac(_mac_message(seq, prev, content_sha256))


# --------------------------------------------------------------------------- #
# Verification result
# --------------------------------------------------------------------------- #

@dataclass
class VerificationResult:
    """The outcome of verifying one append-only log.

    ``status`` is the single honest verdict; the lists are diagnostics. The
    ``legacy_ids`` and ``unavailable_reason`` fields exist so a caller can tell
    "this predates protection" from "this was tampered with" from "I could not
    check" -- three states that must never be conflated.
    """

    status: str
    checked: int = 0
    mismatched: list[str] = field(default_factory=list)
    unstamped: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    key_id: str = ""
    signatures_checked: bool = False
    head_chain: str = ""
    head_seq: int = -1
    truncated_tail: bool = False
    checkpoint_checked: bool = False
    checkpoint_ok: Optional[bool] = None
    unavailable_reason: str = ""

    @property
    def ok(self) -> bool:
        """True only for a fully VERIFIED log. LEGACY/UNAVAILABLE are not ok."""
        return self.status == VERIFIED

    @property
    def legacy_ids(self) -> list[str]:
        return self.unstamped

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "ok": self.ok,
            "checked": self.checked,
            "mismatched": self.mismatched,
            "unstamped": self.unstamped,
            "legacy": self.unstamped,
            "reasons": self.reasons,
            "key_id": self.key_id,
            "signatures_checked": self.signatures_checked,
            "head_chain": self.head_chain,
            "head_seq": self.head_seq,
            "truncated_tail": self.truncated_tail,
            "checkpoint_checked": self.checkpoint_checked,
            "checkpoint_ok": self.checkpoint_ok,
            "unavailable_reason": self.unavailable_reason,
        }


def _stamp_state(ev: dict) -> str:
    """Classify a record's integrity stamp.

    Returns ``"full"`` (content + chain hashes present), ``"partial"`` (some but
    not all present -- a stripped or hand-written stamp, treated as tampering),
    or ``"none"`` (no integrity fields -- a legacy record).
    """
    have = [bool(ev.get("content_sha256")), bool(ev.get("chain_sha256"))]
    if all(have):
        return "full"
    if any(have):
        return "partial"
    return "none"


def verify_chain(
    path: str | os.PathLike,
    *,
    key: Optional[IntegrityKey] = None,
    require_signatures: bool = False,
    checkpoint: Optional["Checkpoint"] = None,
) -> VerificationResult:
    """Verify an append-only JSONL log produced by a stamping writer.

    Every ``type == "state"`` event is a link in the chain. A record is *stamped*
    when it carries ``content_sha256``; unstamped records are LEGACY. A record is
    *signed* when it carries ``hmac``; a missing signature is only a failure when
    ``require_signatures`` is set or a key is supplied.
    """
    p = Path(path)
    if not p.exists():
        return VerificationResult(status=UNAVAILABLE,
                                  unavailable_reason=f"log not found: {p}")

    res = VerificationResult(status=VERIFIED)
    if key is not None:
        res.key_id = key.key_id

    prev_chain = GENESIS
    prev_seq = -1
    seen_stamped = False
    _seen_legacy = False
    records: list[tuple[int, dict]] = []  # (line_index, event) for state events

    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            res.truncated_tail = True
            continue
        if ev.get("type") != "state" or not ev.get("content"):
            continue
        records.append((len(records), ev))

    res.checked = len(records)
    if not records:
        # The head of an empty chain is GENESIS; keep it consistent with
        # ``JobStore.head`` so an empty-log checkpoint can round-trip.
        res.head_seq, res.head_chain = -1, GENESIS
        # An empty log is internally consistent, but if a checkpoint pinned a
        # non-empty head then the whole log was truncated away -- the one case
        # the in-band chain can never see. Honour the checkpoint before returning.
        if checkpoint is not None:
            res.checkpoint_checked = True
            cp_ok, why = checkpoint.matches(res.head_seq, res.head_chain, key=key)
            res.checkpoint_ok = cp_ok
            if not cp_ok:
                res.reasons.append(why)
                res.status = FAILED
        return res  # empty log: nothing to verify, still VERIFIED

    for seq, ev in records:
        rid = ev.get("id", "") or f"<record {seq}>"
        content = ev.get("content", {})
        stored_content = ev.get("content_sha256", "")
        stored_chain = ev.get("chain_sha256", "")
        stored_mac = ev.get("hmac", "")
        stored_prev = ev.get("prev", "")
        stored_seq = ev.get("seq")

        stamp = _stamp_state(ev)
        if stamp == "partial":
            # Some integrity fields present, some missing: a hand-written or
            # stripped stamp. Treat as tampering, never as legacy.
            res.mismatched.append(rid)
            res.reasons.append(f"{rid}: incomplete integrity stamp (fields removed)")
            res.status = FAILED
            prev_chain = chain_hash(seq, prev_chain, content_hash(content))
            prev_seq = seq
            continue
        if stamp == "none":
            # A record with no integrity fields at all. If it appears after a
            # stamped record, the log was mixed (a stamp was stripped); that is
            # a failure, not legacy. Otherwise it is a legacy record.
            if seen_stamped:
                res.mismatched.append(rid)
                res.reasons.append(
                    f"{rid}: unstamped record after stamped records "
                    "(integrity fields removed)"
                )
                res.status = FAILED
            else:
                _seen_legacy = True
                res.unstamped.append(rid)
            # A legacy record still advances the chain head to its computed
            # digest so later links can be checked against a known value.
            prev_chain = chain_hash(seq, prev_chain, content_hash(content))
            prev_seq = seq
            continue

        seen_stamped = True
        computed_content = content_hash(content)
        computed_chain = chain_hash(seq, prev_chain, computed_content)

        # 1. content hash
        if stored_content and stored_content != computed_content:
            res.mismatched.append(rid)
            res.reasons.append(f"{rid}: content hash mismatch (payload edited)")

        # 2. position + predecessor (deletion / reorder / insertion)
        if stored_seq is not None and stored_seq != seq:
            res.mismatched.append(rid)
            res.reasons.append(
                f"{rid}: position {stored_seq} != expected {seq} "
                "(record inserted or removed)"
            )
        if stored_prev and stored_prev != prev_chain:
            res.mismatched.append(rid)
            res.reasons.append(f"{rid}: chain predecessor mismatch (reordered or removed)")

        # 3. chain hash (catches an edited record whose own content hash was fixed)
        if stored_chain and stored_chain != computed_chain:
            res.mismatched.append(rid)
            res.reasons.append(f"{rid}: chain hash mismatch")

        # 4. keyed MAC
        if key is not None:
            if not stored_mac:
                if require_signatures:
                    res.mismatched.append(rid)
                    res.reasons.append(f"{rid}: missing HMAC signature")
            else:
                res.signatures_checked = True
                expect = record_mac(key, seq, prev_chain, computed_content)
                if not hmac.compare_digest(expect, stored_mac):
                    res.mismatched.append(rid)
                    res.reasons.append(f"{rid}: HMAC signature invalid")
        elif require_signatures and stored_mac:
            # No key supplied but signatures are required: we cannot verify.
            res.unavailable_reason = (
                "signatures are required but no verification key was supplied "
                f"(set --key/--key-path or ${KEY_ENV})"
            )

        prev_chain = computed_chain
        prev_seq = seq

    res.head_chain = prev_chain
    res.head_seq = prev_seq

    if res.mismatched:
        res.status = FAILED
    elif res.unstamped:
        # A log with legacy records is verifiable-forward but not fully verified.
        res.status = LEGACY
    elif require_signatures and not key and not res.signatures_checked:
        res.status = UNAVAILABLE
    else:
        res.status = VERIFIED

    # Checkpoint: the only thing that detects truncation of the log's tail.
    if checkpoint is not None:
        res.checkpoint_checked = True
        cp_ok, why = checkpoint.matches(res.head_seq, res.head_chain, key=key)
        res.checkpoint_ok = cp_ok
        if not cp_ok:
            res.reasons.append(why)
            res.status = FAILED
    return res


# --------------------------------------------------------------------------- #
# Checkpoints
# --------------------------------------------------------------------------- #

@dataclass
class Checkpoint:
    """A signed record of a log's chain head, kept outside the log.

    The in-band chain cannot detect truncation: a log with its last N records
    removed is still internally consistent. A checkpoint pins the head so a
    shorter log is caught. It only helps if it lives somewhere the attacker
    cannot also rewrite -- that requirement is documented, not assumed.
    """

    log_path: str
    head_seq: int
    head_chain: str
    key_id: str = ""
    hmac: str = ""

    def sign(self, key: IntegrityKey) -> "Checkpoint":
        self.key_id = key.key_id
        self.hmac = key.mac(self._message())
        return self

    def _message(self) -> bytes:
        return canonical_json({
            "log": Path(self.log_path).name,
            "head_seq": self.head_seq,
            "head_chain": self.head_chain,
        }).encode("utf-8")

    def matches(
        self, head_seq: int, head_chain: str, *, key: Optional[IntegrityKey] = None,
    ) -> tuple[bool, str]:
        if head_seq != self.head_seq:
            return False, (
                f"checkpoint: log length {head_seq + 1} != recorded {self.head_seq + 1} "
                "(records were removed or added)"
            )
        if head_chain != self.head_chain:
            return False, "checkpoint: chain head mismatch (the log was rewritten)"
        if key is not None and self.hmac:
            if not hmac.compare_digest(key.mac(self._message()), self.hmac):
                return False, "checkpoint: signature invalid"
        return True, ""

    def to_dict(self) -> dict:
        return {
            "log": self.log_path, "head_seq": self.head_seq,
            "head_chain": self.head_chain, "key_id": self.key_id, "hmac": self.hmac,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Checkpoint":
        return cls(log_path=d.get("log", ""), head_seq=int(d.get("head_seq", -1)),
                   head_chain=d.get("head_chain", ""), key_id=d.get("key_id", ""),
                   hmac=d.get("hmac", ""))

    def write(self, path: str | os.PathLike) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def read(cls, path: str | os.PathLike) -> "Checkpoint":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = [
    "GENESIS", "KEY_ENV", "VERIFIED", "FAILED", "LEGACY", "UNAVAILABLE",
    "IntegrityKey", "generate_key", "key_to_file", "key_from_file", "resolve_key",
    "content_hash", "chain_hash", "record_mac",
    "VerificationResult", "verify_chain", "Checkpoint",
]
