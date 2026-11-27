"""Opportunity intake: turn read-only mail into *candidates*, never into authority.

This is the integration point between Gmail and BLACKHEART's existing workflow. Its
job is narrow and deliberately so:

  1. **Deduplicate** messages and updates by a stable content key, so a re-sent
     announcement or a re-read page does not create duplicate opportunities.
  2. **Extract** structured opportunities (program, claim kind, entities, links,
     trust) while retaining the message id and a content hash for provenance.
  3. **Emit a candidate**, and -- if a trigger receiver is supplied -- deliver a
     *manual-kind* trigger payload through the **existing**
     :class:`blackheart.triggers.TriggerReceiver`. There is no second scheduler and
     no parallel authorization system.

Three absolute rules, enforced in code:

  * An email can create an opportunity *candidate*. It can **never** create
    authorization. The trigger payload carries a ``scope_reference`` that the
    receiver resolves against BLACKHEART's own authorization records; a message's
    claim is inert unless an operator has independently recorded the scope.
  * No automatic sending, forwarding, submission, or announcement. This module has
    no such operation.
  * A flagged (injection/authority-override) message is still *recorded* as data but
    is marked hazardous, so the operator sees it and the engine never acts on it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..models import utcnow
from .trust import ClaimKind, EmailClaim, MessageFacts, SourceTrust, classify_message


@dataclass
class Opportunity:
    """A candidate research opportunity extracted from one message. Data only."""

    opportunity_id: str
    message_id: str
    program: str
    claim_kinds: list[str]
    entities: list[str]
    links: list[str]
    trust: SourceTrust
    flagged: bool
    flag_kinds: list[str]
    subject: str = ""
    #: The content key used for dedupe (stable across a re-read of the same message).
    content_key: str = ""
    created_at: str = field(default_factory=utcnow)
    #: True only when the message asserts an authorization-affecting change. This is
    #: a *review signal*; it does NOT change authorization.
    needs_scope_review: bool = False

    def to_dict(self) -> dict:
        return {
            "opportunity_id": self.opportunity_id, "message_id": self.message_id,
            "program": self.program, "claim_kinds": list(self.claim_kinds),
            "entities": list(self.entities), "links": list(self.links),
            "trust": self.trust.value, "flagged": self.flagged,
            "flag_kinds": list(self.flag_kinds), "subject": self.subject,
            "content_key": self.content_key, "created_at": self.created_at,
            "needs_scope_review": self.needs_scope_review,
            "note": "a candidate opportunity; never an authorization",
        }


#: Claim kinds that, if true, would affect authorization or scope. Their *arrival*
#: is a review signal only.
_SCOPE_AFFECTING = {
    ClaimKind.SCOPE_ADDED, ClaimKind.SCOPE_REMOVED, ClaimKind.POLICY_CHANGE,
    ClaimKind.NEW_PROGRAM, ClaimKind.INVITATION,
}


def _content_key(facts: MessageFacts, body: str) -> str:
    """A stable dedupe key: sender + subject + a hash of the normalised body."""
    blob = "\x1f".join([
        facts.sender_domain.lower(), facts.subject.strip().lower(),
        hashlib.sha256(" ".join(body.split()).encode("utf-8")).hexdigest(),
    ])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


class OpportunityIntake:
    """Extract, deduplicate, and (optionally) deliver opportunity candidates."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self.opportunities: list[Opportunity] = []

    def ingest(self, facts: MessageFacts, body: str, *, html: str = "",
               program: str = "") -> Optional[Opportunity]:
        """Turn one message into an opportunity, or ``None`` if it is a duplicate.

        Duplicates are recognised by content key, so a re-read, a re-send, or a
        paginated re-list never creates a second opportunity.
        """
        key = _content_key(facts, body)
        if key in self._seen:
            return None
        self._seen.add(key)

        claims: list[EmailClaim] = classify_message(facts, body, html=html)
        kinds = sorted({c.kind.value for c in claims})
        entities = sorted({e for c in claims for e in c.entities})
        flag_kinds = sorted({k for c in claims for k in c.flag_kinds})
        needs_scope_review = any(
            c.kind in _SCOPE_AFFECTING and not c.flagged for c in claims
        )
        opp = Opportunity(
            opportunity_id="opp-" + key[:12],
            message_id=facts.message_id,
            program=program or self._infer_program(facts, claims),
            claim_kinds=kinds,
            entities=entities,
            links=list(facts.links),
            trust=facts.trust(),
            flagged=bool(flag_kinds),
            flag_kinds=flag_kinds,
            subject=facts.subject,
            content_key=key,
            needs_scope_review=needs_scope_review,
        )
        self.opportunities.append(opp)
        return opp

    def ingest_many(self, items: Iterable[tuple[MessageFacts, str]],
                    *, program: str = "") -> list[Opportunity]:
        out: list[Opportunity] = []
        for facts, body in items:
            opp = self.ingest(facts, body, program=program)
            if opp is not None:
                out.append(opp)
        return out

    @staticmethod
    def _infer_program(facts: MessageFacts, claims: list[EmailClaim]) -> str:
        domain = facts.sender_domain
        if domain:
            # A program name from the sender domain's second-level label.
            parts = domain.split(".")
            if len(parts) >= 2:
                return parts[-2]
        return "unknown-program"

    # -- delivery into the existing trigger path ----------------------- #

    def to_trigger_payload(self, opp: Opportunity, *,
                           scope_reference: str) -> dict:
        """Build a manual-kind trigger payload that the *existing* receiver gates.

        The payload is a *request for review*, not an authorization. It carries the
        operator-supplied ``scope_reference`` -- which the receiver resolves against
        BLACKHEART's own authorization records -- plus the opportunity as context.
        A flagged opportunity is delivered with ``priority`` 0 and a note, so it is
        queued for human review rather than actioned.
        """
        if opp.flagged:
            note = (
                "UNTRUSTED-EMAIL-FLAGGED: message resembles an instruction override; "
                "review before any action. " + "; ".join(opp.flag_kinds)
            )
        else:
            note = "opportunity from read-only email intake (data only)"
        return {
            # ``kind`` is the *job* kind the receiver executes, not the delivery
            # source (which is ``manual``); the closed schema allows only these.
            "kind": "investigate",
            "target": opp.program,
            "asset": opp.program,
            "scope_reference": scope_reference,
            "hypothesis": {
                "source": "gmail-intake",
                "opportunity_id": opp.opportunity_id,
                "claim_kinds": list(opp.claim_kinds),
                "entities": list(opp.entities),
                "links": list(opp.links),
                "trust": opp.trust.value,
                "flagged": opp.flagged,
            },
            "priority": 0 if opp.flagged else 1,
            "note": note,
        }

    def deliver(self, opp: Opportunity, receiver, *,
                scope_reference: str) -> object:
        """Deliver the opportunity through the existing :class:`TriggerReceiver`.

        Delegates *entirely* to :meth:`TriggerReceiver.handle`: authentication,
        dedupe, rate limit, authorization and job creation are all the receiver's,
        unchanged. This is the whole integration -- there is no second scheduling
        or authorization path, and the receiver still resolves ``scope_reference``
        against BLACKHEART's own authorization records.
        """
        import json

        from ..triggers import ManualTriggerSource

        payload = self.to_trigger_payload(opp, scope_reference=scope_reference)
        raw = json.dumps(payload).encode("utf-8")
        return receiver.handle(ManualTriggerSource(), raw, {})
