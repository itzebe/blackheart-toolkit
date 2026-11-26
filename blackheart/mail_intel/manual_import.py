"""Manual-import fallback: opportunity intake without any OAuth dependency.

When a live Gmail integration is unavailable -- which it is by default, because the
read-only Gmail scope is a Google *restricted* scope requiring verification -- the
operator can still bring opportunity intelligence in by pasting or exporting the
message text. This is a first-class path, not a degraded one:

  * The imported text goes through the **same trust boundary**
    (:mod:`blackheart.mail_intel.trust`) as a live message: it is untrusted, is
    scanned for injection, and produces claims-not-authority.
  * The same dedupe applies, so an import that duplicates an earlier message is
    recognised.
  * The operator supplies the sender and authentication state explicitly, and the
    importer records that provenance honestly (an imported message has no DKIM
    verification behind it, so it is ``UNVERIFIED_SENDER`` unless the operator
    attests otherwise).

The importer reads a JSON or a simple ``From:``/``Subject:``/body file. It never
executes anything in the message and never treats a link as safe.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .intake import Opportunity, OpportunityIntake
from .trust import MessageFacts, sender_domain


@dataclass
class ImportedMessage:
    """An operator-imported message and the provenance they attest to."""

    body: str
    sender: str = ""
    subject: str = ""
    message_id: str = ""
    #: The operator may assert the sender was authenticated *out of band*. Default
    #: is False: an import is unverified unless explicitly attested.
    authenticated: bool = False
    html: str = ""
    errors: list[str] = field(default_factory=list)

    def to_facts(self) -> MessageFacts:
        return MessageFacts(
            message_id=self.message_id or ("import-" + str(abs(hash(self.body)) % 10**12)),
            sender=self.sender, sender_domain=sender_domain(self.sender),
            authenticated=bool(self.authenticated and self.sender),
            subject=self.subject,
        )


class ManualImporter:
    """Parse an exported/pasted message into an :class:`ImportedMessage`."""

    def parse_text(self, text: str) -> ImportedMessage:
        """Parse ``From:``/``Subject:`` header lines followed by a body.

        Header parsing stops at the first blank line; everything after is body. A
        text with no recognisable headers is treated as an all-body import, and that
        absence is recorded as an error so the operator knows the provenance is thin.
        """
        lines = text.splitlines()
        sender = subject = message_id = ""
        idx = 0
        errors: list[str] = []
        for i, line in enumerate(lines):
            low = line.lower()
            if not line.strip():
                idx = i + 1
                break
            if low.startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif low.startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            elif low.startswith("message-id:"):
                message_id = line.split(":", 1)[1].strip()
            elif ":" not in line:
                idx = i
                break
            idx = i + 1
        body = "\n".join(lines[idx:])
        if not subject and not sender:
            errors.append("no From:/Subject: header found; importing as raw body only")
        return ImportedMessage(body=body, sender=sender, subject=subject,
                               message_id=message_id, errors=errors)

    def parse_json(self, text: str) -> ImportedMessage:
        """Parse a JSON message export."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ImportedMessage(body="", errors=[f"invalid JSON: {exc.msg}"])
        if not isinstance(data, dict):
            return ImportedMessage(body="", errors=["JSON export is not an object"])
        return ImportedMessage(
            body=str(data.get("body", "")),
            sender=str(data.get("from", data.get("sender", ""))),
            subject=str(data.get("subject", "")),
            message_id=str(data.get("id", data.get("message_id", ""))),
            authenticated=bool(data.get("authenticated", False)),
            html=str(data.get("html", "")),
        )

    def ingest(self, importer: OpportunityIntake, message: ImportedMessage, *,
               program: str = "") -> Optional[Opportunity]:
        """Feed an imported message through the same intake as a live one."""
        if not message.body.strip():
            return None
        return importer.ingest(message.to_facts(), message.body,
                               html=message.html, program=program)
