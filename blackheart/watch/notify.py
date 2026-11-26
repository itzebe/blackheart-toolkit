"""Optional email delivery for the bounty watchtower.

Email is a convenience, never a dependency. The monitor runs and reports with
zero credentials; when SMTP is not configured the result says so plainly. The
password is read from the environment and is never logged, echoed, or written to
a report.

Required environment for delivery:

``SMTP_HOST``, ``SMTP_USER``, ``SMTP_PASS``, ``MAIL_TO`` (and optionally
``SMTP_PORT``, ``SMTP_FROM``, ``SMTP_SSL``). The default recipient is the
operator's address, but a message is only sent when every credential is present.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional

from .cycle import CycleReport
from .classify import Status

__all__ = ["EmailConfig", "send_email", "email_cycle_report", "DEFAULT_RECIPIENT"]

DEFAULT_RECIPIENT = "jonathanebi05@gmail.com"


@dataclass(frozen=True)
class EmailConfig:
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    sender: str = ""
    use_ssl: bool = False

    @classmethod
    def from_env(cls) -> "EmailConfig":
        host = os.environ.get("SMTP_HOST", "").strip()
        user = os.environ.get("SMTP_USER", "").strip()
        password = os.environ.get("SMTP_PASS", "")
        port = _int(os.environ.get("SMTP_PORT", "465" if _truthy(os.environ.get("SMTP_SSL", "")) else "587"), 587)
        return cls(
            host=host,
            port=port,
            user=user,
            password=password,
            sender=os.environ.get("SMTP_FROM", "").strip() or user,
            use_ssl=_truthy(os.environ.get("SMTP_SSL", "")) or port == 465,
        )

    @property
    def configured(self) -> bool:
        return bool(self.host and self.user and self.password)


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def send_email(
    subject: str,
    body: str,
    *,
    to: str = "",
    config: Optional[EmailConfig] = None,
    timeout: int = 25,
) -> dict:
    """Send one plain-text email. Returns an honest result, never raises."""
    cfg = config or EmailConfig.from_env()
    recipient = (to or os.environ.get("MAIL_TO", "") or DEFAULT_RECIPIENT).strip()
    if not cfg.configured:
        return {
            "configured": False,
            "sent": False,
            "to": recipient,
            "reason": (
                "SMTP not configured; set SMTP_HOST, SMTP_USER, SMTP_PASS and MAIL_TO "
                "as repository secrets to enable delivery"
            ),
        }
    msg = EmailMessage()
    msg["From"] = cfg.sender or cfg.user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        if cfg.use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=context) as smtp:
                smtp.login(cfg.user, cfg.password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(cfg.user, cfg.password)
                smtp.send_message(msg)
    except Exception as exc:  # noqa: BLE001 -- delivery failure must not fail the cycle
        # Never include the password or the raw SMTP transcript.
        return {
            "configured": True,
            "sent": False,
            "to": recipient,
            "reason": f"{type(exc).__name__}: delivery failed",
        }
    return {"configured": True, "sent": True, "to": recipient, "reason": "sent"}


def email_cycle_report(report: CycleReport, *, to: str = "") -> dict:
    """Email a cycle only when it contains something worth interrupting for."""
    interesting = [
        l for l in report.leads
        if l.status in (
            Status.NEW_ACTIONABLE_CHANGE,
            Status.INVESTIGATE,
            Status.POLICY_BLOCKED,
        )
    ]
    if not interesting and not report.failures:
        return {
            "configured": EmailConfig.from_env().configured,
            "sent": False,
            "to": to or os.environ.get("MAIL_TO", "") or DEFAULT_RECIPIENT,
            "reason": "no actionable change or source failure; no email sent",
        }
    subject = (
        f"[BLACKHEART] {report.cycle_id}: "
        f"{len(interesting)} lead(s), {len(report.failures)} source failure(s)"
    )
    body = report_body(report)
    return send_email(subject, body, to=to)


def report_body(report: CycleReport) -> str:
    c = report.counts()
    lines = [
        f"BLACKHEART bounty watch cycle {report.cycle_id}",
        f"Started: {report.started_at} UTC",
        f"Targets: {c['targets']}  Events: {c['events']}  Deduped: {c['deduped']}",
        f"Actionable: {c['NEW ACTIONABLE CHANGE']}  Investigate: {c['INVESTIGATE']}  "
        f"Policy-blocked: {c['POLICY BLOCKED']}  Inaccessible: {c['SOURCE INACCESSIBLE']}",
        "",
    ]
    for lead in report.leads:
        if lead.status in (Status.NEW_ACTIONABLE_CHANGE, Status.INVESTIGATE, Status.POLICY_BLOCKED):
            lines += [
                f"[{lead.status}] {lead.target.slug} / {lead.event.component} "
                f"(score {lead.score}/100)",
                f"  {lead.event.summary}",
            ]
            if lead.policy_blocked:
                lines.append(f"  blocked: {lead.block_reason}")
            lines += [f"  source: {u}" for u in lead.event.evidence_urls[:3]]
            lines.append("")
    if report.failures:
        lines.append("Source failures (gaps, not clean results):")
        for slug, failure in report.failures[:30]:
            lines.append(f"  - {slug}: {failure}")
        lines.append("")
    lines += [
        "A change is a lead, not a confirmed vulnerability.",
        "No submission, program contact, or mainnet transaction is authorized by this report.",
        "",
    ]
    return "\n".join(lines)
