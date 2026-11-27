"""Chrome VRP engagement: exploit-first, falsifiable boundary probes.

This is a *distinct* engagement from the earlier GitHub Actions scan. It runs
against a real, released Chromium build we control locally, exercises one
security invariant per probe, and records every hypothesis and its disposition
in BLACKHEART's ledger and content-addressed evidence store.

Design rules taken from the mission and the Chrome VRP FAQ:

* One invariant per probe, so a violation is unambiguous.
* A probe that finds no violation is recorded as DISPROVEN -- that is a real
  result, and the ledger stops the hypothesis being re-run as if it were new.
* A probe that finds a violation is only a *candidate*: it is recorded as
  UNCONFIRMED pending independent verification, never announced as a finding.
* Findings must reproduce on a released build with no non-standard flags.

The invariants here are the browser's own enforcement of its boundaries. If they
hold (they do, on a maintained release), that is the honest, useful result: it
tells us where *not* to spend the next hour, and it is reproducible evidence.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..evidence import EvidenceStore
from ..ledger import EngagementLedger
from ..models import Classification
from . import probes
from .harness import Chromium, ChromeNotFound, serve_origins

ENGAGEMENT = "chrome-vrp"
DEFAULT_ROOT = Path("research/private/chrome-vrp")


@dataclass
class Hypothesis:
    """One falsifiable claim about a Chromium security boundary."""

    id: str
    title: str
    category: str
    invariant: str
    run: Callable[[Chromium, object, Path], dict]
    references: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Probe runners -- each returns {"observations": [...], "violations": [...]}
# --------------------------------------------------------------------------- #

def _run_sop_read(chromium: Chromium, pair, workdir: Path) -> dict:
    (pair.root / "sop.html").write_text(probes.SOP_READ, encoding="utf-8")
    (pair.root / "child.html").write_text(
        "<!doctype html><h1>cross-origin child</h1>", encoding="utf-8"
    )
    url = f"{pair.url_a}/sop.html?cross={pair.url_b}/child.html"
    run = chromium.run_probe(url)
    r = run.result
    return {
        "observations": [
            f"contentDocument across origins: {r.get('details', {}).get('contentDocument')}",
            f"location access threw: {r.get('details', {}).get('location_threw')}",
            f"window.document access threw: {r.get('details', {}).get('window_document_threw')}",
        ],
        "violations": list(r.get("violations", [])),
        "runs": [run.to_dict()],
    }


def _run_isolation(chromium: Chromium, pair, workdir: Path) -> dict:
    (pair.root / "isolated.html").write_text(probes.ISOLATED_POSITIVE, encoding="utf-8")
    (pair.root / "isolated.html.headers").write_text(
        probes.ISOLATED_HEADERS, encoding="utf-8"
    )
    (pair.root / "plain.html").write_text(probes.ISOLATED_NEGATIVE, encoding="utf-8")

    pos = chromium.run_probe(f"{pair.url_a}/isolated.html")
    neg = chromium.run_probe(f"{pair.url_a}/plain.html")
    violations = list(pos.result.get("violations", [])) + list(neg.result.get("violations", []))
    return {
        "observations": [
            f"isolated page crossOriginIsolated={pos.result.get('details', {}).get('crossOriginIsolated')}",
            f"isolated page SharedArrayBuffer={pos.result.get('details', {}).get('shared_array_buffer')}",
            f"plain page crossOriginIsolated={neg.result.get('details', {}).get('crossOriginIsolated')}",
            f"plain page SharedArrayBuffer={neg.result.get('details', {}).get('shared_array_buffer')}",
        ],
        "violations": violations,
        "runs": [pos.to_dict(), neg.to_dict()],
    }


def _run_postmessage(chromium: Chromium, pair, workdir: Path) -> dict:
    (pair.root / "pm_top.html").write_text(probes.POSTMESSAGE_TOP, encoding="utf-8")
    (pair.root / "pm_child.html").write_text(probes.POSTMESSAGE_CHILD, encoding="utf-8")
    url = (f"{pair.url_a}/pm_top.html?child={pair.url_b}/pm_child.html"
           f"&child_origin={pair.url_b}")
    run = chromium.run_probe(url)
    r = run.result
    return {
        "observations": [
            f"messages received: {r.get('details', {}).get('messages')}",
            f"declared child origin: {r.get('details', {}).get('child_origin')}",
        ],
        "violations": list(r.get("violations", [])),
        "runs": [run.to_dict()],
    }


def _run_process_model(chromium: Chromium, pair, workdir: Path) -> dict:
    """Read the live process list via CDP; the renderer boundary must be real.

    The renderer-to-browser privilege boundary only exists if the renderer is a
    *separate OS process* from the browser, GPU, and network service. If a build
    silently ran single-process, that boundary would not exist at all -- so this
    is the first thing to verify, and it is read from the running browser rather
    than assumed.
    """
    info = chromium.process_info().get("processInfo", [])
    kinds = sorted({p.get("type", "?") for p in info})
    renderers = [p for p in info if p.get("type") == "renderer"]
    violations = []
    for required in ("browser", "renderer", "GPU"):
        if required not in kinds:
            violations.append(f"process type '{required}' not present in the process list")
    if not renderers:
        violations.append("no renderer process was created")
    return {
        "observations": [
            f"process types: {kinds}",
            f"renderer processes: {len(renderers)}",
            f"total processes: {len(info)}",
        ],
        "violations": violations,
        "runs": [{"processInfo": info}],
    }


HYPOTHESES: list[Hypothesis] = [
    Hypothesis(
        id="H1",
        title="Same-Origin Policy denies cross-origin DOM reads",
        category="site-isolation",
        invariant=(
            "For a cross-origin iframe, contentDocument is null, and reads of "
            "location/document throw SecurityError."
        ),
        run=_run_sop_read,
        references=["https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/"],
    ),
    Hypothesis(
        id="H2",
        title="Cross-origin isolation (COOP+COEP) gates SharedArrayBuffer",
        category="isolation",
        invariant=(
            "crossOriginIsolated is true and SharedArrayBuffer is available only "
            "when COOP: same-origin and COEP: require-corp are served."
        ),
        run=_run_isolation,
        references=[
            "https://web.dev/articles/coop-coep",
            "https://developer.mozilla.org/en-US/docs/Web/API/Window/crossOriginIsolated",
        ],
    ),
    Hypothesis(
        id="H3",
        title="postMessage reports the real, non-spoofable sender origin",
        category="origin-integrity",
        invariant="MessageEvent.origin equals the sender's true origin.",
        run=_run_postmessage,
        references=["https://html.spec.whatwg.org/multipage/web-messaging.html"],
    ),
    Hypothesis(
        id="H4",
        title="The renderer runs in a separate OS process from the browser",
        category="process-model",
        invariant=(
            "CDP SystemInfo reports distinct browser, renderer, and GPU "
            "processes (the renderer-to-browser privilege boundary exists)."
        ),
        run=_run_process_model,
        references=[
            "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md",
            "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md",
        ],
    ),
]


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

def _disposition(violations: list[str]) -> str:
    """Map a probe result to a hypothesis status (BLACKHEART's classification).

    A violation is only a *candidate* -- NEEDS_MORE_EVIDENCE -- because it still
    has to survive independent verification before it may be called a finding.
    No violation means the invariant held: FALSE_POSITIVE, which is the ledger's
    terminal "disproven, do not re-run as new" status.
    """
    if violations:
        return Classification.NEEDS_MORE_EVIDENCE.value
    return Classification.FALSE_POSITIVE.value


def run_engagement(
    root: Path | str = DEFAULT_ROOT,
    *,
    binary: Optional[str] = None,
    only: Optional[list[str]] = None,
    chromium: Optional[Chromium] = None,
) -> dict:
    """Run the Chrome VRP hypotheses and record everything.

    Returns a summary dict. Every value comes from a real browser run or is
    derived from one; nothing is fabricated.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceStore(root / "evidence")
    ledger = EngagementLedger(root / "ledger", ENGAGEMENT)
    probes_dir = root / "probes"
    probes_dir.mkdir(parents=True, exist_ok=True)

    chromium = chromium or Chromium(binary)
    selected = [h for h in HYPOTHESES if not only or h.id in only]

    results: list[dict] = []
    with serve_origins(probes_dir) as pair:
        for h in selected:
            ledger.add_hypothesis(h.id, h.title, h.invariant)
            try:
                outcome = h.run(chromium, pair, probes_dir)
            except Exception as exc:  # a harness failure is not a finding
                ledger.set_status(h.id, Classification.NEEDS_MORE_EVIDENCE.value,
                                  f"harness error: {exc}")
                results.append({
                    "id": h.id, "title": h.title, "category": h.category,
                    "status": Classification.NEEDS_MORE_EVIDENCE.value,
                    "violations": [], "observations": [f"harness error: {exc}"],
                })
                continue

            status = _disposition(outcome["violations"])
            ev = evidence.put_json(
                {"hypothesis": h.id, "title": h.title, "invariant": h.invariant,
                 "browser": chromium.version, **outcome},
                kind="chrome-vrp-probe",
                description=f"{h.id}: {h.title}",
            )
            ledger.record_evidence(h.id, ev.evidence_id)
            ledger.set_status(h.id, status,
                              "; ".join(outcome["violations"]) or "invariant held")
            results.append({
                "id": h.id, "title": h.title, "category": h.category,
                "status": status,
                "violations": outcome["violations"],
                "observations": outcome["observations"],
                "evidence_id": ev.evidence_id,
            })

    candidates = [r for r in results if r["status"] == Classification.NEEDS_MORE_EVIDENCE.value]
    return {
        "engagement": ENGAGEMENT,
        "browser": chromium.version,
        "binary": chromium.binary,
        "hypotheses_run": len(results),
        "disproven": [r["id"] for r in results if r["status"] == Classification.FALSE_POSITIVE.value],
        "candidates": [r["id"] for r in candidates],
        "results": results,
        "evidence_integrity": evidence.verify_integrity(),
    }


def smoke_test(binary: Optional[str] = None) -> dict:
    """A single cheap sanity run: can we launch the browser and read one probe?"""
    chromium = Chromium(binary)
    with tempfile.TemporaryDirectory(prefix="bh-chrome-smoke-") as tmp:
        with serve_origins(Path(tmp)) as pair:
            (pair.root / "sop.html").write_text(probes.SOP_READ, encoding="utf-8")
            (pair.root / "child.html").write_text(
                "<!doctype html><h1>child</h1>", encoding="utf-8"
            )
            run = chromium.run_probe(
                f"{pair.url_a}/sop.html?cross={pair.url_b}/child.html"
            )
    return {"browser": chromium.version, "run": run.to_dict()}


def positive_control(binary: Optional[str] = None) -> dict:
    """Prove the harness *detects* a violation, so a clean run means something.

    The SOP probe is loaded with a **same-origin** child. The probe's invariant
    says a cross-origin frame must be unreadable; with a same-origin child the
    DOM *is* readable, so a working probe must report the exact violation strings
    it would report for a real boundary breach. If this control does not trip,
    the negative results from :func:`run_engagement` are worthless -- so it is a
    required part of the engagement, not an optional extra.
    """
    chromium = Chromium(binary)
    with tempfile.TemporaryDirectory(prefix="bh-chrome-control-") as tmp:
        with serve_origins(Path(tmp)) as pair:
            (pair.root / "sop.html").write_text(probes.SOP_READ, encoding="utf-8")
            (pair.root / "child.html").write_text(
                "<!doctype html><h1>child</h1>", encoding="utf-8"
            )
            # Same origin for the child: the read succeeds, so the probe must flag it.
            run = chromium.run_probe(f"{pair.url_a}/sop.html?cross={pair.url_a}/child.html")
    violations = list(run.result.get("violations", []))
    detected = any("contentDocument readable" in v for v in violations)
    return {
        "browser": chromium.version,
        "control": "same-origin child must be readable (probe must flag it)",
        "violations": violations,
        "detected": detected,
        "run": run.to_dict(),
    }


__all__ = [
    "DEFAULT_ROOT",
    "ENGAGEMENT",
    "HYPOTHESES",
    "Hypothesis",
    "positive_control",
    "run_engagement",
    "smoke_test",
]
