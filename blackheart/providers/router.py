"""Model router: privacy-gated routing, quota tracking, and role dispatch.

The router is where the mission's privacy rules (B3) are actually enforced:

  * **Local-only by default.** With no provider configured, every request goes to
    the offline :class:`~blackheart.providers.adapters.LocalProvider`. Zero-provider
    mode is a real, working mode, not an error.
  * **Classification gate.** A request carries a :class:`DataClass`. Anything above
    the configured ceiling (default ``PUBLIC``) is routed to the local provider and
    never transmitted; ``SECRET`` is hard-blocked everywhere.
  * **No fabricated fallback.** If a remote provider fails and the material is
    above the ceiling, the router does not silently downgrade to a remote retry --
    it reports the failure and the reason.

Quota tracking is local and advisory: it counts calls/tokens per provider per day
so a run can stop before hitting an unknown provider cap. It cannot see the
provider's real remaining quota and says so.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Optional

from ..budget import Budget, budget_from_env
from ..models import ReviewIndependence
from .adapters import (
    HealthResult,
    LocalProvider,
    ModelResponse,
    OpenAICompatibleProvider,
    Provider,
)
from .registry import (
    NEVER_TRANSMIT,
    REMOTE_DEFAULT_CEILING,
    DataClass,
    all_providers,
    get_spec,
    may_transmit,
    resolved_model,
)
from .roles import ROLES, RoleResult, summarise
from ..doctrine import doctrine_prompt_block
from ..mindset import prompt_block

# The identity + question + doctrine that must lead *every* prompt the router
# sends, known role or not. This mirrors the block :mod:`blackheart.providers.roles`
# prepends to each canonical role, and is applied here so an unknown role cannot
# reach a model without the attacker question. Built once; the guard makes it
# idempotent.
_LENS = prompt_block() + " " + doctrine_prompt_block()


class PrivacyViolation(RuntimeError):
    """Raised when a caller tries to send material it may not transmit."""

#: The offline, rule-based analyst. It is *not* a language model, so a remote
#: model is genuinely independent of it -- unlike any real provider whose weights
#: must be named before independence can be claimed.
LOCAL_PROVIDER = "local"


@dataclass
class RouteDecision:
    provider: str
    model: str
    reason: str
    local: bool
    data_class: str
    ceiling: str

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "model": self.model, "reason": self.reason,
            "local": self.local, "data_class": self.data_class, "ceiling": self.ceiling,
        }


class QuotaTracker:
    """Per-provider, per-day call/token counts. Advisory, never authoritative.

    This tracks what *BLACKHEART* has spent; it cannot know a provider's real
    remaining allowance. It exists to stop a run before an unknown cap, and to
    make usage visible. It is persisted as JSONL so a resumed run keeps counting.
    """

    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(path) if path else None
        self._counts: dict[str, dict] = {}
        if self.path and self.path.exists():
            self._load()

    def _today(self) -> str:
        return date.today().isoformat()

    def record(self, provider: str, *, calls: int = 1, prompt_tokens: int = 0,
               completion_tokens: int = 0) -> None:
        day = self._today()
        entry = self._counts.setdefault(f"{provider}:{day}",
                                        {"provider": provider, "day": day,
                                         "calls": 0, "prompt_tokens": 0,
                                         "completion_tokens": 0})
        entry["calls"] += calls
        entry["prompt_tokens"] += prompt_tokens
        entry["completion_tokens"] += completion_tokens
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._counts[f"{e['provider']}:{e['day']}"] = e

    def usage(self) -> list[dict]:
        return sorted(self._counts.values(), key=lambda e: (e["day"], e["provider"]))

    def today(self, provider: str) -> dict:
        return self._counts.get(f"{provider}:{self._today()}",
                                {"provider": provider, "day": self._today(),
                                 "calls": 0, "prompt_tokens": 0,
                                 "completion_tokens": 0})


class ModelRouter:
    """Route a completion request to a provider, respecting privacy and quotas.

    ``providers`` overrides the registry (used by tests with mocks). ``ceiling`` is
    the highest data classification allowed off-host; the default is PUBLIC.
    """

    def __init__(
        self,
        *,
        providers: Optional[dict[str, Provider]] = None,
        ceiling: str = REMOTE_DEFAULT_CEILING,
        prefer: Optional[list[str]] = None,
        quota: Optional[QuotaTracker] = None,
        local: Optional[Provider] = None,
        budget: Optional[Budget] = None,
    ) -> None:
        self._providers = providers or {}
        self.ceiling = ceiling
        self.prefer = prefer or []
        self.quota = quota or QuotaTracker()
        self.local = local or LocalProvider()
        #: A token/turn research budget. When set, a completion is refused once the
        #: budget is inside its wrap-up reserve, so a task summarises instead of
        #: spending past its cap. ``None`` means unbounded.
        self.budget = budget

    # -- provider construction ------------------------------------------- #
    @classmethod
    def from_env(cls, *, ceiling: str = REMOTE_DEFAULT_CEILING,
                 prefer: Optional[list[str]] = None,
                 quota_path: str | os.PathLike | None = None,
                 budget: Optional[Budget] = None) -> "ModelRouter":
        """Build a router from the environment: a provider is available only if
        its key env var is set (or it needs no key) AND it is permitted.

        A keyless provider is **opt-in** (listed in ``BLACKHEART_PROVIDERS``),
        because an unauthenticated public gateway has unverified reliability and
        data-handling terms: it must not become the silent default. With nothing
        configured the router is local-only, which is the intended default.
        """
        import os as _os

        opted_in = {
            p.strip() for p in _os.environ.get("BLACKHEART_PROVIDERS", "").split(",")
            if p.strip()
        }
        providers: dict[str, Provider] = {}
        for spec in all_providers():
            if not spec.openai_compatible:
                continue  # Cloudflare-style endpoints are not wired; not guessed
            if not spec.default_model:
                continue  # no confirmed model id -> do not fabricate one
            if spec.requires_key:
                if not _os.environ.get(spec.env_key, "").strip():
                    continue
            elif spec.name not in opted_in:
                # Keyless providers stay off unless explicitly opted in.
                continue
            providers[spec.name] = OpenAICompatibleProvider(spec)
        return cls(providers=providers, ceiling=ceiling, prefer=prefer,
                   quota=QuotaTracker(quota_path),
                   budget=budget if budget is not None else budget_from_env())

    # -- routing ---------------------------------------------------------- #
    def available(self) -> list[str]:
        return sorted(self._providers)

    def primary(self) -> str:
        """The provider :meth:`route` would choose -- the one the agent runs on.

        Used to decide whether a candidate reviewer is genuinely a *different*
        model. With no providers this is ``"local"``, the rule-based engine.
        """
        if self.prefer and self.prefer[0] in self._providers:
            return self.prefer[0]
        return self.available()[0] if self._providers else LOCAL_PROVIDER

    def route(self, data_class: str = DataClass.PUBLIC,
              *, role: str = "") -> RouteDecision:
        """Decide where a request goes, and record why. Never transmits here."""
        if not may_transmit(data_class, self.ceiling) or not self._providers:
            why = ("data class above the off-host ceiling"
                   if not may_transmit(data_class, self.ceiling)
                   else "no remote provider configured (zero-provider mode)")
            return RouteDecision(LOCAL_PROVIDER, "local-rulebased", why, True,
                                 data_class, self.ceiling)
        chosen = self.prefer[0] if self.prefer and self.prefer[0] in self._providers \
            else self.available()[0]
        try:
            model = resolved_model(get_spec(chosen))
        except KeyError:
            # An injected provider (e.g. a test mock) has no registry entry; the
            # caller supplies the model, so do not fabricate one here.
            model = ""
        return RouteDecision(chosen, model, "remote provider available and permitted",
                             False, data_class, self.ceiling)

    # -- research budget -------------------------------------------------- #
    def _budget_refusal(self, role: str, model: str, data_class: str) -> Optional["RoleResult"]:
        """Refuse a call once the budget is inside its wrap-up reserve."""
        if self.budget is not None and self.budget.wrapped_up:
            return RoleResult(
                role, LOCAL_PROVIDER, model, False, data_class,
                error=("research budget exhausted: the wrap-up reserve is spent, so "
                       "no further model call is started"),
            )
        return None

    def _charge(self, resp: ModelResponse) -> None:
        if self.budget is None:
            return
        self.budget.charge_tokens(
            int(getattr(resp, "prompt_tokens", 0) or 0)
            + int(getattr(resp, "completion_tokens", 0) or 0)
        )
        self.budget.charge_turn()

    def budget_detail(self) -> Optional[dict]:
        return self.budget.to_dict() if self.budget is not None else None

    # -- execution -------------------------------------------------------- #
    def complete(
        self, prompt: str, *, role: str = "", data_class: str = DataClass.PUBLIC,
        model: str = "", system: str = "", json_schema: Optional[dict] = None,
        timeout: int = 60, max_retries: int = 2,
    ) -> RoleResult:
        """Run one role completion, enforcing the privacy gate before any send.

        A known role always uses its canonical system prompt; ``system`` is
        *appended* to it, never substituted for it, so the attacker question
        cannot be dropped. For an unknown role ``system`` is used as given. The
        result is always a :class:`RoleResult`; a failure is ``ok=False`` with the
        reason.
        """
        role_obj = ROLES.get(role)
        # A known role ALWAYS carries its canonical system prompt (persona +
        # attacker question + doctrine + the role's own question). A caller may
        # add instructions after it but may never replace it: `system=` is an
        # *addition*, not an override, so no path can silently drop the question.
        if role_obj is not None:
            sys_prompt = role_obj.system
            if system:
                sys_prompt = f"{sys_prompt}\n\n{system}"
        else:
            # An unknown role must not be a hole through which the question
            # escapes. The lens always leads; the caller's `system` is appended,
            # never substituted. This makes the guarantee structural rather than
            # dependent on every caller choosing a canonical role.
            sys_prompt = _LENS
            if system:
                sys_prompt = f"{sys_prompt}\n\n{system}"
        schema = json_schema if json_schema is not None else (
            role_obj.schema if role_obj else None)

        if data_class == DataClass.SECRET:
            raise PrivacyViolation(
                "SECRET material (credentials, keys, tokens, customer data) is "
                "never transmitted off-host, at any ceiling")

        refused = self._budget_refusal(role, model, data_class)
        if refused is not None:
            return refused

        decision = self.route(data_class, role=role)
        if decision.local:
            resp = self.local.complete(prompt, model=model, system=sys_prompt,
                                       json_schema=schema, timeout=timeout)
            self.quota.record("local")
            self._charge(resp)
            return RoleResult.from_response(role, resp, data_class)
        provider = self._providers[decision.provider]
        resp = provider.complete(prompt, model=model or decision.model,
                                 system=sys_prompt, json_schema=schema,
                                 timeout=timeout, max_retries=max_retries)
        self.quota.record(decision.provider, prompt_tokens=resp.prompt_tokens,
                          completion_tokens=resp.completion_tokens)
        self._charge(resp)
        return RoleResult.from_response(role, resp, data_class)

    def complete_with(
        self, provider: str, prompt: str, *, model: str = "",
        data_class: str = DataClass.PUBLIC, system: str = "",
        timeout: int = 60, max_retries: int = 2,
    ) -> RoleResult:
        """Complete on one named provider, with the same privacy gate.

        This is the first-class reviewer path: the caller resolved a *distinct*
        provider and asks it directly, instead of relying on ``route`` to pick
        the primary again. A missing provider or a disallowed data class is an
        honest failure result, never a silent local answer.
        """
        if data_class == DataClass.SECRET:
            raise PrivacyViolation(
                "SECRET material is never transmitted off-host, at any ceiling")
        if not may_transmit(data_class, self.ceiling):
            return RoleResult("reviewer", provider, model, False, data_class,
                              error=f"data class {data_class} is above the off-host "
                                    f"ceiling {self.ceiling}")
        refused = self._budget_refusal("reviewer", model, data_class)
        if refused is not None:
            return refused
        chosen = self._providers.get(provider)
        if chosen is None:
            return RoleResult("reviewer", provider, model, False, data_class,
                              error=f"provider {provider!r} is not configured")
        try:
            resp = chosen.complete(prompt, model=model, system=system,
                                   timeout=timeout, max_retries=max_retries)
        except Exception as exc:  # noqa: BLE001 -- a reviewer failure is a result
            return RoleResult("reviewer", provider, model, False, data_class,
                              error=f"{type(exc).__name__}: {exc}")
        self.quota.record(provider, prompt_tokens=resp.prompt_tokens,
                          completion_tokens=resp.completion_tokens)
        self._charge(resp)
        return RoleResult.from_response("reviewer", resp, data_class)

    def run_roles(
        self, prompt: str, *, roles: list[str], data_class: str = DataClass.PUBLIC,
        timeout: int = 60,
    ) -> list[RoleResult]:
        """Run several roles on the same material, preserving each answer.

        This is the *independent-intelligence* pattern: different questions, not
        the same question repeated. Disagreement is preserved by design.
        """
        results = []
        for role in roles:
            results.append(self.complete(prompt, role=role, data_class=data_class,
                                         timeout=timeout))
        return results

    def summarise(self, results: list[RoleResult]) -> dict:
        return summarise(results)

    # -- health / benchmark ---------------------------------------------- #
    def health(self, *, timeout: int = 15) -> list[HealthResult]:
        out = [self.local.health(timeout=timeout)]
        for name, provider in sorted(self._providers.items()):
            try:
                out.append(provider.health(timeout=timeout))
            except Exception as exc:  # a provider must not break the health run
                out.append(HealthResult(name, False, f"{type(exc).__name__}: {exc}"))
        return out

    def usage(self) -> list[dict]:
        return self.quota.usage()


def build_router(*, ceiling: str = REMOTE_DEFAULT_CEILING,
                 prefer: Optional[list[str]] = None,
                 quota_path: str | os.PathLike | None = None,
                 budget: Optional[Budget] = None) -> ModelRouter:
    """The default entry point used by the CLI."""
    return ModelRouter.from_env(ceiling=ceiling, prefer=prefer,
                                quota_path=quota_path, budget=budget)


# --------------------------------------------------------------------------- #
# Optional reviewer model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReviewerModel:
    """Whether a *separately authenticated* reviewer model is available.

    The reviewer model is **optional by design**. BLACKHEART's core research and
    release workflow never requires it: when no valid reviewer credentials exist,
    the workflow runs a same-model adversarial review in a fresh context and
    records that honestly (``ReviewIndependence.SAME_MODEL``). This resolves to
    ``available=False`` and explains why, rather than failing or silently
    pretending an independent model reviewed the work.

    ``configured`` means a provider distinct from the primary is configured with a
    key. ``available`` is stronger: it is True only when such a provider is
    configured **and** a liveness probe proved the credential actually works. A
    configured-but-unprobed or failing credential is never reported as available,
    because a key that merely *exists* may be invalid or expired -- reporting it as
    an independent reviewer would be the exact fabrication this type exists to
    prevent.
    """

    available: bool
    provider: str = ""
    model: str = ""
    reason: str = ""
    #: The provenance to record for a review performed with this resolution.
    independence: ReviewIndependence = ReviewIndependence.SAME_MODEL
    #: A distinct provider with a key is present (not proof it authenticates).
    configured: bool = False
    #: A liveness probe succeeded, so the credential demonstrably works.
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "configured": self.configured,
            "verified": self.verified,
            "provider": self.provider,
            "model": self.model,
            "reason": self.reason,
            "independence": self.independence.value,
        }


#: Serving/quantisation/instruction decoration that never names distinct weights.
_DECORATION_TOKENS = frozenset({
    "instruct", "chat", "it", "turbo", "versatile", "latest", "preview",
    "fp8", "fp16", "bf16", "fp32", "int8", "int4", "8bit", "4bit",
    "awq", "gptq", "gguf", "mlx", "hf", "fast",
})

#: Organisation prefixes that name a publisher, not the weights themselves.
_VENDOR_TOKENS = frozenset({
    "meta", "llama", "google", "openai", "anthropic", "mistralai", "mistral",
    "qwen", "deepseek", "microsoft", "nvidia", "ibm", "cohere", "ai21", "xai",
    "moonshot", "minimax", "baidu", "alibaba", "thudm", "bigcode", "allenai",
    "tiiuae", "huggingface", "cf", "nousresearch", "teknium",
})


def _model_tokens(model_id: str) -> list[str]:
    """The model id as lower-case tokens, with tags and trailing decoration removed."""
    name = model_id.strip().lower()
    if not name:
        return []
    name = name.split("@")[-1]  # drop an @provider/@version tag
    name = name.split(":")[0]   # drop a :free / :beta tag
    tokens = [t for t in name.replace("/", "-").split("-") if t]
    # Strip decoration from the end until stable: ids stack it
    # (``-instruct-turbo``, ``-instruct-fp8``), and one pass leaves a suffix.
    while len(tokens) > 1 and tokens[-1] in _DECORATION_TOKENS:
        tokens.pop()
    # Collapse repeats: ``meta-llama/Llama-...`` tokenises to meta,llama,llama and
    # the duplicate would otherwise defeat the prefix comparison below.
    deduped: list[str] = []
    for token in tokens:
        if not deduped or deduped[-1] != token:
            deduped.append(token)
    return deduped


def _model_family(model_id: str) -> str:
    """Reduce a model id to the weights it names, ignoring vendor/serving decoration.

    A different provider that serves the *same weights* under a different label
    (``llama-3.3-70b-versatile`` vs ``meta/llama-3.3-70b-instruct`` vs
    ``@cf/meta/llama-3.3-70b-instruct-fp8-fast``) is not a second model: the blind
    spots are identical, so it cannot be independent verification. Only
    non-semantic decoration is stripped -- serving/quantisation/instruction
    suffixes and a leading publisher prefix -- never a token that names a distinct
    model.
    """
    return "-".join(_model_tokens(model_id))


def _same_model_family(a: str, b: str) -> bool:
    """Do these two ids name the same weights?

    Biased toward ``True``: calling distinct weights "the same" only denies an
    independence claim (safe, and the workflow falls back to a same-model review),
    while calling the same weights "distinct" fabricates one. So a *leading*
    publisher prefix on one side is tolerated (``Meta-Llama-...`` vs a bare
    ``llama-...``); any other differing token means distinct weights and is never
    merged. That asymmetry is required: ``sambanova`` publishes
    ``Meta-Llama-3.3-70B-Instruct`` and ``groq`` publishes ``llama-3.3-70b-versatile``
    -- identical weights, and they must not read as independent models.
    """
    ta, tb = _model_tokens(a), _model_tokens(b)
    if not ta or not tb:
        return False
    if ta == tb:
        return True
    for long_, short_ in ((ta, tb), (tb, ta)):
        if len(long_) > len(short_) and long_[-len(short_):] == short_:
            return all(t in _VENDOR_TOKENS for t in long_[: len(long_) - len(short_)])
    return False


def resolve_reviewer_model(
    router: "ModelRouter",
    *,
    primary: str = "",
    data_class: str = DataClass.PUBLIC,
    preferred: Optional[list[str]] = None,
    probe: bool = False,
    timeout: int = 15,
) -> ReviewerModel:
    """Resolve the optional reviewer model without ever requiring one.

    Returns an *independent* reviewer only when a provider other than ``primary``
    is configured, may receive ``data_class``, and -- when ``probe`` is set -- a
    liveness call proves the credential authenticates. Without ``probe`` the result
    is *configured but unverified*: ``configured=True``, ``available=False``, so a
    caller can never mistake a merely-present key for a working reviewer. Either
    way the caller falls back to a same-model adversarial review when the result is
    not available, and the returned provenance says so.
    """
    if data_class in NEVER_TRANSMIT:
        return ReviewerModel(
            False, reason="SECRET material is never transmitted to a reviewer model",
            independence=ReviewIndependence.SAME_MODEL,
        )
    if not primary:
        # Default to the provider the agent itself runs on. Without this a caller
        # that omits ``primary`` could be handed the very provider serving the
        # primary model and report it as an independent reviewer.
        primary = router.primary()
    if not may_transmit(data_class, router.ceiling):
        return ReviewerModel(
            False,
            reason=f"data class {data_class} is above the off-host ceiling "
                   f"{router.ceiling}; a remote reviewer model is not permitted",
            independence=ReviewIndependence.SAME_MODEL,
        )
    candidates = [p for p in (preferred or []) if p in router.available() and p != primary]
    if not candidates:
        candidates = [p for p in router.available() if p != primary]
    if not candidates:
        why = ("no provider is configured (zero-provider mode)"
               if not router.available()
               else f"only the primary provider {primary!r} is configured")
        return ReviewerModel(
            False,
            reason=f"no separately authenticated reviewer model: {why}",
            independence=ReviewIndependence.SAME_MODEL,
        )
    # Select the first candidate that is genuinely a *different* model. A distinct
    # provider serving the same weights is not a second model: the blind spots are
    # identical, so it can never be independent verification. Skipping to the next
    # candidate matters -- with ``preferred=["cerebras", "gemini"]`` and a groq
    # primary, cerebras serves the same llama-3.3-70b weights, but gemini does not,
    # and refusing the whole resolution would deny a review the architecture grants.
    primary_model = ""
    if primary:
        try:
            primary_model = resolved_model(get_spec(primary))
        except KeyError:
            primary_model = ""
    if not primary_model and primary and primary != LOCAL_PROVIDER:
        return ReviewerModel(
            False,
            reason=f"the primary provider {primary!r} has no identifiable model, "
                   "so independence from it cannot be established",
            independence=ReviewIndependence.SAME_MODEL,
        )

    chosen = ""
    model = ""
    first_rejection = None  # the most informative reason if nothing qualifies
    for candidate in candidates:
        try:
            candidate_model = resolved_model(get_spec(candidate))
        except KeyError:  # an injected test provider has no registry entry
            candidate_model = ""
        if not candidate_model:
            first_rejection = first_rejection or (
                candidate, "",
                f"reviewer provider {candidate!r} has no identifiable model, so "
                "independence from the primary model cannot be established",
            )
            continue
        # ``local`` is the rule-based engine, not a model, so a remote model is
        # genuinely independent of it.
        if primary_model and _same_model_family(primary_model, candidate_model):
            first_rejection = first_rejection or (
                candidate, candidate_model,
                f"reviewer provider {candidate!r} serves the same model family "
                f"({candidate_model!r}) as the primary ({primary_model!r}); a "
                "different provider is not a different model, so this is not an "
                "independent reviewer",
            )
            continue
        chosen, model = candidate, candidate_model
        break

    if not chosen:
        if first_rejection is None:
            first_rejection = (candidates[0], "", "no candidate reviewer model")
        provider, rejected_model, reason = first_rejection
        return ReviewerModel(
            False, provider=provider, model=rejected_model, configured=True,
            verified=False, reason=reason,
            independence=ReviewIndependence.SAME_MODEL,
        )

    if not probe:
        return ReviewerModel(
            False, provider=chosen, model=model, configured=True, verified=False,
            reason=f"reviewer provider {chosen!r} is configured but unverified; "
                   "run with a liveness probe to confirm the credential works",
            independence=ReviewIndependence.SAME_MODEL,
        )

    provider = router._providers.get(chosen)
    if provider is None:
        return ReviewerModel(
            False, provider=chosen, model=model, configured=True, verified=False,
            reason=f"reviewer provider {chosen!r} is not constructible",
            independence=ReviewIndependence.SAME_MODEL,
        )
    try:
        health = provider.health(timeout=timeout)
    except Exception as exc:  # a broken probe is a failure, never a pass
        return ReviewerModel(
            False, provider=chosen, model=model, configured=True, verified=False,
            reason=f"reviewer credential check raised {type(exc).__name__}: {exc}",
            independence=ReviewIndependence.SAME_MODEL,
        )
    if not health.healthy:
        return ReviewerModel(
            False, provider=chosen, model=model, configured=True, verified=False,
            reason=f"reviewer provider {chosen!r} failed its liveness probe "
                   f"({health.detail}); treating it as unavailable",
            independence=ReviewIndependence.SAME_MODEL,
        )
    return ReviewerModel(
        True, provider=chosen, model=model, configured=True, verified=True,
        reason=f"reviewer model served by {chosen!r}, distinct from the primary "
               "and verified by a liveness probe",
        independence=ReviewIndependence.INDEPENDENT_MODEL,
    )
