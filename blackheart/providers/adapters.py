"""Provider adapters for the multi-model research layer (mission Part B).

One small interface, several implementations:

  * :class:`OpenAICompatibleProvider` -- any provider that speaks the OpenAI
    ``/chat/completions`` shape (OpenRouter, Groq, Gemini's compatibility
    endpoint, NVIDIA NIM, SambaNova, Z.ai, Cloudflare Workers AI, Mistral,
    Cohere's compatibility endpoint, LLM7, Cerebras, Kilo, Together). The
    differences that matter (base URL, key env var, model ids) live in the
    registry, not in this class.
  * :class:`LocalProvider` -- a **local-only** deterministic engine. It makes no
    network call at all, so zero-provider mode works and private evidence never
    leaves the host. It is rule-based, not a language model, and says so.
  * :class:`MockProvider` -- a scripted provider for tests. Every response is
    labelled ``simulated=True`` and is never presented as real research.

Nothing here fabricates a result. A provider that fails returns ``ok=False`` with
the error; a caller must handle it rather than treat an empty string as an answer.
Only the standard library is used (``urllib``), so no dependency is added.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .registry import resolved_model


class ProviderError(RuntimeError):
    """Raised for a provider-level failure that is not a network hiccup."""


@dataclass
class ModelResponse:
    """The result of one completion. ``ok`` is the single honest success flag."""

    provider: str
    model: str
    text: str = ""
    structured: Optional[dict] = None
    ok: bool = False
    error: str = ""
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    retries: int = 0
    simulated: bool = False   # True for mock/local engines: never real research
    raw_status: int = 0

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "model": self.model, "ok": self.ok,
            "text": self.text, "structured": self.structured, "error": self.error,
            "latency_ms": round(self.latency_ms, 1),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "retries": self.retries, "simulated": self.simulated,
            "raw_status": self.raw_status,
        }


@dataclass
class HealthResult:
    provider: str
    healthy: bool
    detail: str
    latency_ms: float = 0.0
    models: list[str] = field(default_factory=list)
    requires_key: bool = True
    key_present: bool = False

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "healthy": self.healthy, "detail": self.detail,
            "latency_ms": round(self.latency_ms, 1), "models": self.models,
            "requires_key": self.requires_key, "key_present": self.key_present,
        }


class Provider(Protocol):
    """The one method every provider must implement."""

    name: str

    def complete(
        self, prompt: str, *, model: str = "", system: str = "",
        json_schema: Optional[dict] = None, timeout: int = 60,
        max_retries: int = 2,
    ) -> ModelResponse: ...

    def health(self, *, timeout: int = 15) -> HealthResult: ...


# --------------------------------------------------------------------------- #
# Real, network-backed provider (OpenAI-compatible)
# --------------------------------------------------------------------------- #

class OpenAICompatibleProvider:
    """A provider that speaks the OpenAI ``/chat/completions`` wire shape.

    Retries on transient failures (5xx, timeouts, connection errors) with
    exponential backoff, and honours ``Retry-After`` on 429. A 4xx other than 429
    is not retried: it is a request problem, not a transient one.
    """

    def __init__(self, spec) -> None:
        self.spec = spec
        self.name = spec.name

    def _api_key(self) -> str:
        import os

        return os.environ.get(self.spec.env_key, "").strip()

    def complete(
        self, prompt: str, *, model: str = "", system: str = "",
        json_schema: Optional[dict] = None, timeout: int = 60,
        max_retries: int = 2,
    ) -> ModelResponse:
        key = self._api_key()
        # Resolve once, here, so a call that omits ``model`` uses exactly the id the
        # health probe verified. Defaulting to ``spec.default_model`` instead would
        # let the probe certify an overridden, live model while the real call went
        # to a retired pinned id -- the credential would test healthy and then fail
        # in production.
        model = model or resolved_model(self.spec)
        if self.spec.requires_key and not key:
            return ModelResponse(
                self.name, model, ok=False,
                error=f"no API key in ${self.spec.env_key}",
            )
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body: dict = {"model": model, "messages": messages}
        if json_schema is not None:
            # Most OpenAI-compatible providers accept this; a provider that does
            # not will reject the request and the caller sees a real error rather
            # than a silently-unstructured answer.
            body["response_format"] = {"type": "json_object"}
            body["messages"] = messages + [{
                "role": "system",
                "content": "Reply with a single JSON object matching this schema: "
                           + json.dumps(json_schema),
            }]

        url = self.spec.base_url.rstrip("/") + "/chat/completions"
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        attempt = 0
        last_error = ""
        start = time.monotonic()
        while attempt <= max_retries:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                text, usage = self._extract(payload)
                structured = None
                if json_schema is not None:
                    try:
                        structured = json.loads(text)
                    except json.JSONDecodeError as exc:
                        return ModelResponse(
                            self.name, model, text=text, ok=False,
                            error=f"provider returned non-JSON for a JSON request: {exc}",
                            latency_ms=(time.monotonic() - start) * 1000,
                            retries=attempt, raw_status=200,
                        )
                return ModelResponse(
                    self.name, model, text=text, structured=structured, ok=True,
                    latency_ms=(time.monotonic() - start) * 1000,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    retries=attempt, raw_status=200,
                )
            except urllib.error.HTTPError as exc:
                status = exc.code
                detail = ""
                try:
                    detail = exc.read().decode("utf-8")[:400]
                except Exception:  # pragma: no cover - body may be unreadable
                    pass
                last_error = f"HTTP {status}: {detail}"
                if status == 429 or 500 <= status < 600:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    attempt += 1
                    if attempt <= max_retries:
                        time.sleep(self._backoff(attempt, retry_after))
                        continue
                return ModelResponse(
                    self.name, model, ok=False, error=last_error,
                    latency_ms=(time.monotonic() - start) * 1000,
                    retries=attempt, raw_status=status,
                )
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                attempt += 1
                if attempt <= max_retries:
                    time.sleep(self._backoff(attempt, None))
                    continue
                return ModelResponse(
                    self.name, model, ok=False, error=last_error,
                    latency_ms=(time.monotonic() - start) * 1000,
                    retries=attempt,
                )
        return ModelResponse(self.name, model, ok=False, error=last_error or "unknown")

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 30.0)
            except ValueError:
                pass
        return min(2.0 ** (attempt - 1), 8.0)

    @staticmethod
    def _extract(payload: dict) -> tuple[str, dict]:
        choices = payload.get("choices") or []
        text = ""
        if choices:
            msg = choices[0].get("message") or {}
            text = msg.get("content") or choices[0].get("text") or ""
        return text, payload.get("usage") or {}

    def health(self, *, timeout: int = 15) -> HealthResult:
        key = self._api_key()
        if self.spec.requires_key and not key:
            return HealthResult(self.name, False,
                                f"no API key in ${self.spec.env_key}",
                                requires_key=True, key_present=False)
        start = time.monotonic()
        # A 1-token completion is the least-privilege liveness probe: it proves
        # the key, the model id, and the endpoint all work.
        resp = self.complete("ping", model=resolved_model(self.spec), timeout=timeout,
                             max_retries=0)
        latency = (time.monotonic() - start) * 1000
        return HealthResult(self.name, resp.ok,
                            "reachable" if resp.ok else resp.error,
                            latency_ms=latency, requires_key=self.spec.requires_key,
                            key_present=bool(key))


# --------------------------------------------------------------------------- #
# Local-only provider (no network; zero-provider mode)
# --------------------------------------------------------------------------- #

class LocalProvider:
    """A deterministic, **offline** analyst. No network, no model weights.

    It exists so zero-provider mode is real rather than a stub: the router can
    always fall back to it, and CONFIDENTIAL/SECRET research is confined here by
    default. It is a rule-based summariser, not a language model, and every
    response is marked ``simulated=True`` so it is never mistaken for one.
    """

    name = "local"

    def __init__(self) -> None:
        # Record what was actually delivered, so a test can verify the local
        # fallback received the canonical role prompt (not a substitute).
        self.calls: list[dict] = []

    def complete(
        self, prompt: str, *, model: str = "", system: str = "",
        json_schema: Optional[dict] = None, timeout: int = 60,
        max_retries: int = 2,
    ) -> ModelResponse:
        start = time.monotonic()
        self.calls.append({"prompt": prompt, "model": model, "system": system,
                           "json_schema": json_schema})
        text = self._analyse(prompt, system)
        structured = None
        if json_schema is not None:
            structured = {"local_summary": text, "role": system[:80]}
        return ModelResponse(
            self.name, model or "local-rulebased", text=text, structured=structured,
            ok=True, latency_ms=(time.monotonic() - start) * 1000, simulated=True,
        )

    @staticmethod
    def _analyse(prompt: str, system: str) -> str:
        words = [w for w in prompt.split() if len(w) > 3]
        head = " ".join(words[:20])
        return (
            "LOCAL (offline, rule-based) analysis -- not a language model. "
            f"Role: {system[:60] or 'unspecified'}. "
            f"Input summary ({len(prompt)} chars): {head}... "
            "This offline engine produces structure only; it cannot reason about "
            "novel semantics. Configure an external provider for deeper analysis."
        )

    def health(self, *, timeout: int = 15) -> HealthResult:
        return HealthResult(self.name, True, "local engine always available",
                            requires_key=False, key_present=True)


# --------------------------------------------------------------------------- #
# Mock provider (tests; always labelled simulated)
# --------------------------------------------------------------------------- #

class MockProvider:
    """A scripted provider for tests. Every response is ``simulated=True``.

    ``responses`` may be a list (returned in order, then repeated) or a callable
    ``(prompt, model) -> str``. ``fail_times`` makes the first N calls fail, so
    retry and failure-recovery paths are exercised against real code.
    """

    def __init__(self, name: str = "mock", *, responses=None, fail_times: int = 0,
                 error: str = "simulated failure", healthy: bool = True) -> None:
        self.name = name
        self._responses = responses if responses is not None else ["{}"]
        self._fail_times = fail_times
        self._error = error
        self._healthy = healthy
        # (prompt, model) kept for backwards compatibility; ``calls_detail``
        # additionally records the exact system prompt and schema sent, so a test
        # can verify what the model actually received rather than what was passed.
        self.calls: list[tuple[str, str]] = []
        self.calls_detail: list[dict] = []

    def _next(self, prompt: str, model: str) -> str:
        if callable(self._responses):
            return self._responses(prompt, model)
        idx = min(len(self.calls), len(self._responses) - 1)
        return self._responses[idx]

    def complete(
        self, prompt: str, *, model: str = "", system: str = "",
        json_schema: Optional[dict] = None, timeout: int = 60,
        max_retries: int = 2,
    ) -> ModelResponse:
        self.calls.append((prompt, model))
        self.calls_detail.append({"prompt": prompt, "model": model, "system": system,
                                  "json_schema": json_schema})
        if len(self.calls) <= self._fail_times:
            return ModelResponse(self.name, model or "mock-model", ok=False,
                                 error=self._error, simulated=True)
        text = self._next(prompt, model)
        structured = None
        if json_schema is not None:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError:
                return ModelResponse(self.name, model or "mock-model", text=text,
                                     ok=False, error="mock returned non-JSON",
                                     simulated=True)
        return ModelResponse(self.name, model or "mock-model", text=text,
                             structured=structured, ok=True, simulated=True)

    def health(self, *, timeout: int = 15) -> HealthResult:
        return HealthResult(self.name, self._healthy,
                            "mock healthy" if self._healthy else "mock unhealthy",
                            requires_key=False, key_present=True)
