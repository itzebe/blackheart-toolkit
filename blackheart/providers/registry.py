"""Provider registry: what each provider is, and what it may be used for.

Two things are kept here and nothing else:

  * **Provider specs** -- name, base URL, key env var, default model, and the
    *verified* free-tier facts (as of the date recorded on each entry). Free
    tiers change; the ``verified_on`` field and ``free_tier_note`` are what stop a
    stale "it's free" assumption from being treated as current. No provider is
    assumed free, unlimited, or OpenAI-compatible without a recorded note.

  * **Data classification** -- what a piece of research material *is*, so the
    router can refuse to send CONFIDENTIAL/SECRET material to a third party.

Nothing here contacts the network. ``blackheart models health`` is what actually
probes a provider, and it says so.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Data classification (mission B3)
# --------------------------------------------------------------------------- #

class DataClass:
    """How sensitive a piece of research material is.

    The router refuses to transmit anything above ``PUBLIC`` to an external
    provider unless the caller has explicitly acknowledged that classification.
    """

    PUBLIC = "PUBLIC"          # already public: published source, docs, advisories
    INTERNAL = "INTERNAL"      # non-public but not damaging: drafts, internal notes
    CONFIDENTIAL = "CONFIDENTIAL"  # private vulnerability evidence, unpublished PoC
    SECRET = "SECRET"          # credentials, keys, tokens, customer data


# Ordered by sensitivity; a class may only be sent to a remote provider if the
# caller's allowed ceiling is >= it. Remote providers default to PUBLIC.
_CLASS_ORDER = [DataClass.PUBLIC, DataClass.INTERNAL,
                DataClass.CONFIDENTIAL, DataClass.SECRET]

REMOTE_DEFAULT_CEILING = DataClass.PUBLIC

# Never transmitted off-host, at any ceiling. These are hard-blocked.
NEVER_TRANSMIT = (DataClass.SECRET,)


def class_rank(cls: str) -> int:
    key = (cls or "").upper()
    return _CLASS_ORDER.index(key) if key in _CLASS_ORDER else len(_CLASS_ORDER)


def may_transmit(cls: str, ceiling: str) -> bool:
    """True only when ``cls`` is at or below the ceiling and not hard-blocked.

    Comparison is case-insensitive so a caller passing ``"public"`` is not silently
    treated as an unknown (over-ceiling) class and refused.
    """
    key = (cls or "").upper()
    if key in NEVER_TRANSMIT:
        return False
    return class_rank(key) <= class_rank(ceiling)


# --------------------------------------------------------------------------- #
# Provider specs
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ProviderSpec:
    """One provider endpoint and the facts verified about it.

    ``free_tier_note`` and ``verified_on`` are deliberately required reading:
    a provider is only "free" in the sense recorded here, on the date recorded
    here. ``data_terms_url`` points at the provider's data-handling policy, which
    mission B3 requires the operator to review before sending non-public data.
    """

    name: str
    base_url: str
    env_key: str
    default_model: str
    #: Optional per-provider model override env var. Providers retire model ids
    #: routinely (``gemini-2.0-flash`` was retired), and a retired id makes a
    #: perfectly valid credential probe as unavailable. Without an override the
    #: operator has no way to point at a live model short of editing source.
    model_env_key: str = ""
    requires_key: bool = True
    openai_compatible: bool = True
    free_tier_note: str = ""
    data_terms_url: str = ""
    verified_on: str = ""
    notes: str = ""


def resolved_model(spec: "ProviderSpec") -> str:
    """The model id actually to use: the operator override, else the pinned default.

    Resolution lives here so the health probe, the completion call and the
    *reported* model can never disagree about which id was used. They previously
    could: a probe could succeed against an overridden id while the resolution
    record still named the registry default, which reported a model that was never
    called.
    """
    override = ""
    if spec.model_env_key:
        override = os.environ.get(spec.model_env_key, "").strip()
    return override or spec.default_model


# The registry. Every entry carries a note about the free tier and a data-terms
# URL; where a provider's free tier could not be confirmed, the note says so
# rather than implying availability. Verified 2026-11-11.
PROVIDERS: list[ProviderSpec] = [
    ProviderSpec(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        env_key="OPENROUTER_API_KEY",
        default_model="meta-llama/llama-3.3-70b-instruct:free",
        free_tier_note=(
            "Has a set of ':free' model variants with per-day request caps; caps "
            "and which models are free change often and are account-specific."
        ),
        data_terms_url="https://openrouter.ai/privacy",
        verified_on="2026-11-11",
        notes="Aggregator; the free model list is the part that churns.",
    ),
    ProviderSpec(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        env_key="GROQ_API_KEY",
        default_model="llama-3.3-70b-versatile",
        free_tier_note=(
            "Free tier with per-model rate limits (requests/min and tokens/min); "
            "limits differ per model and change without notice."
        ),
        data_terms_url="https://groq.com/privacy-policy/",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        env_key="GEMINI_API_KEY",
        default_model="gemini-3.6-flash",
        model_env_key="BLACKHEART_GEMINI_MODEL",
        free_tier_note=(
            "Google AI Studio offers a free tier for several Gemini models with "
            "daily request limits; the OpenAI-compatibility endpoint is beta."
        ),
        data_terms_url="https://ai.google.dev/gemini-api/terms",
        verified_on="2026-11-24",
    ),
    ProviderSpec(
        name="nvidia-nim",
        base_url="https://integrate.api.nvidia.com/v1",
        env_key="NVIDIA_API_KEY",
        default_model="meta/llama-3.3-70b-instruct",
        free_tier_note=(
            "NVIDIA NIM offers free API credits for evaluation via build.nvidia.com; "
            "credit amounts and model availability vary."
        ),
        data_terms_url="https://www.nvidia.com/en-us/about-nvidia/privacy-policy/",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="sambanova",
        base_url="https://api.sambanova.ai/v1",
        env_key="SAMBANOVA_API_KEY",
        default_model="Meta-Llama-3.3-70B-Instruct",
        free_tier_note=(
            "Offers a free tier for developers with rate limits; exact quotas are "
            "account-specific and not published as a stable number."
        ),
        data_terms_url="https://sambanova.ai/privacy-policy",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="zai",
        base_url="https://api.z.ai/api/paas/v4",
        env_key="ZAI_API_KEY",
        default_model="glm-4.5-flash",
        free_tier_note=(
            "Offers a free 'flash' model tier; broader model access is paid. "
            "Treat free availability as changeable."
        ),
        data_terms_url="https://z.ai/terms",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="cloudflare",
        base_url="https://api.cloudflare.com/client/v4/accounts",
        env_key="CLOUDFLARE_API_TOKEN",
        default_model="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        openai_compatible=False,
        free_tier_note=(
            "Workers AI has a free daily allocation of neurons; the endpoint is "
            "account-scoped and NOT OpenAI-compatible (different path/body)."
        ),
        data_terms_url="https://www.cloudflare.com/privacypolicy/",
        verified_on="2026-11-11",
        notes="Needs the account id in the URL; adapter treats it as unsupported "
              "rather than guessing the path.",
    ),
    ProviderSpec(
        name="mistral",
        base_url="https://api.mistral.ai/v1",
        env_key="MISTRAL_API_KEY",
        default_model="mistral-small-latest",
        free_tier_note=(
            "Has offered a free experimental tier historically; current pricing "
            "and free availability must be re-checked before relying on it."
        ),
        data_terms_url="https://mistral.ai/terms/",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="cohere",
        base_url="https://api.cohere.ai/compatibility/v1",
        env_key="COHERE_API_KEY",
        default_model="command-r-07-2024",
        free_tier_note=(
            "Offers a trial key with rate limits; the compatibility endpoint is "
            "OpenAI-shaped but not every parameter is supported."
        ),
        data_terms_url="https://cohere.com/privacy",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="ollama",
        base_url="http://localhost:11434/v1",
        env_key="OLLAMA_API_KEY",
        default_model="llama3.1",
        model_env_key="BLACKHEART_OLLAMA_MODEL",
        requires_key=False,
        free_tier_note=(
            "A locally hosted OpenAI-compatible server; no cloud account and no "
            "per-token fee. Availability and model ids depend on the local install."
        ),
        data_terms_url="https://github.com/ollama/ollama",
        verified_on="2026-11-22",
        notes="Opt-in via BLACKHEART_PROVIDERS=ollama. Data stays on the host; a "
              "distinct local model can serve as an independent reviewer.",
    ),
    ProviderSpec(
        name="llm7",
        base_url="https://api.llm7.io/v1",
        env_key="LLM7_API_KEY",
        default_model="gpt-4o-mini",
        requires_key=False,
        free_tier_note=(
            "Public gateway advertising free access with an optional token for "
            "higher limits; availability is best-effort and unverified here."
        ),
        data_terms_url="https://llm7.io/",
        verified_on="2026-11-11",
        notes="requires_key=False: a token is optional, so health is probe-only.",
    ),
    ProviderSpec(
        name="cerebras",
        base_url="https://api.cerebras.ai/v1",
        env_key="CEREBRAS_API_KEY",
        default_model="llama-3.3-70b",
        free_tier_note=(
            "Offers a free tier with rate limits for developers; quotas are "
            "account-specific."
        ),
        data_terms_url="https://www.cerebras.ai/privacy-policy",
        verified_on="2026-11-11",
    ),
    ProviderSpec(
        name="kilo",
        base_url="https://api.kilocode.ai/v1",
        env_key="KILO_API_KEY",
        default_model="",
        free_tier_note=(
            "Kilo Code is primarily an IDE agent; a free OpenAI-compatible "
            "inference endpoint is not confirmed. Treat as unverified."
        ),
        data_terms_url="https://kilocode.ai/",
        verified_on="2026-11-11",
        notes="No confirmed inference endpoint; health reports the gap honestly.",
    ),
    ProviderSpec(
        name="together",
        base_url="https://api.together.xyz/v1",
        env_key="TOGETHER_API_KEY",
        default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        free_tier_note=(
            "Together historically offered free models but now is primarily "
            "paid with trial credits. Do not assume a free tier."
        ),
        data_terms_url="https://www.together.ai/privacy",
        verified_on="2026-11-11",
    ),
]

_BY_NAME = {p.name: p for p in PROVIDERS}


def all_providers() -> list[ProviderSpec]:
    return list(PROVIDERS)


def get_spec(name: str) -> ProviderSpec:
    if name not in _BY_NAME:
        raise KeyError(f"unknown provider {name!r}; known: {', '.join(_BY_NAME)}")
    return _BY_NAME[name]
