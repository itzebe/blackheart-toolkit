"""You.com-first default for external help (pure, no network)."""

from blackheart.intelligence.ask import ORDER_ENV, provider_order
from blackheart.intelligence.providers import DEFAULT_ORDER


def test_provider_order_is_youcom_first():
    assert provider_order() == DEFAULT_ORDER
    assert provider_order()[0] == "you.com"


def test_provider_order_env_override(monkeypatch):
    monkeypatch.setenv(ORDER_ENV, "duckduckgo, wikipedia")
    assert provider_order() == ("duckduckgo", "wikipedia")
