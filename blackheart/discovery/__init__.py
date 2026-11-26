"""Discovery capability: historical-rediscovery benchmarking and economic analysis.

This package upgrades BLACKHEART from hypothesis generation toward independent
vulnerability discovery. It reuses the existing engines rather than duplicating
them:

  * :mod:`blackheart.discovery.corpus` -- a traceable historical vulnerability
    corpus with faithful vulnerable/patched models.
  * :mod:`blackheart.discovery.heldout` -- the blind holdout cases, kept apart.
  * :mod:`blackheart.discovery.harness` -- runs the existing invariant engine and
    the statespace engine over the corpus and reports honest metrics.
  * :mod:`blackheart.discovery.economic` -- economic-invariant analysis and
    capital/profit accounting for a discovered violation.
  * :mod:`blackheart.discovery.missed` -- assigns each miss to a subsystem.
"""

from . import corpus, economic, harness, heldout, missed  # noqa: F401

__all__ = ["corpus", "heldout", "harness", "economic", "missed"]
