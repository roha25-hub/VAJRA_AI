"""Attack attribution — TF-IDF nearest-archetype classifier.

Given the raw payload (and optionally recent untrusted context) of an
attack, returns the most likely named pattern + family + confidence.

Offline, zero LLM, trained once at import time from `library.py`. Uses
word + char n-grams so it's resilient to minor rephrasing / obfuscation.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import FeatureUnion

from .library import LIBRARY, AttackArchetype, archetypes_by_pattern


@dataclass
class Attribution:
    pattern: str                   # machine key, e.g. 'dan_jailbreak'
    label: str                     # human label
    family: str                    # jailbreak | social_engineering | ...
    severity: str                  # low | medium | high | critical
    confidence: float              # 0..1 cosine similarity
    runners_up: list[dict[str, Any]]  # top 2 alternatives for the UI

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern, "label": self.label,
            "family": self.family, "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "runners_up": self.runners_up,
        }


@lru_cache(maxsize=1)
def _trained():
    """Build the vectorizer + matrix once per process."""
    texts = [a.text for a in LIBRARY]
    vec = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), lowercase=True,
                                 min_df=1, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                 lowercase=True, min_df=1, sublinear_tf=True)),
    ])
    X = vec.fit_transform(texts)
    return vec, X


MIN_CONFIDENCE = 0.12   # below this we return 'unknown'


def classify(payload: str, extra_context: str = "") -> Attribution:
    """Return the most similar archetype for `payload`.

    `extra_context` can carry additional untrusted snippets the guardian
    saw during the attack (concatenated). Weighted lightly.
    """
    if not payload or not payload.strip():
        return Attribution("unknown", "Unknown pattern",
                           "unknown", "low", 0.0, [])

    text = payload
    if extra_context:
        text = payload + "\n---\n" + extra_context[:1200]

    vec, X = _trained()
    q = vec.transform([text])
    sims = cosine_similarity(q, X).ravel()

    # Pool per-pattern (max across its archetypes)
    by_pattern: dict[str, tuple[float, AttackArchetype]] = {}
    for i, a in enumerate(LIBRARY):
        cur = by_pattern.get(a.pattern)
        if cur is None or sims[i] > cur[0]:
            by_pattern[a.pattern] = (float(sims[i]), a)

    ranked = sorted(by_pattern.items(), key=lambda kv: kv[1][0], reverse=True)
    top_pat, (top_score, top_arch) = ranked[0]

    runners_up = [
        {"pattern": p, "label": a[1].label,
         "confidence": round(float(a[0]), 3)}
        for p, a in ranked[1:3]
    ]

    if top_score < MIN_CONFIDENCE:
        return Attribution(
            "unknown", "Unknown pattern (low similarity to known families)",
            "unknown", "low", float(top_score), runners_up,
        )

    return Attribution(
        pattern=top_pat,
        label=top_arch.label,
        family=top_arch.family,
        severity=top_arch.severity,
        confidence=float(top_score),
        runners_up=runners_up,
    )


def known_patterns() -> list[dict[str, str]]:
    """List of patterns we can recognize, for the dashboard legend."""
    out = []
    for p, a in archetypes_by_pattern().items():
        out.append({"pattern": p, "label": a.label,
                    "family": a.family, "severity": a.severity})
    return out
