"""Layer 3: learned classifier (plan §6.5.3).

TF-IDF (word 1–2grams + char 3–5grams) + logistic regression. Trained on
TRAIN-split attack payloads vs. benign email bodies. Zero API calls.

The classifier scores the CONCATENATED set of untrusted content in context,
not the tool call itself — we want to detect "there's an injection in the
inputs" and block risky tool calls while that score is high.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Iterable

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .decisions import Decision


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "data" / "detector.pkl"


# Hazard threshold: above this, a HIGH_RISK call gets blocked.
BLOCK_THRESHOLD = 0.60
HIGH_RISK = {"pay", "send_email", "read_file"}


def _build_pipeline() -> Pipeline:
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                     min_df=1, max_features=4000)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                     min_df=1, max_features=4000)),
        ])),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0)),
    ])


def train(attack_texts: Iterable[str], benign_texts: Iterable[str],
          out_path: Path = MODEL_PATH) -> dict[str, Any]:
    X = list(attack_texts) + list(benign_texts)
    y = [1] * len(list(attack_texts := list(attack_texts))) + [0] * len(list(benign_texts := list(benign_texts)))
    # (re-materialize due to generator-exhaustion in the trick above)
    X = attack_texts + benign_texts
    y = [1] * len(attack_texts) + [0] * len(benign_texts)
    if len(set(y)) < 2:
        raise ValueError("need both attack and benign samples to train")

    pipe = _build_pipeline()
    pipe.fit(X, y)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(pipe, f)
    return {"n_attack": len(attack_texts), "n_benign": len(benign_texts),
            "train_acc": float(pipe.score(X, y))}


_cache: Pipeline | None = None


def retrain_with(extra_attack_texts: list[str],
                 extra_benign_texts: list[str] | None = None,
                 base_attacks: list[str] | None = None,
                 base_benign: list[str] | None = None) -> dict[str, Any]:
    """Retrain the classifier with new examples appended to the base set.

    Called between rounds to teach the guardian the round's successful attacks.
    """
    global _cache
    attacks = list(base_attacks or []) + list(extra_attack_texts or [])
    benign = list(base_benign or []) + list(extra_benign_texts or [])
    if not attacks or not benign:
        return {"skipped": True, "reason": "need both attack and benign samples"}
    stats = train(attacks, benign)
    _cache = None  # force reload from disk
    return stats


def load() -> Pipeline | None:
    global _cache
    if _cache is not None:
        return _cache
    if not MODEL_PATH.exists():
        return None
    with open(MODEL_PATH, "rb") as f:
        _cache = pickle.load(f)
    return _cache


def score_text(text: str) -> float:
    pipe = load()
    if pipe is None or not text.strip():
        return 0.0
    return float(pipe.predict_proba([text])[0, 1])


def score_snippets(snippets: list[str]) -> float:
    """Score each snippet separately; return the max.

    Scoring one giant concatenation dilutes the attack signal when the
    inbox also contains legit emails. Per-snippet max captures "the
    worst thing seen so far".
    """
    pipe = load()
    if pipe is None or not snippets:
        return 0.0
    texts = [s for s in snippets if s and s.strip()]
    if not texts:
        return 0.0
    probs = pipe.predict_proba(texts)[:, 1]
    return float(max(probs))


def check(snippets: list[str], tool: str, _args: dict[str, Any]) -> Decision:
    if tool not in HIGH_RISK:
        return Decision("pass", "classifier")
    s = score_snippets(snippets)
    if s >= BLOCK_THRESHOLD:
        return Decision("block", "classifier",
                        f"injection score {s:.2f} ≥ {BLOCK_THRESHOLD}")
    return Decision("pass", "classifier", f"score={s:.2f}")
