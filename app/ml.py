"""Shared text preprocessing and inference for the fitted text classifier."""

import json
import re
from functools import lru_cache
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "spam_classifier.joblib"
REPORT_PATH = ROOT / "models" / "training_report.json"


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def normalize_text(subject: str, body: str) -> str:
    """Use the same visible text representation in training and prediction."""
    if re.search(r"</?(?:html|body|div|p|br|table|a)\b", body, re.I):
        parser = VisibleText()
        parser.feed(body)
        body = " ".join(parser.parts)
    return re.sub(r"\s+", " ", unescape(subject + "\n" + body)).strip().lower()


@lru_cache(maxsize=1)
def load_model():
    if not MODEL_PATH.is_file():
        raise RuntimeError("ML artifact missing. Run: python -m ml.train")
    # Only load the repository's locally trained artifact; never user uploads.
    return joblib.load(MODEL_PATH)


@lru_cache(maxsize=1)
def model_metadata():
    return json.loads(REPORT_PATH.read_text())


def predict(subject: str, body: str) -> dict:
    pipeline = load_model()
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]
    features = vectorizer.transform([normalize_text(subject, body)])
    probability = float(classifier.predict_proba(features)[0, 1])
    # These are learned per-feature log-odds contributions, not policy points.
    contributions = features.multiply(classifier.coef_[0]).tocsr()
    names = vectorizer.get_feature_names_out()
    strongest = sorted(zip(contributions.indices, contributions.data), key=lambda item: -abs(item[1]))[:6]
    return {"probability": probability,
            "evidence": [f"{names[index]}: {value:+.3f} log-odds" for index, value in strongest]}
