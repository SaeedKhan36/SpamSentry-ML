import hashlib

import numpy as np
import pytest

from app.engine import classify
from app.ml import MODEL_PATH, load_model, model_metadata, normalize_text, predict
from app.schemas import EmailInput


def test_trained_artifact_matches_report_and_has_learned_parameters():
    report = model_metadata()
    model = load_model()
    assert hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest() == report["artifact_sha256"]
    assert len(model.named_steps["tfidf"].vocabulary_) == report["feature_count"]
    assert np.any(model.named_steps["classifier"].coef_ > 0)
    assert np.any(model.named_steps["classifier"].coef_ < 0)
    splits = [set(values) for values in report["split_body_hashes"].values()]
    assert len(set.union(*splits)) == sum(map(len, splits)) == report["unique_messages"]
    matrix = report["test"]["confusion_matrix_ham_spam"]
    assert sum(map(sum, matrix)) == report["splits"]["test"]["total"]


def test_model_returns_text_evidence_and_varies_with_content():
    ham = predict("Team lunch", "Hi, shall we meet for lunch tomorrow? Best, Alex")
    spam = predict("Cash rewards", "Congratulations! You won a free luxury vacation. Claim your prize now.")
    assert 0 <= ham["probability"] < spam["probability"] <= 1
    assert spam["evidence"]
    assert all("log-odds" in item for item in spam["evidence"])


@pytest.mark.parametrize("probability,expected", [(0.19, "safe"), (0.20, "suspicious"), (0.49, "suspicious"), (0.50, "spam"), (0.99, "spam")])
def test_model_drives_classification_without_matching_security_rules(monkeypatch, probability, expected):
    monkeypatch.setattr("app.engine.predict", lambda *args: {"probability": probability, "evidence": []})
    result = classify(EmailInput(body="A neutral message."))
    assert result["verdict"] == expected
    assert result["score"] == round(100 * probability)


def test_security_checks_cannot_be_overridden_by_low_model_score(monkeypatch):
    monkeypatch.setattr("app.engine.predict", lambda *args: {"probability": 0.01, "evidence": []})
    result = classify(EmailInput(body="Verify your account immediately."))
    assert result["verdict"] == "spam"
    assert result["score"] == 60


def test_training_and_inference_normalize_visible_html():
    assert normalize_text("Hello", "<p>Hi &amp; welcome</p><script>hidden</script>") == "hello hi & welcome"


def test_model_metadata_api(client):
    response = client.get("/api/model")
    assert response.status_code == 200
    assert response.json()["feature_count"] > 1000
    assert "split_body_hashes" not in response.json()
