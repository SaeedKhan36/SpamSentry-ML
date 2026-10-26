"""Download labeled email corpora, fit TF-IDF + logistic regression, evaluate."""

import hashlib
import io
import json
import platform
import re
import tarfile
import zipfile
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.request import urlopen

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline

from app.ml import ROOT, normalize_text

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus/"
ARCHIVES = {
    "20030228_easy_ham.tar.bz2": 0,
    "20030228_easy_ham_2.tar.bz2": 0,
    "20030228_hard_ham.tar.bz2": 0,
    "20030228_spam.tar.bz2": 1,
    "20050311_spam_2.tar.bz2": 1,
}
SEED = 42
SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"


def read_corpus():
    cache = ROOT / "data" / "corpus"
    cache.mkdir(parents=True, exist_ok=True)
    records, archives = [], []
    skipped = 0
    for filename, label in ARCHIVES.items():
        path = cache / filename
        if not path.exists():
            print(f"Downloading {filename}", flush=True)
            with urlopen(BASE_URL + filename, timeout=90) as response:
                content = response.read()
            temporary = path.with_suffix(".download")
            temporary.write_bytes(content)
            temporary.replace(path)
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        archives.append({"url": BASE_URL + filename, "sha256": checksum, "label": label})
        # Read members in memory; no archive paths are extracted to disk.
        with tarfile.open(path, "r:bz2") as archive:
            for member in sorted(archive.getmembers(), key=lambda item: item.name):
                if not member.isfile() or not re.fullmatch(r"\d+\.[a-f0-9]+", Path(member.name).name):
                    continue
                message = BytesParser(policy=policy.default).parsebytes(archive.extractfile(member).read())
                try:
                    part = message.get_body(preferencelist=("plain", "html"))
                except (AttributeError, TypeError, ValueError):
                    skipped += 1
                    continue
                if part is None:
                    skipped += 1
                    continue
                try:
                    body = part.get_content()
                except (LookupError, UnicodeError):
                    body = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
                if not isinstance(body, str) or not body.strip():
                    skipped += 1
                    continue
                body = body[:50000]
                subject = str(message.get("Subject", ""))[:998]
                # Body-only hashes also group messages with changed subjects.
                body_key = hashlib.sha256(normalize_text("", body).encode()).hexdigest()
                text = normalize_text(subject, body)
                records.append({"body_key": body_key, "text": text, "label": label, "source": "email"})
    # Labeled short-message data supports pasted snippets; report domains separately.
    sms_path = cache / "sms_spam_collection.zip"
    if not sms_path.exists():
        print("Downloading UCI SMS Spam Collection", flush=True)
        with urlopen(SMS_URL, timeout=90) as response:
            content = response.read()
        sms_path.write_bytes(content)
    archives.append({"url": SMS_URL, "sha256": hashlib.sha256(sms_path.read_bytes()).hexdigest(), "label": "per-row ham/spam", "license": "CC BY 4.0", "citation": "Almeida, T. & Hidalgo, J. (2011). SMS Spam Collection. UCI. DOI: 10.24432/C5CC84"})
    with zipfile.ZipFile(io.BytesIO(sms_path.read_bytes())) as archive:
        for line in archive.read("SMSSpamCollection").decode("utf-8").splitlines():
            if not line.strip():
                continue
            label, body = line.split("\t", 1)
            text = normalize_text("", body)
            records.append({"body_key": hashlib.sha256(text.encode()).hexdigest(), "text": text, "label": int(label == "spam"), "source": "sms"})
    labels = {}
    for record in records:
        labels.setdefault(record["body_key"], set()).add(record["label"])
    unique = {}
    for record in records:
        if len(labels[record["body_key"]]) == 1:
            unique.setdefault(record["body_key"], record)
    return [unique[key] for key in sorted(unique)], archives, len(records), skipped


def evaluate(model, texts, labels):
    probability = model.predict_proba(texts)[:, 1]
    predicted = probability >= 0.5
    return {"accuracy": float(accuracy_score(labels, predicted)),
            "spam_precision": float(precision_score(labels, predicted, zero_division=0)),
            "spam_recall": float(recall_score(labels, predicted, zero_division=0)),
            "spam_f1": float(f1_score(labels, predicted, zero_division=0)),
            "roc_auc": float(roc_auc_score(labels, probability)),
            "average_precision": float(average_precision_score(labels, probability)),
            "confusion_matrix_ham_spam": confusion_matrix(labels, predicted, labels=[0, 1]).tolist(),
            "review_or_spam_recall_at_020": float(recall_score(labels, probability >= 0.2)),
            "ham_review_or_spam_rate_at_020": float(np.mean(probability[np.asarray(labels) == 0] >= 0.2))}


def main():
    records, archives, raw_count, skipped = read_corpus()
    strata = lambda rows: [f"{row['source']}:{row['label']}" for row in rows]
    train, remainder = train_test_split(records, test_size=0.3, stratify=strata(records), random_state=SEED)
    validation, test = train_test_split(remainder, test_size=0.5, stratify=strata(remainder), random_state=SEED)
    texts = lambda rows: [row["text"] for row in rows]
    labels = lambda rows: [row["label"] for row in rows]
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.98, max_features=60000, sublinear_tf=True, strip_accents="unicode")),
        ("classifier", LogisticRegression(C=4.0, class_weight="balanced", solver="liblinear", max_iter=1000, random_state=SEED)),
    ])
    print(f"Fitting on {len(train)} labeled messages; validation={len(validation)}, test={len(test)}", flush=True)
    model.fit(texts(train), labels(train))
    # A genuine supervised baseline, using the training vocabulary only.
    baseline = Pipeline([("tfidf", model.named_steps["tfidf"]), ("classifier", ComplementNB(alpha=1.0))])
    baseline.named_steps["classifier"].fit(model.named_steps["tfidf"].transform(texts(train)), labels(train))
    report = {
        "model_version": "tfidf-lr-v1.0", "dataset": "Apache SpamAssassin emails + auxiliary UCI SMS Spam Collection",
        "dataset_source": BASE_URL, "archives": archives,
        "parsed_messages": raw_count, "skipped_malformed_or_empty": skipped, "unique_messages": len(records), "removed_duplicates_or_conflicts": raw_count - len(records),
        "deduplication": "SHA-256 of normalized body; remove conflicting-label bodies, keep one copy otherwise; near-duplicates may remain",
        "seed": SEED, "split": "stratified by source and label, 70/15/15; vocabulary and IDF fitted on training only",
        "splits": {name: {"total": len(rows), "ham": labels(rows).count(0), "spam": labels(rows).count(1)} for name, rows in [("train", train), ("validation", validation), ("test", test)]},
        "split_body_hashes": {name: [row["body_key"] for row in rows] for name, rows in [("train", train), ("validation", validation), ("test", test)]},
        "algorithm": "L2-regularized logistic regression; balanced class weights; C=4; liblinear",
        "features": "TF-IDF word unigrams/bigrams; sublinear term frequency; L2 normalization; max 60000; min_df=2; max_df=0.98",
        "feature_count": len(model.named_steps["tfidf"].vocabulary_),
        "policy": {"review_score": 20, "spam_score": 50, "selection": "Predeclared conservative review policy, not tuned on test data; app applies thresholds after integer rounding and security checks"},
        "validation": evaluate(model, texts(validation), labels(validation)),
        "test": evaluate(model, texts(test), labels(test)),
        "test_by_domain": {source: evaluate(model, texts([row for row in test if row["source"] == source]), labels([row for row in test if row["source"] == source])) for source in ("email", "sms")},
        "domain_counts": {source: {name: sum(row["source"] == source for row in rows) for name, rows in [("train", train), ("validation", validation), ("test", test)]} for source in ("email", "sms")},
        "complement_naive_bayes_test": evaluate(baseline, texts(test), labels(test)),
        "majority_baseline_test_accuracy": max(Counter(labels(test)).values()) / len(test),
        "evaluation_scope": "Text model only; supplemental security rules are not included in these metrics. Final saved model is the evaluated training-split model, without refitting on validation/test.",
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": np.__version__, "scipy": scipy.__version__, "joblib": joblib.__version__},
        "limitations": ["Historical English-heavy email and auxiliary SMS data; not a modern phishing benchmark.", "SMS supports short-text classification but introduces domain differences from email.", "Random holdout is not temporal or thread-separated; near-duplicates and thread overlap can inflate performance.", "Probability estimates are not independently calibrated; conservative review can flag legitimate messages.", "No sender authentication, link browsing, attachment inspection, or safety guarantee."]}
    output = ROOT / "models"
    output.mkdir(exist_ok=True)
    joblib.dump(model, output / "spam_classifier.joblib", compress=3)
    report["artifact_sha256"] = hashlib.sha256((output / "spam_classifier.joblib").read_bytes()).hexdigest()
    (output / "training_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("unique_messages", "splits", "feature_count", "test", "versions")}, indent=2), flush=True)


if __name__ == "__main__":
    main()
