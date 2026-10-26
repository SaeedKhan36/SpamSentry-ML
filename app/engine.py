"""Trained text classification with a conservative supplemental security policy."""

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlparse

from app.schemas import EmailInput, Signal
from app.ml import predict

ENGINE_VERSION = "tfidf-lr-rules-v2.0"
CATEGORIES = ["Model", "Language", "Links", "Sender", "Formatting"]
RULES = [
    {"id": "credentials", "name": "Sensitive information request", "category": "Language", "points": 40,
     "description": "Requests passwords, banking details, or identity verification.",
     "patterns": [r"\b(?:verify|confirm|update)\s+your\s+(?:account|password|identity|bank(?:ing)?\s+details)\b", r"\b(?:send|enter|provide|share)\s+(?:us\s+)?your\s+(?:password|credit card|bank details|otp|one.time (?:code|password))\b"]},
    {"id": "urgency", "name": "Pressure & urgency", "category": "Language", "points": 20,
     "description": "Uses time pressure, threats, or urgent calls to action.",
     "patterns": [r"\b(?:urgent|immediately|act now|last chance|final warning|within 24 hours|account (?:will be |has been )?(?:suspended|blocked|closed))\b"]},
    {"id": "prize", "name": "Unexpected reward", "category": "Language", "points": 35,
     "description": "Promises unsolicited prizes, lottery winnings, or free money.",
     "patterns": [r"\b(?:claim your (?:prize|reward)|you(?:'ve| have)? (?:been selected|won)|lottery|cash prize|free money|million dollars)\b"]},
    {"id": "money", "name": "Financial solicitation", "category": "Language", "points": 30,
     "description": "Requests transfers or promotes unusually profitable financial offers.",
     "patterns": [r"\b(?:wire transfer|processing fee|guaranteed (?:returns?|profit)|risk.free investment|double your (?:money|income)|send (?:money|bitcoin)|gift cards?)\b"]},
    {"id": "marketing", "name": "Promotional language", "category": "Language", "points": 10,
     "description": "Contains common commercial and bulk marketing phrases.",
     "patterns": [r"\b(?:limited.time offer|buy now|exclusive deal|discount|unsubscribe|special offer|free trial)\b"]},
    {"id": "short_link", "name": "Shortened destination", "category": "Links", "points": 20,
     "description": "Contains a link shortener that hides the final destination."},
    {"id": "insecure_link", "name": "Unencrypted link", "category": "Links", "points": 10,
     "description": "Contains an HTTP link without transport encryption."},
    {"id": "ip_link", "name": "IP address destination", "category": "Links", "points": 25,
     "description": "Links directly to an IP address instead of a named website."},
    {"id": "many_links", "name": "High link volume", "category": "Links", "points": 15,
     "description": "Contains five or more links."},
    {"id": "sender_format", "name": "Unusual sender format", "category": "Sender", "points": 15,
     "description": "A supplied sender does not have a recognizable email address."},
    {"id": "brand_mismatch", "name": "Brand / sender mismatch", "category": "Sender", "points": 30,
     "description": "The sender display name uses a known brand with a different domain. This is a limited heuristic, not authentication."},
    {"id": "caps", "name": "Excessive capitalization", "category": "Formatting", "points": 12,
     "description": "More than 55% of letters are uppercase (at least 20 letters)."},
    {"id": "punctuation", "name": "Repeated punctuation", "category": "Formatting", "points": 10,
     "description": "Uses three or more exclamation or question marks together."},
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd", "ow.ly", "cutt.ly"}
BRANDS = {"paypal": ("paypal.com",), "microsoft": ("microsoft.com", "outlook.com", "accountprotection.microsoft.com"), "amazon": ("amazon.com", "amazon.in"), "apple": ("apple.com", "icloud.com"), "google": ("google.com",)}


def classify(email: EmailInput) -> dict:
    content = email.subject + "\n" + email.body
    links = re.findall(r"https?://[^\s<>\"']+", content, flags=re.I)
    signals = []

    def add(rule_id, matches):
        rule = next(rule for rule in RULES if rule["id"] == rule_id)
        signals.append(Signal(id=rule_id, name=rule["name"], category=rule["category"],
                              points=rule["points"], explanation=rule["description"],
                              matches=list(dict.fromkeys(matches))[:5]))

    for rule in RULES:
        matches = [match.group(0) for pattern in rule.get("patterns", [])
                   for match in re.finditer(pattern, content, re.I)]
        if matches:
            add(rule["id"], matches)

    shortened, insecure, numeric = [], [], []
    for link in links:
        try:
            parsed = urlparse(link.rstrip(".,;!?)"))
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host in SHORTENERS:
            shortened.append(link)
        if parsed.scheme.lower() == "http":
            insecure.append(link)
        try:
            ipaddress.ip_address(host)
            numeric.append(link)
        except ValueError:
            pass
    for rule_id, matches in [("short_link", shortened), ("insecure_link", insecure), ("ip_link", numeric)]:
        if matches:
            add(rule_id, matches)
    if len(links) >= 5:
        add("many_links", [str(len(links)) + " links detected"])

    display, address = parseaddr(email.sender)
    valid_sender = bool(re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", address))
    if email.sender and not valid_sender:
        add("sender_format", [email.sender])
    if valid_sender:
        domain = address.rsplit("@", 1)[-1].lower().rstrip(".")
        mismatches = []
        for brand, allowed in BRANDS.items():
            if re.search(r"\b" + brand + r"\b", display, re.I) and not any(domain == item or domain.endswith("." + item) for item in allowed):
                mismatches.append(display + " <" + address + ">")
        if mismatches:
            add("brand_mismatch", mismatches)

    letters = [char for char in content if char.isalpha()]
    if len(letters) >= 20 and sum(char.isupper() for char in letters) / len(letters) > 0.55:
        add("caps", ["High uppercase ratio"])
    punctuation = re.findall(r"[!?]{3,}", content)
    if punctuation:
        add("punctuation", punctuation)

    policy_score = min(100, sum(signal.points for signal in signals))
    prediction = predict(email.subject, email.body)
    model_score = round(prediction["probability"] * 100)
    signals.append(Signal(
        id="ml_model", name="Trained text classifier", category="Model", points=model_score,
        explanation=(f"TF-IDF + logistic regression estimates {prediction['probability']:.1%} spam likelihood. "
                     "Displayed terms are learned log-odds contributions: positive favors spam, negative favors ham. "
                     "The final risk score is the higher of model score and supplemental security points; they are not added."),
        matches=prediction["evidence"]))
    score = max(model_score, policy_score)
    verdict = "spam" if score >= 50 else "suspicious" if score >= 20 else "safe"
    summaries = {
        "spam": "The trained classifier or security checks flagged this email as likely spam. Avoid its links and verify the sender independently.",
        "suspicious": "This email has signals worth checking. Review the findings before responding or opening links.",
        "safe": "The classifier estimates low spam likelihood and security checks found few indicators. This does not verify the sender or establish that the content is true.",
    }
    return {"verdict": verdict, "score": score, "summary": summaries[verdict],
            "signals": [signal.model_dump() for signal in sorted(signals, key=lambda signal: -signal.points)],
            "categories": {category: sum(signal.points for signal in signals if signal.category == category) for category in CATEGORIES},
            "word_count": len(email.body.split()), "link_count": len(links), "engine_version": ENGINE_VERSION}
