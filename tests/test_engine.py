import pytest

from app.engine import classify
from app.schemas import EmailInput


def test_normal_message_is_not_classified_as_spam():
    result = classify(EmailInput(sender="alex@example.com", subject="Lunch?", body="Hi, are you free for lunch tomorrow? Best, Alex"))
    # Conservative review can flag benign text; it should not be labeled spam.
    assert result["verdict"] in ("safe", "suspicious")
    assert result["score"] < 50
    assert {signal["id"] for signal in result["signals"]} == {"ml_model"}


def test_phishing_is_flagged_with_explanations():
    result = classify(EmailInput(sender="PayPal Security <security@evil.example>", subject="Urgent account warning",
                                 body="Verify your account immediately. Please enter your password at http://bit.ly/check !!!"))
    assert result["verdict"] == "spam"
    assert 55 <= result["score"] <= 100
    assert {"credentials", "urgency", "short_link", "insecure_link", "brand_mismatch"} <= {signal["id"] for signal in result["signals"]}
    assert sum(result["categories"].values()) >= result["score"]


def test_rule_matches_are_case_insensitive_and_not_repeated_points():
    once = classify(EmailInput(body="Please verify your account."))
    repeated = classify(EmailInput(body="Please VERIFY YOUR ACCOUNT. Please verify your account."))
    for result in (once, repeated):
        credentials = next(signal for signal in result["signals"] if signal["id"] == "credentials")
        assert credentials["points"] == 40
        assert result["verdict"] in ("suspicious", "spam")


@pytest.mark.parametrize("sender", ["PayPal <support@paypal.com>", "PayPal <support@mail.paypal.com>"])
def test_legitimate_brand_domain_does_not_trigger_mismatch(sender):
    result = classify(EmailInput(sender=sender, body="Hello, here is your monthly summary."))
    assert "brand_mismatch" not in [signal["id"] for signal in result["signals"]]


def test_lookalike_brand_domain_is_not_trusted():
    result = classify(EmailInput(sender="PayPal <support@paypal.com.evil.example>", body="Hello there."))
    assert "brand_mismatch" in [signal["id"] for signal in result["signals"]]


def test_ip_links_and_trailing_punctuation():
    result = classify(EmailInput(body="See http://192.0.2.1/login. Also https://tinyurl.com/demo."))
    assert result["link_count"] == 2
    assert {"ip_link", "insecure_link", "short_link"} <= {signal["id"] for signal in result["signals"]}


def test_malformed_url_does_not_crash_engine():
    result = classify(EmailInput(body="Try https://[broken/ and see the details."))
    assert result["link_count"] == 1


def test_whitespace_body_is_rejected():
    with pytest.raises(ValueError):
        EmailInput(body="  \n ")
