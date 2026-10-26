import base64
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, inspect, text

from app.auth import clerk_domain, current_user
from app.database import initialize_database
from app.main import app


@pytest.mark.parametrize("method,url", [("get", "/api/analyses"), ("get", "/api/stats"), ("get", "/api/export"),
                                      ("get", "/api/analyses/some-id"), ("get", "/api/rules"), ("get", "/api/model"), ("get", "/api/me"),
                                      ("post", "/api/analyze"), ("post", "/api/import")])
def test_private_endpoints_require_sign_in(client, method, url):
    app.dependency_overrides.pop(current_user)
    options = {"json": {"body": "An email."}} if url == "/api/analyze" else {}
    if url == "/api/import":
        options = {"files": {"file": ("note.txt", b"Hello", "text/plain")}}
    response = getattr(client, method)(url, **options)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_history_reports_stats_and_exports_are_owned(client):
    alex = client.post("/api/analyze", json={"subject": "Alex private message", "body": "Coffee tomorrow?"}).json()
    app.dependency_overrides[current_user] = lambda: "user_test_jamie"
    assert client.get("/api/analyses").json()["total"] == 0
    assert client.get("/api/stats").json()["total"] == 0
    assert client.get("/api/analyses/" + alex["id"]).status_code == 404
    assert "Alex private message" not in client.get("/api/export").text
    jamie = client.post("/api/analyze", json={"subject": "Jamie private message", "body": "Hello there."}).json()
    assert client.get("/api/analyses").json()["total"] == 1
    assert client.get("/api/stats").json()["safe"] == 1
    app.dependency_overrides[current_user] = lambda: "user_test_alex"
    assert client.get("/api/analyses/" + jamie["id"]).status_code == 404
    assert client.get("/api/analyses").json()["items"][0]["id"] == alex["id"]
    assert "Jamie private message" not in client.get("/api/export").text


@pytest.fixture
def jwt_session(client, monkeypatch):
    app.dependency_overrides.pop(current_user)
    domain = "example.clerk.accounts.dev"
    monkeypatch.setenv("CLERK_PUBLISHABLE_KEY", "pk_test_" + base64.b64encode((domain + "$").encode()).decode())
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "http://127.0.0.1:8000")
    monkeypatch.delenv("CLERK_AUDIENCE", raising=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr("app.auth.signing_keys", lambda issuer: SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key())))

    def make_token(changes=None, signing_key=None):
        now = int(time.time())
        claims = {"sub": "user_signed", "sid": "sess_signed", "iss": "https://" + domain,
                  "iat": now - 5, "nbf": now - 5, "exp": now + 60, "azp": "http://127.0.0.1:8000", "v": 2}
        claims.update(changes or {})
        return jwt.encode(claims, signing_key or key, algorithm="RS256", headers={"kid": "test-key"})

    return make_token


def test_signed_session_is_verified(client, jwt_session):
    response = client.get("/api/me", headers={"Authorization": "Bearer " + jwt_session()})
    assert response.status_code == 200
    assert response.json() == {"user_id": "user_signed"}


@pytest.mark.parametrize("changes", [{"exp": 1}, {"nbf": int(time.time()) + 3600}, {"iss": "https://evil.example"},
                                     {"azp": "https://untrusted.example"}, {"sts": "pending"}, {"sub": ""}, {"sid": ""}])
def test_rejects_invalid_session_claims(client, jwt_session, changes):
    response = client.get("/api/me", headers={"Authorization": "Bearer " + jwt_session(changes)})
    assert response.status_code == 401


def test_rejects_wrong_signature(client, jwt_session):
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    response = client.get("/api/me", headers={"Authorization": "Bearer " + jwt_session(signing_key=wrong_key)})
    assert response.status_code == 401


def test_rejects_unsigned_or_malformed_tokens(client):
    app.dependency_overrides.pop(current_user)
    unsigned = jwt.encode({"sub": "user_fake"}, key="", algorithm="none")
    for token in [unsigned, "not-a-jwt"]:
        assert client.get("/api/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_configuration_never_exposes_secret_keys(client, monkeypatch):
    monkeypatch.setenv("CLERK_SECRET_KEY", "private-server-secret")
    response = client.get("/api/auth/config")
    assert response.status_code == 200
    assert "private-server-secret" not in response.text
    assert "CLERK_SECRET_KEY" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_unconfigured_auth_fails_closed(client, monkeypatch):
    app.dependency_overrides.pop(current_user)
    monkeypatch.delenv("CLERK_PUBLISHABLE_KEY", raising=False)
    monkeypatch.delenv("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", raising=False)
    assert client.get("/api/auth/config").json()["configured"] is False
    assert client.get("/api/me", headers={"Authorization": "Bearer fake"}).status_code == 503


def test_publishable_key_domain_validation(monkeypatch):
    for value in ["", "sk_test_secret", "pk_test_!!!", "pk_test_" + base64.b64encode(b"evil.example/path$").decode()]:
        monkeypatch.setenv("CLERK_PUBLISHABLE_KEY", value)
        with pytest.raises(ValueError):
            clerk_domain()


def test_ownership_migration_preserves_unassigned_history(tmp_path):
    bind = create_engine("sqlite:///" + str(tmp_path / "legacy.db"))
    with bind.begin() as connection:
        connection.execute(text("CREATE TABLE analyses (id VARCHAR(36) PRIMARY KEY, subject VARCHAR(998))"))
        connection.execute(text("INSERT INTO analyses (id, subject) VALUES ('old', 'An old analysis')"))
    initialize_database(bind)
    initialize_database(bind)
    with bind.connect() as connection:
        assert "user_id" in {column["name"] for column in inspect(connection).get_columns("analyses")}
        assert connection.execute(text("SELECT user_id FROM analyses WHERE id = 'old'")).scalar() is None
        assert connection.execute(text("SELECT subject FROM analyses WHERE id = 'old'")).scalar() == "An old analysis"
    bind.dispose()
