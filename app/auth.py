"""Verify Clerk browser session JWTs with the instance's cached public signing keys."""

import base64
import os
import re
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer = HTTPBearer(auto_error=False)


def publishable_key() -> str:
    return (os.getenv("CLERK_PUBLISHABLE_KEY") or os.getenv("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY") or "").strip()


def clerk_domain() -> str:
    key = publishable_key()
    if not re.fullmatch(r"pk_(?:test|live)_[A-Za-z0-9+/=]+", key):
        raise ValueError("A valid Clerk publishable key is required.")
    encoded = key.split("_", 2)[2]
    decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True).decode("ascii")
    if not decoded.endswith("$"):
        raise ValueError("Invalid Clerk publishable key domain.")
    domain = decoded[:-1]
    if len(domain) > 253 or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", domain) or "." not in domain:
        raise ValueError("Invalid Clerk publishable key domain.")
    return domain.lower()


@lru_cache(maxsize=4)
def signing_keys(issuer: str):
    # Never follow a JWT-supplied issuer or jku URL. Only this configured instance.
    return jwt.PyJWKClient(issuer + "/.well-known/jwks.json", lifespan=300, timeout=5)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "Sign in to continue.", headers={"WWW-Authenticate": "Bearer"})
    if len(credentials.credentials) > 16384:
        raise HTTPException(401, "Invalid session.", headers={"WWW-Authenticate": "Bearer"})
    try:
        issuer = "https://" + clerk_domain()
    except (ValueError, UnicodeError):
        raise HTTPException(503, "Authentication is not configured yet.")
    token = credentials.credentials
    try:
        # Reject non-RSA tokens before any network request.
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or not header["kid"]:
            raise jwt.InvalidTokenError("Unsupported session token.")
        key = signing_keys(issuer).get_signing_key_from_jwt(token).key
        audience = os.getenv("CLERK_AUDIENCE") or None
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=issuer, audience=audience,
                            options={"require": ["exp", "iat", "nbf", "iss", "sub", "sid", "azp"], "verify_aud": bool(audience)})
        allowed = {origin.strip().rstrip("/") for origin in os.getenv("CLERK_AUTHORIZED_PARTIES", "http://127.0.0.1:8000,http://localhost:8000").split(",") if origin.strip()}
        if claims["azp"] not in allowed or claims.get("sts", "active") != "active":
            raise jwt.InvalidTokenError("Session is not authorized for this application.")
        if not isinstance(claims["sub"], str) or not claims["sub"].startswith("user_") or len(claims["sub"]) > 255:
            raise jwt.InvalidTokenError("Invalid user.")
        if not isinstance(claims["sid"], str) or not claims["sid"].startswith("sess_"):
            raise jwt.InvalidTokenError("Invalid session.")
        return claims["sub"]
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(503, "Unable to verify your session right now. Please try again.")
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise HTTPException(401, "Your session is invalid or expired. Please sign in again.", headers={"WWW-Authenticate": "Bearer"})
