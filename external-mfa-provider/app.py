import base64
from contextlib import closing
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import time
from uuid import UUID

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, make_response, render_template, request
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

app = Flask(__name__)

ISSUER = (
    "https://authge-external-mfa-lab-e5cucad6gxe5gzc9"
    ".japanwest-01.azurewebsites.net"
)
CERT_PATH = Path(__file__).resolve().parent / "cert.pem"
PRIVATE_KEY_PATH = CERT_PATH.with_name("private.pem")
app.config["ENTRA_TENANT_ID"] = os.environ.get(
    "ENTRA_TENANT_ID", "3d1e1786-0de5-4781-933e-a80e0f1a0e6a"
)
app.config["ENTRA_CLIENT_ID"] = os.environ.get(
    "ENTRA_CLIENT_ID", "9aadf8c5-12f3-4847-91cb-22c474968aab"
)
app.config["TRANSACTION_DB"] = str(
    Path(tempfile.gettempdir()) / "mini-external-mfa-lab.sqlite3"
)
TRANSACTION_TTL = 240
ID_TOKEN_TTL = 120
LAB_ACR = "possessionorinherence"
LAB_AMR = "otp"
ENTRA_REDIRECT_URI = (
    "https://login.microsoftonline.com/common/federation/externalauthprovider"
)
AUTHORIZATION_PARAMETERS = {
    "scope", "response_type", "response_mode", "client_id", "redirect_uri",
    "nonce", "state", "id_token_hint", "claims", "client-request-id",
}


class AuthorizationRequestError(ValueError):
    pass


class EntraMetadataError(RuntimeError):
    pass


def validate_lab_claims(claims):
    requested = claims.get("id_token", {}) if claims else {}
    for name, selected in (("acr", LAB_ACR), ("amr", LAB_AMR)):
        constraint = requested.get(name)
        if not isinstance(constraint, dict):
            raise AuthorizationRequestError(
                f"claims.id_token.{name} must explicitly allow the lab value."
            )
        if "essential" in constraint and type(constraint["essential"]) is not bool:
            raise AuthorizationRequestError(f"{name}.essential must be a boolean.")
        if "value" in constraint and "values" in constraint:
            raise AuthorizationRequestError(f"{name} cannot specify both value and values.")
        values = (
            [constraint["value"]] if "value" in constraint
            else constraint.get("values")
        )
        if (
            not isinstance(values, list) or not values
            or any(not isinstance(value, str) for value in values)
            or selected not in values
        ):
            raise AuthorizationRequestError(
                f"The lab only simulates {name}={selected}; the request must allow it."
            )
    for name, constraint in requested.items():
        if name in ("acr", "amr") or constraint is None:
            continue
        if not isinstance(constraint, dict):
            raise AuthorizationRequestError(f"Invalid constraint for claim {name}.")
        if constraint.get("essential"):
            raise AuthorizationRequestError(
                f"The lab does not support additional essential claim requests: {name}."
            )


def transaction_connection():
    connection = sqlite3.connect(app.config["TRANSACTION_DB"], timeout=5)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS transactions ("
            "id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, "
            "expires_at INTEGER NOT NULL, payload TEXT NOT NULL)"
        )
    except sqlite3.Error:
        connection.close()
        raise
    return connection


def create_transaction(parameters, hint):
    transaction_id = secrets.token_urlsafe(24)
    browser_token = secrets.token_urlsafe(24)
    payload = {
        "client_id": parameters["client_id"],
        "redirect_uri": parameters["redirect_uri"],
        "sub": hint["sub"],
    }
    for name in ("nonce", "state"):
        if name in parameters:
            payload[name] = parameters[name]
    now = int(time.time())
    # SQLite shares transactions across Gunicorn workers on one App Service instance.
    with closing(transaction_connection()) as connection, connection:
        connection.execute("DELETE FROM transactions WHERE expires_at <= ?", (now,))
        connection.execute(
            "INSERT INTO transactions VALUES (?, ?, ?, ?)",
            (
                transaction_id,
                hashlib.sha256(browser_token.encode("ascii")).hexdigest(),
                now + TRANSACTION_TTL,
                json.dumps(payload),
            ),
        )
    return transaction_id, browser_token


def consume_transaction(transaction_id, browser_token):
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{32}", transaction_id)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32}", browser_token)
    ):
        raise AuthorizationRequestError("Missing or invalid approval transaction.")
    with closing(transaction_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT browser_hash, expires_at, payload FROM transactions WHERE id = ?",
            (transaction_id,),
        ).fetchone()
        if row is None or row[1] <= int(time.time()):
            raise AuthorizationRequestError(
                "Approval has expired or was already used. Restart sign-in."
            )
        browser_hash = hashlib.sha256(browser_token.encode("ascii")).hexdigest()
        if not secrets.compare_digest(row[0], browser_hash):
            raise AuthorizationRequestError("Approval belongs to a different browser.")
        payload = json.loads(row[2])
        if (
            payload["client_id"] != app.config["ENTRA_CLIENT_ID"]
            or payload["redirect_uri"] != ENTRA_REDIRECT_URI
        ):
            raise AuthorizationRequestError("Approval configuration changed. Restart sign-in.")
        connection.execute("DELETE FROM transactions WHERE id = ?", (transaction_id,))
    return payload


@lru_cache(maxsize=4)
def entra_verifier(tenant_id):
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    response = requests.get(
        f"{issuer}/.well-known/openid-configuration", timeout=10
    )
    response.raise_for_status()
    metadata = response.json()
    if not isinstance(metadata, dict):
        raise EntraMetadataError("Entra discovery did not return an object.")
    jwks_uri = metadata.get("jwks_uri")
    expected_jwks_uri = (
        f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    )
    if metadata.get("issuer") != issuer or jwks_uri != expected_jwks_uri:
        raise EntraMetadataError("Unexpected Entra issuer or signing-key URL.")
    return issuer, jwt.PyJWKClient(jwks_uri, timeout=10)


def validate_authorization_request(client_id, tenant_id):
    for name in AUTHORIZATION_PARAMETERS:
        if name in request.args or len(request.form.getlist(name)) > 1:
            raise AuthorizationRequestError(
                f"{name} must appear only once, in the POST form body."
            )
    parameters = {
        name: request.form[name]
        for name in AUTHORIZATION_PARAMETERS if name in request.form
    }
    expected = {
        "scope": "openid",
        "response_type": "id_token",
        "response_mode": "form_post",
        "client_id": client_id,
        "redirect_uri": ENTRA_REDIRECT_URI,
    }
    for name, value in expected.items():
        if parameters.get(name) != value:
            raise AuthorizationRequestError(f"Missing or unsupported {name}.")
    if not parameters.get("id_token_hint"):
        raise AuthorizationRequestError("id_token_hint is required.")
    for name in ("nonce", "state"):
        if name in parameters and not parameters[name]:
            raise AuthorizationRequestError(f"{name} must not be empty if supplied.")
    claims = None
    if "claims" in parameters:
        try:
            claims = json.loads(parameters["claims"])
        except ValueError as error:
            raise AuthorizationRequestError("claims must be valid JSON.") from error
        if not isinstance(claims, dict) or (
            "id_token" in claims and not isinstance(claims["id_token"], dict)
        ):
            raise AuthorizationRequestError(
                "claims must be an object with an object-valued id_token if supplied."
            )

    # Unverified headers can reject invalid input, but never establish trust.
    header = jwt.get_unverified_header(parameters["id_token_hint"])
    if header.get("alg") != "RS256":
        raise jwt.InvalidTokenError("id_token_hint must use RS256.")
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise jwt.InvalidTokenError("id_token_hint must identify its signing key.")

    issuer, jwks_client = entra_verifier(tenant_id)
    signing_key = jwks_client.get_signing_key_from_jwt(parameters["id_token_hint"])
    # External MFA hints are issued expired; all other JWT checks remain enabled.
    hint = jwt.decode(
        parameters["id_token_hint"],
        signing_key.key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=client_id,
        options={
            "verify_exp": False,
            "strict_aud": True,
            "require": ["iss", "aud", "exp", "iat", "tid", "oid", "sub"],
        },
    )
    if hint["tid"] != tenant_id:
        raise AuthorizationRequestError("id_token_hint tenant does not match.")
    if (
        not isinstance(hint["sub"], str) or not hint["sub"]
        or not isinstance(hint["oid"], str) or not hint["oid"]
    ):
        raise AuthorizationRequestError("id_token_hint subject is invalid.")
    if type(hint["exp"]) is not int or type(hint["iat"]) is not int:
        raise AuthorizationRequestError("id_token_hint timestamps must be integers.")
    validate_lab_claims(claims)
    return parameters, claims, hint


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def load_signing_jwk():
    certificate = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("cert.pem must contain an RSA public key for RS256.")

    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": base64url_encode(certificate.fingerprint(hashes.SHA256())),
        "alg": "RS256",
        "n": base64url_encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        ),
        "e": base64url_encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        ),
        "x5c": [
            base64.b64encode(
                certificate.public_bytes(serialization.Encoding.DER)
            ).decode("ascii")
        ],
    }


# Fail at startup if the public signing certificate is missing or invalid.
SIGNING_JWK = load_signing_jwk()


def load_signing_private_key():
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(), password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("private.pem must contain an RSA private key.")
    public_key = jwt.PyJWK.from_dict(SIGNING_JWK).key
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise ValueError("private.pem does not match cert.pem.")
    return private_key


SIGNING_PRIVATE_KEY = load_signing_private_key()


def error_response(message, status, code):
    app.logger.warning("MFA request failed: %s", code)
    return jsonify({"error": code, "error_description": message}), status


@app.route("/")
def home():
    return "Mini External MFA Provider is running!"


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "mini-external-mfa-provider"
    })


@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "jwks_uri": f"{ISSUER}/.well-known/jwks",
        "scopes_supported": ["openid"],
        "response_types_supported": ["id_token"],
        "response_modes_supported": ["form_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["implicit"],
    })


@app.route("/.well-known/jwks")
def jwks():
    return jsonify({"keys": [SIGNING_JWK]})


@app.route("/authorize", methods=["POST"])
def authorize():
    client_id = app.config["ENTRA_CLIENT_ID"]
    tenant_id = app.config["ENTRA_TENANT_ID"]
    try:
        UUID(client_id)
        UUID(tenant_id)
    except (ValueError, TypeError, AttributeError):
        return error_response(
            "Set ENTRA_CLIENT_ID to the Application (client) ID of your Entra "
            "integration app, and ENTRA_TENANT_ID to its tenant ID.",
            503, "provider_not_configured",
        )
    if request.mimetype != "application/x-www-form-urlencoded":
        return error_response(
            "Send an application/x-www-form-urlencoded POST body.",
            415, "invalid_request",
        )
    try:
        parameters, claims, hint = validate_authorization_request(client_id, tenant_id)
    except AuthorizationRequestError as error:
        return error_response(str(error), 400, "invalid_request")
    except (requests.RequestException, EntraMetadataError,
            PyJWKClientConnectionError) as error:
        app.logger.error(
            "Entra metadata/signing-key retrieval failed (%s): %s",
            type(error).__name__, error,
        )
        return error_response(
            "Could not retrieve trusted Entra metadata or signing keys. Try again.",
            502, "entra_metadata_unavailable",
        )
    except (jwt.InvalidTokenError, PyJWKClientError):
        return error_response(
            "id_token_hint failed signature or claim validation.",
            400, "invalid_id_token_hint",
        )
    try:
        transaction_id, browser_token = create_transaction(parameters, hint)
    except sqlite3.Error:
        app.logger.exception("Could not save the approval transaction.")
        return error_response(
            "Could not store the approval request. Try signing in again.",
            503, "transaction_store_unavailable",
        )
    response = make_response(render_template(
        "authorize.html", parameters=parameters, requested_claims=claims, hint=hint,
        transaction_id=transaction_id, lab_acr=LAB_ACR, lab_amr=LAB_AMR,
    ))
    response.set_cookie(
        f"mfa_lab_{transaction_id}", browser_token,
        max_age=TRANSACTION_TTL, httponly=True, secure=request.is_secure,
        samesite="Strict", path="/approve",
    )
    return response


@app.route("/approve", methods=["POST"])
def approve():
    if request.mimetype != "application/x-www-form-urlencoded":
        return error_response("Send a POST form body.", 415, "invalid_request")
    if (
        request.args or set(request.form) != {"transaction_id"}
        or len(request.form.getlist("transaction_id")) != 1
    ):
        return error_response(
            "Send only the transaction_id from the approval page.",
            400, "invalid_request",
        )
    transaction_id = request.form["transaction_id"]
    browser_token = request.cookies.get(f"mfa_lab_{transaction_id}", "")
    try:
        payload = consume_transaction(transaction_id, browser_token)
    except AuthorizationRequestError as error:
        return error_response(str(error), 400, "invalid_transaction")
    except sqlite3.Error:
        app.logger.exception("Could not consume the approval transaction.")
        return error_response(
            "Could not read the approval request. Try signing in again.",
            503, "transaction_store_unavailable",
        )
    now = int(time.time())
    token_claims = {
        "iss": ISSUER,
        "aud": payload["client_id"],
        "sub": payload["sub"],
        "iat": now,
        "exp": now + ID_TOKEN_TTL,
        # LAB ONLY: no OTP or possession factor is actually performed.
        "acr": LAB_ACR,
        "amr": [LAB_AMR],
    }
    if "nonce" in payload:
        token_claims["nonce"] = payload["nonce"]
    id_token = jwt.encode(
        token_claims, SIGNING_PRIVATE_KEY, algorithm="RS256",
        headers={"kid": SIGNING_JWK["kid"]},
    )
    response = make_response(render_template(
        "form_post.html", redirect_uri=payload["redirect_uri"],
        id_token=id_token, state=payload.get("state"),
    ))
    response.delete_cookie(
        f"mfa_lab_{transaction_id}", path="/approve",
        secure=request.is_secure, httponly=True, samesite="Strict",
    )
    return response


@app.after_request
def protect_authorization_response(response):
    if request.path in ("/authorize", "/approve"):
        response = make_response(response)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)