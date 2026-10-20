from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from werkzeug.datastructures import MultiDict

import app as provider


class FormParser(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.inputs = {}
        self.action = None
        self.method = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input":
            self.inputs[attributes["name"]] = attributes.get("value", "")
        elif tag == "form":
            self.action = attributes.get("action")
            self.method = attributes.get("method")


class AuthorizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.signing_key = jwt.PyJWK.from_dict(
            json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key()))
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        config = patch.dict(provider.app.config, {
            "TRANSACTION_DB": str(Path(directory.name) / "transactions.sqlite3"),
        })
        config.start()
        self.addCleanup(config.stop)
        self.client = provider.app.test_client()
        self.tenant_id = provider.app.config["ENTRA_TENANT_ID"]
        self.client_id = provider.app.config["ENTRA_CLIENT_ID"]
        self.issuer = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
        self.jwks_client = Mock()
        self.jwks_client.get_signing_key_from_jwt.return_value = self.signing_key
        self.verifier = patch.object(
            provider, "entra_verifier", return_value=(self.issuer, self.jwks_client)
        )
        self.verifier.start()
        self.addCleanup(self.verifier.stop)
        now = int(time.time())
        self.hint = {
            "iss": self.issuer,
            "aud": self.client_id,
            "tid": self.tenant_id,
            "sub": "lab-subject",
            "oid": "lab-user-object",
            "iat": now - 120,
            "exp": now - 60,
        }
        self.form = {
            "scope": "openid",
            "response_type": "id_token",
            "response_mode": "form_post",
            "client_id": self.client_id,
            "redirect_uri": provider.ENTRA_REDIRECT_URI,
            "nonce": "lab-nonce",
            "state": "lab-state",
            "claims": json.dumps({
                "id_token": {
                    "acr": {"essential": True, "values": ["possessionorinherence"]},
                    "amr": {"essential": True, "values": ["otp"]},
                }
            }),
        }

    def post(self, hint=None, form=None, key=None, **kwargs):
        data = dict(self.form if form is None else form)
        data["id_token_hint"] = jwt.encode(
            self.hint if hint is None else hint,
            self.private_key if key is None else key,
            algorithm="RS256", headers={"kid": "test-only"},
        )
        return self.client.post("/authorize", data=data, **kwargs)

    def test_valid_expired_hint_displays_lab_approval_button(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        for expected in ("lab-subject", "lab-nonce", "lab-state", "LAB ONLY", "otp"):
            self.assertIn(expected, body)
        self.assertNotIn("disabled", body)
        self.assertIn('action="/approve"', body)
        self.assertEqual(set(FormParser(body).inputs), {"transaction_id"})
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_invalid_claims_rejected(self):
        cases = {
            "iss": "https://attacker.invalid",
            "aud": "wrong-client",
            "tid": "wrong-tenant",
            "sub": "",
            "oid": "",
            "iat": int(time.time()) + 3600,
            "exp": "not-an-integer",
        }
        for name, value in cases.items():
            with self.subTest(claim=name):
                self.assertEqual(self.post(hint={**self.hint, name: value}).status_code, 400)
        for name in self.hint:
            with self.subTest(missing_claim=name):
                hint = dict(self.hint)
                del hint[name]
                self.assertEqual(self.post(hint=hint).status_code, 400)

    def test_wrong_signature_and_unsigned_hint_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(self.post(key=other_key).status_code, 400)
        form = {**self.form, "id_token_hint": jwt.encode(self.hint, None, algorithm="none")}
        self.assertEqual(self.client.post("/authorize", data=form).status_code, 400)

    def test_invalid_parameters_rejected(self):
        for name, value in {
            "scope": "profile", "response_type": "code", "response_mode": "query",
            "client_id": "wrong-client", "redirect_uri": "https://attacker.invalid",
            "claims": "{", "nonce": "", "state": "",
        }.items():
            with self.subTest(parameter=name):
                self.assertEqual(self.post(form={**self.form, name: value}).status_code, 400)
        for claims in ("[]", '{"id_token": []}'):
            self.assertEqual(self.post(form={**self.form, "claims": claims}).status_code, 400)

    def test_optional_and_unknown_parameters(self):
        form = {name: value for name, value in self.form.items()
                if name not in ("state", "nonce")}
        form["ignored-extension"] = "ignored"
        self.assertEqual(self.post(form=form).status_code, 200)

    def test_missing_hint_duplicates_and_query_parameters_rejected(self):
        self.assertEqual(self.client.post("/authorize", data=self.form).status_code, 400)
        form = MultiDict(self.form)
        form.add("client_id", self.client_id)
        self.assertEqual(self.client.post("/authorize", data=form).status_code, 400)
        self.assertEqual(
            self.client.post("/authorize?client_id=unexpected", data=self.form).status_code, 400
        )
        self.assertEqual(self.client.get("/authorize").status_code, 405)
        self.assertEqual(self.client.post("/authorize", json=self.form).status_code, 415)

    def test_configuration_and_metadata_errors(self):
        with patch.dict(provider.app.config, {"ENTRA_CLIENT_ID": ""}):
            self.assertEqual(self.post().status_code, 503)
        with patch.object(provider, "entra_verifier", side_effect=requests.Timeout):
            self.assertEqual(self.post().status_code, 502)
        self.jwks_client.get_signing_key_from_jwt.side_effect = (
            jwt.exceptions.PyJWKClientConnectionError("test outage")
        )
        self.assertEqual(self.post().status_code, 502)

    def test_malformed_hint_is_rejected_before_network_access(self):
        with patch.object(provider, "entra_verifier") as verifier:
            verifier.side_effect = requests.Timeout("network unavailable")
            for token in (
                "not-a-real-token",
                jwt.encode(self.hint, None, algorithm="none"),
                jwt.encode(self.hint, self.private_key, algorithm="RS256"),
            ):
                with self.subTest(token_type=token.split(".")[0]):
                    response = self.client.post(
                        "/authorize", data={**self.form, "id_token_hint": token}
                    )
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.json["error"], "invalid_id_token_hint")
            verifier.assert_not_called()

    def test_metadata_failure_logs_cause_without_logging_hint(self):
        with patch.object(
            provider, "entra_verifier", side_effect=requests.Timeout("test timeout")
        ), self.assertLogs(provider.app.logger, level="ERROR") as logs:
            response = self.post()
        self.assertEqual(response.status_code, 502)
        self.assertIn("Timeout", logs.output[0])
        self.assertIn("test timeout", logs.output[0])
        self.assertNotIn("eyJ", logs.output[0])

    def test_html_is_escaped_and_raw_hint_not_displayed(self):
        form = {**self.form, "state": "<script>alert(1)</script>"}
        response = self.post(form=form)
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("eyJ", body)

    def test_existing_routes_and_unrequested_approval(self):
        for path in ("/", "/health", "/.well-known/openid-configuration", "/.well-known/jwks"):
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertEqual(self.client.post("/approve", data={"transaction_id": "invalid"}).status_code, 400)
        self.assertEqual(self.client.get("/approve").status_code, 405)
        self.assertEqual(self.client.post("/approve", json={}).status_code, 415)

    def approval_page(self, **kwargs):
        response = self.post(**kwargs)
        self.assertEqual(response.status_code, 200)
        return FormParser(response.get_data(as_text=True))

    def decode_result(self, response):
        self.assertEqual(response.status_code, 200)
        form = FormParser(response.get_data(as_text=True))
        key = self.client.get("/.well-known/jwks").json["keys"][0]
        token = jwt.decode(
            form.inputs["id_token"], jwt.PyJWK.from_dict(key).key,
            algorithms=["RS256"], issuer=provider.ISSUER, audience=self.client_id,
            options={"require": ["iss", "aud", "sub", "iat", "exp", "acr", "amr"]},
        )
        header = jwt.get_unverified_header(form.inputs["id_token"])
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["kid"], key["kid"])
        self.assertEqual(form.action, provider.ENTRA_REDIRECT_URI)
        self.assertEqual(form.method, "post")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        return form, token

    def test_approval_signs_correct_token_and_form_post(self):
        state = '<lab-state>&"test'
        nonce = '<lab-nonce>&"test'
        page = self.approval_page(
            hint={**self.hint, "nonce": "hint-nonce-is-not-request-nonce"},
            form={**self.form, "nonce": nonce, "state": state},
        )
        cookie_name = "mfa_lab_" + page.inputs["transaction_id"]
        self.assertIsNotNone(self.client.get_cookie(cookie_name, path="/approve"))
        response = self.client.post("/approve", data=page.inputs)
        form, token = self.decode_result(response)
        self.assertEqual(set(form.inputs), {"id_token", "state"})
        self.assertEqual(form.inputs["state"], state)
        self.assertEqual(token, {
            "iss": provider.ISSUER, "aud": self.client_id,
            "sub": self.hint["sub"], "iat": token["iat"],
            "exp": token["iat"] + 120,
            "nonce": nonce, "acr": "possessionorinherence", "amr": ["otp"],
        })
        self.assertIsNone(self.client.get_cookie(cookie_name, path="/approve"))
        self.assertIn('.submit();', response.get_data(as_text=True))
        self.assertNotIn('value="<lab-state>', response.get_data(as_text=True))

    def test_absent_nonce_and_state_are_not_invented(self):
        parameters = {name: value for name, value in self.form.items()
                      if name not in ("nonce", "state")}
        page = self.approval_page(form=parameters)
        form, token = self.decode_result(self.client.post("/approve", data=page.inputs))
        self.assertNotIn("state", form.inputs)
        self.assertNotIn("state", token)
        self.assertNotIn("nonce", token)

    def test_transaction_is_single_use_even_with_original_cookie(self):
        page = self.approval_page()
        name = "mfa_lab_" + page.inputs["transaction_id"]
        browser_token = self.client.get_cookie(name, path="/approve").value
        self.assertEqual(self.client.post("/approve", data=page.inputs).status_code, 200)
        self.client.set_cookie(name, browser_token, path="/approve")
        response = self.client.post("/approve", data=page.inputs)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "invalid_transaction")

    def test_transaction_requires_same_browser(self):
        page = self.approval_page()
        other_browser = provider.app.test_client()
        self.assertEqual(other_browser.post("/approve", data=page.inputs).status_code, 400)
        other_browser.set_cookie(
            "mfa_lab_" + page.inputs["transaction_id"], "x" * 32, path="/approve"
        )
        self.assertEqual(other_browser.post("/approve", data=page.inputs).status_code, 400)
        self.assertEqual(self.client.post("/approve", data=page.inputs).status_code, 200)

    def test_expired_transaction_is_rejected(self):
        page = self.approval_page()
        with patch.object(provider.time, "time", return_value=int(time.time()) + 240):
            response = self.client.post("/approve", data=page.inputs)
        self.assertEqual(response.status_code, 400)
        self.assertIn("expired", response.json["error_description"])

    def test_approval_form_tampering_is_rejected(self):
        page = self.approval_page()
        for changes in (
            {"redirect_uri": "https://attacker.invalid"}, {"sub": "other-subject"},
            {"nonce": "other-nonce"}, {"state": "other-state"},
        ):
            self.assertEqual(
                self.client.post("/approve", data={**page.inputs, **changes}).status_code, 400
            )
        duplicated = MultiDict(page.inputs)
        duplicated.add("transaction_id", page.inputs["transaction_id"])
        self.assertEqual(self.client.post("/approve", data=duplicated).status_code, 400)
        self.assertEqual(
            self.client.post("/approve?state=modified", data=page.inputs).status_code, 400
        )
        self.assertEqual(self.client.post("/approve", data=page.inputs).status_code, 200)

    def test_claim_constraints_must_allow_simulated_factor(self):
        requests_to_reject = (
            None,
            {},
            {"id_token": {"acr": None, "amr": None}},
            {"id_token": {
                "acr": {"values": ["inherence"]}, "amr": {"values": ["otp"]},
            }},
            {"id_token": {
                "acr": {"values": ["possessionorinherence"]}, "amr": {"values": ["fpt"]},
            }},
            {"id_token": {
                "acr": {"value": "possessionorinherence", "values": ["possessionorinherence"]},
                "amr": {"values": ["otp"]},
            }},
            {"id_token": {
                "acr": {"values": ["possessionorinherence"]},
                "amr": {"values": ["otp"], "essential": "true"},
            }},
        )
        for claims in requests_to_reject:
            with self.subTest(claims=claims):
                parameters = {name: value for name, value in self.form.items() if name != "claims"}
                if claims is not None:
                    parameters["claims"] = json.dumps(claims)
                self.assertEqual(self.post(form=parameters).status_code, 400)
        claims = json.loads(self.form["claims"])
        claims["id_token"]["auth_time"] = {"essential": True}
        self.assertEqual(
            self.post(form={**self.form, "claims": json.dumps(claims)}).status_code, 400
        )

    def test_claim_single_value_constraints_are_supported(self):
        claims = {"id_token": {
            "acr": {"value": "possessionorinherence"}, "amr": {"value": "otp"},
        }}
        self.assertEqual(
            self.post(form={**self.form, "claims": json.dumps(claims)}).status_code, 200
        )

    def test_transaction_store_errors_are_explicit(self):
        with patch.object(
            provider, "transaction_connection", side_effect=sqlite3.OperationalError("test outage")
        ), self.assertLogs(provider.app.logger, level="ERROR"):
            self.assertEqual(self.post().status_code, 503)
        page = self.approval_page()
        with patch.object(
            provider, "transaction_connection", side_effect=sqlite3.OperationalError("test outage")
        ), self.assertLogs(provider.app.logger, level="ERROR"):
            self.assertEqual(self.client.post("/approve", data=page.inputs).status_code, 503)

    def test_https_approval_cookie_flags(self):
        response = self.post(base_url="https://localhost")
        self.assertEqual(response.status_code, 200)
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/approve"):
            self.assertIn(attribute, response.headers["Set-Cookie"])

    def test_shared_database_transaction_can_be_consumed_only_once_concurrently(self):
        transaction_id, browser_token = provider.create_transaction(self.form, self.hint)

        def consume():
            try:
                provider.consume_transaction(transaction_id, browser_token)
                return "approved"
            except provider.AuthorizationRequestError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        self.assertCountEqual(results, ["approved", "rejected"])

    def test_configuration_change_invalidates_pending_approval(self):
        page = self.approval_page()
        with patch.dict(provider.app.config, {"ENTRA_CLIENT_ID": "changed"}):
            self.assertEqual(self.client.post("/approve", data=page.inputs).status_code, 400)

    def test_private_key_must_be_rsa_and_match_certificate(self):
        for key in (
            self.private_key,
            ec.generate_private_key(ec.SECP256R1()),
        ):
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            with patch.object(Path, "read_bytes", return_value=pem):
                with self.assertRaises(ValueError):
                    provider.load_signing_private_key()


class EntraMetadataTests(unittest.TestCase):
    def tearDown(self):
        provider.entra_verifier.cache_clear()

    @patch.object(provider.requests, "get")
    def test_metadata_validation_and_caching(self, get):
        tenant = provider.app.config["ENTRA_TENANT_ID"]
        issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
        keys = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        get.return_value.json.return_value = {"issuer": issuer, "jwks_uri": keys}
        provider.entra_verifier.cache_clear()
        actual_issuer, client = provider.entra_verifier(tenant)
        self.assertEqual(actual_issuer, issuer)
        self.assertIsInstance(client, jwt.PyJWKClient)
        provider.entra_verifier(tenant)
        get.assert_called_once_with(f"{issuer}/.well-known/openid-configuration", timeout=10)
        for metadata in (
            [], {"issuer": "wrong", "jwks_uri": keys},
            {"issuer": issuer, "jwks_uri": "https://attacker.invalid/keys"},
        ):
            provider.entra_verifier.cache_clear()
            get.return_value.json.return_value = metadata
            with self.assertRaises(provider.EntraMetadataError):
                provider.entra_verifier(tenant)


if __name__ == "__main__":
    unittest.main()
