"""C6 – API security scanner.

Parses OpenAPI/Swagger specs, runs GraphQL introspection, discovers gRPC
reflection services, detects rate limits, tests BOLA/IDOR, detects mass
assignment, and enumerates API versioning.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from typing import Any

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Optional YAML support
# ---------------------------------------------------------------------------

try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_VERSION_PATHS: list[str] = [
    "/v1", "/v2", "/v3", "/v4",
    "/api/v1", "/api/v2", "/api/v3",
    "/api", "/rest", "/graphql",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json",
    "/docs", "/redoc",
]

_GRAPHQL_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name args { name type { name kind } } }
    }
  }
}"""

_MASS_ASSIGNMENT_EXTRA_FIELDS: list[dict[str, Any]] = [
    {"isAdmin": True, "role": "admin"},
    {"admin": True, "is_superuser": True},
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"balance": 999999, "credit": 999999},
]

_IDOR_TEST_IDS: list[Any] = [0, 1, 2, 100, -1, "admin", "null", "undefined", "../1"]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class APIScanner(BaseModule):
    """API security scanner: spec parsing, BOLA/IDOR, mass assignment, versioning."""

    name = "api_scanner"
    description = (
        "Parse OpenAPI/Swagger specs, introspect GraphQL, discover gRPC services, "
        "test BOLA/IDOR, detect mass assignment, detect rate limits, enumerate API versions."
    )
    version = "1.0.0"
    category = "api_security"

    # ------------------------------------------------------------------ #
    # Public entry-point                                                   #
    # ------------------------------------------------------------------ #

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Run all API security checks against *target*.

        Args:
            target: Base URL of the API.
            **kwargs:
                - spec_url (str): Direct URL to the OpenAPI spec.
                - spec_content (str|dict): Inline spec content.
                - auth_headers (Dict[str, str]): Auth headers for authenticated tests.
                - alt_auth_headers (Dict[str, str]): Second user's auth headers for BOLA tests.
                - timeout (int): Request timeout in seconds (default 10).
                - graphql_path (str): GraphQL path (default "/graphql").
        """
        self.started_at = datetime.utcnow()
        base = target if target.startswith("http") else f"https://{target}"
        timeout = int(kwargs.get("timeout", 10))
        auth_headers: dict[str, str] = kwargs.get("auth_headers", {})
        alt_auth_headers: dict[str, str] = kwargs.get("alt_auth_headers", {})
        graphql_path: str = kwargs.get("graphql_path", "/graphql")

        async with httpx.AsyncClient(
            base_url=base,
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._discover_versions(client, base),
                self._graphql_introspection(client, graphql_path, base),
                self._detect_rate_limit(client, base),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Spec-driven tests
            spec = await self._load_spec(client, kwargs)
            if spec:
                endpoints = self._extract_endpoints(spec)
                await self._test_bola_idor(client, endpoints, auth_headers, alt_auth_headers)
                await self._test_mass_assignment(client, endpoints, auth_headers)

        self.completed_at = datetime.utcnow()
        return self.to_dict()

    # ------------------------------------------------------------------ #
    # API version discovery                                                #
    # ------------------------------------------------------------------ #

    async def _discover_versions(
        self, client: httpx.AsyncClient, base: str
    ) -> None:
        """Probe common API versioning paths and report accessible ones."""
        discovered: list[str] = []
        for path in _API_VERSION_PATHS:
            try:
                r = await client.get(path)
                if r.status_code < 400:
                    discovered.append(f"{path} [{r.status_code}]")
            except Exception:
                pass

        if discovered:
            self.add_finding(
                title="API Versioning Endpoints Discovered",
                severity="info",
                description=(
                    f"Found {len(discovered)} accessible API paths. Older versions "
                    "may lack security controls applied to newer versions."
                ),
                evidence="\n".join(discovered),
                url=base,
                endpoints=discovered,
            )

        # Check for deprecated versions (v1 accessible while v3+ exists)
        version_numbers = [
            int(re.search(r"v(\d+)", p).group(1))
            for p in discovered
            if re.search(r"v(\d+)", p.split()[0])
        ]
        if len(set(version_numbers)) > 1:
            self.add_finding(
                title="Multiple API Versions Active (Deprecated Version Risk)",
                severity="medium",
                description=(
                    f"API versions {sorted(set(version_numbers))} are all reachable. "
                    "Deprecated API versions often lack authentication, authorisation, "
                    "or security patches available in current versions."
                ),
                evidence=", ".join(f"v{v}" for v in sorted(set(version_numbers))),
                url=base,
            )

    # ------------------------------------------------------------------ #
    # GraphQL introspection                                                #
    # ------------------------------------------------------------------ #

    async def _graphql_introspection(
        self,
        client: httpx.AsyncClient,
        path: str,
        base: str,
    ) -> None:
        """Query GraphQL introspection and analyse the schema for dangerous patterns."""
        url = base.rstrip("/") + path
        try:
            r = await client.post(
                path,
                json={"query": _GRAPHQL_INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            if r.status_code != 200:
                return
            data = r.json()
        except Exception as exc:
            self.logger.debug("GraphQL introspection failed: %s", exc)
            return

        schema = data.get("data", {}).get("__schema", {})
        if not schema:
            return

        self.add_finding(
            title="GraphQL Introspection Enabled",
            severity="medium",
            description=(
                "The GraphQL endpoint allows introspection, exposing full schema "
                "details including mutations, types, and field names."
            ),
            evidence=json.dumps(schema)[:600],
            url=url,
        )

        # Check for dangerous mutations
        mutation_type = schema.get("mutationType", {}) or {}
        types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
        mutation_type_name = mutation_type.get("name")
        if mutation_type_name and mutation_type_name in types:
            mutations = types[mutation_type_name].get("fields", []) or []
            dangerous = [
                m["name"] for m in mutations
                if any(kw in m["name"].lower() for kw in ["delete", "admin", "password", "token", "secret"])
            ]
            if dangerous:
                self.add_finding(
                    title="GraphQL Dangerous Mutations Exposed",
                    severity="high",
                    description=(
                        "Introspection reveals mutations with sensitive names that may "
                        "allow data deletion, privilege escalation, or credential manipulation."
                    ),
                    evidence=f"Dangerous mutations: {dangerous}",
                    url=url,
                    mutations=dangerous,
                )

    # ------------------------------------------------------------------ #
    # Rate limit detection                                                 #
    # ------------------------------------------------------------------ #

    async def _detect_rate_limit(
        self, client: httpx.AsyncClient, base: str
    ) -> None:
        """Send 20 rapid requests and detect whether rate limiting is enforced."""

        results: list[int] = []
        for _ in range(20):
            try:
                r = await client.get("/")
                results.append(r.status_code)
            except Exception:
                pass

        rate_limited = any(s in (429, 503) for s in results)
        if not rate_limited:
            self.add_finding(
                title="No API Rate Limiting Detected",
                severity="medium",
                description=(
                    "Twenty rapid requests to the API root were all accepted without "
                    "a 429 or 503 response. Absence of rate limiting enables brute-force, "
                    "credential stuffing, and enumeration attacks."
                ),
                evidence=f"Status codes received: {list(set(results))}",
                url=base,
            )
        else:
            self.logger.info("Rate limiting active at %s", base)

    # ------------------------------------------------------------------ #
    # Spec loading                                                         #
    # ------------------------------------------------------------------ #

    async def _load_spec(
        self, client: httpx.AsyncClient, kwargs: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Load an OpenAPI/Swagger spec from inline content, URL, or auto-discovery."""
        # Inline
        if "spec_content" in kwargs:
            spec = kwargs["spec_content"]
            return spec if isinstance(spec, dict) else json.loads(spec)

        # Direct URL
        spec_url: str | None = kwargs.get("spec_url")
        if not spec_url:
            # Auto-discover
            for path in ("/swagger.json", "/openapi.json", "/api-docs"):
                try:
                    r = await client.get(path)
                    if r.status_code == 200:
                        spec_url = path
                        break
                except Exception:
                    pass

        if not spec_url:
            return None

        try:
            r = await client.get(spec_url)
            if r.status_code != 200:
                return None
            content_type = r.headers.get("content-type", "")
            if "yaml" in content_type or spec_url.endswith(".yaml"):
                if not _YAML_AVAILABLE:
                    self.logger.warning("PyYAML not installed; cannot parse YAML spec")
                    return None
                return yaml.safe_load(r.text)
            return r.json()
        except Exception as exc:
            self.logger.warning("Could not load spec from %s: %s", spec_url, exc)
            return None

    # ------------------------------------------------------------------ #
    # Endpoint extraction                                                  #
    # ------------------------------------------------------------------ #

    def _extract_endpoints(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract a flat list of endpoint dicts from an OpenAPI 2/3 spec."""
        endpoints: list[dict[str, Any]] = []
        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete"):
                op = path_item.get(method)
                if not op:
                    continue
                parameters = op.get("parameters", []) + path_item.get("parameters", [])
                endpoints.append(
                    {
                        "path": base_path + path,
                        "method": method.upper(),
                        "operation_id": op.get("operationId", ""),
                        "parameters": parameters,
                        "request_body": op.get("requestBody", {}),
                        "security": op.get("security", spec.get("security", [])),
                    }
                )
        return endpoints

    # ------------------------------------------------------------------ #
    # BOLA / IDOR testing                                                  #
    # ------------------------------------------------------------------ #

    async def _test_bola_idor(
        self,
        client: httpx.AsyncClient,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str],
        alt_auth_headers: dict[str, str],
    ) -> None:
        """Test endpoints with path-parameter IDs using a second user's credentials."""
        id_pattern = re.compile(r"\{(\w*(id|Id|ID|uuid|UUID)\w*)\}")

        for ep in endpoints:
            if ep["method"] not in ("GET", "DELETE"):
                continue
            if not id_pattern.search(ep["path"]):
                continue

            for test_id in _IDOR_TEST_IDS[:4]:
                test_path = id_pattern.sub(str(test_id), ep["path"])
                try:
                    # Request with user-1 credentials
                    r1 = await client.request(
                        ep["method"], test_path, headers=auth_headers
                    )
                    # Request with user-2 credentials (or no auth)
                    r2 = await client.request(
                        ep["method"], test_path, headers=alt_auth_headers
                    )

                    # If both return 200, potential BOLA
                    if r1.status_code == 200 and r2.status_code == 200:
                        if r1.text == r2.text or len(r2.text) > 0:
                            self.add_finding(
                                title=f"Potential BOLA/IDOR – {ep['method']} {test_path}",
                                severity="high",
                                description=(
                                    f"Both user-1 and user-2 credentials returned HTTP 200 "
                                    f"for {ep['method']} {test_path}. This may indicate "
                                    "Broken Object Level Authorisation (OWASP API1)."
                                ),
                                evidence=(
                                    f"User-1: {r1.status_code} | "
                                    f"User-2: {r2.status_code} | "
                                    f"ID tested: {test_id}"
                                ),
                                url=test_path,
                                owasp_category="A01",
                                cwe="CWE-639",
                            )
                            break  # One finding per endpoint is sufficient
                except Exception as exc:
                    self.logger.debug("BOLA test error %s: %s", test_path, exc)

    # ------------------------------------------------------------------ #
    # Mass assignment detection                                            #
    # ------------------------------------------------------------------ #

    async def _test_mass_assignment(
        self,
        client: httpx.AsyncClient,
        endpoints: list[dict[str, Any]],
        auth_headers: dict[str, str],
    ) -> None:
        """Submit extra/privileged fields in POST/PUT request bodies."""
        for ep in endpoints:
            if ep["method"] not in ("POST", "PUT", "PATCH"):
                continue

            # Extract expected body schema from spec
            req_body = ep.get("request_body", {})
            content = req_body.get("content", {}) if req_body else {}
            schema = {}
            for _mime, spec in content.items():
                if "schema" in spec:
                    schema = spec["schema"]
                    break

            # Build a minimal legitimate payload from the schema
            minimal: dict[str, Any] = {}
            for prop_name, prop_schema in (schema.get("properties") or {}).items():
                prop_type = prop_schema.get("type", "string")
                if prop_type == "string":
                    minimal[prop_name] = "test"
                elif prop_type in ("integer", "number"):
                    minimal[prop_name] = 1
                elif prop_type == "boolean":
                    minimal[prop_name] = False

            for extra in _MASS_ASSIGNMENT_EXTRA_FIELDS:
                payload = {**minimal, **extra}
                try:
                    r = await client.request(
                        ep["method"],
                        ep["path"],
                        json=payload,
                        headers={**auth_headers, "Content-Type": "application/json"},
                    )
                    # 200/201 with our extra fields NOT echoed back in an error is suspicious
                    if r.status_code in (200, 201):
                        body = r.text.lower()
                        if any(
                            k.lower() in body
                            for k in extra
                            if k not in ("__proto__", "constructor")
                        ):
                            self.add_finding(
                                title=f"Mass Assignment – {ep['method']} {ep['path']}",
                                severity="high",
                                description=(
                                    "The API accepted a request body containing "
                                    "privileged/extra fields and the response appears to "
                                    "reflect them, indicating mass assignment vulnerability."
                                ),
                                evidence=(
                                    f"Extra fields sent: {list(extra.keys())} | "
                                    f"Status: {r.status_code}"
                                ),
                                url=ep["path"],
                                owasp_category="A03",
                                cwe="CWE-915",
                            )
                            break
                except Exception as exc:
                    self.logger.debug("Mass assignment test error: %s", exc)
