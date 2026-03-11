"""C12 – Supply chain security analyzer.

Parses dependency manifests (requirements.txt, package.json, Gemfile, pom.xml,
go.mod), checks for known-malicious packages, detects typosquatting, scans
licences, generates a CycloneDX SBOM, and checks for dependency confusion.
"""

from __future__ import annotations

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import uuid

import httpx

from app.modules.base_module import BaseModule

# ---------------------------------------------------------------------------
# Known-malicious package lists (static snapshot, for offline scanning)
# ---------------------------------------------------------------------------

# PyPI
_KNOWN_MALICIOUS_PYPI: set[str] = {
    "colourama", "colorama-dev", "python-dateutil2",
    "request-lib", "requests-dev", "urllib4",
    "setup-tools", "py-crypto", "pycryptodome2",
    "python-jwt", "python-openssl", "pip-requests",
    "discord-self", "discordpy-self", "fake-requests",
    "acqusition", "apidev-coop", "bzip", "cligoogle",
    "httplib3", "libpython", "libssl", "pyyam1",
    "pyyaml-dev", "pygrata", "loglib-modules",
}

# npm
_KNOWN_MALICIOUS_NPM: set[str] = {
    "cross-env.js", "loadyaml", "d3.js", "jquery.js",
    "lodash.js", "event-source-polyfill-ex",
    "ua-parser-js-bugfix", "react-native-sdk",
    "node-fetch-commonjs-polyfill", "browserify-lite",
    "express-mongoose-ra-json-server", "httpsclient",
    "netmask2", "node-ipc-hacked", "peacenotwar",
    "flatmap-stream", "eslint-scope-hacked",
    "event-stream-malicious", "nodemon-hacked",
    "is-promise-hacked", "styled-components-hacked",
}

# Popular packages to compare against for typosquatting
_POPULAR_PYPI = [
    "requests", "numpy", "pandas", "flask", "django",
    "boto3", "sqlalchemy", "pytest", "setuptools", "pip",
    "pyyaml", "cryptography", "paramiko", "celery", "redis",
    "pillow", "scipy", "matplotlib", "fastapi", "uvicorn",
]

_POPULAR_NPM = [
    "react", "express", "lodash", "axios", "moment",
    "webpack", "babel-core", "eslint", "typescript", "jest",
    "next", "vue", "angular", "jquery", "underscore",
    "async", "bluebird", "chalk", "commander", "dotenv",
]

# Licence keywords → canonical name
_LICENSE_MAP: dict[str, str] = {
    "gpl-3": "GPL-3.0", "gpl-2": "GPL-2.0", "gpl": "GPL",
    "lgpl-3": "LGPL-3.0", "lgpl-2": "LGPL-2.0", "lgpl": "LGPL",
    "mit": "MIT", "apache-2.0": "Apache-2.0", "apache 2": "Apache-2.0",
    "bsd-3": "BSD-3-Clause", "bsd-2": "BSD-2-Clause", "bsd": "BSD",
    "isc": "ISC", "cc0": "CC0-1.0", "unlicense": "Unlicense",
    "agpl": "AGPL-3.0", "mpl": "MPL-2.0", "epl": "EPL-2.0",
    "proprietary": "Proprietary", "commercial": "Proprietary",
}

_COPYLEFT_LICENSES = {"GPL", "GPL-2.0", "GPL-3.0", "LGPL", "LGPL-2.0", "LGPL-3.0", "AGPL-3.0"}


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class SupplyChainAnalyzer(BaseModule):
    """Analyses dependency manifests for supply-chain risks: malicious packages,
    typosquatting, licence issues, dependency confusion, and generates a CycloneDX SBOM."""

    name = "supply_chain_analyzer"
    description = (
        "Parses requirements.txt, package.json, Gemfile, pom.xml, go.mod; "
        "detects known-malicious packages, typosquatting, licence violations, "
        "dependency confusion, and emits a CycloneDX SBOM."
    )
    version = "1.0.0"
    category = "supply_chain"

    async def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Analyse supply-chain security for *target*.

        Args:
            target: Either a URL (to fetch manifest files) or a local directory path.
            **kwargs:
                manifest_content (str): Raw manifest content to parse directly.
                manifest_type (str): One of requirements/npm/gemfile/pom/gomod.
                check_public_registry (bool): Whether to query public registries (default False).
                timeout (int): HTTP timeout in seconds (default: 10).

        Returns:
            Dict with ``findings``, ``sbom``, ``dependencies``, and metadata.
        """
        self.started_at = datetime.utcnow()
        timeout = int(kwargs.get("timeout", 10))
        manifest_content: str = kwargs.get("manifest_content", "")
        manifest_type: str = kwargs.get("manifest_type", "")
        check_public: bool = bool(kwargs.get("check_public_registry", False))

        dependencies: list[dict[str, Any]] = []

        if manifest_content and manifest_type:
            dependencies = _parse_manifest(manifest_content, manifest_type)
        else:
            # Try to fetch common manifest files from the target URL
            dependencies = await self._fetch_manifests(target, timeout)

        # Run all checks
        self._check_malicious(dependencies)
        self._check_typosquatting(dependencies)
        self._check_licenses(dependencies)
        if check_public:
            await self._check_dependency_confusion(dependencies, timeout)

        sbom = _generate_cyclonedx_sbom(target, dependencies)

        self.completed_at = datetime.utcnow()
        return {
            "module": self.name,
            "target": target,
            "findings": self.results,
            "dependencies": dependencies,
            "sbom": sbom,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Manifest fetching                                                    #
    # ------------------------------------------------------------------ #

    async def _fetch_manifests(self, target: str, timeout: int) -> list[dict[str, Any]]:
        """Attempt to download manifest files from *target* URL."""
        if not target.startswith(("http://", "https://")):
            # treat as local path
            return _parse_local_directory(target)

        manifest_paths = {
            "requirements": "/requirements.txt",
            "npm": "/package.json",
            "gemfile": "/Gemfile",
            "pom": "/pom.xml",
            "gomod": "/go.mod",
        }
        dependencies: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            for mtype, path in manifest_paths.items():
                url = target.rstrip("/") + path
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and resp.text.strip():
                        deps = _parse_manifest(resp.text, mtype)
                        dependencies.extend(deps)
                except Exception:
                    continue
        return dependencies

    # ------------------------------------------------------------------ #
    # Checks                                                               #
    # ------------------------------------------------------------------ #

    def _check_malicious(self, dependencies: list[dict[str, Any]]) -> None:
        """Flag packages found in the known-malicious lists."""
        for dep in dependencies:
            name_lower = dep.get("name", "").lower()
            ecosystem = dep.get("ecosystem", "")
            if ecosystem == "pypi" and name_lower in _KNOWN_MALICIOUS_PYPI:
                self.add_finding(
                    title=f"Known-malicious package: {dep['name']}",
                    severity="critical",
                    description=(
                        f"The package '{dep['name']}' ({ecosystem}) is in the "
                        "known-malicious package database. Remove or replace it immediately."
                    ),
                    evidence=f"Package: {dep['name']} version: {dep.get('version', 'unknown')}",
                    url="",
                    ecosystem=ecosystem,
                )
                dep["malicious"] = True
            elif ecosystem == "npm" and name_lower in _KNOWN_MALICIOUS_NPM:
                self.add_finding(
                    title=f"Known-malicious package: {dep['name']}",
                    severity="critical",
                    description=(
                        f"The npm package '{dep['name']}' is in the known-malicious "
                        "package database."
                    ),
                    evidence=f"Package: {dep['name']} version: {dep.get('version', 'unknown')}",
                    url="",
                    ecosystem=ecosystem,
                )
                dep["malicious"] = True

    def _check_typosquatting(self, dependencies: list[dict[str, Any]]) -> None:
        """Detect potential typosquatting using Levenshtein distance ≤ 2."""
        for dep in dependencies:
            name = dep.get("name", "")
            ecosystem = dep.get("ecosystem", "")
            popular = _POPULAR_PYPI if ecosystem == "pypi" else _POPULAR_NPM if ecosystem == "npm" else []
            for popular_name in popular:
                if name.lower() == popular_name.lower():
                    break  # exact match, not a typo
                dist = _levenshtein(name.lower(), popular_name.lower())
                if 0 < dist <= 2:
                    self.add_finding(
                        title=f"Possible typosquatting: {name} ≈ {popular_name}",
                        severity="high",
                        description=(
                            f"Package '{name}' ({ecosystem}) is very similar to the popular "
                            f"package '{popular_name}' (edit distance {dist}). This may be "
                            "a typosquatting attack."
                        ),
                        evidence=f"Levenshtein distance: {dist}",
                        url="",
                        popular_package=popular_name,
                        edit_distance=dist,
                    )
                    dep["typosquat_risk"] = popular_name

    def _check_licenses(self, dependencies: list[dict[str, Any]]) -> None:
        """Identify copyleft and unknown licences."""
        for dep in dependencies:
            lic = dep.get("license", "unknown").lower()
            canonical = "Unknown"
            for key, val in _LICENSE_MAP.items():
                if key in lic:
                    canonical = val
                    break
            dep["license_canonical"] = canonical
            if canonical in _COPYLEFT_LICENSES:
                self.add_finding(
                    title=f"Copyleft licence: {dep['name']} ({canonical})",
                    severity="medium",
                    description=(
                        f"Package '{dep['name']}' uses a copyleft licence ({canonical}). "
                        "Ensure your project's distribution terms are compatible."
                    ),
                    evidence=f"Declared licence: {dep.get('license', 'unknown')}",
                    url="",
                    license=canonical,
                )
            elif canonical == "Unknown":
                self.add_finding(
                    title=f"Unknown licence: {dep['name']}",
                    severity="low",
                    description=(
                        f"Package '{dep['name']}' has no recognised licence. "
                        "Review before use."
                    ),
                    evidence=f"Declared licence: {dep.get('license', 'not specified')}",
                    url="",
                    license="Unknown",
                )

    async def _check_dependency_confusion(
        self, dependencies: list[dict[str, Any]], timeout: int
    ) -> None:
        """Check whether internal/private package names also exist on public registries."""
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for dep in dependencies:
                name = dep.get("name", "")
                ecosystem = dep.get("ecosystem", "")
                url = ""
                if ecosystem == "pypi":
                    url = f"https://pypi.org/pypi/{name}/json"
                elif ecosystem == "npm":
                    url = f"https://registry.npmjs.org/{name}"
                else:
                    continue
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        dep["public_registry_exists"] = True
                    else:
                        dep["public_registry_exists"] = False
                        # Only flag if source looks internal (no dots, has company prefix etc.)
                        if _looks_internal(name):
                            self.add_finding(
                                title=f"Dependency confusion risk: {name}",
                                severity="high",
                                description=(
                                    f"Package '{name}' ({ecosystem}) appears to be an "
                                    "internal package that does NOT exist on the public "
                                    "registry. An attacker could register a malicious "
                                    "package with the same name."
                                ),
                                evidence=f"Registry check: HTTP {resp.status_code}",
                                url=url,
                            )
                except Exception:
                    continue


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_manifest(content: str, mtype: str) -> list[dict[str, Any]]:
    """Dispatch to the appropriate parser."""
    parsers = {
        "requirements": _parse_requirements_txt,
        "npm": _parse_package_json,
        "gemfile": _parse_gemfile,
        "pom": _parse_pom_xml,
        "gomod": _parse_go_mod,
    }
    parser = parsers.get(mtype)
    if parser is None:
        return []
    try:
        return parser(content)
    except Exception:
        return []


def _parse_requirements_txt(content: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~^].*)?$", line)
        if m:
            deps.append({"name": m.group(1), "version": (m.group(2) or "").strip(), "ecosystem": "pypi"})
    return deps


def _parse_package_json(content: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append({"name": name, "version": version, "ecosystem": "npm", "section": section})
    return deps


def _parse_gemfile(content: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for line in content.splitlines():
        m = re.match(r"^\s*gem\s+'([^']+)'(?:,\s*'([^']+)')?", line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "rubygems"})
    return deps


def _parse_pom_xml(content: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(content)
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in root.findall(".//m:dependency", ns):
            group_id = dep.findtext("m:groupId", namespaces=ns) or ""
            artifact_id = dep.findtext("m:artifactId", namespaces=ns) or ""
            version = dep.findtext("m:version", namespaces=ns) or ""
            deps.append({
                "name": f"{group_id}:{artifact_id}",
                "version": version,
                "ecosystem": "maven",
            })
    except ET.ParseError:
        pass
    return deps


def _parse_go_mod(content: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            clean = re.sub(r"^require\s+", "", line)
            parts = clean.split()
            if len(parts) >= 2:
                deps.append({"name": parts[0], "version": parts[1], "ecosystem": "go"})
    return deps


def _parse_local_directory(path: str) -> list[dict[str, Any]]:
    """Walk a local directory and parse all manifest files found."""
    deps: list[dict[str, Any]] = []
    root = Path(path)
    manifest_files = {
        "requirements.txt": "requirements",
        "package.json": "npm",
        "Gemfile": "gemfile",
        "pom.xml": "pom",
        "go.mod": "gomod",
    }
    for filename, mtype in manifest_files.items():
        for fpath in root.rglob(filename):
            try:
                deps.extend(_parse_manifest(fpath.read_text(errors="replace"), mtype))
            except Exception:
                continue
    return deps


# ---------------------------------------------------------------------------
# CycloneDX SBOM generator
# ---------------------------------------------------------------------------


def _generate_cyclonedx_sbom(target: str, dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate a minimal CycloneDX 1.4 JSON SBOM."""
    components = []
    for dep in dependencies:
        purl_type = {
            "pypi": "pypi", "npm": "npm", "rubygems": "gem",
            "maven": "maven", "go": "golang",
        }.get(dep.get("ecosystem", ""), "generic")
        name = dep.get("name", "unknown")
        version = dep.get("version", "")
        purl = f"pkg:{purl_type}/{name}@{version}" if version else f"pkg:{purl_type}/{name}"
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        }
        if dep.get("license_canonical"):
            component["licenses"] = [{"license": {"id": dep["license_canonical"]}}]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application", "name": target},
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between *a* and *b*."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _looks_internal(name: str) -> bool:
    """Heuristic: name looks like an internal/private package."""
    internals = ["internal", "private", "corp", "company", "mycompany", "internal-"]
    name_lower = name.lower()
    return any(i in name_lower for i in internals)
