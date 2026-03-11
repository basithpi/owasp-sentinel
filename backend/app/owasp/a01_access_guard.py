from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A01AccessGuard(BaseOWASPModule):
    category = "A01"
    name = "Broken Access Control"
    description = "Tests for IDOR, SSRF, CORS misconfigurations, forced browsing, and JWT attacks"
    tools = ["nuclei", "ffuf", "ssrfmap", "jwt_tool"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        nuclei_config = {**config, "templates": "access-control,idor,ssrf", "severity": "critical,high,medium"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        ffuf_config = {**config, "wordlist": "/usr/share/wordlists/dirb/common.txt"}
        findings.extend(await self.run_tool("ffuf", target, ffuf_config))
        findings.extend(await self.run_tool("ssrfmap", target, config))
        findings.extend(await self.run_tool("jwt_tool", target, config))
        return findings
