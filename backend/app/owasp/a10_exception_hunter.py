from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A10ExceptionHunter(BaseOWASPModule):
    category = "A10"
    name = "Exception Handling Failures"
    description = "Tests for improper error handling, stack trace exposure, and fail-open vulnerabilities"
    tools = ["nuclei", "ffuf", "nikto"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        nuclei_config = {**config, "templates": "error-pages,stack-trace,debug-endpoints", "severity": "high,medium,low,info"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        findings.extend(await self.run_tool("nikto", target, config))
        ffuf_config = {**config, "wordlist": "/usr/share/wordlists/dirb/common.txt"}
        findings.extend(await self.run_tool("ffuf", target, ffuf_config))
        return findings
