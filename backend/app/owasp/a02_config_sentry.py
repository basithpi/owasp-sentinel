from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A02ConfigSentry(BaseOWASPModule):
    category = "A02"
    name = "Security Misconfiguration"
    description = "Tests for security misconfigurations using Nikto, Nuclei, header analysis"
    tools = ["nikto", "nuclei", "sslyze"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        findings.extend(await self.run_tool("nikto", target, config))
        nuclei_config = {**config, "templates": "misconfiguration,exposed-panels,default-credentials", "severity": "critical,high,medium,low"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        findings.extend(await self.run_tool("sslyze", target, config))
        return findings
