from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A03SupplyChain(BaseOWASPModule):
    category = "A03"
    name = "Supply Chain Failures"
    description = "Detects supply chain vulnerabilities including secrets and dependency issues"
    tools = ["trufflehog", "gitleaks"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        findings.extend(await self.run_tool("trufflehog", target, config))
        findings.extend(await self.run_tool("gitleaks", target, config))
        nuclei_config = {**config, "templates": "exposures/tokens,exposures/keys", "severity": "critical,high"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        return findings
