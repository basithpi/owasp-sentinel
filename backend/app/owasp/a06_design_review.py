from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A06DesignReview(BaseOWASPModule):
    category = "A06"
    name = "Insecure Design"
    description = "Reviews for insecure design patterns and business logic flaws"
    tools = ["nuclei", "ffuf"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        nuclei_config = {**config, "templates": "business-logic,rate-limit,idor", "severity": "critical,high,medium"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        findings.extend(await self.run_tool("ffuf", target, config))
        return findings
