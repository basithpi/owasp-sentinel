from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A07AuthBreaker(BaseOWASPModule):
    category = "A07"
    name = "Authentication Failures"
    description = "Tests authentication mechanisms including brute force and JWT attacks"
    tools = ["hydra", "jwt_tool", "nuclei"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        findings.extend(await self.run_tool("jwt_tool", target, config))
        nuclei_config = {**config, "templates": "authentication,default-logins,oauth", "severity": "critical,high,medium"}
        findings.extend(await self.run_tool("nuclei", target, nuclei_config))
        if config.get("brute_force", False):
            findings.extend(await self.run_tool("hydra", target, config))
        return findings
