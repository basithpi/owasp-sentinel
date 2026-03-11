from typing import List, Dict, Any
from .base_module import BaseOWASPModule


class A05InjectionStrike(BaseOWASPModule):
    category = "A05"
    name = "Injection"
    description = "Tests for SQL, XSS, command, NoSQL, and template injection"
    tools = ["sqlmap", "xsstrike", "dalfox", "commix", "nosqlmap", "ssti_map"]

    async def scan(self, target: str, config: Dict[str, Any]) -> List[Any]:
        findings = []
        findings.extend(await self.run_tool("sqlmap", target, config))
        findings.extend(await self.run_tool("xsstrike", target, config))
        findings.extend(await self.run_tool("dalfox", target, config))
        findings.extend(await self.run_tool("commix", target, config))
        findings.extend(await self.run_tool("nosqlmap", target, config))
        findings.extend(await self.run_tool("ssti_map", target, config))
        return findings
