import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class HydraTool(BaseTool):
    name = "hydra"
    category = "brute-force"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        service = config.get("service", "http-get")
        userlist = config.get("userlist", "/usr/share/wordlists/metasploit/unix_users.txt")
        passlist = config.get("passlist", "/usr/share/wordlists/rockyou.txt")
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_file = f.name
        try:
            cmd = ["hydra", "-L", userlist, "-P", passlist, target, service, "-o", out_file, "-t", "4"]
            rc, stdout, stderr = await self._run_command(cmd, timeout=self.timeout)
            with open(out_file) as f:
                raw = f.read()
            findings = await self.parse_output(raw)
            return ToolResult(success=True, findings=findings, raw_output=raw)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        for line in raw_output.strip().split("\n"):
            if "login:" in line and "password:" in line:
                findings.append(Finding(
                    title="Weak Credentials Found",
                    description=f"Hydra brute-forced credentials: {line.strip()}",
                    severity=FindingSeverity.CRITICAL,
                    owasp_category="A07",
                    evidence=line.strip(),
                    tool_name="hydra",
                    raw_output={"line": line.strip()},
                ))
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["hydra", "-h"])
        if rc in (0, 255):
            return HealthCheckResult(status=HealthStatus.HEALTHY, version="installed")
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="hydra not found")
