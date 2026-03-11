import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class FeroxbusterTool(BaseTool):
    name = "feroxbuster"
    category = "content-discovery"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            wordlist = config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = ["feroxbuster", "-u", target, "--json", "-o", out_file, "-w", wordlist, "-q", "--no-state"]
            rc, stdout, stderr = await self._run_command(cmd, timeout=180)
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
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("type") == "response" and data.get("status") in (200, 201, 204, 301, 302, 403):
                    findings.append(Finding(
                        title=f"Discovered Path: {data.get('url', '')}",
                        description=f"Status {data.get('status')} — {data.get('url')}",
                        severity=FindingSeverity.INFO,
                        url=data.get("url", ""),
                        tool_name="feroxbuster",
                        raw_output=data,
                    ))
            except Exception:
                continue
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["feroxbuster", "--version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="feroxbuster not found")
