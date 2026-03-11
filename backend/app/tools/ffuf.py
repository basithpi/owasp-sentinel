import json
import os
import uuid
from typing import List, Dict, Any

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class FfufTool(BaseTool):
    name = "ffuf"
    category = "directory-fuzzing"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        run_id = uuid.uuid4().hex[:8]
        output_file = f"/tmp/ffuf_{run_id}.json"
        wordlist = config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd = [
            "ffuf", "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-json", "-o", output_file,
            "-silent",
        ]
        returncode, stdout, stderr = await self._run_command(cmd)
        raw = stdout
        if os.path.isfile(output_file):
            with open(output_file) as f:
                raw = f.read()
            os.remove(output_file)
        findings = await self.parse_output(raw)
        return ToolResult(
            success=returncode == 0,
            findings=findings,
            raw_output=raw,
            error=stderr if returncode != 0 else None,
        )

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            for result in results:
                url = result.get("url", "")
                status = result.get("status", 0)
                length = result.get("length", 0)
                findings.append(Finding(
                    title=f"Directory/file discovered: {url}",
                    description=f"Status: {status}, Length: {length}",
                    severity=FindingSeverity.INFO,
                    url=url,
                    tool_name="ffuf",
                    raw_output=result,
                ))
        except json.JSONDecodeError:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        returncode, stdout, stderr = await self._run_command(["ffuf", "-V"])
        if returncode == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="ffuf not found")
