import json
import os
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class SslyzeTool(BaseTool):
    name = "sslyze"
    category = "tls-scanner"
    priority = "P0"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_file = f.name
        try:
            cmd = ["sslyze", target, f"--json_out={out_file}"]
            rc, stdout, stderr = await self._run_command(cmd)
            with open(out_file) as f:
                raw = f.read()
            findings = await self.parse_output(raw)
            return ToolResult(success=rc == 0, findings=findings, raw_output=raw, error=stderr if rc != 0 else None)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            for result in data.get("server_scan_results", []):
                scan_result = result.get("scan_result", {})
                for proto in ["ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"]:
                    proto_result = scan_result.get(proto, {})
                    if proto_result.get("result", {}).get("accepted_cipher_suites"):
                        findings.append(Finding(
                            title=f"Weak Protocol Enabled: {proto.replace('_cipher_suites','').replace('_','.')}",
                            description=f"Deprecated protocol {proto} is enabled",
                            severity=FindingSeverity.HIGH,
                            url=result.get("server_location", {}).get("hostname", ""),
                            owasp_category="A02",
                            tool_name="sslyze",
                            raw_output=proto_result,
                        ))
                cert_info = scan_result.get("certificate_info", {})
                if cert_info:
                    findings.append(Finding(
                        title="TLS Certificate Info",
                        description="Certificate analysis completed",
                        severity=FindingSeverity.INFO,
                        tool_name="sslyze",
                        raw_output=cert_info,
                    ))
        except Exception:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        rc, stdout, _ = await self._run_command(["sslyze", "--version"])
        if rc == 0:
            return HealthCheckResult(status=HealthStatus.HEALTHY, version=stdout.strip())
        return HealthCheckResult(status=HealthStatus.UNHEALTHY, message="sslyze not found")
