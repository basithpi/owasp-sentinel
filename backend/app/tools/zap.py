import asyncio
import json
from typing import Dict, Any, List

from .base import BaseTool, Finding, FindingSeverity, ToolResult, HealthCheckResult, HealthStatus
from .registry import registry


@registry.register
class ZapTool(BaseTool):
    name = "zap"
    category = "web-scanner"
    priority = "P0"
    ZAP_API = "http://localhost:8090"

    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        import httpx as httpx_client
        try:
            async with httpx_client.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.ZAP_API}/JSON/spider/action/scan/", params={"url": target})
                scan_id = resp.json().get("scan", "0")
                for _ in range(60):
                    await asyncio.sleep(2)
                    r = await client.get(f"{self.ZAP_API}/JSON/spider/view/status/", params={"scanId": scan_id})
                    if int(r.json().get("status", 0)) >= 100:
                        break
                resp = await client.get(f"{self.ZAP_API}/JSON/ascan/action/scan/", params={"url": target})
                ascan_id = resp.json().get("scan", "0")
                for _ in range(150):
                    await asyncio.sleep(2)
                    r = await client.get(f"{self.ZAP_API}/JSON/ascan/view/status/", params={"scanId": ascan_id})
                    if int(r.json().get("status", 0)) >= 100:
                        break
                alerts_resp = await client.get(f"{self.ZAP_API}/JSON/core/view/alerts/", params={"baseurl": target})
                raw = alerts_resp.text
                findings = await self.parse_output(raw)
                return ToolResult(success=True, findings=findings, raw_output=raw)
        except Exception as e:
            return ToolResult(success=False, findings=[], raw_output="", error=str(e))

    async def parse_output(self, raw_output: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(raw_output)
            risk_map = {
                "High": FindingSeverity.HIGH,
                "Medium": FindingSeverity.MEDIUM,
                "Low": FindingSeverity.LOW,
                "Informational": FindingSeverity.INFO,
            }
            for alert in data.get("alerts", []):
                findings.append(Finding(
                    title=alert.get("name", "ZAP Alert"),
                    description=alert.get("description", ""),
                    severity=risk_map.get(alert.get("risk", "Low"), FindingSeverity.LOW),
                    url=alert.get("url", ""),
                    parameter=alert.get("param", ""),
                    evidence=alert.get("evidence", ""),
                    remediation=alert.get("solution", ""),
                    tool_name="zap",
                    raw_output=alert,
                ))
        except Exception:
            pass
        return findings

    async def health_check(self) -> HealthCheckResult:
        try:
            import httpx as httpx_client
            async with httpx_client.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.ZAP_API}/JSON/core/view/version/")
                ver = r.json().get("version", "unknown")
                return HealthCheckResult(status=HealthStatus.HEALTHY, version=ver)
        except Exception as e:
            return HealthCheckResult(status=HealthStatus.UNHEALTHY, message=str(e))
