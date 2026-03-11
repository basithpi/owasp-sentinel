from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class AIService:
    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.model = settings.OPENAI_MODEL

    async def analyze_finding(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "OpenAI API key not configured", "analysis": None}

        prompt = f"""Analyze this security finding and provide:
1. Risk assessment (1-10)
2. Exploitation difficulty (easy/medium/hard)
3. Business impact summary
4. Recommended remediation steps
5. Similar CVEs if applicable

Finding:
Title: {finding_data.get('title')}
Severity: {finding_data.get('severity')}
Description: {finding_data.get('description')}
URL: {finding_data.get('url')}
OWASP Category: {finding_data.get('owasp_category')}
"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a security expert analyzing vulnerability findings."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 1000,
                    },
                )
                if response.status_code == 200:
                    result = response.json()
                    content = result["choices"][0]["message"]["content"]
                    return {"analysis": content, "model": self.model, "tokens_used": result.get("usage", {})}
                else:
                    logger.error("OpenAI API error", status=response.status_code)
                    return {"error": f"API error: {response.status_code}", "analysis": None}
        except Exception as e:
            logger.error("AI analysis failed", error=str(e))
            return {"error": str(e), "analysis": None}

    async def generate_remediation(self, vulnerability_type: str, context: Dict[str, Any]) -> str:
        if not self.api_key:
            return "AI remediation not available. Configure OPENAI_API_KEY."
        return f"Remediation guidance for {vulnerability_type}: Review OWASP guidelines and apply security patches."

    async def triage_findings(self, findings: list) -> list:
        triaged = []
        for finding in findings:
            analysis = await self.analyze_finding(finding)
            finding["ai_analysis"] = analysis
            triaged.append(finding)
        return triaged


ai_service = AIService()
