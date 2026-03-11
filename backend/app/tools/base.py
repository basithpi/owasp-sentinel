from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import asyncio
import logging
import shutil


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    description: str
    severity: FindingSeverity
    url: str = ""
    parameter: str = ""
    payload_used: str = ""
    evidence: str = ""
    remediation: str = ""
    owasp_category: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    tool_name: str = ""
    raw_output: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    success: bool
    findings: List[Finding]
    raw_output: str
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class HealthCheckResult:
    status: HealthStatus
    version: str = ""
    message: str = ""


class BaseTool(ABC):
    name: str = ""
    version: str = ""
    category: str = ""
    docker_image: str = ""
    priority: str = "P0"

    def __init__(self):
        self.logger = logging.getLogger(f"tools.{self.name}")
        self.timeout = 300

    @abstractmethod
    async def execute(self, target: str, config: Dict[str, Any]) -> ToolResult:
        """Execute the tool against target."""
        pass

    @abstractmethod
    async def parse_output(self, raw_output: str) -> List[Finding]:
        """Parse tool-specific output to normalized Finding objects."""
        pass

    @abstractmethod
    async def health_check(self) -> HealthCheckResult:
        """Check if tool is installed and operational."""
        pass

    async def install(self) -> bool:
        """Install the tool. Override if needed."""
        return shutil.which(self.name) is not None

    async def update(self) -> bool:
        """Update the tool. Override if needed."""
        return True

    async def _run_command(self, cmd: List[str], timeout: int = None) -> tuple:
        """Run a subprocess command and return (returncode, stdout, stderr)."""
        timeout = timeout or self.timeout
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            if proc is not None:
                proc.kill()
            return -1, "", f"Command timed out after {timeout}s"
        except FileNotFoundError:
            return -1, "", f"Tool '{cmd[0]}' not found in PATH"
