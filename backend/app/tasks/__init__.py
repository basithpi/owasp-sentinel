"""OWASP Sentinel v3 – Celery tasks package.

Public re-exports so callers can import task functions directly from
``app.tasks`` rather than from the individual sub-modules.
"""
from .celery_app import celery_app  # noqa: F401 – Celery application instance

# Scan orchestration
from .scan_tasks import (  # noqa: F401
    aggregate_results,
    execute_scan,
    publish_scan_progress,
    run_tool,
)

# Individual security-tool tasks
from .tool_tasks import (  # noqa: F401
    check_tool_health,
    run_httpx_probe,
    run_nmap_scan,
    run_nuclei_scan,
    run_sqlmap_scan,
    run_subfinder_scan,
    run_xsstrike_scan,
)

# Report generation
from .report_tasks import (  # noqa: F401
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_pdf_report,
)

# Continuous monitoring
from .monitor_tasks import (  # noqa: F401
    check_certificate_expiry,
    check_subdomain_changes,
    check_technology_changes,
    check_uptime,
    run_continuous_monitors,
)

# Notifications
from .notification_tasks import (  # noqa: F401
    broadcast_realtime_notification,
    send_email_notification,
    send_slack_notification,
    send_webhook_notification,
)

__all__ = [
    # Celery app
    "celery_app",
    # Scan
    "execute_scan",
    "run_tool",
    "aggregate_results",
    "publish_scan_progress",
    # Tools
    "run_nuclei_scan",
    "run_nmap_scan",
    "run_sqlmap_scan",
    "run_xsstrike_scan",
    "run_subfinder_scan",
    "run_httpx_probe",
    "check_tool_health",
    # Reports
    "generate_pdf_report",
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_report",
    # Monitors
    "run_continuous_monitors",
    "check_subdomain_changes",
    "check_certificate_expiry",
    "check_technology_changes",
    "check_uptime",
    # Notifications
    "send_email_notification",
    "send_webhook_notification",
    "send_slack_notification",
    "broadcast_realtime_notification",
]
