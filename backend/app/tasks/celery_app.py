from celery import Celery

from ..config import settings


def create_celery_app() -> Celery:
    app = Celery(
        "owasp_sentinel",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=[
            "app.tasks.scan_tasks",
            "app.tasks.tool_tasks",
            "app.tasks.report_tasks",
            "app.tasks.monitor_tasks",
            "app.tasks.notification_tasks",
        ],
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_default_retry_delay=60,
        task_max_retries=3,
        # Rate limiting
        task_annotations={
            "app.tasks.tool_tasks.*": {"rate_limit": "10/m"},
            "app.tasks.scan_tasks.execute_scan": {"rate_limit": "5/m"},
        },
        # Beat schedule for monitors
        beat_schedule={
            "run-continuous-monitors": {
                "task": "monitor_tasks.run_continuous_monitors",
                "schedule": 300.0,  # Every 5 minutes
            },
        },
    )
    return app


celery_app = create_celery_app()
