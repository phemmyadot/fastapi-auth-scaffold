"""Non-blocking audit log writer using asyncio.create_task (Spec §4 Complex)."""
import asyncio
import uuid
from typing import Any

import structlog

from app.core.config import settings
from app.db.models.audit_log import AuditEventType

logger = structlog.get_logger(__name__)


async def _write_audit_log(
    event_type: AuditEventType,
    user_id: uuid.UUID | None = None,
    ip_address: str = "",
    user_agent: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Persist an audit log entry in its own session (fire-and-forget safe)."""
    try:
        from app.db.base import async_session_factory
        from app.db.models.audit_log import AuditLog

        async with async_session_factory() as session:
            log_entry = AuditLog(
                user_id=user_id,
                event_type=event_type,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata_=metadata or {},
            )
            session.add(log_entry)
            await session.commit()
    except Exception:
        logger.error("Failed to write audit log", event_type=event_type.value, exc_info=True)


def emit_audit_log(
    event_type: AuditEventType,
    user_id: uuid.UUID | None = None,
    ip_address: str = "",
    user_agent: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Fire-and-forget audit log. Safe to call from sync context within an async event loop."""
    if not settings.ENABLE_AUDIT_LOGGING:
        return

    asyncio.create_task(
        _write_audit_log(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )
    )
