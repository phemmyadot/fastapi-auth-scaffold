import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    event_type: str
    ip_address: str
    user_agent: str
    metadata_: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}
