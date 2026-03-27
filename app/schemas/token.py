import uuid
from datetime import datetime

from pydantic import BaseModel


class RefreshTokenInfo(BaseModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    user_agent: str
    ip_address: str

    model_config = {"from_attributes": True}
