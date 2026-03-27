import uuid
from datetime import datetime

from pydantic import BaseModel


class OAuthAccountResponse(BaseModel):
    id: uuid.UUID
    provider: str
    provider_user_id: str
    created_at: datetime

    model_config = {"from_attributes": True}
