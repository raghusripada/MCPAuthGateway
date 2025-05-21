from pydantic import BaseModel, SecretStr
from typing import Optional, List
import time

class ExternalUserToken(BaseModel):
    user_id: str # Identifier for the user within our system
    service_name: str # e.g., "google", "github"
    access_token: SecretStr
    refresh_token: Optional[SecretStr] = None
    expires_at: Optional[int] = None # Timestamp of expiry
    scopes: Optional[List[str]] = None # Scopes granted

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False # If no expiry, assume not expired (e.g. Opaque tokens without explicit lifetime)
        return time.time() >= self.expires_at
