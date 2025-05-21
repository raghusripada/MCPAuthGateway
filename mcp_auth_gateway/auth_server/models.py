from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
import time

class OAuthClient(BaseModel):
    client_id: str
    client_secret: Optional[str] = None # For confidential clients
    client_name: Optional[str] = None
    redirect_uris: List[HttpUrl]
    scope: str # Space-separated list of scopes this client is allowed to request
    client_id_issued_at: int = Field(default_factory=lambda: int(time.time()))
    client_secret_expires_at: int = 0 # 0 means never expires

    # For public clients using PKCE, client_secret might be None
    # token_endpoint_auth_method: str = "client_secret_basic" # or "none" for public

class AuthorizationCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: HttpUrl
    scopes: str # Space-separated
    user_id: str # The user who authorized
    expires_at: int # Timestamp
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None # "S256" or "plain"

class IssuedToken(BaseModel): # MCP Access Token (JWT)
    access_token: str
    token_type: str = "Bearer"
    expires_in: int # Lifetime in seconds
    refresh_token: Optional[str] = None
    scope: str # Space-separated scopes granted
    user_id: str # User for whom token was issued

class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[HttpUrl] = None
    client_id: Optional[str] = None # Optional if using client auth header
    client_secret: Optional[str] = None # Optional if using client auth header
    refresh_token: Optional[str] = None
    code_verifier: Optional[str] = None # For PKCE

class ClientRegistrationRequest(BaseModel):
    redirect_uris: List[HttpUrl]
    client_name: Optional[str] = None
    token_endpoint_auth_method: Optional[str] = "client_secret_basic"
    scope: Optional[str] = "tools/list tools/call" # Default scopes client requests
    grant_types: Optional[List[str]] = ["authorization_code", "refresh_token"]
    response_types: Optional[List[str]] = ["code"]
    # software_id: Optional[str]
    # software_version: Optional[str]

class ClientRegistrationResponse(OAuthClient):
    registration_access_token: Optional[str] = None # For accessing client config endpoint
    registration_client_uri: Optional[HttpUrl] = None # URL for client to manage its registration
