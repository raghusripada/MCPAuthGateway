import json
import time
import uuid
from typing import Optional, Dict # Added Dict as per subtask description
import redis
from .models import OAuthClient, AuthorizationCode # ClientRegistrationResponse removed as per subtask
from mcp_auth_gateway.core.config import settings

# Initialize Redis client (similar to token_manager.storage)
try:
    redis_client = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=1, decode_responses=True) # db=1 to separate from ext_tokens
    redis_client.ping()
    print("Successfully connected to Redis for auth_server.")
except redis.exceptions.ConnectionError as e:
    print(f"Could not connect to Redis for auth_server: {e}")
    redis_client = None
except Exception as e: # Catch other potential errors
    print(f"An error occurred while initializing Redis for auth_server: {e}")
    redis_client = None # Redis client instance


# --- Client Registration Storage ---
def _get_client_key(client_id: str) -> str:
    """Generates a Redis key for storing OAuth client details."""
    return f"oauth_client:{client_id}"

def save_client(client: OAuthClient) -> OAuthClient:
    """
    Saves an OAuth client's details to Redis.

    Args:
        client (OAuthClient): The client object to save.

    Returns:
        OAuthClient: The saved client object.
    
    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    redis_client.set(_get_client_key(client.client_id), client.json())
    return client

def get_client(client_id: str) -> Optional[OAuthClient]:
    """
    Retrieves an OAuth client's details from Redis.

    Args:
        client_id (str): The ID of the client to retrieve.

    Returns:
        Optional[OAuthClient]: The client object if found, else None.

    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    client_data = redis_client.get(_get_client_key(client_id))
    return OAuthClient(**json.loads(client_data)) if client_data else None

# --- Authorization Code Storage ---
def _get_auth_code_key(code: str) -> str:
    """Generates a Redis key for storing an authorization code."""
    return f"auth_code:{code}"

def save_auth_code(auth_code: AuthorizationCode):
    """
    Saves an authorization code to Redis with an expiration.

    Args:
        auth_code (AuthorizationCode): The authorization code object to save.
    
    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    ttl = auth_code.expires_at - int(time.time())
    if ttl > 0:
        redis_client.set(_get_auth_code_key(auth_code.code), auth_code.json(), ex=ttl)

def get_auth_code(code: str) -> Optional[AuthorizationCode]:
    """
    Retrieves an authorization code from Redis.
    Also checks for server-side expiry and deletes if expired.

    Args:
        code (str): The authorization code string.

    Returns:
        Optional[AuthorizationCode]: The code object if found and not expired, else None.

    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    code_data = redis_client.get(_get_auth_code_key(code))
    if code_data:
        auth_code_obj = AuthorizationCode(**json.loads(code_data))
        # Double check expiry, Redis TTL is a backup
        if time.time() >= auth_code_obj.expires_at:
            redis_client.delete(_get_auth_code_key(code)) # Clean up expired code
            return None
        return auth_code_obj
    return None

def delete_auth_code(code: str):
    """
    Deletes an authorization code from Redis.

    Args:
        code (str): The authorization code string to delete.
    
    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    redis_client.delete(_get_auth_code_key(code))

# --- Refresh Token Storage (Example, might need more robust approach) ---
def _get_refresh_token_key(refresh_token: str) -> str:
    """Generates a Redis key for storing refresh token information."""
    return f"refresh_token:{refresh_token}"

def save_refresh_token_info(refresh_token: str, client_id: str, user_id: str, scopes: str, expires_in_seconds: int = 24*60*60*30): # e.g. 30 days
    """
    Saves information associated with a refresh token to Redis.

    Args:
        refresh_token (str): The refresh token string.
        client_id (str): The client ID associated with the token.
        user_id (str): The user ID associated with the token.
        scopes (str): A space-separated string of scopes.
        expires_in_seconds (int): Expiration time for the token info in seconds.
    
    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    data = {"client_id": client_id, "user_id": user_id, "scopes": scopes}
    redis_client.set(_get_refresh_token_key(refresh_token), json.dumps(data), ex=expires_in_seconds)

def get_refresh_token_info(refresh_token: str) -> Optional[Dict]:
    """
    Retrieves information associated with a refresh token from Redis.

    Args:
        refresh_token (str): The refresh token string.

    Returns:
        Optional[Dict]: A dictionary containing client_id, user_id, and scopes, or None if not found.
    
    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    data = redis_client.get(_get_refresh_token_key(refresh_token))
    return json.loads(data) if data else None

def delete_refresh_token_info(refresh_token: str):
    """
    Deletes refresh token information from Redis.

    Args:
        refresh_token (str): The refresh token string to delete.

    Raises:
        ConnectionError: If Redis client is not available.
    """
    if not redis_client: raise ConnectionError("Redis client not available in auth_server.storage")
    redis_client.delete(_get_refresh_token_key(refresh_token))
