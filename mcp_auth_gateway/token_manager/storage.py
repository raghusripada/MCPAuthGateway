# In mcp_auth_gateway/token_manager/storage.py
import json
from typing import Optional
import redis
import time # Added for save_external_token TTL calculation
from .models import ExternalUserToken
from mcp_auth_gateway.core.config import settings # For Redis config

# Placeholder for encryption utilities - to be implemented separately
def _encrypt_token_value(value: str) -> str:
    # print("DEBUG: _encrypt_token_value called (placeholder)")
    # In a real implementation, this would use a strong encryption library
    # (e.g., cryptography.fernet) with keys managed securely.
    return f"encrypted_{value}" # Simple placeholder

def _decrypt_token_value(encrypted_value: str) -> str:
    # print("DEBUG: _decrypt_token_value called (placeholder)")
    # Corresponding decryption logic.
    if encrypted_value.startswith("encrypted_"):
        return encrypted_value[len("encrypted_"):]
    return encrypted_value # Fallback if not in expected placeholder format

# Initialize Redis client (basic initialization)
try:
    redis_client = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=0, decode_responses=False)
    redis_client.ping() 
    print("Successfully connected to Redis for token_manager.")
except redis.exceptions.ConnectionError as e:
    print(f"Could not connect to Redis for token_manager: {e}")
    redis_client = None # Redis client instance

def _get_token_key(user_id: str, service_name: str) -> str:
    """Generates a consistent Redis key for storing an external token."""
    return f"ext_token:{user_id}:{service_name}"

def save_external_token(token: ExternalUserToken) -> bool:
    """
    Saves an external user token to Redis after encrypting sensitive fields.

    Args:
        token (ExternalUserToken): The token object to save.

    Returns:
        bool: True if saving was successful, False otherwise.
    """
    if not redis_client:
        print("Redis client not available in token_manager.storage. Cannot save token.")
        return False

    key = _get_token_key(token.user_id, token.service_name)
    
    # Apply encryption to sensitive fields before storing
    encrypted_access_token = _encrypt_token_value(token.access_token.get_secret_value())
    encrypted_refresh_token = None
    if token.refresh_token:
        encrypted_refresh_token = _encrypt_token_value(token.refresh_token.get_secret_value())

    token_dict_to_store = {
        "user_id": token.user_id,
        "service_name": token.service_name,
        "access_token": encrypted_access_token, # Store encrypted
        "refresh_token": encrypted_refresh_token, # Store encrypted
        "expires_at": token.expires_at,
        "scopes": token.scopes,
    }
    try:
        redis_client.set(key, json.dumps(token_dict_to_store))
        if token.expires_at:
            ttl = token.expires_at - int(time.time())
            if ttl > 0:
                redis_client.expire(key, ttl)
        return True
    except redis.exceptions.RedisError as e:
        print(f"Redis error saving token: {e}")
        return False


def get_external_token(user_id: str, service_name: str) -> Optional[ExternalUserToken]:
    """
    Retrieves and decrypts an external user token from Redis.

    Args:
        user_id (str): The user's ID.
        service_name (str): The name of the external service.

    Returns:
        Optional[ExternalUserToken]: The token object if found and valid, else None.
    """
    if not redis_client:
        print("Redis client not available in token_manager.storage. Cannot get token.")
        return None

    key = _get_token_key(user_id, service_name)
    try:
        stored_token_bytes = redis_client.get(key) # Returns bytes as decode_responses=False
        if stored_token_bytes:
            token_data_from_redis = json.loads(stored_token_bytes.decode('utf-8')) # Decode bytes then parse JSON
            
            # Decrypt sensitive fields after retrieving
            decrypted_access_token = _decrypt_token_value(token_data_from_redis["access_token"])
            decrypted_refresh_token = None
            if token_data_from_redis.get("refresh_token"):
                decrypted_refresh_token = _decrypt_token_value(token_data_from_redis["refresh_token"])

            # Reconstruct the ExternalUserToken model
            return ExternalUserToken(
                user_id=token_data_from_redis["user_id"],
                service_name=token_data_from_redis["service_name"],
                access_token=decrypted_access_token, # Use decrypted
                refresh_token=decrypted_refresh_token, # Use decrypted
                expires_at=token_data_from_redis.get("expires_at"),
                scopes=token_data_from_redis.get("scopes")
            )
    except redis.exceptions.RedisError as e:
        print(f"Redis error getting token: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding token from Redis: {e}")
    return None

def delete_external_token(user_id: str, service_name: str) -> bool:
    """
    Deletes an external user token from Redis.

    Args:
        user_id (str): The user's ID.
        service_name (str): The name of the external service.
    
    Returns:
        bool: True if deletion was successful or key did not exist, False on Redis error.
    """
    if not redis_client:
        print("Redis client not available in token_manager.storage. Cannot delete token.")
        return False
        
    key = _get_token_key(user_id, service_name)
    try:
        redis_client.delete(key)
        return True
    except redis.exceptions.RedisError as e:
        print(f"Redis error deleting token: {e}")
        return False
