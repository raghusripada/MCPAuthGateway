import secrets
import hashlib
import base64
import time
from jose import jwt, JWTError
from datetime import datetime, timedelta # Ensure timedelta is imported from datetime
from typing import Optional, List, Dict
from pydantic import HttpUrl

from mcp_auth_gateway.core.config import settings # Import settings

# Configuration for JWTs
# JWT_SECRET_KEY = secrets.token_urlsafe(32) # Old way
JWT_SECRET_KEY = settings.jwt_secret_key # New way
JWT_ALGORITHM = "HS256" # HS256 is fine for symmetric keys
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Default lifetime for access tokens
REFRESH_TOKEN_EXPIRE_DAYS = 7 # Default lifetime for refresh tokens

def generate_token(length: int = 32) -> str:
    """Generates a cryptographically secure URL-safe string token."""
    return secrets.token_urlsafe(length)

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None, token_type: str = "access") -> str:
    """
    Creates a JWT token.

    Args:
        data (dict): The data payload to include in the token. Must contain 'user_id'.
        expires_delta (Optional[timedelta]): Custom expiration time. Defaults based on token_type.
        token_type (str): Type of token ('access', 'refresh', or other), affects default expiry.

    Returns:
        str: The encoded JWT.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        if token_type == "access":
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        elif token_type == "refresh":
             expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        else: # Default short expiry
            expire = datetime.utcnow() + timedelta(minutes=15)
            
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    if "sub" not in to_encode and "user_id" in to_encode : # Add subject if not present
        to_encode["sub"] = str(to_encode["user_id"])

    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str) -> Optional[dict]:
    """
    Decodes a JWT token.

    Args:
        token (str): The JWT string to decode.

    Returns:
        Optional[dict]: The decoded payload if the token is valid and not expired, else None.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e: # Catches ExpiredSignatureError, InvalidTokenError, etc.
        print(f"JWT Error: {e}")
    return None

def verify_pkce(code_verifier: str, code_challenge: str, code_challenge_method: str) -> bool:
    """
    Verifies a PKCE code_verifier against a code_challenge.

    Args:
        code_verifier (str): The plain text verifier.
        code_challenge (str): The challenge string.
        code_challenge_method (str): The method used for the challenge ('S256' or 'PLAIN').

    Returns:
        bool: True if verification succeeds, False otherwise.
    """
    if code_challenge_method.upper() == "S256":
        hashed_verifier = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        recreated_challenge = base64.urlsafe_b64encode(hashed_verifier).decode('utf-8').rstrip('=')
        return recreated_challenge == code_challenge
    elif code_challenge_method.upper() == "PLAIN": # Be explicit about case
        return code_verifier == code_challenge
    return False

def validate_redirect_uri(client_redirect_uris: List[HttpUrl], requested_redirect_uri: HttpUrl) -> bool:
    """
    Validates if the requested_redirect_uri is among the client's registered URIs.

    Args:
        client_redirect_uris (List[HttpUrl]): A list of pre-registered redirect URIs for the client.
        requested_redirect_uri (HttpUrl): The redirect URI requested by the client.

    Returns:
        bool: True if the URI is valid, False otherwise.
    """
    return str(requested_redirect_uri) in [str(uri) for uri in client_redirect_uris] # Compare as strings

def generate_client_credentials() -> tuple[str, str]:
    """
    Generates a new client_id and client_secret.

    Returns:
        tuple[str, str]: A tuple containing the new client_id and client_secret.
    """
    client_id = generate_token(16) 
    client_secret = generate_token(32)
    return client_id, client_secret
