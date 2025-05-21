import pytest
import time
from datetime import timedelta
from mcp_auth_gateway.auth_server import utils as auth_utils 
from jose import JWTError


def test_create_decode_jwt_token():
    # Ensure JWT_SECRET_KEY is consistent for testing if it's dynamically generated in utils
    # If auth_utils.JWT_SECRET_KEY is module-level global and generated once on import, this is fine.
    # Otherwise, consider patching or setting it.
    original_secret_key = auth_utils.JWT_SECRET_KEY # Store original
    auth_utils.JWT_SECRET_KEY = "test_secret_key_for_jwt_tests" # Override for test predictability

    data = {"user_id": "testuser", "custom_claim": "value"}
    token = auth_utils.create_jwt_token(data)
    assert token is not None

    decoded_payload = auth_utils.decode_jwt_token(token)
    assert decoded_payload is not None
    assert decoded_payload["user_id"] == "testuser"
    assert decoded_payload["custom_claim"] == "value"
    assert "exp" in decoded_payload
    assert "iat" in decoded_payload
    assert decoded_payload.get("sub") == "testuser"
    
    auth_utils.JWT_SECRET_KEY = original_secret_key # Restore

def test_jwt_token_expiration():
    original_secret_key = auth_utils.JWT_SECRET_KEY
    auth_utils.JWT_SECRET_KEY = "test_secret_key_for_jwt_tests_expiration"

    data = {"user_id": "exp_user"}
    token = auth_utils.create_jwt_token(data, expires_delta=timedelta(milliseconds=1)) 
    
    time.sleep(0.1) 

    with pytest.raises(JWTError): # python-jose raises JWTError for expired tokens
       auth_utils.decode_jwt_token(token) # This should raise due to expiration
    
    # Or if decode_jwt_token catches and returns None:
    # assert auth_utils.decode_jwt_token(token) is None
    
    auth_utils.JWT_SECRET_KEY = original_secret_key


def test_decode_invalid_jwt_token():
    original_secret_key = auth_utils.JWT_SECRET_KEY
    auth_utils.JWT_SECRET_KEY = "test_secret_key_for_jwt_tests_invalid"
    # Assuming decode_jwt_token catches JWTError and returns None
    assert auth_utils.decode_jwt_token("invalid.token.string") is None
    assert auth_utils.decode_jwt_token("") is None
    auth_utils.JWT_SECRET_KEY = original_secret_key


def test_pkce_verification_s256():
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert auth_utils.verify_pkce(code_verifier, code_challenge, "S256") is True
    assert auth_utils.verify_pkce(code_verifier + "a", code_challenge, "S256") is False

def test_pkce_verification_plain():
    code_verifier = "plainverifier"
    assert auth_utils.verify_pkce(code_verifier, code_verifier, "PLAIN") is True
    assert auth_utils.verify_pkce(code_verifier + "a", code_verifier, "PLAIN") is False
