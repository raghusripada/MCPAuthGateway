import pytest
from mcp_auth_gateway.token_manager.storage import save_external_token, get_external_token, delete_external_token, _encrypt_token_value, _decrypt_token_value, redis_client
from mcp_auth_gateway.token_manager.models import ExternalUserToken
from pydantic import SecretStr
import time

@pytest.fixture
def redis_is_available():
    if redis_client is None:
        return False
    try:
        return redis_client.ping()
    except Exception:
        return False

@pytest.fixture(autouse=True)
def clear_test_token_after_test(redis_is_available):
    if not redis_is_available:
        yield
        return 
    user_id, service_name = "test_user_enc", "test_service_enc"
    delete_external_token(user_id, service_name) 
    yield
    delete_external_token(user_id, service_name) 

def test_encryption_decryption_placeholders():
    original_value = "mysecrettoken"
    encrypted = _encrypt_token_value(original_value)
    assert encrypted == f"encrypted_{original_value}"
    decrypted = _decrypt_token_value(encrypted)
    assert decrypted == original_value
    assert _decrypt_token_value(original_value) == original_value

def test_save_get_external_token_with_encryption_stubs(redis_is_available):
    if not redis_is_available:
        pytest.skip("Redis not available, skipping test_save_get_external_token")

    user_id = "test_user_enc"
    service_name = "test_service_enc"
    token_data = ExternalUserToken(
        user_id=user_id,
        service_name=service_name,
        access_token=SecretStr("access_123"),
        refresh_token=SecretStr("refresh_456"),
        expires_at=int(time.time()) + 3600,
        scopes=["api:read"]
    )
    
    save_success = save_external_token(token_data)
    assert save_success is True

    retrieved_token = get_external_token(user_id, service_name)
    assert retrieved_token is not None
    assert retrieved_token.user_id == user_id
    assert retrieved_token.service_name == service_name
    assert retrieved_token.access_token.get_secret_value() == "access_123" 
    assert retrieved_token.refresh_token.get_secret_value() == "refresh_456" 
    assert retrieved_token.scopes == ["api:read"]
