import pytest
from pathlib import Path
import yaml
from mcp_auth_gateway.registry.loader import load_registry_data, get_external_service_config, get_mcp_server_config, _registry_data as registry_cache # Import cache to reset it
from mcp_auth_gateway.registry.models import RegistryData, ExternalServiceConfig, MCPServiceConfig

TEST_REGISTRY_CONTENT = {
    "external_services": {
        "test_google": {
            "client_id": "test_google_id", "client_secret": "test_google_secret",
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "redirect_url": "http://localhost:8000/atag/callback/external/test_google",
            "scopes": ["email", "profile"]
        }
    },
    "mcp_servers": {
        "test_mcp_server": {
            "name": "Test MCP Server", "description": "A test server",
            "host": "test-mcp.example.com", "port": 8080,
            "target_external_service": "test_google",
            "default_scopes_for_target_service": ["email"]
        }
    }
}

@pytest.fixture(autouse=True)
def clear_registry_cache():
    global registry_cache
    registry_cache_original_ref = registry_cache
    registry_cache = None # Reset cache before each test
    yield
    registry_cache = registry_cache_original_ref # Restore if needed, though None should cause reload

@pytest.fixture
def temp_registry_file(tmp_path: Path) -> Path:
    file_path = tmp_path / "test_registry_data.yaml"
    with open(file_path, 'w') as f:
        yaml.dump(TEST_REGISTRY_CONTENT, f)
    return file_path

def test_load_registry_data(temp_registry_file: Path):
    registry = load_registry_data(path=temp_registry_file)
    assert registry is not None
    assert "test_google" in registry.external_services
    assert "test_mcp_server" in registry.mcp_servers
    assert registry.external_services["test_google"].client_id == "test_google_id"

def test_get_external_service_config(temp_registry_file: Path):
    load_registry_data(path=temp_registry_file) 
    config = get_external_service_config("test_google")
    assert config is not None
    assert config.client_id == "test_google_id"
    assert get_external_service_config("non_existent") is None

def test_get_mcp_server_config(temp_registry_file: Path):
    load_registry_data(path=temp_registry_file) 
    config = get_mcp_server_config("test_mcp_server")
    assert config is not None
    assert config.name == "Test MCP Server"
    assert get_mcp_server_config("non_existent") is None
    
def test_load_non_existent_registry_file(tmp_path: Path):
    # Test the behavior when the registry file does not exist
    # The current implementation prints a warning and returns an empty registry.
    registry = load_registry_data(path=tmp_path / "non_existent.yaml")
    assert registry is not None
    assert not registry.external_services # Should be empty
    assert not registry.mcp_servers     # Should be empty
