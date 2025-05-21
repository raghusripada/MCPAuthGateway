import yaml
from pathlib import Path
from typing import Optional, Dict
from .models import RegistryData, ExternalServiceConfig, MCPServiceConfig
from mcp_auth_gateway.core.config import settings # Assuming settings might define the path

REGISTRY_FILE_PATH = Path(__file__).parent / "registry_data.yaml"

_registry_data: Optional[RegistryData] = None # Internal cache for registry data

def load_registry_data(path: Path = REGISTRY_FILE_PATH) -> RegistryData:
    """
    Loads registry data from a YAML file.
    Caches the data after the first load.
    If the file is not found or data is invalid, returns an empty RegistryData object.

    Args:
        path (Path): The path to the YAML registry file.

    Returns:
        RegistryData: The loaded (or empty) registry data.
    """
    global _registry_data
    if _registry_data is None:
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            _registry_data = RegistryData(**data)
        except FileNotFoundError:
            # Fallback to empty registry if file not found, or raise error
            print(f"Warning: Registry file {path} not found. Using empty registry.")
            _registry_data = RegistryData(external_services={}, mcp_servers={})
        except Exception as e:
            print(f"Error loading registry data from {path}: {e}")
            # Depending on strictness, could raise here or return empty/default
            _registry_data = RegistryData(external_services={}, mcp_servers={})
    return _registry_data

def get_external_service_config(service_name: str) -> Optional[ExternalServiceConfig]:
    """
    Retrieves the configuration for a specific external service.

    Args:
        service_name (str): The name of the external service.

    Returns:
        Optional[ExternalServiceConfig]: The service configuration if found, else None.
    """
    registry = load_registry_data()
    return registry.external_services.get(service_name)

def get_mcp_server_config(server_name: str) -> Optional[MCPServiceConfig]:
    """
    Retrieves the configuration for a specific MCP server.

    Args:
        server_name (str): The name of the MCP server.

    Returns:
        Optional[MCPServiceConfig]: The MCP server configuration if found, else None.
    """
    registry = load_registry_data()
    return registry.mcp_servers.get(server_name)

def get_all_mcp_servers() -> Dict[str, MCPServiceConfig]:
    """Returns a dictionary of all configured MCP servers."""
    registry = load_registry_data()
    return registry.mcp_servers

def get_all_external_services() -> Dict[str, ExternalServiceConfig]:
    """Returns a dictionary of all configured external services."""
    registry = load_registry_data()
    return registry.external_services

# Example of how to make it available in the app context if needed
# from fastapi import Request
# def get_registry(request: Request) -> RegistryData:
#     return request.app.state.registry
