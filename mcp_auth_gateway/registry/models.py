from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional

class ExternalServiceConfig(BaseModel):
    client_id: str
    client_secret: str # Consider using SecretStr for actual secret handling if available/needed
    auth_url: HttpUrl
    token_url: HttpUrl
    redirect_url: HttpUrl # This gateway's callback URL for this service
    scopes: List[str]
    # service_specific_params: Optional[Dict[str, str]] # If needed later

class MCPServiceConfig(BaseModel): # Renamed from MCPServiceConfig to avoid confusion with ExternalServiceConfig
    name: str
    description: str
    host: str # Hostname of the MCP server
    port: int
    health_check_path: Optional[str] = "/health"
    
    # This MCP server's own OAuth 2.1 metadata (if it acts as its own provider)
    # Or, if it relies on the central gateway for all OAuth:
    # external_service_name: str # Name of the external service it connects to (e.g., "google", "github")
    # required_scopes: List[str] # Scopes required from the external_service_name

    # Based on the second document, each MCP server might have its own auth requirements
    # or an MCP server might be an umbrella for tools needing different external auths.
    # For now, let's assume an MCP server is tied to ONE primary external service for its tools.
    # The ATAG pattern suggests the gateway helps users get tokens for these external services.
    
    # Let's align with the "MCP Server Registry" ConfigMap example from the problem description:
    # It seems MCP Servers have their *own* auth_base_url and metadata_url,
    # which implies they could be independent OAuth servers, or these URLs could
    # point back to our central gateway, but parameterized for that service.

    # For the ATAG flow, the critical part is knowing which *external service*
    # an MCP server's tools will ultimately need to access.
    # Let's assume for now that an "MCP Server" in the registry is a logical grouping
    # that might use a specific external service (like Google, GitHub).
    # The `auth_base_url` and `metadata_url` in the example `mcp-server-registry`
    # seems to be for clients of that MCP server, not for the gateway to get tokens *for* that server.

    # Let's simplify: an MCP Server entry will define what external service its tools use.
    # The MCP Auth Gateway then helps the user get a token for that *external service*.
    
    # This field will map to an entry in the ExternalServiceConfig registry
    # to find the actual OAuth endpoints for "Google", "GitHub", etc.
    target_external_service: str 
    default_scopes_for_target_service: List[str]


class RegistryData(BaseModel):
    external_services: Dict[str, ExternalServiceConfig]
    mcp_servers: Dict[str, MCPServiceConfig]
