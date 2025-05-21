from fastapi import APIRouter, Request, Depends, HTTPException, Body, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests # For forwarding requests to backend MCP servers
import secrets
import json
from typing import Optional, Union, Dict, Any

from .models import JsonRpcRequest, JsonRpcResponse, JsonRpcErrorData, ToolsListResult, ToolDefinition, ToolParameters, ToolParameterProperty, PendingAuthContext
from mcp_auth_gateway.auth_server.utils import decode_jwt_token # For validating gateway's own JWT
from mcp_auth_gateway.token_manager import get_external_token, ExternalUserToken
from mcp_auth_gateway.registry import get_mcp_server_config, get_external_service_config, get_all_mcp_servers
from mcp_auth_gateway.auth_server.storage import redis_client as mcp_redis_client # db=1 for ATAG pending contexts (same as atag_endpoints)

mcp_router = APIRouter(tags=["MCP JSON-RPC"]) # Router for MCP JSON-RPC endpoint

# HTTPBearer for getting the "Authorization: Bearer <token>"
oauth2_scheme = HTTPBearer(auto_error=False) # auto_error=False to handle missing token manually

def _get_pending_atag_auth_key(state: str) -> str: # Duplicated from atag_endpoints, consider moving to a shared util
    """Generates a Redis key for storing pending ATAG authentication context."""
    return f"pending_atag_auth:{state}"

async def get_authenticated_user_from_gateway_jwt(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme)
) -> Dict[str, Any]:
    """
    Dependency to authenticate requests to the /mcp endpoint using a JWT
    issued by this gateway's own OAuth server.
    Decodes the token and returns its payload.
    Raises HTTPException if authentication fails.
    """
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated with MCP Gateway",
            headers={"WWW-Authenticate": "Bearer"}, # Important for OAuth
        )
    
    token_data = decode_jwt_token(auth.credentials)
    if not token_data or "user_id" not in token_data: # Check for user_id or sub
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MCP Gateway token",
            headers={"WWW-Authenticate": "Bearer error="invalid_token""},
        )
    # Ensure 'scopes' is a list if present, or handle as needed
    if "scopes" in token_data and not isinstance(token_data["scopes"], list):
        token_data["scopes"] = str(token_data.get("scopes", "")).split()

    return token_data # Contains user_id, scopes, cid, etc.

@mcp_router.post("/mcp", response_model=JsonRpcResponse)
async def handle_mcp_request(
    request: Request, # FastAPI request object
    payload: JsonRpcRequest, # Body will be parsed as JsonRpcRequest
    # Authorization: MCP Gateway's own JWT (Bearer token)
    gateway_auth_data: Dict[str, Any] = Depends(get_authenticated_user_from_gateway_jwt)
):
    """
    Main MCP JSON-RPC endpoint.
    Handles 'tools/list' and 'tools/call' methods.
    - Authenticates requests using a JWT from this gateway's OAuth server.
    - For 'tools/call', it checks for required external service tokens.
    - If a token is missing/expired, it initiates the ATAG flow by returning a 401 error
      with an 'auth_url' pointing to the ATAG initiation endpoint.
    - If tokens are available, it proxies the call to the appropriate backend MCP server,
      injecting the external service token into the request.
    """
    user_id = gateway_auth_data.get("user_id") or gateway_auth_data.get("sub") # Extract user_id from gateway's JWT
    if not user_id:
         return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32000, message="User ID not found in gateway token"))

    # --- Method: tools/list ---
    if payload.method == "tools/list":
        # For simplicity, list tools from all configured MCP servers or a specific one if provided in params
        # This is a simplified mock based on the problem description's example.
        all_tools = []
        # Example: list tools from a specific MCP server if specified, else all
        # target_mcp_server_name = payload.params.get("mcp_server_name") if payload.params else None
        
        mcp_servers = get_all_mcp_servers()
        for server_name, mcp_server_cfg in mcp_servers.items():
            # This is a mock. Real tool listing might involve calling the actual MCP server's tools/list
            # or having a more detailed tool definition in our registry.
            # For now, creating one or two dummy tools per configured MCP server.
            all_tools.append(ToolDefinition(
                name=f"{server_name}_sample_tool_1",
                description=f"Sample tool 1 from {mcp_server_cfg.description}",
                parameters=ToolParameters(properties={
                    "param1": ToolParameterProperty(type="string", description="Sample parameter 1")
                }, required=["param1"])
            ))
        return JsonRpcResponse(id=payload.id, result=ToolsListResult(tools=all_tools))

    # --- Method: tools/call ---
    elif payload.method == "tools/call":
        if not payload.params or not isinstance(payload.params, dict) or "name" not in payload.params:
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32602, message="Invalid params: 'name' of tool is required."))
        
        tool_name = payload.params["name"] 
        # This is where we need to determine which MCP server hosts this tool.
        # And what external service that MCP server/tool requires.
        # For now, let's assume tool_name format is like "mcp_server_name/actual_tool_name"
        # or we look it up in a more detailed tool registry (not implemented yet).
        # Simplified: Assume tool_name directly maps to an MCP server for this example,
        # e.g., "google_drive_reader_sample_tool_1" implies "google_drive_reader" MCP server.
        
        target_mcp_server_name = None
        # Crude way to find server from tool name for this example
        for mcp_s_name in get_all_mcp_servers().keys():
            if tool_name.startswith(mcp_s_name):
                target_mcp_server_name = mcp_s_name
                break
        
        if not target_mcp_server_name:
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32601, message=f"Tool '{tool_name}' not found or MCP server cannot be determined."))

        mcp_server_cfg = get_mcp_server_config(target_mcp_server_name)
        if not mcp_server_cfg: # Should not happen if logic above is correct
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32601, message="MCP Server configuration not found."))

        ext_service_name = mcp_server_cfg.target_external_service
        ext_service_cfg = get_external_service_config(ext_service_name)
        if not ext_service_cfg:
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32001, message=f"External service '{ext_service_name}' for tool '{tool_name}' not configured."))

        # Check for existing valid token for the external service
        external_token: Optional[ExternalUserToken] = get_external_token(user_id, ext_service_name)
        
        if not external_token or external_token.is_expired():
            # Token needed or expired. Initiate ATAG flow.
            # 1. Generate state
            atag_state = secrets.token_urlsafe(32)
            # 2. Store PendingAuthContext
            pending_context = PendingAuthContext(
                user_id=user_id,
                service_name=ext_service_name,
                original_request_data=payload.dict() # Store the original MCP request
            )
            if not mcp_redis_client:
                 return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32000, message="Redis client not available for ATAG context storage."))
            mcp_redis_client.set(_get_pending_atag_auth_key(atag_state), pending_context.json(), ex=1800) # 30 min expiry

            # 3. Construct auth_url for the 401 response
            # The URL points to our ATAG initiator endpoint
            # request.url_for requires the endpoint function name. Need to ensure atag_router is setup for this.
            # For now, constructing manually. Ensure prefix is correct.
            # initiate_auth_url = request.url_for('initiate_external_auth', service_name=ext_service_name) # This needs endpoint name
            initiate_auth_url_path = f"/atag/initiate-auth/{ext_service_name}?state={atag_state}"
            # Construct full URL including base
            base_url_for_atag = str(request.base_url).rstrip('/')
            full_initiate_auth_url = f"{base_url_for_atag}{initiate_auth_url_path}"


            error_data_401 = {
                "auth_url": full_initiate_auth_url,
                "service": ext_service_name,
                "scopes": ext_service_cfg.scopes # Scopes that will be requested
            }
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=401, message="Authentication required for external service", data=error_data_401))

        # Token exists and is valid, proceed to call the backend MCP server
        try:
            actual_mcp_server_url = f"http://{mcp_server_cfg.host}:{mcp_server_cfg.port}/mcp" # Assuming backend also has /mcp
            
            # Prepare new JSON-RPC request for the backend MCP server
            # It should get the original method and params, but with new auth info
            backend_payload = payload.dict() # Get the original payload
            
            # Inject external service token into the `authorization` field as per problem description's example
            # This structure is specific to how backend MCP servers expect it.
            backend_payload["authorization"] = {
                "tokens": {ext_service_name: external_token.access_token.get_secret_value()},
                "user_id": user_id 
            }
            # Alternatively, some servers might expect a simple Bearer token in header:
            # headers = {"Authorization": f"Bearer {external_token.access_token.get_secret_value()}"}

            # For this example, we assume the backend MCP server expects the JSON-RPC payload
            # to be exactly what the client sent, but we add an `authorization` field.
            # The problem description's python snippet for MCP server request includes `authorization`:
            # "authorization": { "tokens": tokens, "user_id": user_id }

            # Let's reconstruct the params for the backend to include the actual tool name without the server prefix if we used that convention
            # For now, assume the backend MCP server knows how to handle the tool_name as is.

            mcp_response = requests.post(actual_mcp_server_url, json=backend_payload, timeout=15)
            mcp_response.raise_for_status() # Check for HTTP errors from backend
            
            backend_json_response = mcp_response.json()
            # Ensure the backend response is a valid JsonRpcResponse structure
            # For now, directly forward what we got if it's JSON
            return backend_json_response # This assumes backend returns a full JsonRpcResponse structure

        except requests.exceptions.Timeout:
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32002, message="Request to backend MCP server timed out."))
        except requests.exceptions.RequestException as e:
            return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32003, message=f"Error calling backend MCP server: {str(e)}"))
        except ValueError as e: # JSONDecodeError
             return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32004, message=f"Backend MCP server returned non-JSON response: {str(e)}"))

    else:
        return JsonRpcResponse(id=payload.id, error=JsonRpcErrorData(code=-32601, message="Method not found"))
