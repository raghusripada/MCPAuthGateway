from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
import secrets
import json
import time

from mcp_auth_gateway.token_manager import (
    build_authorization_url, 
    exchange_code_for_token, 
    save_external_token,
    ExternalUserToken
)
from mcp_auth_gateway.registry import get_external_service_config
from mcp_auth_gateway.core.config import settings # For Redis config
from .models import PendingAuthContext # Assuming models.py is in the same mcp_gateway package

# Get the same Redis client instance as used elsewhere or initialize a new one for this specific need.
# For consistency, ideally, this comes from a central Redis utility or app state.
# Re-using the one from auth_server.storage for simplicity, assuming it's compatible.
from mcp_auth_gateway.auth_server.storage import redis_client as atag_redis_client # db=1

atag_router = APIRouter(tags=["ATAG OAuth Flow"]) # Router for ATAG specific endpoints

# This is the key for storing original request during ATAG OAuth Dance
def _get_pending_atag_auth_key(state: str) -> str:
    """Generates a Redis key for storing pending ATAG authentication context."""
    return f"pending_atag_auth:{state}"

# Mock user authentication (similar to auth_server.endpoints)
# In a real scenario, user_id would be reliably determined from the request to /mcp endpoint first.
# Then, that user_id would be part of the PendingAuthContext.
async def get_atag_user_id(request: Request) -> str:
    """
    Mock user authentication for ATAG flow. 
    Retrieves or sets a dummy user_id in the session.
    """
    # This is a placeholder. The actual user_id should be the one for whom the ATAG flow is initiated.
    # It should be passed into /initiate-auth or retrieved from a secure session/token
    # that links to the user who made the original MCP call.
    # For now, using the same dummy session as /oauth/authorize for testing.
    if 'dummy_user_id' not in request.session:
        # This state implies user is not logged into our main app, which shouldn't happen if ATAG is triggered
        # by an MCP call that itself should be authenticated.
        raise HTTPException(status_code=401, detail="User session not found for ATAG flow.")
    return request.session['dummy_user_id']


@atag_router.get("/initiate-auth/{service_name}")
async def initiate_external_auth(
    service_name: str,
    request: Request, # FastAPI request
    state: str = Query(..., description="The state parameter linking to a pending auth context."),
    user_id: str = Depends(get_atag_user_id) # Ensure user is identified
):
    """
    Initiates the OAuth 2.0 authorization flow for an external service.
    Redirects the user to the external service's authorization endpoint.
    The 'state' parameter is used to store and later retrieve the original request context.
    """
    ext_service_cfg = get_external_service_config(service_name)
    if not ext_service_cfg:
        raise HTTPException(status_code=404, detail=f"External service '{service_name}' not configured.")

    auth_url_tuple = build_authorization_url(service_name, state, user_hint=user_id) # user_id as hint
    if not auth_url_tuple:
        raise HTTPException(status_code=500, detail=f"Could not build authorization URL for {service_name}.")
    
    actual_auth_url, scopes_used = auth_url_tuple
    
    return RedirectResponse(url=actual_auth_url)


@atag_router.get("/callback/external/{service_name}", name="atag_external_callback")
async def handle_external_auth_callback(
    service_name: str,
    request: Request, # FastAPI request
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    state: Optional[str] = Query(None) # This state is CRITICAL
):
    """
    Handles the OAuth 2.0 callback from the external service.
    Exchanges the authorization code for an access token, saves the token,
    and cleans up the pending authentication context.
    """
    if error:
        return JSONResponse(
            status_code=400,
            content={"error": error, "error_description": error_description, "state": state, "service_name": service_name}
        )

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state in callback from external service.")

    pending_context_key = _get_pending_atag_auth_key(state)
    if not atag_redis_client: 
        raise HTTPException(status_code=500, detail="Redis client not available for ATAG callback.")
        
    pending_context_json = atag_redis_client.get(pending_context_key)
    if not pending_context_json:
        raise HTTPException(status_code=400, detail="Invalid or expired state. Authentication session not found.")
    
    pending_context = PendingAuthContext(**json.loads(pending_context_json))
    
    if pending_context.service_name != service_name:
        raise HTTPException(status_code=400, detail="Service name mismatch in state and callback URL.")

    token_data = exchange_code_for_token(service_name, code, state) 
    if not token_data or "access_token" not in token_data:
        atag_redis_client.delete(pending_context_key)
        raise HTTPException(status_code=500, detail=f"Failed to exchange code for token with {service_name}.")

    expires_in = token_data.get("expires_in")
    user_token = ExternalUserToken(
        user_id=pending_context.user_id,
        service_name=service_name,
        access_token=token_data["access_token"], 
        refresh_token=token_data.get("refresh_token"),
        expires_at=int(time.time()) + expires_in if expires_in else None,
        scopes=token_data.get("scope", "").split() 
    )

    if not save_external_token(user_token):
        atag_redis_client.delete(pending_context_key)
        raise HTTPException(status_code=500, detail=f"Failed to save token for {service_name}.")

    atag_redis_client.delete(pending_context_key)

    html_content = f"""
        <html>
            <head><title>Authentication Successful</title></head>
            <body>
                <h1>Authentication with {service_name.capitalize()} Successful!</h1>
                <p>User ID: {pending_context.user_id}</p>
                <p>Access token for {service_name} has been obtained and stored.</p>
                <p>You can now return to your chat application or original tab.</p>
                <script>
                    // Optionally, try to close the window if opened by script
                    // window.close(); 
                </script>
            </body>
        </html>
    """
    return HTMLResponse(content=html_content)
