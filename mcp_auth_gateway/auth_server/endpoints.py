from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import HttpUrl, ValidationError
from typing import Optional, List, Dict, Union 
import time
import urllib.parse
import base64 # Added for Basic Auth decoding
from datetime import timedelta # Ensure timedelta is imported from datetime

from . import storage, utils, models
from mcp_auth_gateway.core.config import settings # For base URL if needed
# Assume user_id comes from an upstream authenticator (e.g. OAuth2Proxy headers)
# For now, we'll mock it or expect it in session for the /authorize endpoint.

auth_router = APIRouter(prefix="/oauth", tags=["OAuth 2.1 Server"]) # Main router for OAuth server endpoints

# Mock user authentication for /authorize - replace with actual user session/token
async def get_current_user_id(request: Request) -> str:
    """
    Mock user authentication. Retrieves or sets a dummy user_id in the session.
    In a real application, this would integrate with a proper authentication system.
    """
    # In a real app, this would come from session cookie, decoded JWT from header, etc.
    # For example, if OAuth2Proxy sets a header like X-User-ID:
    # user_id = request.headers.get("X-User-ID")
    # if not user_id:
    #    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not authenticated")
    # return user_id
    # For now, returning a dummy user for testing the flow
    if 'dummy_user_id' not in request.session:
        request.session['dummy_user_id'] = 'test_user_123' # Simulate login
    return request.session['dummy_user_id']


@auth_router.get("/.well-known/oauth-authorization-server")
async def get_oauth_server_metadata(request: Request):
    """
    OAuth 2.1 Authorization Server Metadata endpoint (RFC 8414).
    Provides configuration information about the OAuth server.
    """
    base_url = str(request.base_url).rstrip('/') + auth_router.prefix
    # Derived from problem spec & RFC8414
    metadata = {
        "issuer": str(request.base_url).rstrip('/'),
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",
        "scopes_supported": ["tools/call", "tools/list", "resource/get", "openid", "profile", "email"], # Added OIDC scopes
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"], # 'none' for public clients
        "code_challenge_methods_supported": ["S256", "plain"],
        # "jwks_uri": f"{base_url}/.well-known/jwks.json", # If using asymmetric keys
        "service_documentation": f"{str(request.base_url).rstrip('/')}/docs", # Point to FastAPI docs
    }
    return JSONResponse(content=metadata)

@auth_router.post("/register", response_model=models.ClientRegistrationResponse, status_code=status.HTTP_201_CREATED)
async def register_client_endpoint(reg_request: models.ClientRegistrationRequest):
    """
    OAuth 2.1 Dynamic Client Registration endpoint (RFC 7591).
    Allows clients to register with the authorization server.
    """
    client_id, client_secret = utils.generate_client_credentials()
    
    # Validate redirect_uris
    for uri in reg_request.redirect_uris:
        if not isinstance(uri, HttpUrl): # Basic check, Pydantic handles format
            raise HTTPException(status_code=400, detail=f"Invalid redirect_uri: {uri}")

    new_client = models.OAuthClient(
        client_id=client_id,
        client_secret=client_secret, # For confidential clients
        client_name=reg_request.client_name,
        redirect_uris=reg_request.redirect_uris,
        scope=" ".join(sorted(list(set(reg_request.scope.split())))) if reg_request.scope else "",
        # token_endpoint_auth_method=reg_request.token_endpoint_auth_method # TODO: Store and use this
    )
    storage.save_client(new_client)
    
    # Construct response, omitting secret if not supposed to be returned directly, or based on spec.
    # RFC7591 suggests returning client_secret.
    return models.ClientRegistrationResponse(**new_client.dict())


@auth_router.get("/authorize", name="authorize") 
async def authorize(
    request: Request, # FastAPI Request object
    response_type: str,
    client_id: str,
    redirect_uri: HttpUrl, # Pydantic will validate format
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    # current_user_id: str = Depends(get_current_user_id) # This would trigger login if not authenticated
):
    """
    OAuth 2.1 Authorization Endpoint (RFC 6749, Section 4.1).
    Handles user authorization for a client application.
    Supports PKCE (RFC 7636).
    """
    # --- User Authentication (Simulated) ---
    # This is where you'd typically redirect to a login page if user is not authenticated.
    # For this example, we'll assume user is 'test_user_123' or prompt for consent.
    # If using an upstream like OAuth2Proxy, user ID should be injected or retrievable.
    try:
        current_user_id = await get_current_user_id(request) # Simulate getting user
    except HTTPException: # Not authenticated by upstream
        # Redirect to an actual login page, or error if login is mandatory before /authorize
        # For now, let's assume this endpoint is hit *after* user login on the platform.
        # Or, the consent screen itself is the "login" for this app's authorization.
        return JSONResponse({"error": "unauthorized", "error_description": "User not authenticated upstream"}, status_code=401)


    client = storage.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if not utils.validate_redirect_uri(client.redirect_uris, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")

    # PKCE Checks (Required for public clients, good for all)
    if code_challenge and not code_challenge_method:
        code_challenge_method = "plain" # Default to plain if challenge is present but no method
    if code_challenge_method and code_challenge_method.upper() not in ["S256", "PLAIN"]:
        raise HTTPException(status_code=400, detail="Unsupported code_challenge_method")
    if client.client_secret is None and not code_challenge: # Public client must use PKCE
         # Actually, spec says server MAY require PKCE. Let's make it recommended for public clients
        pass # raise HTTPException(status_code=400, detail="PKCE required for public clients")

    # TODO: Implement a consent screen if scopes are being requested for the first time
    # For now, auto-approve scopes defined for the client or requested scopes if within client's allowance

    auth_code_value = utils.generate_token(32)
    auth_code = models.AuthorizationCode(
        code=auth_code_value,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scope or client.scope, # Use requested scope or client's default
        user_id=current_user_id,
        expires_at=int(time.time()) + 600, # 10 minutes
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method.upper() if code_challenge_method else None
    )
    storage.save_auth_code(auth_code)

    redirect_url_params = {"code": auth_code_value}
    if state:
        redirect_url_params["state"] = state
    
    # Ensure redirect_uri is a string for URL parsing
    final_redirect_uri = str(redirect_uri)
    if urllib.parse.urlparse(final_redirect_uri).query:
        final_redirect_uri += "&" + urllib.parse.urlencode(redirect_url_params)
    else:
        final_redirect_uri += "?" + urllib.parse.urlencode(redirect_url_params)
        
    return RedirectResponse(url=final_redirect_uri)


@auth_router.post("/token", response_model=models.IssuedToken)
async def token_exchange(
    # Using Form data as per OAuth2 spec for token endpoint
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[HttpUrl] = Form(None), # Must match if provided during auth code
    client_id: Optional[str] = Form(None), # Optional if using Basic Auth
    client_secret: Optional[str] = Form(None), # Optional if using Basic Auth
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None), # For PKCE
    request: Request # To check Basic Auth
):
    """
    OAuth 2.1 Token Endpoint (RFC 6749, Section 3.2).
    Issues access tokens (and optionally refresh tokens) based on various grant types.
    Supports: authorization_code, refresh_token, client_credentials.
    Handles client authentication via Basic Auth or request body parameters.
    """
    # Client Authentication (Basic Auth or client_id/secret in body)
    auth_client_id = client_id
    auth_client_secret = client_secret

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("basic "):
        try:
            decoded_creds = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            auth_client_id, auth_client_secret = decoded_creds.split(":", 1)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Basic auth header")
    
    if not auth_client_id:
        raise HTTPException(status_code=400, detail="Client authentication required (client_id missing)")

    client = storage.get_client(auth_client_id)
    if not client:
        raise HTTPException(status_code=401, detail="Invalid client_id")

    if client.client_secret and client.client_secret != auth_client_secret:
        # This check applies if client is confidential and secret is provided
        # For public clients, client.client_secret would be None.
        # TODO: Check client.token_endpoint_auth_method
        raise HTTPException(status_code=401, detail="Invalid client_secret")


    if grant_type == "authorization_code":
        if not code or not redirect_uri: # redirect_uri is required for auth_code grant
            raise HTTPException(status_code=400, detail="Missing code or redirect_uri for authorization_code grant")
        
        auth_code_data = storage.get_auth_code(code)
        storage.delete_auth_code(code) # Code must be used only once

        if not auth_code_data:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
        if auth_code_data.client_id != client.client_id:
            raise HTTPException(status_code=400, detail="Code not issued to this client")
        if str(auth_code_data.redirect_uri) != str(redirect_uri): # Compare as strings
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")

        # PKCE Verification
        if auth_code_data.code_challenge:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="Code verifier required for PKCE")
            if not utils.verify_pkce(code_verifier, auth_code_data.code_challenge, auth_code_data.code_challenge_method):
                raise HTTPException(status_code=400, detail="Invalid code_verifier for PKCE")
        elif client.client_secret is None: # Public client without PKCE used in auth flow
             # Server policy might reject this if PKCE was expected for public clients
             pass 

        user_id = auth_code_data.user_id
        scopes_granted = auth_code_data.scopes
    
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token for refresh_token grant")
        
        rt_info = storage.get_refresh_token_info(refresh_token)
        if not rt_info or rt_info["client_id"] != client.client_id:
            # Optionally delete invalid refresh token: storage.delete_refresh_token_info(refresh_token)
            raise HTTPException(status_code=400, detail="Invalid or expired refresh token")
        
        user_id = rt_info["user_id"]
        scopes_granted = rt_info["scopes"]
        # Optional: Issue a new refresh token and invalidate the old one (rotation)
        # storage.delete_refresh_token_info(refresh_token)
        # new_refresh_token_value = utils.generate_token(64)
        # storage.save_refresh_token_info(new_refresh_token_value, client.client_id, user_id, scopes_granted)
        # refresh_token_to_return = new_refresh_token_value

    elif grant_type == "client_credentials":
        # Typically used for M2M communication. User might be a service account ID.
        if not client.client_secret: # Client credentials flow requires a confidential client
             raise HTTPException(status_code=400, detail="Client credentials grant requires a confidential client")
        user_id = client.client_id # For M2M, user_id can be the client_id itself
        scopes_granted = client.scope # Grant client's pre-configured scopes
        # No refresh token for client_credentials typically
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    # Issue JWT access token
    access_token_jwt = utils.create_jwt_token(
        data={"user_id": user_id, "cid": client.client_id, "scopes": scopes_granted.split()}, # scopes as list
        expires_delta=timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES), 
        token_type="access"
    )

    # Issue refresh token if applicable (not for client_credentials)
    refresh_token_to_return = None
    if grant_type in ["authorization_code", "refresh_token"]:
        # If not doing refresh token rotation, reuse the existing one for "refresh_token" grant if it was provided
        # For "authorization_code", always issue a new one.
        if grant_type == "authorization_code" or (grant_type == "refresh_token" and not refresh_token): # Or if rotating
            new_refresh_token_value = utils.generate_token(64) # Longer for refresh tokens
            storage.save_refresh_token_info(new_refresh_token_value, client.client_id, user_id, scopes_granted)
            refresh_token_to_return = new_refresh_token_value
        elif grant_type == "refresh_token" and refresh_token: # Re-use if not rotating
            refresh_token_to_return = refresh_token


    return models.IssuedToken(
        access_token=access_token_jwt,
        expires_in=utils.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token_to_return,
        scope=scopes_granted,
        user_id=user_id # Added user_id to IssuedToken response as per model
    )
