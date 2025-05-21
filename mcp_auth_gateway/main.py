from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse # For testing authorize
from starlette.middleware.sessions import SessionMiddleware # For dummy_user_id in /authorize
import urllib.parse # For urlencode in test-auth, make sure it's imported

# Import storage and models for the /test-auth endpoint's client registration
from mcp_auth_gateway.auth_server import storage # Corrected import
from mcp_auth_gateway.auth_server import models # Corrected import
from pydantic import HttpUrl # For HttpUrl in test_client, ensure this is imported

from mcp_auth_gateway.auth_server.endpoints import auth_router
from mcp_auth_gateway.core.config import settings # For JWT_SECRET_KEY if moved there

app = FastAPI(title="MCP Authentication Gateway")

# Add SessionMiddleware for /authorize user simulation
# In production, JWT_SECRET_KEY for sessions should be from settings and secure
# Using a placeholder secret for now.
# IMPORTANT: The secret key should be a strong, randomly generated string,
# and ideally loaded from environment variables or a secrets manager.
# Using settings.redis_host here is just for placeholder convenience
# if it's a somewhat random-looking string. Replace with a real secret.
# SESSION_SECRET_KEY = getattr(settings, "session_secret_key", "your-fallback-very-secret-key-32-chars")
# if SESSION_SECRET_KEY == "your-fallback-very-secret-key-32-chars":
#     print("WARNING: Using fallback session secret key. Please set a strong, random key in your settings.")

app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key) # New way

app.include_router(auth_router) # auth_router already has prefix "/oauth"

@app.get("/")
async def read_root():
    return {"message": "MCP Authentication Gateway is running. Visit /docs for API details."}

# Simple test page for initiating authorization (for development)
@app.get("/test-auth", response_class=HTMLResponse)
async def test_auth_page(request: Request):
    client_id = "testclient"
    redirect_uri_str = "http://localhost:8000/test-auth-callback" # Must be one of the client's registered URIs
    
    # Pre-register a test client for this page to work easily
    # This check and registration should ideally be in a startup event or a separate script.
    if not storage.get_client(client_id): # storage is from mcp_auth_gateway.auth_server
        try:
            # Use HttpUrl from pydantic for redirect_uris list
            test_client = models.OAuthClient( # models is from mcp_auth_gateway.auth_server
                client_id=client_id,
                client_secret="testsecret", 
                redirect_uris=[HttpUrl(redirect_uri_str)], # Wrap string in HttpUrl
                scope="tools/call tools/list openid profile email" # Added OIDC scopes
            )
            storage.save_client(test_client)
            print(f"Test client '{client_id}' registered for /test-auth.")
        except Exception as e: # Catch potential errors during client creation/saving
            print(f"Error registering test client '{client_id}': {e}")
            return HTMLResponse(f"Error registering test client: {e}", status_code=500)


    auth_url_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri_str,
        "scope": "tools/call openid", # Request specific scopes
        "state": "randomstate123",
        # Example PKCE S256 challenge for code_verifier 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", 
        "code_challenge_method": "S256"
    }
    
    # Construct authorize URL relative to the application root
    # The auth_router has prefix "/oauth", so endpoint is "/oauth/authorize"
    # request.url_for('authorize') might not work if authorize endpoint isn't named or router setup is complex.
    # Building manually based on known prefix and path.
    # Giving the authorize route a name='authorize' in endpoints.py allows using request.url_for
    try:
        authorize_path = request.url_for('authorize') # Assuming 'authorize' is the name of the route
    except Exception: # Fallback if url_for fails (e.g. route not named)
        authorize_path = auth_router.prefix + "/authorize"

    base_url = str(request.base_url).rstrip('/')
    full_auth_url = f"{base_url}{authorize_path}?{urllib.parse.urlencode(auth_url_params)}"
    
    return f'''
        <html><body>
            <h1>Test OAuth Authorization</h1>
            <p>Client ID: {client_id}</p>
            <p>Redirect URI: {redirect_uri_str}</p>
            <p><a href="{full_auth_url}">Login and Authorize Test Client</a></p>
            <p>Ensure client '{client_id}' is registered with redirect URI '{redirect_uri_str}' and scope 'tools/call openid'.</p>
            <p>If you see errors, check server logs. Client registration happens on first load of this page if client doesn't exist.</p>
        </body></html>
    '''

@app.get("/test-auth-callback") # Example callback for the test client
async def test_auth_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    if error:
        return {"status": "error", "error": error, "state": state}
    if code:
        # In a real client, you'd now exchange this code for a token via the /oauth/token endpoint.
        # This callback is just for demonstration.
        return {
            "status": "success", 
            "code": code, 
            "state": state, 
            "message": "Authorization code received. Next step for a real client: Exchange this code for a token at the /oauth/token endpoint."
        }
    return {"status": "unknown_callback_state", "message": "No code or error received."}
