from fastapi import FastAPI, Form, Query, HTTPException # Removed Depends as it's not used
# from flask import Flask, request, jsonify # Removed Flask imports
from mcp_oauth_service import MCPOAuthService, MCPBadRequest 
import asyncio
import uvicorn # Added uvicorn

class MCPServerInstance:
    def __init__(self, server_id: str, oauth_service: MCPOAuthService):
        self.server_id = server_id
        self.oauth_service = oauth_service
        self.app = FastAPI() # Changed from Flask to FastAPI
        self._setup_routes()
        print(f"MCPServerInstance '{server_id}' initialized with FastAPI.")

    def _setup_routes(self):
        @self.app.get("/authorize")
        async def authorize(
            client_id: str = Query(...), 
            redirect_uri: str = Query(...), 
            code_challenge: str = Query(...), 
            state: str = Query(...),
            # response_type: str = Query(...) # Optional: if strict validation needed
        ):
            print(f"MCPServerInstance[{self.server_id}]: Received GET /authorize request.")
            # FastAPI handles missing required parameters automatically with Query(...)
            # if response_type != 'code': # Example of additional validation if needed
            #     raise HTTPException(status_code=400, detail={"error": "invalid_response_type", "description": "Only 'code' response_type is supported."})
            try:
                print(f"MCPServerInstance[{self.server_id}]: /authorize - Calling oauth_service.handle_authorization_for_server...")
                result = await self.oauth_service.handle_authorization_for_server(
                    server_id=self.server_id,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    state=state
                )
                print(f"MCPServerInstance[{self.server_id}]: /authorize - Success. Result: {result}")
                return result
            except MCPBadRequest as e:
                print(f"MCPServerInstance[{self.server_id}]: /authorize - MCPBadRequest: {e}")
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                print(f"MCPServerInstance[{self.server_id}]: /authorize - Unexpected error: {e}")
                # In a real app, log the exception e more thoroughly
                raise HTTPException(status_code=500, detail="An unexpected error occurred.")

        @self.app.post("/token")
        async def token(
            grant_type: str = Form(...),
            code: str = Form(...),
            code_verifier: str = Form(...),
            client_id: str = Form(...)
            # redirect_uri: str = Form(None) # Optional: if your service requires it
        ):
            print(f"MCPServerInstance[{self.server_id}]: Received POST /token request.")
            if grant_type != 'authorization_code':
                print(f"MCPServerInstance[{self.server_id}]: /token - Unsupported grant_type: {grant_type}")
                raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type", 
                                                              "description": "Only 'authorization_code' grant_type is supported."})
            
            # FastAPI handles missing required parameters automatically with Form(...)
            try:
                print(f"MCPServerInstance[{self.server_id}]: /token - Calling oauth_service.exchange_code_for_token...")
                result = await self.oauth_service.exchange_code_for_token(
                    server_id=self.server_id,
                    code=code,
                    code_verifier=code_verifier,
                    client_id=client_id
                    # redirect_uri=redirect_uri # Pass if your service logic needs it
                )
                print(f"MCPServerInstance[{self.server_id}]: /token - Success. Result: {result}")
                return result
            except MCPBadRequest as e:
                print(f"MCPServerInstance[{self.server_id}]: /token - MCPBadRequest: {e}")
                # According to OAuth 2.0, error for token endpoint can be 'invalid_grant' or 'invalid_client'
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                print(f"MCPServerInstance[{self.server_id}]: /token - Unexpected error: {e}")
                # In a real app, log the exception e more thoroughly
                raise HTTPException(status_code=500, detail="An unexpected error occurred.")
                
    # def run(self, host='0.0.0.0', port=8080): # Removed run method
    #     print(f"MCPServerInstance[{self.server_id}]: Starting Flask app on {host}:{port}...")
    #     self.app.run(host=host, port=port, debug=True) 

# __main__ block for testing
if __name__ == '__main__':
    host = '0.0.0.0' # Or '127.0.0.1'
    port = 8080

    oauth_service_instance = MCPOAuthService()
    
    async def setup_dummy_client_for_testing():
        test_client_id = "test_mcp_client_001" 
        await oauth_service_instance.client_registry.register_client(
            test_client_id, 
            {"name": "Test MCP Client Application", 
             "redirect_uris": [f"http://{host}:{port}/callback", f"http://localhost:{port}/callback"]}
        )
        print(f"Dummy client '{test_client_id}' registered in MCPOAuthService for testing.")

    asyncio.run(setup_dummy_client_for_testing())

    server_instance = MCPServerInstance(
        server_id="mcp_instance_alpha_001_fastapi", 
        oauth_service=oauth_service_instance
    )
    
    # The FastAPI application instance to run with uvicorn
    # This makes it explicit for uvicorn.run
    app_to_run = server_instance.app 

    print(f"Attempting to start MCPServerInstance (FastAPI) 'mcp_instance_alpha_001_fastapi' on http://{host}:{port}...")
    # Use uvicorn to run the FastAPI app
    uvicorn.run(app_to_run, host=host, port=port) # Removed reload=True, can be added for dev
    
    print("MCPServerInstance (FastAPI) has finished (this message may not be reached if server runs indefinitely).")
