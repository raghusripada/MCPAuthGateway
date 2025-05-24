import time
import hashlib
import base64

class MCPBadRequest(Exception):
    """Custom exception for OAuth bad requests."""
    pass

class SecureTokenStore:
    """
    Manages the storage of authorization codes and tokens.
    """
    def __init__(self):
        self.auth_codes = {}  # Stores details related to auth codes
        self.tokens = {}      # Stores access/refresh tokens

    async def store_auth_code_details(self, auth_code: str, details: dict):
        """
        Stores details (e.g., client_id, code_challenge, server_id, redirect_uri)
        associated with an authorization code.
        """
        self.auth_codes[auth_code] = details
        print(f"SecureTokenStore: Stored auth code details for {auth_code}")

    async def get_auth_code_details(self, auth_code: str) -> dict:
        """
        Retrieves details for an authorization code.
        Returns None if not found.
        """
        details = self.auth_codes.get(auth_code)
        if details:
            print(f"SecureTokenStore: Retrieved auth code details for {auth_code}")
        else:
            print(f"SecureTokenStore: No details found for auth code {auth_code}")
        return details

    async def save_tokens(self, user_id: str, server_id: str, client_id: str, 
                          access_token: str, refresh_token: str, expires_in: int):
        """
        Placeholder method to save access and refresh tokens.
        """
        token_key = f"{user_id}_{client_id}_{server_id}"
        self.tokens[token_key] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "timestamp": time.time()
        }
        print(f"SecureTokenStore: Tokens saved for user {user_id}, client {client_id}, server {server_id}")

    async def get_token_for_user(self, user_id: str, client_id: str, server_id: str):
        """
        Placeholder method to retrieve a token for a user.
        Returns a dummy token or None.
        """
        token_key = f"{user_id}_{client_id}_{server_id}"
        token_info = self.tokens.get(token_key)
        if token_info:
            print(f"SecureTokenStore: Retrieved token for user {user_id}, client {client_id}, server {server_id}")
            return token_info["access_token"]
        print(f"SecureTokenStore: No token found for user {user_id}, client {client_id}, server {server_id}")
        return None

class ClientRegistry:
    """
    Manages the registration and retrieval of client information.
    """
    def __init__(self):
        self.clients = {}

    async def register_client(self, client_id: str, client_info: dict):
        """
        Stores client information for a given client_id.
        """
        self.clients[client_id] = client_info
        print(f"ClientRegistry: Registered client {client_id}")

    async def get_client(self, client_id: str) -> dict:
        """
        Retrieves client information for a given client_id.
        Returns None if not found.
        """
        client_info = self.clients.get(client_id)
        if client_info:
            print(f"ClientRegistry: Retrieved info for client {client_id}")
        else:
            print(f"ClientRegistry: No info found for client {client_id}")
        return client_info

class MCPOAuthService:
    """
    OAuth Service for MCP, handling authorization and token generation.
    """
    def __init__(self):
        self.token_store = SecureTokenStore()
        self.client_registry = ClientRegistry()
        print("MCPOAuthService initialized with SecureTokenStore and ClientRegistry.")

    async def generate_authorization_code(self, server_id: str, client_id: str, 
                                          redirect_uri: str, code_challenge: str) -> str:
        """
        Generates an authorization code.
        Placeholder implementation.
        """
        print("MCPOAuthService: generate_authorization_code (placeholder)")
        auth_code = f"auth_code_for_{client_id}_{server_id}_{int(time.time())}"
        # Store the code challenge along with other details
        await self.token_store.store_auth_code_details(
            auth_code,
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "server_id": server_id,
                "timestamp": time.time()
            }
        )
        return auth_code

    async def validate_pkce(self, auth_code_details: dict, code_verifier: str) -> bool:
        """
        Validates the PKCE code challenge and verifier.
        Placeholder implementation with simplified validation.
        """
        print("MCPOAuthService: validate_pkce (simplified placeholder)")
        if not auth_code_details:
            print("MCPOAuthService: validate_pkce - No auth_code_details provided.")
            return False
        
        # In a real implementation, you would hash the code_verifier:
        # hashed_verifier = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        # expected_challenge = base64.urlsafe_b64encode(hashed_verifier).rstrip(b'=').decode('utf-8')
        # For this placeholder, we do a simplified check or just return True
        # stored_challenge = auth_code_details.get('code_challenge')
        # print(f"MCPOAuthService: validate_pkce - Stored challenge: {stored_challenge}, Verifier: {code_verifier}")
        # For now, returning True as per subtask instructions for simplified validation.
        print("MCPOAuthService: validate_pkce returning True (simplified validation)")
        return True

    async def generate_access_token(self, server_id: str, client_id: str, user_id: str = None) -> str:
        """
        Generates an access token.
        Placeholder implementation.
        """
        print(f"MCPOAuthService: generate_access_token for client {client_id}, user {user_id or 'server'} (placeholder)")
        return f"access_token_for_{client_id}_{user_id or 'server'}_{int(time.time())}"

    async def generate_refresh_token(self, server_id: str, client_id: str, user_id: str = None) -> str:
        """
        Generates a refresh token.
        Placeholder implementation.
        """
        print(f"MCPOAuthService: generate_refresh_token for client {client_id}, user {user_id or 'server'} (placeholder)")
        return f"refresh_token_for_{client_id}_{user_id or 'server'}_{int(time.time())}"

    async def handle_authorization_for_server(self, server_id: str, client_id: str, 
                                             redirect_uri: str, code_challenge: str, state: str):
        """
        Handles the authorization request for a server.
        """
        print(f"MCPOAuthService: handle_authorization_for_server for server {server_id}, client {client_id}")
        auth_code = await self.generate_authorization_code(
            server_id=server_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge
        )
        return {"code": auth_code, "state": state}

    async def exchange_code_for_token(self, server_id: str, code: str, 
                                      code_verifier: str, client_id: str):
        """
        Exchanges an authorization code for an access token and refresh token.
        """
        print(f"MCPOAuthService: exchange_code_for_token for code {code}, client {client_id}")
        auth_code_details = await self.token_store.get_auth_code_details(code)

        if not auth_code_details:
            raise MCPBadRequest("Invalid authorization code or code expired")

        if auth_code_details.get('client_id') != client_id:
            raise MCPBadRequest("Client ID mismatch")

        # Validate PKCE
        pkce_valid = await self.validate_pkce(auth_code_details, code_verifier)
        if not pkce_valid:
            raise MCPBadRequest("Invalid code verifier or code expired")

        # Assuming successful validation, generate tokens
        # User ID might be part of auth_code_details if user authentication happened
        user_id = auth_code_details.get("user_id", "default_user") # Placeholder user_id

        access_token = await self.generate_access_token(
            server_id=server_id,
            client_id=client_id,
            user_id=user_id 
        )
        refresh_token = await self.generate_refresh_token(
            server_id=server_id,
            client_id=client_id,
            user_id=user_id
        )

        expires_in = 3600
        await self.token_store.save_tokens(
            user_id=user_id,
            server_id=server_id,
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in
        )
        
        # Conceptually, the auth code should be invalidated after use
        # self.token_store.delete_auth_code(code) 
        print(f"MCPOAuthService: Auth code {code} exchanged for tokens.")

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh_token
        }

if __name__ == '__main__':
    import asyncio

    async def main():
        # Test MCPBadRequest
        try:
            raise MCPBadRequest("This is a test error.")
        except MCPBadRequest as e:
            print(f"Caught expected error: {e}")

        # Test ClientRegistry
        client_registry = ClientRegistry()
        await client_registry.register_client("client123", {"name": "Test Client App", "redirect_uris": ["http://localhost/callback"]})
        client_info = await client_registry.get_client("client123")
        print(f"Client info for client123: {client_info}")
        non_existent_client = await client_registry.get_client("nonexistent")
        print(f"Client info for nonexistent: {non_existent_client}")
        print("-" * 20)

        # Test SecureTokenStore
        token_store = SecureTokenStore()
        code_details_to_store = {"client_id": "client123", "code_challenge": "challenge_string", "server_id": "server789"}
        await token_store.store_auth_code_details("authcodeABC", code_details_to_store)
        retrieved_details = await token_store.get_auth_code_details("authcodeABC")
        print(f"Retrieved auth code details: {retrieved_details}")
        await token_store.save_tokens("user001", "server789", "client123", "new_access_token", "new_refresh_token", 3600)
        user_token = await token_store.get_token_for_user("user001", "client123", "server789")
        print(f"Token for user001: {user_token}")
        print("-" * 20)

        # Test MCPOAuthService
        oauth_service = MCPOAuthService()
        
        # Simulate client registration (if MCPOAuthService were to handle it directly or via registry)
        await oauth_service.client_registry.register_client(
            "test_client_id", 
            {"name": "My Test App", "redirect_uris": ["https://client.example.com/callback"]}
        )

        # 1. Authorization Request
        print("\nSimulating Authorization Request:")
        auth_response = await oauth_service.handle_authorization_for_server(
            server_id="mcp_server_1",
            client_id="test_client_id",
            redirect_uri="https://client.example.com/callback",
            code_challenge="example_code_challenge_string_S256", # In real flow, this is client-generated
            state="csrf_state_token_123"
        )
        print(f"Authorization response: {auth_response}")
        generated_auth_code = auth_response["code"]
        print("-" * 20)

        # 2. Token Exchange
        print("\nSimulating Token Exchange:")
        # Client would use the 'generated_auth_code' and its 'code_verifier'
        # For this test, we assume the code_verifier matches the placeholder logic in validate_pkce
        code_verifier_by_client = "example_code_verifier_corresponding_to_challenge" 
        
        try:
            token_response = await oauth_service.exchange_code_for_token(
                server_id="mcp_server_1",
                code=generated_auth_code,
                code_verifier=code_verifier_by_client,
                client_id="test_client_id" 
            )
            print(f"Token exchange response: {token_response}")
        except MCPBadRequest as e:
            print(f"Token exchange failed: {e}")

        print("-" * 20)
        # Test exchange with a non-existent code
        print("\nSimulating Token Exchange with invalid code:")
        try:
            token_response_invalid_code = await oauth_service.exchange_code_for_token(
                server_id="mcp_server_1",
                code="non_existent_code_123",
                code_verifier="verifier",
                client_id="test_client_id"
            )
            print(f"Token exchange response (invalid code): {token_response_invalid_code}")
        except MCPBadRequest as e:
            print(f"Token exchange failed as expected (invalid code): {e}")
            
        # Test exchange with client_id mismatch
        print("\nSimulating Token Exchange with client_id mismatch:")
        # First, generate a valid code
        auth_res_for_mismatch = await oauth_service.handle_authorization_for_server(
            server_id="mcp_server_1", client_id="actual_client", redirect_uri="uri", code_challenge="cc", state="s"
        )
        valid_code_for_mismatch = auth_res_for_mismatch["code"]
        try:
            await oauth_service.exchange_code_for_token(
                server_id="mcp_server_1",
                code=valid_code_for_mismatch,
                code_verifier="cv",
                client_id="mismatched_client" # This client_id is different from "actual_client"
            )
        except MCPBadRequest as e:
            print(f"Token exchange failed as expected (client_id mismatch): {e}")


    if __name__ == "__main__":
        asyncio.run(main())
