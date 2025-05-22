# MCPAuthGateway

## Overview

The MCP Authentication Gateway is a Python-based service built with FastAPI that acts as a secure authentication and authorization layer for applications using the Model Context Protocol (MCP). It enables agentic systems, such as chat interfaces, to securely access external services (like Google Drive, GitHub, etc.) on behalf of users.

The primary goal of this project is to implement the **Authenticated Tool Access Gateway (ATAG)** pattern. This involves managing OAuth 2.1 flows both as a client (to external services) and as a server (for MCP clients authorizing against the gateway itself). The gateway ensures that users grant proper consent and that tokens are handled securely.

This project was developed based on detailed technical specifications outlining the architecture, authentication flows, and security considerations for such a gateway.

## Key Features

*   **MCP OAuth 2.1 Compliant Server:**
    *   Provides standard OAuth 2.1 endpoints for MCP clients:
        *   `/.well-known/oauth-authorization-server`: Server metadata discovery (RFC8414).
        *   `/oauth/register`: Dynamic client registration for MCP clients (RFC7591).
        *   `/oauth/authorize`: Handles authorization requests from MCP clients.
        *   `/oauth/token`: Issues JWT-based access tokens and refresh tokens to MCP clients (supports Authorization Code grant with PKCE, Refresh Token grant, and Client Credentials grant).
*   **External Service Authentication (ATAG Flow):**
    *   Manages OAuth 2.1 authentication flows with external services (e.g., Google, GitHub).
    *   If an MCP tool call requires access to an external service for which the user hasn't granted permission, the gateway triggers the ATAG flow:
        *   Returns a `401 Authentication Required` error to the MCP client with a specific `auth_url`.
        *   This `auth_url` directs the user through an OAuth flow with the external service, orchestrated by the gateway.
    *   Handles callbacks from external services, securely obtains and stores external service tokens (access and refresh tokens) associated with the user.
*   **Token Management:**
    *   Stores external service tokens in Redis.
    *   Includes placeholder hooks for encrypting sensitive token data at rest.
*   **MCP JSON-RPC Endpoint (`/mcp`):**
    *   Secured endpoint requiring a valid JWT issued by this gateway's own OAuth server.
    *   Handles `tools/list` method (provides a sample list of available tools).
    *   Handles `tools/call` method:
        *   Determines the required external service for the requested tool.
        *   Triggers the ATAG flow if necessary.
        *   If authorized, proxies the tool call to the appropriate backend MCP server, injecting the required external service token.
*   **Configurable Registries:**
    *   External service configurations (client IDs, secrets, endpoints, scopes) are managed via a YAML registry (`registry/registry_data.yaml`).
    *   Backend MCP server definitions are also managed in this registry.
*   **Security Focused:**
    *   Supports PKCE (Proof Key for Code Exchange) for enhanced security in OAuth flows.
    *   Uses JWTs for access tokens issued to MCP clients.
    *   Manages sensitive configurations (JWT secret, Session secret) via environment variables.
*   **Built with FastAPI:** Leverages modern Python features, asynchronous capabilities, and Pydantic for data validation.

## Project Structure

*   `mcp_auth_gateway/`: Root directory for the FastAPI application.
    *   `main.py`: FastAPI application initialization and main routers.
    *   `core/`: Core components like configuration management (`config.py`) and base Pydantic models.
    *   `auth_server/`: Implements the MCP OAuth 2.1 Authorization Server functionality.
    *   `token_manager/`: Manages OAuth tokens for external services (storage, client interactions).
    *   `mcp_gateway/`: Implements the `/mcp` JSON-RPC endpoint and the ATAG flow logic.
    *   `registry/`: Handles loading of external service and MCP server configurations.
    *   `tests/`: Contains unit tests for the application.
*   `pyproject.toml`: Project metadata and dependencies (managed by Poetry).
*   `README.md`: This file.

## Configuration

Core service configuration (like Redis connection details, JWT secrets, and session secrets) is managed via environment variables, loaded by `mcp_auth_gateway/core/config.py` using Pydantic's `BaseSettings`. Create a `.env` file in the project root for local development.

**Example `.env` file:**
```env
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET_KEY=your_strong_random_secret_for_jwt_please_change_me
SESSION_SECRET_KEY=your_strong_random_secret_for_sessions_please_change_me
```
**Note:** `JWT_SECRET_KEY` must be a persistent, strong, random string in production. `SESSION_SECRET_KEY` also requires a strong, random string for production.

External services (like Google, GitHub) and backend MCP Server definitions are configured in `mcp_auth_gateway/registry/registry_data.yaml`.
For sensitive data like `client_id` and `client_secret` for these external services:
- In a development environment, these can be placeholders in the YAML or directly set.
- **In production, these should be injected securely, e.g., by referencing environment variables that are then loaded by the application at runtime into the configuration models.** The current YAML example uses placeholder strings like `"YOUR_GOOGLE_CLIENT_ID_ENV_VAR_OR_VALUE"`. These must be replaced with actual values or a secure loading mechanism.

## Running the Application

1.  **Prerequisites:**
    *   Python 3.8+
    *   Poetry (for dependency management)
    *   Redis server running

2.  **Installation:**
    ```bash
    git clone https://github.com/raghusripada/MCPAuthGateway.git
    cd MCPAuthGateway
    poetry install
    ```

3.  **Configure Environment:**
    *   Copy `.env.example` to `.env` (if an example is provided, otherwise create `.env` as shown above).
    *   Update `.env` with your Redis details and generate strong secret keys.
    *   Update `mcp_auth_gateway/registry/registry_data.yaml` with actual client IDs/secrets for any external services you intend to use.

4.  **Run the Service:**
    ```bash
    poetry run uvicorn mcp_auth_gateway.main:app --reload --port 8000
    ```
    The service will be available at `http://localhost:8000`.

## Running Tests
```bash
poetry run pytest tests/
```

## Key Endpoints

*   **OAuth 2.1 Server (for MCP Clients):**
    *   `GET /oauth/.well-known/oauth-authorization-server`: Server metadata.
    *   `POST /oauth/register`: Dynamic client registration.
    *   `GET /oauth/authorize`: Authorization endpoint.
    *   `POST /oauth/token`: Token endpoint.
*   **ATAG Flow (for User Authentication with External Services):**
    *   `GET /atag/initiate-auth/{service_name}`: Initiates the OAuth flow with the specified external service. (Triggered via `auth_url` from `/mcp` 401 response).
    *   `GET /atag/callback/external/{service_name}`: Handles the OAuth callback from the external service.
*   **MCP Endpoint:**
    *   `POST /mcp`: Main endpoint for `tools/list` and `tools/call` JSON-RPC methods.

## Security Notes

*   **PKCE:** Enforced for confidential and public clients interacting with the `/oauth/token` endpoint.
*   **JWT Security:** Access tokens issued by the gateway are JWTs. Ensure `JWT_SECRET_KEY` is kept confidential and is a strong, unique key in production.
*   **Session Security:** The `SESSION_SECRET_KEY` for FastAPI's `SessionMiddleware` must also be strong and confidential.
*   **Token Encryption:** Placeholder hooks (`_encrypt_token_value`, `_decrypt_token_value`) are in place in `token_manager/storage.py` for external service tokens stored in Redis. Actual encryption logic (e.g., using `cryptography.fernet` with a securely managed encryption key) should be implemented for production deployments.
*   **HTTPS:** In a production environment, the service must be deployed behind a reverse proxy (like Nginx or Traefik) that handles HTTPS termination.
*   **Input Validation:** Pydantic is used for request body and parameter validation, providing a good baseline.
*   **Redirect URIs:** Ensure all OAuth client configurations (both for MCP clients registered with this gateway and for this gateway's client configurations for external services) use exact and validated redirect URIs.
