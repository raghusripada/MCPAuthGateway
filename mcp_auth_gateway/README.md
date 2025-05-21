# MCP Authentication Gateway

## Overview

This service acts as an authentication and authorization gateway for MCP (Model Context Protocol) based tools and agents. It provides two main functionalities:

1.  **OAuth 2.1 Authorization Server**: Issues JWT-based access tokens to client applications (e.g., MCP-enabled chat applications, testing tools) that need to interact with the gateway's MCP endpoint.
2.  **ATAG (Agent-Triggered Auth Gateway) Flow**: Facilitates user authentication with external services (like Google, GitHub) when an MCP tool, invoked by an agent, requires access to resources on those services. The gateway manages external tokens securely.
3.  **MCP Endpoint Proxy**: Exposes a `/mcp` JSON-RPC endpoint that:
    *   Authenticates requests using its own issued JWTs.
    *   Handles `tools/list` to inform clients about available tools.
    *   For `tools/call`, it checks if the required external service token for the user is present and valid.
    *   If external authentication is needed, it triggers the ATAG flow.
    *   If authenticated, it proxies the `tools/call` request to the appropriate backend MCP server, injecting the necessary external service token and user information.

## Features

*   **OAuth 2.1 Compliant Authorization Server**:
    *   Dynamic Client Registration (`/oauth/register`)
    *   Authorization Code Grant with PKCE (`/oauth/authorize`, `/oauth/token`)
    *   Refresh Token Grant (`/oauth/token`)
    *   Client Credentials Grant (`/oauth/token`)
    *   Server Metadata Endpoint (`/oauth/.well-known/oauth-authorization-server`)
    *   JWT-based Access Tokens (signed using HS256)
*   **External Service Token Management (ATAG Flow)**:
    *   Initiation endpoint (`/atag/initiate-auth/{service_name}`)
    *   Callback handling (`/atag/callback/external/{service_name}`)
    *   Secure storage of external service tokens in Redis (with placeholder encryption for access/refresh tokens).
*   **MCP Endpoint (`/mcp`)**:
    *   Handles `tools/list` and `tools/call` methods.
    *   Integrates with ATAG flow for `tools/call` when external authentication is required.
    *   Proxies authorized `tools/call` requests to backend MCP servers.
*   **Service Registry**:
    *   Configuration for external OAuth providers (e.g., Google, GitHub).
    *   Configuration for backend MCP servers, linking them to required external services.
    *   Loaded from `registry/registry_data.yaml`.
*   **Redis Integration**:
    *   Stores OAuth client details, authorization codes, refresh token info.
    *   Stores external service tokens.
    *   Stores pending ATAG contexts.
*   **Basic Unit Tests**: For registry loading, JWT utilities, and token storage encryption placeholders.

## Project Structure

```
mcp_auth_gateway/
├── auth_server/             # OAuth 2.1 Authorization Server implementation
│   ├── endpoints.py         # FastAPI routes for OAuth server
│   ├── models.py            # Pydantic models for OAuth entities
│   ├── storage.py           # Redis storage for OAuth clients, codes, refresh tokens
│   ├── utils.py             # JWT generation, PKCE, other auth utilities
│   └── __init__.py
├── core/                    # Core application settings and shared components
│   ├── config.py            # Application settings (Redis, secrets)
│   └── __init__.py
├── mcp_gateway/             # MCP endpoint and ATAG flow implementation
│   ├── atag_endpoints.py    # FastAPI routes for ATAG flow
│   ├── mcp_endpoints.py     # FastAPI route for /mcp JSON-RPC endpoint
│   ├── models.py            # Pydantic models for MCP, JSON-RPC, ATAG context
│   └── __init__.py
├── registry/                # Service registry for external services and MCP servers
│   ├── loader.py            # Loads registry data from YAML
│   ├── models.py            # Pydantic models for registry configuration
│   ├── registry_data.yaml   # Default registry configuration file
│   └── __init__.py
├── token_manager/           # Management of external service tokens
│   ├── oauth_client.py      # Client for interacting with external OAuth providers
│   ├── storage.py           # Redis storage for external tokens (with encryption hooks)
│   ├── models.py            # Pydantic models for external tokens
│   └── __init__.py
├── tests/                   # Unit tests
│   ├── test_auth_utils.py
│   ├── test_registry_loader.py
│   └── test_token_manager_storage.py
│   └── __init__.py
├── main.py                  # FastAPI application entry point
├── pyproject.toml           # Project dependencies and metadata
└── README.md                # This file
```

## Configuration

Configuration is managed via `mcp_auth_gateway/core/config.py` and environment variables (typically in a `.env` file).

Key configuration variables:

*   `REDIS_HOST`: Hostname for the Redis server (default: `localhost`).
*   `REDIS_PORT`: Port for the Redis server (default: `6379`).
*   `JWT_SECRET_KEY`: **Critical secret** used to sign JWTs issued by the gateway's OAuth server. Must be a strong, random string and kept consistent across application restarts.
*   `SESSION_SECRET_KEY`: **Critical secret** used by `SessionMiddleware` for signing session cookies (e.g., for mock user authentication in test endpoints). Must be a strong, random string.

**Example `.env` file:**

```env
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET_KEY="your_very_strong_and_random_jwt_secret_key_here_at_least_32_chars"
SESSION_SECRET_KEY="another_very_strong_and_random_session_secret_key_here"
```

**Registry Configuration (`registry/registry_data.yaml`):**
This YAML file defines:
*   `external_services`: Client ID, secret, auth/token URLs, redirect URIs, and scopes for external OAuth providers (e.g., Google, GitHub).
    *   **Important**: The `redirect_url` for each external service must point to this gateway's ATAG callback endpoint: `http://<gateway_host>:<port>/atag/callback/external/{service_name}`.
*   `mcp_servers`: Details of backend MCP servers, including which `target_external_service` they rely on.

## Running the Application

1.  **Prerequisites**:
    *   Python 3.9+
    *   Poetry (for dependency management)
    *   Redis server running

2.  **Installation**:
    ```bash
    poetry install
    ```

3.  **Environment Variables**:
    *   Create a `.env` file in the `mcp_auth_gateway` directory with your configuration (see Configuration section).
    *   **Ensure `JWT_SECRET_KEY` and `SESSION_SECRET_KEY` are set to strong, unique values.**

4.  **Run with Uvicorn**:
    ```bash
    poetry run uvicorn mcp_auth_gateway.main:app --reload --port 8000
    ```
    The application will be available at `http://localhost:8000`.

## Testing

1.  **Setup**: Ensure development dependencies are installed:
    ```bash
    poetry install --with dev 
    ```
    (If you already ran `poetry install` without `--with dev`, you might need to ensure dev dependencies are included or run `poetry install` again.)

2.  **Run Tests**:
    From the `mcp_auth_gateway` directory:
    ```bash
    poetry run pytest
    ```
    Tests cover:
    *   Registry loading logic.
    *   JWT issuance and validation utilities.
    *   Placeholder encryption/decryption in token storage.

## Key Endpoints

*   **OAuth Server Metadata**: `GET /oauth/.well-known/oauth-authorization-server`
*   **Client Registration**: `POST /oauth/register`
*   **Authorization**: `GET /oauth/authorize`
*   **Token Exchange**: `POST /oauth/token`
*   **ATAG Auth Initiation**: `GET /atag/initiate-auth/{service_name}`
*   **ATAG External Callback**: `GET /atag/callback/external/{service_name}`
*   **MCP JSON-RPC Endpoint**: `POST /mcp`
    *   Methods: `tools/list`, `tools/call`

*   **API Docs (Swagger UI)**: `GET /docs`
*   **Test Auth Page (for OAuth server)**: `GET /test-auth` (initiates flow with a test client)
*   **Test Auth Callback (for OAuth server)**: `GET /test-auth-callback`

## Security Notes

*   **Secret Management**: `JWT_SECRET_KEY` and `SESSION_SECRET_KEY` are critical. In a production environment, these should be managed securely (e.g., via environment variables injected by a secrets manager) and not hardcoded or committed to version control if they were default values.
*   **PKCE**: The OAuth authorization flow supports PKCE (S256 and plain) and is enforced for confidential clients.
*   **Token Encryption**: External service tokens (access and refresh) stored by the `token_manager` have placeholder encryption hooks. **These must be replaced with a robust encryption mechanism (e.g., using `cryptography.fernet`) in a production system.** The encryption key for this would also be a critical secret.
*   **Input Validation**: Pydantic models provide baseline input validation. Further specific validation is implemented where necessary.
*   **HTTPS**: In production, ensure the gateway is deployed behind a reverse proxy that terminates TLS/SSL (HTTPS).
*   **Redis Security**: Secure your Redis instance (authentication, network exposure).
*   **User Authentication**: The current mock user authentication in `/oauth/authorize` and `/atag/*` endpoints is for development purposes and must be replaced with a robust authentication system integrated with your platform. The `/mcp` endpoint relies on JWTs issued by this gateway, ensuring that only authenticated clients can access it.
```
