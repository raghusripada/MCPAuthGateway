import requests
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlencode
from mcp_auth_gateway.registry.loader import get_external_service_config
from .models import ExternalUserToken # Assuming this model might be enhanced or used here

def build_authorization_url(service_name: str, state: str, user_hint: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """
    Builds the authorization URL for the specified external service.

    Args:
        service_name (str): The name of the external service (from registry).
        state (str): An opaque value used to maintain state between the request and callback.
        user_hint (Optional[str]): Optional hint for the authorization server about the user.

    Returns:
        Optional[Tuple[str, str]]: A tuple containing the authorization URL and scopes string,
                                    or None if the service configuration is not found.
    """
    config = get_external_service_config(service_name)
    if not config:
        return None

    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": config.redirect_url, # This is this gateway's callback URL
        "scope": " ".join(config.scopes),
        "state": state,
    }
    if user_hint:
        params["login_hint"] = user_hint # Common but not universal

    auth_url_with_params = f"{config.auth_url}?{urlencode(params)}"
    return auth_url_with_params, " ".join(config.scopes)

def exchange_code_for_token(service_name: str, code: str, state: Optional[str] = None) -> Optional[Dict]:
    """
    Exchanges an authorization code for an access token and other token data.

    Args:
        service_name (str): The name of the external service.
        code (str): The authorization code received from the service.
        state (Optional[str]): The state parameter (recommended to verify if provided).

    Returns:
        Optional[Dict]: A dictionary containing token data (e.g., access_token, 
                        refresh_token, expires_in) or None if an error occurs.
    """
    config = get_external_service_config(service_name)
    if not config:
        print(f"Service config not found for {service_name}")
        return None

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_url, # Must match the one used in auth request
        "client_id": config.client_id,
        "client_secret": config.client_secret, # Handled by SecretStr automatically by requests if it were a Pydantic model
    }

    try:
        response = requests.post(config.token_url, data=payload, timeout=10)
        response.raise_for_status()  # Raises HTTPError for bad responses (4XX or 5XX)
        token_data = response.json()
        
        # Basic validation of response
        if "access_token" not in token_data:
            print(f"Error exchanging code for {service_name}: 'access_token' not in response. Response: {token_data}")
            return None
            
        return token_data # e.g., {"access_token": "...", "refresh_token": "...", "expires_in": 3600, "scope": "..."}
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error exchanging code for {service_name}: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Request error exchanging code for {service_name}: {e}")
    except ValueError as e: # Includes JSONDecodeError
        print(f"Error decoding JSON response from {service_name} token endpoint: {e}")
        
    return None

# Placeholder for token refresh logic (to be implemented in a later step if specified)
# def refresh_external_token(user_id: str, service_name: str) -> Optional[ExternalUserToken]:
#     pass
