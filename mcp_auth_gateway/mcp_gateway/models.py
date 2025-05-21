from pydantic import BaseModel, Field, HttpUrl # Added HttpUrl
from typing import Optional, Dict, Any, List, Union

class PendingAuthContext(BaseModel): 
    user_id: str
    service_name: str
    original_request_data: Optional[Dict[str, Any]] = None

# JSON-RPC Models
class JsonRpcRequest(BaseModel):
    jsonrpc: str = Field(default="2.0", const="2.0")
    method: str
    params: Optional[Union[Dict[str, Any], List[Any]]] = None
    id: Optional[Union[str, int]] = None

class JsonRpcErrorData(BaseModel):
    code: int
    message: str
    data: Optional[Dict[str, Any]] = None

class JsonRpcResponse(BaseModel):
    jsonrpc: str = Field(default="2.0", const="2.0")
    result: Optional[Any] = None
    error: Optional[JsonRpcErrorData] = None
    id: Optional[Union[str, int]] = None

# MCP Specific Models
class ToolParameterProperty(BaseModel):
    type: str
    description: Optional[str] = None
    enum: Optional[List[Any]] = None

class ToolParameters(BaseModel):
    type: str = "object"
    properties: Dict[str, ToolParameterProperty]
    required: Optional[List[str]] = None

class ToolDefinition(BaseModel):
    name: str
    description: str
    parameters: ToolParameters
    # required_auth: Optional[List[Dict[str, Any]]] = None # This might be part of MCP server config

class ToolsListResult(BaseModel):
    tools: List[ToolDefinition]

# For MCP tools/call authorization field (as per problem description)
class MCPAuthorization(BaseModel):
    tokens: Dict[str, str] # service_name: token
    user_id: str
