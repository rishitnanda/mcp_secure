from typing import Any, List, Dict, Union, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

# Represents a standard JSON-RPC 2.0 Request shape
class JSONRPCRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: Optional[Union[str, int]] = None
    method: str = Field(..., min_length=1)
    params: Optional[Union[Dict[str, Any], List[Any]]] = None

    @field_validator("jsonrpc")
    @classmethod
    def check_jsonrpc(cls, v: str) -> str:
        # Enforce exact version compliance for JSON-RPC 2.0
        if v != "2.0":
            raise ValueError("jsonrpc version must be '2.0'")
        return v

# Standard error payload for JSON-RPC responses
class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None

# Represents a standard JSON-RPC 2.0 Response shape
class JSONRPCResponse(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: Optional[Union[str, int]] = None
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None

    @field_validator("jsonrpc")
    @classmethod
    def check_jsonrpc(cls, v: str) -> str:
        if v != "2.0":
            raise ValueError("jsonrpc version must be '2.0'")
        return v

    @model_validator(mode="after")
    def check_result_xor_error(self) -> "JSONRPCResponse":
        # XOR Validation: a response must carry a result OR an error, never both.
        # Explicitly checking presence against None to support model instantiation 
        # with explicit default fields (avoiding model_fields_set bugs).
        has_result = self.result is not None
        has_error = self.error is not None

        if has_result and has_error:
            raise ValueError("JSON-RPC response cannot contain both result and error members")
        if not has_result and not has_error:
            raise ValueError("JSON-RPC response must contain either result or error member")
        return self

# Cryptographic token validating registered capabilities for a given server
class CapabilityCert(BaseModel):
    server_id: str = Field(..., min_length=1)
    capabilities: List[str]
    issued_by: str = Field(..., min_length=1)
    issued_at: float
    expires_at: float
    cert_pem: str = Field(..., min_length=1)

    @field_validator("capabilities")
    @classmethod
    def check_capabilities(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("capabilities list cannot be empty")
        for cap in v:
            if not cap or not cap.strip():
                raise ValueError("capabilities cannot contain empty strings")
        return v

    @model_validator(mode="after")
    def check_dates(self) -> "CapabilityCert":
        # Reject expired or temporally impossible certificates
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly after issued_at")
        return self

# Header fields validating origin and preventing replay attacks
class MCPSecHeader(BaseModel):
    server_id: str = Field(..., min_length=1)
    timestamp: float
    nonce: str = Field(..., min_length=1)
    hmac: str = Field(..., min_length=1)

    @field_validator("timestamp")
    @classmethod
    def check_timestamp(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timestamp must be positive")
        return v

# List of stages in the proxy interception pipeline
VALID_STAGES = {"regex", "ast", "namespace", "attestation", "hmac", "sanitizer", "sequence", "passed"}

class PolicyResult(BaseModel):
    allowed: bool
    reason: str
    stage: str

    @field_validator("stage")
    @classmethod
    def check_stage(cls, v: str) -> str:
        if v not in VALID_STAGES:
            raise ValueError(f"stage must be one of {VALID_STAGES}")
        return v


class ExecutionContext(BaseModel):
    code: str
    server_id: str
    request_id: Optional[Union[str, int]] = None

class SandboxResult(BaseModel):
    exit_code: int
    logs: str
    status: str
    duration_ms: float
