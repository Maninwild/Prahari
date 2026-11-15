from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    event_id: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{1,128}$')
    sensor_id: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    stream_id: str = Field(default='live', pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    mode: Literal['live', 'replay'] = 'live'
    observed_at: datetime
    kind: Literal['http', 'flow']
    # A shared HMAC of source address permits HTTP/flow correlation without raw IP storage.
    actor_id: str = Field(pattern=r'^[a-f0-9]{64}$')
    session_id: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')
    route: str = Field(default='/', max_length=256)
    method: Literal['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] = 'GET'
    status_code: int = Field(default=200, ge=100, le=599)
    auth_failed: bool = False
    scan_id: str | None = Field(default=None, pattern=r'^[a-f0-9]{32}$')
    destination: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal['tcp', 'udp', 'icmp', 'unknown'] = 'unknown'
    bytes_out: int = Field(default=0, ge=0, le=10**12)
    bytes_in: int = Field(default=0, ge=0, le=10**12)
    packets: int = Field(default=0, ge=0, le=10**9)
    duration_ms: float = Field(default=0, ge=0, le=86400000)
    connection_failed: bool = False

    @field_validator('observed_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None: raise ValueError('An explicit timezone is required')
        return value.astimezone(timezone.utc)

    @field_validator('route')
    @classmethod
    def safe_route(cls, value):
        if not value.startswith('/') or any(c in value for c in ['?', '#', '\r', '\n']):
            raise ValueError('Use a route template without query strings or fragments')
        return value

    @field_validator('destination')
    @classmethod
    def address(cls, value):
        return str(ip_address(value)) if value is not None else None

    @model_validator(mode='after')
    def appropriate_fields(self):
        if self.kind == 'flow' and (self.destination is None or self.destination_port is None):
            raise ValueError('Flows require destination and destination_port')
        if self.kind == 'flow' and (self.scan_id or self.session_id or self.auth_failed):
            raise ValueError('Application fields cannot be attached to a flow')
        if self.kind == 'http' and (self.destination is not None or self.destination_port is not None):
            raise ValueError('Network fields cannot be attached to an HTTP event')
        return self

class IncidentReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['open', 'investigating', 'resolved', 'false_positive']
