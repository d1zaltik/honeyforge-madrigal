import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# ----------------- User & Auth Schemas -----------------
class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst_l1"

class UserRoleUpdate(BaseModel):
    role: str

class UserStatusUpdate(BaseModel):
    is_active: bool

class UserPasswordReset(BaseModel):
    new_password: str

class KeyStoreExportRequest(BaseModel):
    master_password: str
    description: Optional[str] = "HoneyForge SOC KeyStore"

class KeyStoreInspectRequest(BaseModel):
    master_password: str
    keystore_data: Any  # JSON-serialized string or parsed object

# ----------------- Persona Schemas -----------------
class PersonaSchema(BaseModel):
    hostname: str = Field(default="prod-srv-01", description="System hostname")
    os: str = Field(default="Ubuntu 22.04.4 LTS", description="Operating System release name")
    kernel: str = Field(default="5.15.0-105-generic", description="Kernel release string")
    users: List[str] = Field(default_factory=lambda: ["root", "deploy", "ubuntu"], description="Simulated system accounts")
    uptime_base: int = Field(default=172800, description="Base uptime in seconds")
    timezone: str = Field(default="UTC", description="System timezone")
    banners: Dict[str, str] = Field(default_factory=dict, description="Custom protocol banners by port")
    mac: Optional[str] = Field(default="02:42:0a:c8:00:2c", description="Primary NIC MAC address")
    ip: Optional[str] = Field(default="10.0.1.5", description="Simulated host IP address")

    class Config:
        extra = "allow"

# ----------------- Profile Schemas -----------------
class ProfileCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    interaction_level: str = "medium"  # low, medium, high
    services: List[str] = Field(default_factory=lambda: ["ssh", "http"])
    banners: Dict[str, str] = Field(default_factory=dict)
    decoy_credentials: List[Dict[str, str]] = Field(default_factory=list)
    honeytokens_config: List[Dict[str, Any]] = Field(default_factory=list)
    logging_params: Dict[str, Any] = Field(default_factory=dict)
    stealth_params: Dict[str, Any] = Field(default_factory=dict)
    persona: PersonaSchema = Field(default_factory=PersonaSchema)

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    interaction_level: Optional[str] = None
    services: Optional[List[str]] = None
    banners: Optional[Dict[str, str]] = None
    decoy_credentials: Optional[List[Dict[str, str]]] = None
    honeytokens_config: Optional[List[Dict[str, Any]]] = None
    logging_params: Optional[Dict[str, Any]] = None
    stealth_params: Optional[Dict[str, Any]] = None
    persona: Optional[PersonaSchema] = None

class ProfileOut(BaseModel):
    id: int
    name: str
    description: str
    interaction_level: str
    services: List[str]
    banners: Dict[str, str]
    decoy_credentials: List[Dict[str, str]]
    honeytokens_config: List[Dict[str, Any]]
    logging_params: Dict[str, Any]
    stealth_params: Dict[str, Any]
    persona: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_at: datetime.datetime
    updated_at: datetime.datetime
    traps_count: int = 0

    class Config:
        from_attributes = True

# ----------------- Trap Schemas -----------------
class TrapRegister(BaseModel):
    trap_id: str
    name: str
    profile_id: Optional[int] = None
    interaction_level: str = "medium"
    ip_address: str = "127.0.0.1"
    mgmt_ip: str = "127.0.0.1"
    secret_key: Optional[str] = None

class TrapHeartbeat(BaseModel):
    trap_id: str
    uptime_seconds: int = 0
    cpu_usage: float = 0.0
    mem_usage: float = 0.0
    status: str = "online"
    config_version: int = 1

class TrapOut(BaseModel):
    id: int
    trap_id: str
    name: str
    profile_id: Optional[int]
    interaction_level: str
    ip_address: str
    mgmt_ip: str
    status: str
    last_seen: Optional[datetime.datetime]
    uptime_seconds: int
    cpu_usage: float
    mem_usage: float
    config_version: int
    created_at: datetime.datetime
    profile_name: Optional[str] = None
    services: List[str] = Field(default_factory=list)
    events_24h: int = 0
    secret_key: Optional[str] = None

    class Config:
        from_attributes = True

# ----------------- Telemetry & Events Schemas -----------------
class AttackEventCreate(BaseModel):
    event_id: str
    event_uid: Optional[str] = None
    trap_id: str
    timestamp: Optional[datetime.datetime] = None
    source_ip: str
    source_port: int = 0
    protocol: str = "TCP"
    destination_port: int
    event_type: str
    severity: str = "medium"
    credentials: Optional[Dict[str, str]] = None
    command_text: Optional[str] = None
    http_data: Optional[Dict[str, Any]] = None
    payload_raw: Optional[str] = None
    artifact_hash: Optional[str] = None
    session_id: Optional[str] = None
    is_ioc: bool = False
    geo_country: Optional[str] = "Unknown"
    geo_city: Optional[str] = "Unknown"
    source_asn: Optional[str] = "AS-LOCAL"
    captured_at: Optional[float] = None
    session_duration_s: Optional[float] = None

class TelemetryBatchIn(BaseModel):
    # Masked payload structure disguised as metrics telemetry
    trap_id: str
    nonce: str
    timestamp: float
    signature: str
    heartbeat: Optional[TrapHeartbeat] = None
    events: List[AttackEventCreate] = Field(default_factory=list)
    session_logs: List[Dict[str, Any]] = Field(default_factory=list)

class AttackEventOut(BaseModel):
    id: int
    event_id: str
    event_uid: Optional[str] = None
    trap_id: str
    timestamp: datetime.datetime
    source_ip: str
    source_port: int
    protocol: str
    destination_port: int
    event_type: str
    severity: str
    credentials: Optional[Dict[str, str]]
    command_text: Optional[str]
    http_data: Optional[Dict[str, Any]]
    payload_raw: Optional[str]
    artifact_hash: Optional[str]
    session_id: Optional[str]
    is_ioc: bool
    geo_country: str
    geo_city: str
    source_asn: Optional[str] = "AS-LOCAL"
    ingest_latency_seconds: Optional[float] = None
    session_duration_s: Optional[float] = None

    class Config:
        from_attributes = True

class SessionLogOut(BaseModel):
    id: int
    session_id: str
    trap_id: str
    source_ip: str
    protocol: str
    started_at: datetime.datetime
    ended_at: Optional[datetime.datetime]
    total_commands: int
    commands_history: List[Dict[str, Any]]
    captured_artifacts: List[Dict[str, Any]]

    class Config:
        from_attributes = True

# ----------------- Honeytoken Schemas -----------------
class HoneytokenCreate(BaseModel):
    token_type: str  # aws_key, canary_url, ssh_key, shadow_hash
    token_value: Optional[str] = None
    canary_path: str = ""
    trap_id: Optional[str] = None
    description: str = ""

class HoneytokenOut(BaseModel):
    id: int
    token_id: str
    token_type: str
    token_value: str
    canary_path: str
    trap_id: Optional[str]
    is_triggered: bool
    triggered_at: Optional[datetime.datetime]
    triggered_by_ip: Optional[str]
    description: str

    class Config:
        from_attributes = True

# ----------------- Alert Schemas -----------------
class AlertRuleCreate(BaseModel):
    name: str
    rule_type: str
    threshold: int = 5
    window_seconds: int = 60
    trap_id: Optional[str] = None
    severity: str = "high"
    is_enabled: bool = True

class AlertRuleOut(BaseModel):
    id: int
    name: str
    rule_type: str
    threshold: int
    window_seconds: int
    trap_id: Optional[str] = None
    severity: str
    is_enabled: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class AlertEventOut(BaseModel):
    id: int
    rule_id: Optional[int]
    rule_name: str
    trap_id: str
    source_ip: str
    message: str
    severity: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# ----------------- Audit Log Schemas -----------------
class AuditLogOut(BaseModel):
    id: int
    username: str
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    details: str
    timestamp: datetime.datetime
    ip_address: str

    class Config:
        from_attributes = True

# ----------------- Overview Dashboard Stats -----------------
class OverviewStats(BaseModel):
    total_traps: int
    online_traps: int
    traps_low: int = 0
    traps_medium: int = 0
    total_events: int
    critical_events: int
    captured_credentials: int
    captured_payloads: int
    honeytokens_count: int
    honeytokens_triggered: int
    top_attackers: List[Dict[str, Any]]
    top_ports: List[Dict[str, Any]]
    events_per_type: Dict[str, int]
