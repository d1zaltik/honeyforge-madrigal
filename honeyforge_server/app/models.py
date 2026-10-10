import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from honeyforge_server.app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="soc_analyst")  # admin, soc_analyst
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Profile(Base):
    __tablename__ = "profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, index=True, nullable=False)
    description = Column(Text, default="")
    interaction_level = Column(String(32), default="medium")  # low, medium, high
    
    # List of services to activate: ["ssh", "http", "ftp", "telnet", "redis"]
    services = Column(JSON, default=list)
    
    # Custom banners dictionary: {"21": "220 ProFTPD 1.3.5", "22": "SSH-2.0-OpenSSH_8.9p1"}
    banners = Column(JSON, default=dict)
    
    # Decoy credentials accepted or monitored: [{"user": "root", "pass": "admin123"}, ...]
    decoy_credentials = Column(JSON, default=list)
    
    # Honeytokens templates: [{"type": "aws_key", "path": "/root/.aws/credentials"}, ...]
    honeytokens_config = Column(JSON, default=list)
    
    # Logging configuration: {"level": "DEBUG", "capture_payload": True, "max_payload_bytes": 65536}
    logging_params = Column(JSON, default=dict)
    
    # Stealth parameters (MASK requirements):
    # {"beacon_interval_s": 10, "jitter_pct": 35, "dummy_padding": True, "proc_masquerade": "systemd-resolved", "disguise_headers": True}
    stealth_params = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    traps = relationship("Trap", back_populates="profile")

class Trap(Base):
    __tablename__ = "traps"
    
    id = Column(Integer, primary_key=True, index=True)
    trap_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    profile_id = Column(Integer, ForeignKey("profiles.id"), nullable=True)
    interaction_level = Column(String(32), default="medium")  # low, medium, high
    
    # Network addresses
    ip_address = Column(String(64), default="0.0.0.0")       # DMZ facing address
    mgmt_ip = Column(String(64), default="127.0.0.1")        # Out-of-band management IP
    
    # Status monitoring
    status = Column(String(32), default="offline")           # online, offline, degraded
    last_seen = Column(DateTime, nullable=True)
    config_version = Column(Integer, default=1)
    
    # System telemetry
    uptime_seconds = Column(Integer, default=0)
    cpu_usage = Column(Float, default=0.0)
    mem_usage = Column(Float, default=0.0)
    
    # Cryptographic identity / agent authentication (HMAC-SHA256)
    secret_key = Column(String(128), nullable=False)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    profile = relationship("Profile", back_populates="traps")
    events = relationship("AttackEvent", back_populates="trap", cascade="all, delete-orphan")
    sessions = relationship("SessionLog", back_populates="trap", cascade="all, delete-orphan")
    honeytokens = relationship("Honeytoken", back_populates="trap", cascade="all, delete-orphan")

class AttackEvent(Base):
    __tablename__ = "attack_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    trap_id = Column(String(64), ForeignKey("traps.trap_id"), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Network metadata
    source_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, default=0)
    protocol = Column(String(32), default="TCP")             # TCP, UDP, HTTP, SSH, FTP, etc.
    destination_port = Column(Integer, index=True, nullable=False)
    
    # Event classification
    # types: port_scan, auth_attempt, shell_command, web_request, honeytoken_triggered, file_download, sql_injection
    event_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), default="medium", index=True)  # low, medium, high, critical
    
    # Captured telemetry
    credentials = Column(JSON, nullable=True)                # {"username": "admin", "password": "password"}
    command_text = Column(Text, nullable=True)               # e.g. "cat /etc/passwd" or "curl http://.../sh"
    http_data = Column(JSON, nullable=True)                  # {"method": "POST", "path": "/login", "headers": {...}, "body": "..."}
    payload_raw = Column(Text, nullable=True)                # Raw bytes / snippet
    artifact_hash = Column(String(64), nullable=True)        # SHA-256 of downloaded malware
    
    session_id = Column(String(64), index=True, nullable=True)
    is_ioc = Column(Boolean, default=False)
    geo_country = Column(String(64), default="Unknown")
    geo_city = Column(String(64), default="Unknown")
    
    trap = relationship("Trap", back_populates="events")

class SessionLog(Base):
    __tablename__ = "session_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    trap_id = Column(String(64), ForeignKey("traps.trap_id"), index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    protocol = Column(String(32), default="SSH")
    
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    
    total_commands = Column(Integer, default=0)
    commands_history = Column(JSON, default=list)  # [{"timestamp": "...", "cmd": "uname -a", "response": "Linux..."}]
    captured_artifacts = Column(JSON, default=list)  # [{"sha256": "...", "filename": "miner.sh", "size": 1024}]
    
    trap = relationship("Trap", back_populates="sessions")

class Honeytoken(Base):
    __tablename__ = "honeytokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token_id = Column(String(64), unique=True, index=True, nullable=False)
    token_type = Column(String(32), nullable=False)  # aws_key, canary_url, ssh_key, shadow_hash
    token_value = Column(String(256), nullable=False)
    canary_path = Column(String(256), default="")
    trap_id = Column(String(64), ForeignKey("traps.trap_id"), nullable=True)
    
    is_triggered = Column(Boolean, default=False, index=True)
    triggered_at = Column(DateTime, nullable=True)
    triggered_by_ip = Column(String(64), nullable=True)
    description = Column(String(256), default="")
    
    trap = relationship("Trap", back_populates="honeytokens")

class AlertRule(Base):
    __tablename__ = "alert_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    rule_type = Column(String(64), nullable=False)  # brute_force, honeytoken, high_severity, file_download
    threshold = Column(Integer, default=5)          # e.g. 5 attempts
    window_seconds = Column(Integer, default=60)    # within 60 seconds
    severity = Column(String(32), default="high")
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AlertEvent(Base):
    __tablename__ = "alert_events"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, nullable=True)
    rule_name = Column(String(128), nullable=False)
    trap_id = Column(String(64), nullable=False)
    source_ip = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(32), default="high")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)  # login, create_profile, deploy_trap, export_ioc, rule_update
    target_type = Column(String(64), nullable=True)
    target_id = Column(String(64), nullable=True)
    details = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String(64), default="127.0.0.1")
