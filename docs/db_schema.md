# Схема базы данных HoneyForge (PostgreSQL / SQLite)

Архитектура хранения данных построена на базе реляционной СУБД (PostgreSQL в docker-окружении, aiosqlite для автономного запуска). Все модели реализованы через SQLAlchemy 2.0 Asyncio.

```mermaid
erDiagram
    User ||--o{ AuditLog : performs
    Profile ||--o{ Trap : configures
    Trap ||--o{ AttackEvent : generates
    Trap ||--o{ SessionLog : records
    Trap ||--o{ Honeytoken : contains
    AlertRule ||--o{ AlertEvent : triggers

    User {
        int id PK
        string username UK
        string password_hash
        string role
        boolean is_active
        datetime created_at
    }

    Profile {
        int id PK
        string name UK
        string description
        string interaction_level
        json services
        json banners
        json decoy_credentials
        json honeytokens_config
        json logging_params
        json stealth_params
        json persona
        datetime created_at
        datetime updated_at
    }

    Trap {
        int id PK
        string trap_id UK
        string name
        int profile_id FK
        string interaction_level
        string ip_address
        string mgmt_ip
        string status
        datetime last_seen
        int config_version
        int uptime_seconds
        float cpu_usage
        float mem_usage
        string secret_key
        datetime created_at
    }

    AttackEvent {
        int id PK
        string event_id UK
        string event_uid UK
        string trap_id FK
        datetime timestamp
        string source_ip
        int source_port
        string protocol
        int destination_port
        string event_type
        string severity
        json credentials
        text command_text
        json http_data
        text payload_raw
        string artifact_hash
        string session_id
        boolean is_ioc
        string geo_country
        string geo_city
        string source_asn
        float ingest_latency_seconds
        float session_duration_s
    }

    SessionLog {
        int id PK
        string session_id UK
        string trap_id FK
        string source_ip
        string protocol
        datetime started_at
        datetime ended_at
        int total_commands
        json commands_history
        json captured_artifacts
    }

    Honeytoken {
        int id PK
        string token_id UK
        string token_type
        string token_value
        string canary_path
        string trap_id FK
        boolean is_triggered
        datetime triggered_at
        string triggered_by_ip
        string description
    }

    AlertRule {
        int id PK
        string name
        string rule_type
        int threshold
        int window_seconds
        string trap_id
        string severity
        boolean is_enabled
        datetime created_at
    }

    AlertEvent {
        int id PK
        int rule_id
        string rule_name
        string trap_id
        string source_ip
        text message
        string severity
        datetime created_at
    }

    AuditLog {
        int id PK
        string username
        string action
        string target_type
        string target_id
        text details
        datetime timestamp
        string ip_address
    }
```

## Особенности структуры
1. **Идемпотентность и дедупликация (FR-A4)**: Поле `event_uid` в таблице `attack_events` обеспечивает строгую дедупликацию телеметрии при повторной передаче из локального буфера SQLite.
2. **Хостовая персона (MASK-6)**: Поле `persona` в таблице `profiles` хранит параметры эмуляции реальной ОС (hostname, OS, kernel, uptime, users).
3. **Безопасность учетных записей (FR-C5)**: В таблице `users` пароли хранятся в формате `pbkdf2$<salt_hex>$<hash_hex>` (600,000 итераций).
