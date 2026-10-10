# Схема базы данных HoneyForge

База данных HoneyForge спроектирована на базе SQLAlchemy 2.0 ORM и совместима как с легковесной встраиваемой **SQLite** (через асинхронный драйвер `aiosqlite`), так и с высокопроизводительной **PostgreSQL** (через `asyncpg`).

---

## 1. ER-Диаграмма

```mermaid
erDiagram
    PROFILES ||--o{ TRAPS : "configures"
    TRAPS ||--o{ ATTACK_EVENTS : "intercepts"
    TRAPS ||--o{ SESSION_LOGS : "records"
    TRAPS ||--o{ HONEYTOKENS : "contains"
    ALERT_RULES ||--o{ ALERT_EVENTS : "triggers"

    USERS {
        int id PK
        string username
        string password_hash
        string role
        boolean is_active
        datetime created_at
    }

    PROFILES {
        int id PK
        string name UK
        text description
        string interaction_level
        json services
        json banners
        json decoy_credentials
        json honeytokens_config
        json logging_params
        json stealth_params
        datetime created_at
        datetime updated_at
    }

    TRAPS {
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

    ATTACK_EVENTS {
        int id PK
        string event_id UK
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
    }

    SESSION_LOGS {
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

    HONEYTOKENS {
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

    ALERT_RULES {
        int id PK
        string name
        string rule_type
        int threshold
        int window_seconds
        string severity
        boolean is_enabled
        datetime created_at
    }

    ALERT_EVENTS {
        int id PK
        int rule_id
        string rule_name
        string trap_id
        string source_ip
        text message
        string severity
        datetime created_at
    }

    AUDIT_LOGS {
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

---

## 2. Описание таблиц

### 2.1 `profiles` (Профили ловушек — FR-C1)
Хранит шаблоны конфигураций deception-окружения:
- `services`: список активируемых служб (e.g. `["ssh", "http", "redis", "ftp"]`).
- `banners`: словарь аутентичных сетевых баннеров `{21: "220 ProFTPD...", 22: "SSH-2.0-OpenSSH..."}`.
- `decoy_credentials`: список учетных записей-приманок для принятия или мониторинга.
- `stealth_params`: параметры скрытности (джиттер, размер padding, имя процесса маскировки).

### 2.2 `traps` (Парк ловушек — FR-C2)
Реестр развернутых ловушек:
- `trap_id`: уникальный идентификатор ловушки.
- `status`: текущее состояние (`online`, `offline`, `degraded`).
- `last_seen`: время последнего полученного beacon-сигнала.
- `secret_key`: HMAC-ключ для взаимной аутентификации.

### 2.3 `attack_events` (Телеметрия атак — FR-C4)
События входящей активности:
- `event_type`: тип активности (`port_scan`, `banner_probe`, `auth_attempt`, `shell_command`, `web_request`, `honeytoken_triggered`, `file_download`).
- `credentials`: захваченная пара логин/пароль.
- `command_text`: выполненная в шелле команда.
- `artifact_hash`: SHA-256 хэш загруженного вредоноса.
- `is_ioc`: флаг для включения в выгрузку Threat Intelligence (STIX 2.1).

### 2.4 `session_logs` (Интерактивные сессии — Asciinema Replay)
Полная хронология действий атакующего:
- `commands_history`: упорядоченный список введенных команд и ответов терминала с временными метками.
- `captured_artifacts`: метаданные перехваченных файлов.

### 2.5 `honeytokens` (Приманки Honeytokens — FR-A6)
- Отслеживание canary-артефактов (AWS ключи, вебхуки, хэши паролей). При фиксации чтения или перехода статус меняется на `is_triggered = True`.
