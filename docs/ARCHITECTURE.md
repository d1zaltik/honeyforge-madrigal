# Сетевая архитектура и потоки данных HoneyForge

## 1. Сегментация сети и изоляция (MASK-3)

Платформа HoneyForge реализует строгое разделение сетевых сегментов в Docker Compose:
- **Сегмент `edge_dmz` (`172.28.0.0/16`)**: изолированная демилитаризованная зона. Содержит контейнеры ловушек (`systemd-resolved-low`, `rsyslogd-med`), симулятор атак (`sec-scanner`) и внешний интерфейс шлюза обратного прокси (`static-edge`: `172.28.0.3`).
- **Сегмент `internal_mgmt` (`172.29.0.0/16`)**: изолированная out-of-band сеть управления. Содержит внутренний интерфейс шлюза (`static-edge`: `172.29.0.3`), сервер управления C2 (`app-backend`: `172.29.0.2`) и СУБД (`db-store`: `172.29.0.5`).

Ловушки в `edge_dmz` **физически не имеют маршрута** к серверу управления (порт 8000) или к базе данных (порт 5432). Единственная точка взаимодействия — защищенный HTTPS обратный прокси (`static-edge`, порт 443).

```mermaid
flowchart TD
    subgraph DMZ["Изолированный сегмент DMZ: edge_dmz (172.28.0.0/16)"]
        Scanner["Атакующий / Сканер\n(sec-scanner: 172.28.0.30)"]
        LowTrap["Низкоинтерактивная ловушка\n(systemd-resolved-low: 172.28.0.10)\nПорты: 2121 (FTP), 2323 (Telnet), 6379 (Redis)"]
        MedTrap["Среднеинтерактивная ловушка\n(rsyslogd-med: 172.28.0.20)\nПорты: 2222 (SSH), 8088 (HTTP)"]
    end

    subgraph Edge["DMZ Шлюз приёма телеметрии (Static-Edge)"]
        EdgeProxy["Static-Edge Nginx (172.28.0.3 / 172.29.0.3)\nПринимает только /cdn-cgi/rum, /static/v2/metrics, /sync/\nСкрытность: stock Nginx 404 HTML без JSON\nСкрывает Server, Vary, X-Powered-By"]
    end

    subgraph MGMT["Внутренняя сеть управления: internal_mgmt (172.29.0.0/16)"]
        MgmtProxy["Mgmt-Gateway Nginx (172.29.0.4)\nПубликует порты хоста 80 / 443\nТолько для оператора SOC\nRate Limit: 5r/m на логин, CORS, WS Ticket"]
        C2["Центральный сервер HoneyForge\n(app-backend: 172.29.0.2:8000)\nFastAPI / Lifespan / RBAC / Correlation Alerts"]
        DB[("СУБД PostgreSQL 16\n(db-store: 172.29.0.5:5432)\nСобытия, Сессии, Аудит, Персоны")]
    end

    subgraph SOC["Рабочее место оператора SOC"]
        Browser["Веб-интерфейс SOC Дашборда\n(HTTPS :443 / WSS :443 через mgmt-gateway)"]
    end

    Scanner -->|"Сетевые зондирования (FTP/Telnet/Redis)"| LowTrap
    Scanner -->|"SSH брутфорс / HTTP сканирование"| MedTrap

    LowTrap -->|"HTTPS :443 (/cdn-cgi/rum, CA Pinned)"| EdgeProxy
    MedTrap -->|"HTTPS :443 (/cdn-cgi/rum, CA Pinned)"| EdgeProxy

    EdgeProxy -->|"HTTP :8000 (Internal Only)"| C2
    MgmtProxy -->|"HTTP :8000 (API & Web UI)"| C2
    C2 -->|"Asyncpg connection pool"| DB

    Browser -->|"HTTPS :443 (Web UI)"| MgmtProxy
    Browser -->|"WSS :443 (/ws/attacks?ticket=...)"| MgmtProxy
```

---

## 2. Сквозной поток телеметрии (Data Flow Pipeline)

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Атакующий
    participant Trap as Ловушка (Agent)
    participant Buffer as SQLite Буфер (Store & Forward)
    participant Edge as Static-Edge (Nginx TLS 443)
    participant C2 as C2 Backend (FastAPI)
    participant DB as PostgreSQL
    participant WS as WebSocket Hub
    actor Analyst as Аналитик SOC (UI)

    Attacker->>Trap: Взлом SSH / HTTP / порт-сканирование
    Trap->>Buffer: Запись события (push_event с уникальным event_uid)
    Note over Buffer: Сохранение на диск.<br/>Гарантия 0 потерь при обрыве сети

    Trap->>Trap: Сериализация JSON + паддинг пакета (32-128 байт, MASK-5)
    Trap->>Trap: Расчет SHA-256 тела и подписи HMAC-SHA256 (MASK-1/7)
    Trap->>Edge: POST /cdn-cgi/rum (TLS с pinning CA сертификата)
    Edge->>C2: Проксирование запроса на порт 8000 в internal_mgmt

    C2->>C2: Проверка сырого тела await request.body()<br/>Проверка timestamp <= 180с и уникальности nonce
    alt Невалидная подпись или поддельный запрос
        C2-->>Edge: HTTP 404 {"detail":"Not Found"} (Stealth Telemetry, неотличима от несуществующего пути)
        Edge-->>Trap: HTTP 404 Not Found
    else Валидная HMAC подпись
        C2->>DB: Идемпотентная запись (проверка дедупликации по event_uid)
        C2->>C2: Оценка правил корреляции (AlertEngine)
        C2->>WS: Broadcast события атаки активным клиентам
        WS->>Analyst: Мгновенное появление в Ленте событий (<0.1с)
        C2-->>Edge: HTTP 200 {"status":"ok","processed":N}
        Edge-->>Trap: Подтверждение доставки
        Trap->>Buffer: Очистка доставленных событий (mark_delivered)
    end
```

---

## 3. Маскировка каналов связи и процессов (MASK-1...7)

1. **Криптографическая верификация**: Защита от подделки телеметрии через HMAC-SHA256 подпись: `f"{trap_id}:{ts}:{nonce}:{sha256(raw_body)}"`. Срок жизни nonce — 180 секунд.
2. **Stealth Telemetry**: Запросы без валидной HMAC-подписи возвращают стандартный FastAPI 404 Not Found (`{"detail":"Not Found"}` с заголовком `content-length: 22` и `content-type: application/json`), полностью неотличимый от обращения к случайному несуществующему эндпоинту.
3. **Сертификатный пиннинг**: Все агенты в контейнерах используют параметр `SSL_CERT_PATH=/etc/ssl/certs/static-edge.crt` для строгой валидации открытого ключа шлюза без доверия системному хранилищу ОС.
4. **Маскировка процессов**: Исполняемые процессы ловушек подменяют имя в выводе `ps` и `/proc` через `prctl(PR_SET_NAME)` и `setproctitle`:
   - Низкоинтерактивная ловушка: `systemd-resolved`
   - Среднеинтерактивная ловушка: `rsyslogd`
