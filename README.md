# HoneyForge — Платформа управления honeypot-ловушками для SOC

[![Status](https://img.shields.io/badge/Status-Production%20Ready-emerald.svg)]()
[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688.svg)]()
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2016-blue.svg)]()
[![Reverse%20Proxy](https://img.shields.io/badge/Gateway-Dual%20Nginx%20TLS-009639.svg)]()
[![Threat%20Intel](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-red.svg)]()

HoneyForge — платформа класса Deception / Honeynet Management для центров мониторинга и реагирования (SOC / Blue Team), разработанная в рамках кейса «Мадригал» (хакатон UmirHack). Платформа обеспечивает централизованное развертывание парка реалистичных ловушек с многоуровневой маскировкой каналов связи, криптографической защитой телеметрии, защитой от автоматизированного фингерпринтинга и интеграцией с SIEM/NIDS.

---

## 1. Архитектура системы и сегментация сетей

Архитектура HoneyForge разделена на изолированные сегменты с жестким разграничением прав и разделением шлюза приёма телеметрии (`static-edge`) и шлюза оператора (`mgmt-gateway`):

```mermaid
flowchart TD
    subgraph DMZ["Изолированный сегмент DMZ: edge_dmz (172.28.0.0/16)"]
        Scanner["Атакующий / Сканер\n(sec-scanner: 172.28.0.30)"]
        LowTrap["Низкоинтерактивная ловушка\n(systemd-resolved-low: 172.28.0.10)\nПорты: 2121 (FTP), 2323 (Telnet), 6379 (Redis), 50000-50050 (PASV)"]
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

### Сетевые сегменты:
1. **`edge_dmz` (`172.28.0.0/16`)**: Демилитаризованная зона. Содержит контейнеры сетевых ловушек (`systemd-resolved-low`, `rsyslogd-med`), симулятор атак (`sec-scanner`) и внешний сетевой интерфейс шлюза `static-edge` (`172.28.0.3`).
2. **`internal_mgmt` (`172.29.0.0/16`)**: Out-of-band сеть управления. Содержит внутренний сетевой интерфейс шлюза (`static-edge`: `172.29.0.3`), C2-сервер (`app-backend`: `172.29.0.2`) и СУБД (`db-store`: `172.29.0.5`).
3. **Изоляция портов**: Порты 8000 (C2) и 5432 (PostgreSQL) физически не опубликованы наружу и не имеют маршрута из DMZ. Вся телеметрия передается строго через HTTPS (порт 443) шлюза `static-edge`.

Дополнительная документация:
- [Сетевая архитектура и потоки данных (docs/ARCHITECTURE.md)](docs/ARCHITECTURE.md)
- [Схема базы данных и ER-диаграмма (docs/db_schema.md)](docs/db_schema.md)
- [Пошаговый сценарий демонстрации (docs/demo_scenario.md)](docs/demo_scenario.md)

---

## 2. Быстрый запуск и доступ к стенду

### Вариант А: Мгновенный доступ через публичный HTTPS (Без установки)
Платформа развернута на живом демонстрационном стенде и доступна по безопасному каналу:
> 🌐 **Публичный адрес для жюри и экспертов:** [https://million-heights-nursing-loud.trycloudflare.com](https://million-heights-nursing-loud.trycloudflare.com)  
> ⚡ **Мгновенный вход для жюри без ввода пароля (по ссылке / QR-коду):** [https://million-heights-nursing-loud.trycloudflare.com/?demo=jury](https://million-heights-nursing-loud.trycloudflare.com/?demo=jury)

#### Учетные записи операторов SOC для проверки:
| Роль в SOC | Логин | Пароль | Права доступа |
| :--- | :--- | :--- | :--- |
| **Жюри / Демо-просмотр (1-Click)** | `jury` | `jury2026` | 👁️ Режим просмотра без риска сломать стенд (или кнопка «Быстрый вход для жюри») |
| **CISO / Главный администратор** | `admin` | `zd4maiMGqDrbARkXKbQDJQ` | Полный доступ (управление ловушками, симулятор атак, KeyStore) |
| **Руководитель смены SOC** | `soc_lead` | `SocLead2026!Secure` | Управление профилями, правилами корреляции и инцидентами |
| **Старший аналитик L2** | `analyst_l2` | `HunterL2_2026!` | Анализ сессий, экспорт IoC, аудит угроз |
| **Дежурный аналитик L1** | `analyst_l1` | `L1Watcher2026!` | Мониторинг ленты событий, квитирование оповещений |
| **Аудитор / Комплаенс** | `auditor` | `ComplianceAuditor2026!` | Журнал безопасности (`audit_logs`) и верификация KeyStore |
| **Аналитик SOC** | `analyst` | `JAYu043ohhy7ZLeiAcXBrg` | Доступ только для чтения (лента событий, карта, IoC) |

---

### Вариант Б: Локальный запуск через Docker Compose (Рекомендуемый)

#### 1. Клонирование и переход в каталог:
```bash
git clone <URL_РЕПОЗИТОРИЯ>
cd umirhack
```

#### 2. Запуск контейнеров (одна команда):
```bash
docker compose up -d --build
```

Все необходимые конфигурационные файлы (`.env`, SSL-сертификаты, ключи шифрования узлов) уже преднастроены и готовы к работе «из коробки».

#### 3. Доступные локальные сервисы:
* **Веб-интерфейс SOC**: `https://localhost` (порт 80 автоматически перенаправляет на 443 с кодом 301).
* **Fake SSH (Medium-Interaction)**: `localhost:2222`
* **Fake Web Portal (Medium-Interaction)**: `localhost:8088`
* **Fake FTP (Low-Interaction)**: `localhost:2121` (PASV: `50000-50050`)
* **Fake Telnet (Low-Interaction)**: `localhost:2323`
* **Fake Redis (Low-Interaction)**: `localhost:6379`

#### 4. Остановка стенда:
```bash
docker compose down
```

---

## 3. Конфигурация (.env.example)

Шаблон переменных окружения описан в [.env.example](.env.example):

```dotenv
# База данных PostgreSQL
POSTGRES_DB=honeyforge
POSTGRES_USER=honeyforge
POSTGRES_PASSWORD=CHANGE_ME_POSTGRES_PASSWORD
DATABASE_URL=postgresql+asyncpg://honeyforge:CHANGE_ME_POSTGRES_PASSWORD@db-store:5432/honeyforge

# Секрет подписи JWT (32+ байт URL-safe)
JWT_SECRET=CHANGE_ME_JWT_SECRET
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Первоначальные пароли операторов (генерируются случайным образом)
ADMIN_PASSWORD=CHANGE_ME_ADMIN_PASSWORD
ANALYST_PASSWORD=CHANGE_ME_ANALYST_PASSWORD

# Предопределенные идентификаторы и ключи нод (HMAC-SHA256)
NODE_LOW_ID=n-7f3a
NODE_KEY_LOW=CHANGE_ME_NODE_KEY_LOW

NODE_MED_ID=n-8c1b
NODE_KEY_MED=CHANGE_ME_NODE_KEY_MED

# Привязка сетевых портов сервера
HONEYFORGE_HOST=0.0.0.0
HONEYFORGE_PORT=8000
```

---

## 4. Профили и хостовая персона (Persona)

Каждая ловушка настраивается через профиль, определяющий её роль в сети и поведенческие характеристики:
- **`services`**: список активных протоколов (`["ssh", "http", "ftp", "telnet", "redis"]`).
- **`banners`**: подлинные сетевые баннеры, строго согласованные с заявленным дистрибутивом.
- **`decoy_credentials`**: список принимаемых приманочных учетных записей.
- **`honeytokens_config`**: приманки (ключи AWS, токены, canary-файлы).
- **`stealth_params`**: интервалы опроса, джиттер (30–40%), случайный паддинг пакетов (32–128 байт), маскировка имени процесса (`prctl`/`setproctitle`).
- **`persona`**: схема [`PersonaSchema`](honeyforge_server/app/schemas.py), определяющая цифровую личность сервера:
  - `hostname`: уникальное сетевое имя хоста (например, `int-syslog-01`, `edge-gw-01`).
  - `os`: релиз дистрибутива (`Ubuntu 22.04.4 LTS`).
  - `kernel`: подлинная версия ядра Linux (`5.15.0-105-generic`).
  - `uptime_base`: базовое время работы системы в секундах (непрерывно увеличивается в рантайме).
  - `users`: список локальных пользователей (`root`, `deploy`, `ubuntu`).
  - `mac` и `ip`: виртуальные сетевые параметры.

### Динамическая синхронизация
Агент ловушки периодически опрашивает C2 через защищенный эндпоинт `/sync/v1/config` (или получает конфигурацию при старте). Изменение персоны в профиле автоматически обновляет:
1. SSH хост-ключи, баннер и окружение сессии (uname, uptime, /etc/shadow, /etc/passwd);
2. HTTP заголовки Apache 2.4.52 и HTML-шаблоны ошибок;
3. Баннеры FTP ProFTPD 1.3.5 и задержки приветствия;
4. Telnet getty приглашение Ubuntu;
5. Вывод команды `INFO` в Redis 7.0.

---

## 5. API сервера управления (C2) и безопасность

Центральный сервер HoneyForge (`honeyforge_server`) реализует промышленный уровень защищенности:

- **Хранение паролей (FR-C5)**: Алгоритм PBKDF2-HMAC-SHA256 с 600,000 итерациями и индивидуальной солью (`pbkdf2$<salt>$<hash>`). Устаревшие хэши автоматически обновляются при успешной авторизации.
- **Защита от подбора паролей**:
  - Ограничение частоты запросов Nginx: 5 запросов/мин (burst 5) на `/api/v1/auth/login`.
  - In-app блокировка: 5 неудачных попыток входа приводят к временной блокировке аккаунта на 5 минут с кодом **HTTP 429 Too Many Requests** и записью в `AuditLog`.
- **Сессии и отзыв токенов**:
  - `POST /api/v1/auth/login`: получение JWT Access Token (срок жизни 8 часов).
  - `POST /api/v1/auth/logout`: немедленный отзыв токена с занесением `jti` в потокобезопасный Denylist.
  - `POST /api/v1/auth/ws-ticket`: получение одноразового билета с TTL 30 секунд для безопасного подключения к WebSocket без передачи JWT в URL.
- **Ролевая модель доступа (RBAC)**:
  - На каждом запросе роль пользователя проверяется по базе данных.
  - `admin`: полный доступ к управлению парком ловушек, профилями, запуску симулятора атак и настройке правил.
  - `analyst`: доступ только для чтения (лента инцидентов, дашборд, аналитика, экспорт IoC в STIX 2.1 / Suricata / CSV). Вызовы методов модификации возвращают **HTTP 403 Forbidden**.
- **Stealth Telemetry (MASK-2)**:
  - Пути телеметрии замаскированы под RUM-метрики: `/cdn-cgi/rum`, `/static/v2/metrics`.
  - Неавторизованные запросы без валидной HMAC-подписи возвращают стандартный ответ **HTTP 404 `{"detail": "Not Found"}`**, полностью идентичный несуществующим путям по коду, телу и заголовкам (`Content-Length: 22`, `Content-Type: application/json`), предотвращая обнаружение сервера управления атакующими.

---

## 6. Статус соответствия требованиям кейса «Мадригал» (MASK-1...7)

Полная матрица всех функциональных требований (FR-C1..C7, FR-A1..A6, MASK-1..7) с номерами строк и описанием доступна в [docs/compliance_matrix.md](docs/compliance_matrix.md), а спецификация версий в [docs/persona_versions.md](docs/persona_versions.md).

| Идентификатор | Требование | Статус | Реализация в коде |
| :--- | :--- | :---: | :--- |
| **MASK-1** | Сетевая маскировка и изоляция | **ВЫПОЛНЕНО** | Двойной независимый Nginx (`static-edge` для агентов и `mgmt-gateway` для оператора). Порты 8000 и 5432 закрыты снаружи. |
| **MASK-2** | Скрытый эндпоинт телеметрии (Stealth 404) | **ВЫПОЛНЕНО** | Мимикрия под RUM/статику (`/cdn-cgi/rum`, `/static/v2/metrics`, `/sync/`). Любые невалидные запросы возвращают stock Nginx 404 HTML без JSON. |
| **MASK-3** | Защита транспортного уровня и TLS Pinning | **ВЫПОЛНЕНО** | TLS 1.3 с проверкой CA-сертификата (`static-edge.crt`), строгий pinning на агентах. Чужие сертификаты немедленно отклоняются. |
| **MASK-4** | Маскировка процессов и контейнеров | **ВЫПОЛНЕНО** | Подмена имени процесса через `setproctitle` (`rsyslogd`, `systemd-resolved`), очистка `/proc/1/environ` и `/proc/1/cmdline`. |
| **MASK-5** | Исключение статических детектов и маркеров | **ВЫПОЛНЕНО** | Реалистичные хеши Yescrypt (`$y$j9T$...`), разные для пользователей; уникальные hostname/MAC/ключи хоста; 0 маркеров honeypot/fake. |
| **MASK-6** | Специфичное поведение сервисов (Realism) | **ВЫПОЛНЕНО** | Apache 2.4.52 ISO-8859-1 страницы ошибок (400, 403, 404, 405, 414); ProFTPD 1.3.7a с динамическим PASV (50000..50050); Redis 7 формат ошибок. |
| **MASK-7** | Консистентность стека ОС (Ubuntu 22.04 LTS) | **ВЫПОЛНЕНО** | Согласованный стек версий: Ubuntu 22.04.4 LTS, Linux 5.15.0-105-generic, OpenSSH 8.9p1 Ubuntu-3ubuntu0.10, Apache 2.4.52, Redis 7.0.15. |

---

## 7. Ограничения архитектуры (Limitations)

Для прозрачности и честной оценки архитектуры выделены следующие проектные ограничения:

1. **Самоподписанный TLS сертификат и Certificate Pinning**:
   - В текущей сборке Nginx использует самоподписанный CA-сертификат (`docker/certs/static-edge.crt`).
   - Агенты ловушек и проверочные скрипты используют жесткую привязку (pinning) данного CA. В корпоративном развертывании требуется интеграция с корпоративным PKI или доверенными сертификатами Let's Encrypt.
2. **In-Memory хранилище состояния безопасности (Nonce, Denylist, WS Tickets)**:
   - Кэш использованных одноразовых nonce, Denylist отозванных JWT-токенов (`jti`) и одноразовые билеты WebSocket реализованы в виде потокобезопасных in-memory структур с блокировками (`threading.Lock`) внутри процесса C2.
   - Данное решение оптимально для стандартного развертывания с одним воркером Uvicorn. При горизонтальном масштабировании C2 (`--workers > 1`) требуется подключение внешнего хранилища Redis для распределенной синхронизации состояния.
3. **Отсутствие mTLS на транспортном уровне**:
   - Взаимная аутентификация ловушек и сервера C2 реализована на прикладном уровне через HMAC-SHA256 подпись тела с preshared ключом ноды (`NODE_KEY`), а не через клиентские TLS-сертификаты (mTLS).
4. **Отсутствие High-Interaction песочницы с аппаратной виртуализацией**:
   - Платформа реализует Low-Interaction и продвинутые Medium-Interaction ловушки (интерактивный shell, сессионная POSIX VFS, симуляция загрузки файлов без внешнего сетевого egress).
   - Запуск произвольных недоверенных бинарных файлов (ELF) в изолированных виртуальных машинах (QEMU/KVM/gVisor) с анализом системных вызовов в ядре в текущей версии не предусмотрен.

---

## 8. Тестирование и верификация

Набор автоматических тестов платформы:

```powershell
# 1. Запуск набора модульных и интеграционных тестов (Pytest)
pytest tests/ -v

# 2. Сквозная верификация Этапов 1-5 (криптография HMAC, буферизация SQLite, VFS, эмуляторы)
python scripts/verify_phase_three.py

# 3. Комплексная проверка сетевого реализма и скрытности (MASK-6/7): локальный режим (10/10 PASS)
python scripts/selfcheck_realism.py --local

# 4. Комплексная проверка сетевого реализма и скрытности: живой режим против Docker-стенда (10/10 PASS)
python scripts/selfcheck_realism.py --live

# 5. Сквозной E2E-тест живого стенда: RBAC, 429 lockout, изоляция DMZ, SSH SLA, Store & Forward, PostgreSQL 16 (12/12 PASS)
python scripts/e2e_live.py
```
