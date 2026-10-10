# 🛡️ HoneyForge — Платформа управления реалистичными ловушками-приманками

[![UmirHack](https://img.shields.io/badge/III%20Межрегиональный%20Хакатон-UmirHack-blue.svg)](https://umirhack.ru)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-emerald.svg)]()
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-2496ED.svg)]()
[![STIX](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-red.svg)]()

> **Кейс:** Конструктор и центр управления реалистичными ловушками-приманками «HoneyForge»  
> **Команда:** МАДРИГАЛ 1  

HoneyForge — промышленная платформа класса Deception / Honeynet Management для команд мониторинга и реагирования (Blue Team / SOC). Система обеспечивает централизованное развертывание парка ловушек разного уровня взаимодействия (Low, Medium, High) со **скрытым каналом связи**, защищенным от обнаружения продвинутым нарушителем.

---

## 🚀 Ключевые возможности и соответствие требованиям

### 1. Центральная система (C2 Core)
* **FR-C1 (Must):** CRUD профилей ловушек — уровень, наборы сервисов, баннеры, учетные данные-приманки, параметры маскировки.
* **FR-C2 (Must):** Регистрация ловушек, привязка к профилям, мониторинг статусов (online/offline/last-seen) с автоматическим определением доступности.
* **FR-C3 (Must):** Защищенная выдача конфигурации и прием телеметрии через замаскированный эндпоинт.
* **FR-C4 (Must):** Хранение событий атак в БД с гибкой фильтрацией (по ловушке, времени, источнику, типу, критичности).
* **FR-C5 (Must):** Аутентификация оператора (JWT + RBAC) и подробный журнал аудита действий.
* **FR-C6 (Bonus):** Оркестратор развертывания в 1 клик — мгновенная генерация `docker-compose.yml`, Bash (curl) и PowerShell скриптов развертывания.
* **FR-C7 (Bonus):** Движок автоматических алертов (brute-force threshold $\ge$ 5 попыток/мин, canary breach) и экспорт индикаторов компрометации в форматах **STIX 2.1 JSON**, **CSV** и **Suricata/Snort IDS Rules**.

### 2. Агент и ловушки (Trap Engines)
* **FR-A1 (Must):** Поддержка уровней Low и Medium (+ High Sandbox isolation).
  * **Low-Interaction:** Асинхронный TCP/UDP multi-port listener (FTP 2121, Telnet 2323, Redis 6379) с реалистичными баннерами версий.
  * **Medium-Interaction SSH:** Полноценный SSH-демон на Paramiko с честным криптографическим handshake, сбором логинов/паролей, виртуальным bash-шеллом и перехватом загрузок вредоносного ПО с фиксацией SHA-256.
  * **Medium-Interaction Fake Web:** Веб-портал авторизации SSO с перехватом POST-учеток, SQL-инъекций и path traversal.
* **FR-A2 (Must):** Логирование подключений, учетных записей, команд шелла, HTTP-запросов и сетевых метаданных.
* **FR-A3 (Must):** Периодический двусторонний обмен (джиттер-beacon) и получение обновленных конфигураций.
* **FR-A4 (Must):** Устойчивость к потере связи: надежная локальная буферизация на SQLite (Store & Forward) и гарантированная досылка при восстановлении канала.
* **FR-A5 (Bonus):** High-interaction изолированная песочница с логированием TTY.
* **FR-A6 (Bonus):** Honeytokens: генерация и размещение canary-приманок (AWS API keys, Canary URLs, `/etc/shadow`), с мгновенной фиксацией компрометации.

### 3. Комплекс маскировки связи (Ключевое требование кейса!)
* **MASK-1:** TLS-шифрование и HMAC-SHA256 подпись каждого сообщения с контролем nonce от replay-атак.
* **MASK-2:** Неприметный Endpoint: прием телеметрии спрятан за `/v1/telemetry/collect` и `/cdn-cgi/telemetry/pixel.gif`, трафик маскируется под метрики CDN/веб-аналитики с заголовками Google Chrome.
* **MASK-3:** Разделение интерфейсов (OOB Mgmt): ловушка слушает атаки в сегменте DMZ, а связь с C2 держит через отдельную скрытую подсеть управления.
* **MASK-4:** Скрытность на хосте: процесс маскируется под системный демон `systemd-resolved` или `rsyslogd`, без маркеров «honeypot/c2» в памяти и логах.
* **MASK-5:** Джиттер (±35%) и случайный Dummy Padding: плавающие интервалы и переменный размер пакетов исключают обнаружение периодичности системами NTA/Zeek.
* **MASK-6:** Анти-фингерпринтинг: актуальные баннеры (OpenSSH 8.9p1, Apache 2.4.52), реалистичные коды ошибок и структура каталогов Linux.
* **MASK-7:** Взаимная аутентификация агента и центра через криптографические токены с валидацией временного дрейфа.

---

## ⚡ Быстрый запуск

### Вариант 1. Локальный запуск (1 команда, без Docker)
Платформа спроектирована для мгновенного запуска на любой ОС (Windows / Linux / macOS):

```bash
# 1. Активировать виртуальное окружение
.\venv\Scripts\activate       # Windows
# source venv/bin/activate    # Linux / macOS

# 2. Запустить все компоненты платформы (C2 + Low Trap + Medium Trap)
python scripts/run_all.py
```

После запуска открываются:
* **Cyber SOC Dashboard:** [http://localhost:8000](http://localhost:8000)
* **Интерактивная документация API (Swagger):** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Medium SSH Honeypot:** `localhost:2222` (тестовый логин: `root:admin123`)
* **Medium Fake Web Admin:** [http://localhost:8088](http://localhost:8088)
* **Low Interaction Ports:** `2121` (FTP), `2323` (Telnet), `6379` (Redis)

---

### Вариант 2. Развертывание через Docker Compose
Для промышленного развертывания в изолированных сетях DMZ и OOB Mgmt:

```bash
docker compose up -d --build
```

Архитектура развертывания поднимает:
1. `honeyforge-c2` — центр управления в сети `honeyforge_mgmt` (порт 8000).
2. `nginx-proxy` — обратный прокси с маскировкой телеметрии (порт 80).
3. `honeyforge-trap-low` — ловушка Low Interaction (DMZ + Mgmt OOB).
4. `honeyforge-trap-med` — ловушка Medium Interaction Fake SSH/Web (DMZ + Mgmt OOB).

---

## 🎬 Сценарий живой демонстрации (Для жюри)

В проект встроен автоматический симулятор атак для наглядной проверки всех критериев:

```bash
python -m simulator.attack_simulator --all
```

**Цепочка проверки:**
1. **Scenario 1:** Сканирование портов (FTP, Telnet, Redis) $\rightarrow$ фиксация баннеров и probe-пакетов в дашборде.
2. **Scenario 2:** Высокоскоростной брутфорс SSH $\rightarrow$ перехват логинов/паролей и срабатывание правила `Credential Brute-Force Wave (≥5 попыток/мин)`.
3. **Scenario 3:** Вход в Fake SSH терминал, выполнение команд разведки (`whoami`, `uname -a`, `cat /etc/passwd`) и скачивание майнера `wget miner.sh` $\rightarrow$ расчет SHA-256 хэша артефакта и запись полной сессии в плеер Asciinema Replay!
4. **Scenario 4:** Веб-атака на форму авторизации с SQL-инъекцией `' OR '1'='1` $\rightarrow$ захват полезной нагрузки.
5. **Scenario 5:** Чтение приманки Honeytoken или переход по Canary URL $\rightarrow$ немедленный **CRITICAL ALERT** в SOC дашборде!

*(Все сценарии также запускаются нажатием кнопок в верхней панели веб-интерфейса!)*

---

## 🧪 Запуск автотестов
Для подтверждения надежности компонентов реализован полный набор end-to-end тестов:

```bash
python scripts/test_all.py
```

Проверяются:
* Хэширование паролей, JWT аутентификация и HMAC-подписи агентов.
* CRUD профилей и хранение в базе данных (FR-C1).
* Надежность локального буфера Store-and-Forward (FR-A4).
* Джиттер и переменный dummy padding (MASK-5).
* Движок корреляции алертов при брутфорсе и атаке на Honeytoken (FR-C7).
* Экспорт индикаторов компрометации в STIX 2.1, CSV и Suricata rules.
* 1-Click генерация артефактов развертывания (FR-C6).

---

## 📁 Структура репозитория

```
c:\умир\
├── honeyforge_server/             # Центр управления (C2 Server & Dashboard)
│   ├── app/
│   │   ├── main.py                # FastAPI приложение, startup seed, routes, WebSockets
│   │   ├── config.py              # Настройки сервера и параметры маскировки
│   │   ├── database.py            # Асинхронное подключение SQLAlchemy (SQLite/PostgreSQL)
│   │   ├── models.py              # Модели: Trap, Profile, AttackEvent, Honeytoken, Sessions
│   │   ├── schemas.py             # Pydantic v2 схемы валидации данных
│   │   ├── security.py            # JWT, хэширование, HMAC-SHA256 подпись агентов
│   │   ├── websocket_hub.py       # WebSocket Hub для реалтайм-вещания на дашборд
│   │   ├── alert_engine.py        # Движок корреляции алертов и детекции атак
│   │   ├── ioc_exporter.py        # Экспорт IoC (STIX 2.1, CSV, Suricata rules)
│   │   ├── orchestrator.py        # Генератор 1-Click деплоя (Docker/Bash/PS1)
│   │   └── routes/                # Модули API: auth, profiles, traps, events, honeytokens
│   └── static/                    # Cyber SOC Web-UI Dashboard
│       ├── index.html             # Главный интерфейс оператора
│       ├── css/style.css          # Стильный кибер-SOC тёмный интерфейс
│       └── js/app.js              # WebSocket клиент, графики, плеер сессий
├── honeyforge_agent/              # Агент ловушки (HoneyForge Agent)
│   ├── main.py                    # Демон ловушки с подменой процесса и джиттер-циклом
│   ├── config.py                  # Конфигурация портов и ключей агента
│   ├── stealth.py                 # Модуль маскировки (Process spoof, Jitter, Padding)
│   ├── buffer.py                  # Локальный транзакционный буфер SQLite (Store & Forward)
│   ├── sender.py                  # Клиент защищенной отправки телеметрии на C2
│   ├── honeytokens.py             # Менеджер локальных приманок (AWS, Canary URLs)
│   └── traps/                     # Движки ловушек
│       ├── base.py                # Базовый интерфейс ловушки
│       ├── low_interaction.py     # Multi-port TCP listener (FTP, Telnet, Redis)
│       ├── fake_ssh.py            # Fake SSH daemon (Paramiko, Fake Shell, Malware recorder)
│       └── fake_web.py            # Fake Web Admin (SSO portal, SQLi collector)
├── simulator/
│   └── attack_simulator.py        # Автоматизированный симулятор атак для демонстрации
├── docker/
│   ├── Dockerfile.server          # Сборка C2 сервера
│   ├── Dockerfile.agent           # Сборка агента ловушки
│   └── nginx.conf                 # Nginx прокси с маскировкой эндпоинта
├── scripts/
│   ├── run_all.py                 # Единый запуск всей платформы на хосте
│   └── test_all.py                # Автоматический тестовый набор
├── docs/
│   ├── ARCHITECTURE.md            # Детальная архитектура и диаграмма потоков данных
│   ├── DATABASE.md                # Схема БД и ER-диаграмма
│   ├── HONEYPOT_LEVELS.md         # Сравнение уровней взаимодействия (Low/Medium/High)
│   └── PRESENTATION.md            # Готовый сценарий защиты для презентации
├── docker-compose.yml             # Главный docker-compose манифест
└── requirements.txt               # Зависимости Python
```

---

## 🏆 Заключение
Платформа HoneyForge полностью реализует все обязательные (**Must**) и бонусные (**Bonus**) требования хакатона, предоставляя готовое решение промышленного уровня с акцентом на реалистичность эмуляции, глубокий сбор киберразведки и надежную маскировку канала управления.
