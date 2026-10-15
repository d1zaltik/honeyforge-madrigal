# Матрица соответствия требованиям кейса «Мадригал» (Compliance Matrix)

Платформа управления распределенными ловушками для SOC **HoneyForge** разработана в рамках хакатона UmirHack (кейс «Мадригал»). Ниже представлена официальная матрица соответствия всем требованиям технического задания: функциональным требованиям центра управления (**FR-C1..FR-C7**), функциональным требованиям агента (**FR-A1..FR-A6**) и требованиям к маскировке и скрытности (**MASK-1..MASK-7**).

Статусы требований строго стандартизированы: **сделано** / **частично** / **не сделано**.

---

## 1. Центр управления C2 (Серверная часть: FR-C1 .. FR-C7)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **FR-C1** | CRUD профилей | **сделано** | [`profiles.py:15`](../honeyforge_server/app/routes/profiles.py#L15), [`models.py:50`](../honeyforge_server/app/models.py#L50) | Полный CRUD профилей (создание, чтение, обновление, удаление) с параметрами сервисов, persona, сетевых портов и honeytokens | `pytest tests/test_profiles.py`, `step_01_rbac` в `e2e_live.py` |
| **FR-C2** | Регистрация ловушки и статусы online/offline/last-seen | **сделано** | [`traps.py:20`](../honeyforge_server/app/routes/traps.py#L20), [`models.py:30`](../honeyforge_server/app/models.py#L30) | Регистрация ловушек, фиксация last_seen при каждом beacon/событии, вычисление статуса online/offline по динамическому порогу таймаута | `pytest tests/test_traps.py`, `step_04_ssh_attack_and_latency` в `e2e_live.py` |
| **FR-C3** | Выдача конфига и приём телеметрии через защищённый endpoint | **сделано** | [`telemetry.py:45`](../honeyforge_server/app/routes/telemetry.py#L45), [`security.py:75`](../honeyforge_server/app/security.py#L75) | Защищенный прием телеметрии и выдача конфига нодам через эндпоинт маскировки с валидацией HMAC-SHA256, контролем окна времени (±300с) и in-memory кэшем nonce | `pytest tests/test_security.py`, `selfcheck_realism.py` Пункт 9 |
| **FR-C4** | События в PostgreSQL с фильтрами (ловушка, время, источник, тип) | **сделано** | [`events.py:15`](../honeyforge_server/app/routes/events.py#L15), [`database.py:10`](../honeyforge_server/app/database.py#L10) | Хранение событий в PostgreSQL 15, фильтрация по `trap_id`, периодам времени (`period=15m/1h/24h`), `source_ip`, `event_type`, пагинация (`limit`/`offset`) | `step_12_postgresql_and_persistence` в `e2e_live.py` |
| **FR-C5** | Аутентификация и разграничение доступа | **сделано** | [`auth.py:45`](../honeyforge_server/app/routes/auth.py#L45), [`security.py:40`](../honeyforge_server/app/security.py#L40) | Аутентификация на JWT-токенах с разграничением ролей (Admin/Analyst), защита эндпоинта логина с блокировкой перебора (429 Lockout на 15 мин после 5 неудач) | `step_01_rbac` и `step_02_lockout_and_audit` в `e2e_live.py` |
| **FR-C6** (bonus) | Оркестратор одной кнопкой | **частично** | [`orchestrator.py:15`](../honeyforge_server/app/orchestrator.py#L15), [`orchestrator.py:80`](../honeyforge_server/app/orchestrator.py#L80) | Реализована генерация файлов `docker-compose.yml`, shell-скриптов развертывания и конфигураций; прямой демон управления Docker socket (`/var/run/docker.sock`) в целях безопасности намеренно не используется | `pytest tests/test_orchestrator.py` |
| **FR-C7** (bonus) | Правила/алерты и экспорт IoC | **сделано** | [`alert_engine.py:10`](../honeyforge_server/app/alert_engine.py#L10), [`ioc_exporter.py:25`](../honeyforge_server/app/ioc_exporter.py#L25) | Корреляция событий (brute-force, command injection, honeytoken trigger), формирование алертов в реальном времени, экспорт IoC в STIX 2.1 JSON, Suricata IDS rules, CSV | `step_06_correlation_rule_alert`, `pytest tests/test_export.py` |

---

## 2. Агент-ловушка (Локальная эмуляция: FR-A1 .. FR-A6)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **FR-A1** | Low и medium | **сделано** | [`low_interaction.py:97`](../honeyforge_agent/traps/low_interaction.py#L97), [`fake_ssh.py:750`](../honeyforge_agent/traps/fake_ssh.py#L750), [`fake_web.py:149`](../honeyforge_agent/traps/fake_web.py#L149) | Low-interaction (FTP ProFTPD 1.3.7a, Telnet getty, Redis 7.0.15, multi-port) и Medium-interaction (OpenSSH 8.9p1 с псевдотерминалом и Apache 2.4.52 с веб-формами) | `selfcheck_realism.py` Пункты 1, 7, 8; `step_04_ssh_attack_and_latency` и `step_05_low_trap_port_scan` в `e2e_live.py` |
| **FR-A2** | Логирование активности | **сделано** | [`main.py:120`](../honeyforge_agent/main.py#L120), [`base.py:5`](../honeyforge_agent/traps/base.py#L5) | Фиксация попыток авторизации, вводимых учетных данных, выполненных команд, перехваченных сессий и сетевых пробингов, передача в очередь буферизации | `step_04_ssh_attack_and_latency`, `step_05_low_trap_port_scan` в `e2e_live.py` |
| **FR-A3** | Периодическая отправка телеметрии и получение конфига | **сделано** | [`sender.py:45`](../honeyforge_agent/sender.py#L45), [`main.py:180`](../honeyforge_agent/main.py#L180) | Фоновый цикл периодических маяков (sync loop), передача батчей событий и опрос центра управления для динамического обновления persona и настроек | `step_04_ssh_attack_and_latency` в `e2e_live.py` |
| **FR-A4** | Буферизация и дослылка | **сделано** | [`buffer.py:20`](../honeyforge_agent/buffer.py#L20), [`sender.py:60`](../honeyforge_agent/sender.py#L60) | Локальное хранилище SQLite с режимом WAL на постоянном томе `sys_med_state`, права 0600, сохранение при остановке прокси и перезапуске контейнера, 100% дослылка без потерь | `step_08_store_and_forward` в `e2e_live.py` |
| **FR-A5** (bonus) | High-interaction | **не сделано** | [`docs/architecture.md`](../docs/architecture.md) | Полноценные микро-ВМ (QEMU/KVM/Firecracker) с изоляцией гипервизора не реализованы; в платформе реализована глубокая medium-interaction эмуляция с VirtualFS и перехватом команд | Запланировано в дорожной карте следующего релиза |
| **FR-A6** (bonus) | Honeytokens | **сделано** | [`honeytokens.py:15`](../honeyforge_agent/honeytokens.py#L15), [`fake_ssh.py:103`](../honeyforge_agent/traps/fake_ssh.py#L103) | Генерация реалистичных приманок (ключи AWS API `AKIA...`, canary URLs), детекция их использования и мгновенная генерация критического алерта | `step_07_honeytoken_trigger` в `e2e_live.py` |

---

## 3. Маскировка и скрытность (MASK-1 .. MASK-7)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **MASK-1** | TLS | **сделано** | [`docker/nginx-edge.conf:15`](../docker/nginx-edge.conf#L15), [`sender.py:30`](../honeyforge_agent/sender.py#L30) | Принудительное шифрование канала телеметрии по TLS 1.3 через прокси `static-edge` | `step_11_tls_pinning` в `e2e_live.py` |
| **MASK-2** | Неприметный endpoint | **сделано** | [`telemetry.py:45`](../honeyforge_server/app/routes/telemetry.py#L45), [`nginx-edge.conf:45`](../docker/nginx-edge.conf#L45) | Маскировка под RUM и веб-статику (`/cdn-cgi/rum`, `/static/pixel.gif`). При запросе без подписи или с неверным HMAC выдается стандартный stock Nginx 404 HTML (153 байта), идентичный несуществующим путям | `selfcheck_realism.py` Пункт 9 (локально и через HTTPS) |
| **MASK-3** | Разделение интерфейсов | **сделано** | [`docker-compose.yml:85`](../docker-compose.yml#L85), [`nginx-edge.conf:1`](../docker/nginx-edge.conf#L1), [`nginx-mgmt.conf:1`](../docker/nginx-mgmt.conf#L1) | Разделение периметров: `static-edge` (DMZ + mgmt) принимает только телеметрию; `mgmt-gateway` (только mgmt) публикует Web UI / API; порты 8000 и 5432 закрыты наружу | `step_03_network_isolation` и `step_10_host_port_exposure` в `e2e_live.py` |
| **MASK-4** | Скрытность агента | **сделано** | [`stealth.py:15`](../honeyforge_agent/stealth.py#L15), [`Dockerfile.agent:16`](../docker/Dockerfile.agent#L16) | Подмена имени процесса в `ps aux` (`rsyslogd`, `systemd-resolved`), очистка `/proc/1/environ` и `/proc/1/cmdline`, отсутствие маркеров honeypot/fake во всей файловой системе контейнера и метаданных docker inspect | `step_09_container_markers` в `e2e_live.py` |
| **MASK-5** (bonus) | Джиттер и рандомизация beacon | **сделано** | [`stealth.py:50`](../honeyforge_agent/stealth.py#L50), [`config.py:32`](../honeyforge_agent/config.py#L32) | Псевдослучайный джиттер интервалов отправки маяков (30–40%) по формуле $T = T_0 \cdot (1 \pm \text{jitter})$, исключающий периодические тайминг-сигнатуры в сетевом анализе | `step_04_ssh_attack_and_latency` в `e2e_live.py` |
| **MASK-6** (bonus) | Анти-фингерпринтинг | **сделано** | [`fake_ssh.py:1270`](../honeyforge_agent/traps/fake_ssh.py#L1270), [`low_interaction.py:146`](../honeyforge_agent/traps/low_interaction.py#L146), [`fake_web.py:270`](../honeyforge_agent/traps/fake_web.py#L270) | Имитация сетевых задержек (0.45..0.95с со стд. отклонением > 0), аутентичные ошибки GNU bash/coreutils, согласованные даты `ls -la`, криптографический набор OpenSSH 8.9p1, Yescrypt хеши shadow | `selfcheck_realism.py` Пункты 1–10 |
| **MASK-7** (bonus) | mTLS, pinning, ротация ключей | **частично** | [`sender.py:30`](../honeyforge_agent/sender.py#L30), [`traps.py:110`](../honeyforge_server/app/routes/traps.py#L110) | TLS Pinning корневого сертификата `static-edge.crt` реализован; API ротации ключей узлов реализовано; двусторонний mTLS с клиентскими сертификатами не реализован (заменен HMAC подписью прикладного уровня для сохранения stealth 404) | `step_11_tls_pinning` в `e2e_live.py` |

---

## 4. Дополнительные возможности платформы (Extra Capabilities)

Помимо обязательных и бонусных пунктов ТЗ, платформа HoneyForge реализует следующие промышленные возможности:
1. **Двухуровневая ролевая модель RBAC (Admin / Analyst)**:
   Разграничение доступа на уровне роутов FastAPI: роль `analyst` имеет доступ только к просмотру событий, фильтрации и экспорту IoC; роль `admin` управляет профилями, ловушками и правилами корреляции.
2. **Анти-брутфорс защита веб-интерфейса (Lockout 429)**:
   При 5 последовательных неудачных попытках входа на `/api/v1/auth/login` IP-адрес временно блокируется на 15 минут с отдачей HTTP 429 и фиксацией в Security Audit Log.
3. **Одноразовые тикеты WebSocket (One-Time Ticket Authentication)**:
   Подключение к WebSocket `/ws/attacks` выполняется не по постоянному JWT, а по одноразовому билету (ticket), инвалидируемому сразу после установления соединения.
4. **Сессионная виртуальная файловая система (VirtualFS)**:
   В SSH-ловушке реализована полнофункциональная in-memory VFS, поддерживающая создание файлов, директорий, редактирование, удаление, навигацию `cd` и чтение виртуального дерева `/proc/uptime`, `/proc/version`.
5. **Захват и хэширование загружаемых артефактов (Payload Capture)**:
   При попытке атакующего скачать скрипт или пейлоад командами `wget`/`curl` агент симулирует скачивание, сохраняет вычисленный SHA256-хеш и имя файла в структурированной телеметрии без выхода во внешнюю сеть (Zero Egress).
