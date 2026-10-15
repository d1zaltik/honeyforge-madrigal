# Итоговый отчёт аудита реализма, скрытности и E2E-верификации HoneyForge

**Проект:** HoneyForge (Платформа управления распределенными ловушками для SOC)  
**Хакатон:** UmirHack — Кейс «Мадригал»  
**Дата проведения аудита:** 15 октября 2026 г.  
**Стенд:** Docker Compose (7 сервисов: `db-store` [PostgreSQL 15.19], `app-backend`, `static-edge`, `mgmt-gateway`, `systemd-resolved-low`, `rsyslogd-med`, `sec-scanner`)  
**Итоговый статус верификации:**  
- `pytest tests/`: **28/28 PASS (100%)**
- `python scripts/verify_phase_three.py`: **UNIT-LEVEL 100% PASS**
- `python scripts/selfcheck_realism.py --local`: **11/11 PASS (100%)**
- `python scripts/selfcheck_realism.py --live`: **11/11 PASS (100%)**
- `python scripts/e2e_live.py`: **13/13 PASS (100%)**
- `python scripts/check_matrix_refs.py`: **42/42 PASS (100%)**

---

## 1. Официальная матрица соответствия ТЗ (Compliance Matrix)

Статусы требований строго стандартизированы: **сделано** / **частично** / **не сделано**.  
Каждая строка проверена автоматическим валидатором `scripts/check_matrix_refs.py` против AST/кодовой базы (42/42 PASS).

### 1.1. Серверные требования центра управления (FR-C1 … FR-C7)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **FR-C1** | CRUD профилей | **сделано** | [`profiles.py:14`](honeyforge_server/app/routes/profiles.py#L14), [`models.py:22`](honeyforge_server/app/models.py#L22) | Полный CRUD профилей (создание, чтение, обновление, удаление) с параметрами сервисов, persona, сетевых портов и honeytokens | `pytest tests/test_profiles.py`, `step_01_rbac` в `e2e_live.py` |
| **FR-C2** | Регистрация ловушки и статусы online/offline/last-seen | **сделано** | [`traps.py:20`](honeyforge_server/app/routes/traps.py#L20), [`models.py:58`](honeyforge_server/app/models.py#L58) | Регистрация ловушек, фиксация last_seen при каждом beacon/событии, вычисление статуса online/offline по динамическому порогу таймаута | `pytest tests/test_traps.py`, `step_04_ssh_attack_and_latency` в `e2e_live.py` |
| **FR-C3** | Выдача конфига и приём телеметрии через защищённый endpoint | **сделано** | [`telemetry.py:42`](honeyforge_server/app/routes/telemetry.py#L42), [`security.py:167`](honeyforge_server/app/security.py#L167) | Защищенный прием телеметрии и выдача конфига нодам через эндпоинт маскировки с валидацией HMAC-SHA256, контролем окна времени (±300с) и in-memory кэшем nonce | `pytest tests/test_security.py`, `selfcheck_realism.py` Пункт 9 |
| **FR-C4** | События в PostgreSQL с фильтрами (ловушка, время, источник, тип) | **сделано** | [`events.py:15`](honeyforge_server/app/routes/events.py#L15), [`database.py:12`](honeyforge_server/app/database.py#L12) | Хранение событий в PostgreSQL 15, фильтрация по `trap_id`, периодам времени (`period=15m/1h/24h`), `source_ip`, `event_type`, пагинация (`limit`/`offset`) | `step_12_postgresql_and_persistence` в `e2e_live.py` |
| **FR-C5** | Аутентификация и разграничение доступа | **сделано** | [`auth.py:45`](honeyforge_server/app/routes/auth.py#L45), [`security.py:32`](honeyforge_server/app/security.py#L32) | Аутентификация на JWT-токенах с разграничением ролей (Admin/Analyst), защита эндпоинта логина с блокировкой перебора (429 Lockout на 15 мин после 5 неудач) | `step_01_rbac` и `step_02_lockout_and_audit` в `e2e_live.py` |
| **FR-C6** (bonus) | Оркестратор одной кнопкой | **частично** | [`orchestrator.py:6`](honeyforge_server/app/orchestrator.py#L6), [`orchestrator.py:71`](honeyforge_server/app/orchestrator.py#L71) | Реализована генерация файлов `docker-compose.yml`, shell-скриптов развертывания и PowerShell-сценариев; прямой демон управления Docker socket (`/var/run/docker.sock`) в целях безопасности намеренно не используется | `pytest tests/test_orchestrator.py` |
| **FR-C7** (bonus) | Правила/алерты и экспорт IoC | **сделано** | [`alert_engine.py:10`](honeyforge_server/app/alert_engine.py#L10), [`ioc_exporter.py:9`](honeyforge_server/app/ioc_exporter.py#L9) | Корреляция событий (brute-force, command injection, honeytoken trigger), формирование алертов в реальном времени, экспорт IoC в STIX 2.1 JSON, Suricata IDS rules, CSV | `step_06_correlation_rule_alert`, `pytest tests/test_export.py` |

---

### 1.2. Требования к агентам-ловушкам (FR-A1 … FR-A6)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **FR-A1** | Low и medium | **сделано** | [`low_interaction.py:97`](honeyforge_agent/traps/low_interaction.py#L97), [`fake_ssh.py:659`](honeyforge_agent/traps/fake_ssh.py#L659), [`fake_web.py:149`](honeyforge_agent/traps/fake_web.py#L149) | Low-interaction (FTP ProFTPD 1.3.7a, Telnet getty, Redis 7.0.15, multi-port) и Medium-interaction (OpenSSH 8.9p1 с псевдотерминалом и Apache 2.4.52 с веб-формами) | `selfcheck_realism.py` Пункты 1, 7, 8; `step_04_ssh_attack_and_latency` и `step_05_low_trap_port_scan` в `e2e_live.py` |
| **FR-A2** | Логирование активности | **сделано** | [`main.py:62`](honeyforge_agent/main.py#L62), [`base.py:4`](honeyforge_agent/traps/base.py#L4) | Фиксация попыток авторизации, вводимых учетных данных, выполненных команд, перехваченных сессий и сетевых пробингов, передача в очередь буферизации | `step_04_ssh_attack_and_latency`, `step_05_low_trap_port_scan` в `e2e_live.py` |
| **FR-A3** | Периодическая отправка телеметрии и получение конфига | **сделано** | [`sender.py:44`](honeyforge_agent/sender.py#L44), [`main.py:175`](honeyforge_agent/main.py#L175) | Фоновый цикл периодических маяков (sync loop), передача батчей событий и опрос центра управления для динамического обновления persona и настроек | `step_04_ssh_attack_and_latency` в `e2e_live.py` |
| **FR-A4** | Буферизация и дослылка | **сделано** | [`buffer.py:14`](honeyforge_agent/buffer.py#L14), [`sender.py:44`](honeyforge_agent/sender.py#L44) | Локальное хранилище SQLite с режимом WAL на постоянном томе `sys_med_state`, права 0600, сохранение при остановке прокси и перезапуске контейнера, 100% дослылка без потерь | `step_08_store_and_forward` в `e2e_live.py` |
| **FR-A5** (bonus) | High-interaction | **не сделано** | [`docs/architecture.md:1`](docs/architecture.md#L1) | Полноценные микро-ВМ (QEMU/KVM/Firecracker) с изоляцией гипервизора не реализованы; в платформе реализована глубокая medium-interaction эмуляция с VirtualFS и перехватом команд | Запланировано в дорожной карте следующего релиза |
| **FR-A6** (bonus) | Honeytokens | **сделано** | [`honeytokens.py:35`](honeyforge_agent/honeytokens.py#L35), [`fake_ssh.py:379`](honeyforge_agent/traps/fake_ssh.py#L379) | Генерация реалистичных приманок (ключи AWS API `AKIA...`, canary URLs), детекция их использования и мгновенная генерация критического алерта | `step_07_honeytoken_trigger` в `e2e_live.py` |

---

### 1.3. Требования маскировки и анти-фингерпринтинга (MASK-1 … MASK-7)

| Идентификатор | Требование ТЗ | Статус | Файл и строка | Описание реализации | Метод верификации |
|:---|:---|:---:|:---|:---|:---|
| **MASK-1** | TLS | **сделано** | [`docker/nginx-edge.conf:21`](docker/nginx-edge.conf#L21), [`sender.py:30`](honeyforge_agent/sender.py#L30) | Принудительное шифрование канала телеметрии по TLS 1.3 через прокси `static-edge` | `step_11_tls_pinning` в `e2e_live.py` |
| **MASK-2** | Неприметный endpoint | **сделано** | [`telemetry.py:42`](honeyforge_server/app/routes/telemetry.py#L42), [`nginx-edge.conf:45`](docker/nginx-edge.conf#L45) | Маскировка под RUM и веб-статику (`/cdn-cgi/rum`, `/static/pixel.gif`). При запросе без подписи или с неверным HMAC выдается стандартный stock Nginx 404 HTML (153 байта), идентичный несуществующим путям | `selfcheck_realism.py` Пункт 9 (локально и через HTTPS) |
| **MASK-3** | Разделение интерфейсов | **сделано** | [`docker-compose.yml:85`](docker-compose.yml#L85), [`nginx-edge.conf:1`](docker/nginx-edge.conf#L1), [`nginx-mgmt.conf:1`](docker/nginx-mgmt.conf#L1) | Разделение периметров: `static-edge` (DMZ + mgmt) принимает только телеметрию; `mgmt-gateway` (только mgmt) публикует Web UI / API; порты 8000 и 5432 закрыты наружу | `step_03_network_isolation` и `step_10_host_port_exposure` в `e2e_live.py` |
| **MASK-4** | Скрытность агента | **сделано** | [`stealth.py:9`](honeyforge_agent/stealth.py#L9), [`Dockerfile.agent:22`](docker/Dockerfile.agent#L22) | Подмена имени процесса в `ps aux` (`rsyslogd`, `systemd-resolved`), очистка `/proc/1/environ` и `/proc/1/cmdline`, отсутствие маркеров honeypot/fake во всей файловой системе контейнера и метаданных docker inspect | `step_09_container_markers` в `e2e_live.py` |
| **MASK-5** (bonus) | Джиттер и рандомизация beacon | **сделано** | [`stealth.py:29`](honeyforge_agent/stealth.py#L29), [`config.py:32`](honeyforge_agent/config.py#L32) | Псевдослучайный джиттер интервалов отправки маяков (30–40%) по формуле $T = T_0 \cdot (1 \pm \text{jitter})$, исключающий периодические тайминг-сигнатуры в сетевом анализе ($CV \ge 0.10$) | `step_13_mask5_beacon_jitter` в `e2e_live.py` |
| **MASK-6** (bonus) | Анти-фингерпринтинг | **сделано** | [`fake_ssh.py:866`](honeyforge_agent/traps/fake_ssh.py#L866), [`low_interaction.py:163`](honeyforge_agent/traps/low_interaction.py#L163), [`fake_web.py:105`](honeyforge_agent/traps/fake_web.py#L105) | Имитация сетевых задержек (0.45..0.95с со стд. отклонением > 0), аутентичные ошибки GNU bash/coreutils, согласованные даты `ls -la`, криптографический набор OpenSSH 8.9p1, Yescrypt хеши shadow | `selfcheck_realism.py` Пункты 1–11 |
| **MASK-7** (bonus) | mTLS, pinning, ротация ключей | **частично** | [`sender.py:30`](honeyforge_agent/sender.py#L30), [`traps.py:181`](honeyforge_server/app/routes/traps.py#L181) | TLS Pinning корневого сертификата `static-edge.crt` реализован; API ротации ключей узлов реализовано; двусторонний mTLS с клиентскими сертификатами не реализован (заменен HMAC подписью прикладного уровня для сохранения stealth 404) | `step_11_tls_pinning` в `e2e_live.py` |

---

### 1.4. Дополнительные возможности платформы (Extra Capabilities)

Помимо обязательных и бонусных пунктов ТЗ, платформа HoneyForge реализует следующие возможности:
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

---

## 2. Результаты проверок реализма (selfcheck_realism.py)

Скрипт `scripts/selfcheck_realism.py` поддерживает режимы `--local` и `--live` (**11/11 PASS в обоих режимах**).

### 2.1. Результаты режима `--live` (против запущенного Docker Compose)
```text
================================================================================
  HONEYFORGE REALISM & STEALTH AUDIT SUITE (MASK-6) [MODE: LIVE]
================================================================================
[PASS] Пункт 01: Согласованность стека с persona - Ubuntu 22.04 LTS / OpenSSH 8.9p1 / Apache 2.4.52 / ProFTPD 1.3.7a (PASV 50000..50050) / Redis 7.0.15
[PASS] Пункт 02: Правдоподобность ошибок bash и coreutils - GNU-authentic cat, cd, rm, and command not found errors
[PASS] Пункт 03: Формат вывода ls -la и GNU даты - Standard POSIX column layout with GNU date formatting
[PASS] Пункт 04: Задержки и их variance (FTP, HTTP, SSH auth & disconnect) - FTP N=10 (min=0.55s, max=0.83s, stddev=0.108s), HTTP N=10 (min=0.56s, max=0.93s, stddev=0.132s), SSH disconnect on attempt 3
       SSH commands executed & response sizes:
         $ cat /etc/shadow                                          ->   387 bytes
         $ cat /etc/passwd                                          ->  1438 bytes
         $ wget -q -O test_script.sh http://127.0.0.1/test_script.sh ->     0 bytes
         $ cat test_script.sh                                       ->   107 bytes
         $ curl -s -o test_curl.sh http://127.0.0.1/test_curl.sh    ->     0 bytes
         $ cat test_curl.sh                                         ->   107 bytes
         $ cat .bash_history                                        ->    90 bytes
         $ cat ~/.bash_history                                      ->    90 bytes
         $ cat /var/log/auth.log                                    -> 32704 bytes
         $ cat /proc/version                                        ->   124 bytes
         $ uname -a                                                 ->   112 bytes
         $ env                                                      ->   159 bytes
         $ ps aux                                                   ->  5699 bytes
         $ history                                                  ->   112 bytes
[PASS] Пункт 05: Запрещённые слова в ответах (SSH, Telnet, Redis, HTTP, VirtualFS) - 0 leak words across SSH (9 cmds), Telnet, Redis, HTTP, and VirtualFS
[PASS] Пункт 06: Постоянство хост-ключей (RSA, ECDSA, Ed25519) на volume - RSA, ECDSA, and Ed25519 keys persisted and preserved
[PASS] Пункт 07: Шаблоны страниц ошибок HTTP (Apache 2.4.52 HTML) - Apache 2.4.52 error templates with exact ISO-8859-1 charset and signatures
[PASS] Пункт 08: Ответ Redis на неизвестные команды (Redis 7) - Authentic Redis 7 '-ERR unknown command ... with args beginning with' format
       Measured 404 baseline on /404-ghost-9c2438eb43ed:
         Status: 404
         Headers: ['server', 'date', 'content-type', 'content-length', 'connection']
         Content-Type: text/html
         Body Length: 153 bytes
         Body Preview: b'<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<'
[PASS] Пункт 09: 404-идентичность скрытого эндпоинта (Stealth Telemetry) - 5 stealth paths across 4 HTTP verbs match stock 404 byte-for-byte (153B, Content-Type: text/html)
[PASS] Пункт 10: Алгоритмы KEX SSH (OpenSSH 8.9p1 reference) - Strict subset of Ubuntu 22.04 LTS OpenSSH 8.9p1 cryptographic policy
[PASS] Пункт 11: Режим non-interactive Exec SSH (id, uname, os-release, non-zero exit code) - Authentic Exec-mode SSH: stdout/stderr separation, exit codes (0 and 127), zero PTY sequences
================================================================================
  ИТОГ САМОПРОВЕРКИ: 11/11 проверок успешно пройдены.
================================================================================
```

### 2.2. Измеренные параметры ответа static-edge (Nginx) для Пункта 9
При обращении к скрытым эндпоинтам телеметрии (`/cdn-cgi/rum`, `/sync/v1/config`, `/static/pixel.gif`, `/cdn-cgi/telemetry/pixel.gif`) без валидной HMAC-подписи или с некорректной подписью через Nginx по HTTPS:
- **HTTP статус:** `404 Not Found`
- **Заголовки:** `Server: nginx`, `Content-Type: text/html`, `Content-Length: 153`, `Connection: keep-alive` (идентично дефолтному Nginx 404).
- **Размер тела:** ровно **153 байта**.
- **Тело ответа:** стандартный HTML Nginx:
  ```html
  <html>
  <head><title>404 Not Found</title></head>
  <body>
  <center><h1>404 Not Found</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```
- **Сравнение:** Побайтово идентично запросу на несуществующий URL (`/404-ghost-...`). Отсутствуют какие-либо JSON-ошибки (`{"detail": "..."}`), маркеры FastAPI или заголовки Python/Uvicorn.

---

## 3. Результаты живого сквозного тестирования (scripts/e2e_live.py)

```text
================================================================================
  HONEYFORGE — E2E ЖИВАЯ ВЕРИФИКАЦИЯ СТЕНДА (e2e_live.py)
  Target: https://127.0.0.1 | Host: 127.0.0.1 | CA: docker/certs/static-edge.crt
================================================================================
[PASS] Шаг 01 (0.24s): RBAC Авторизация (Analyst 403 vs Admin 200)
       -> Аналитик ограничен, админ создал профиль, аудит доступен
[PASS] Шаг 02 (1.26s): Блокировка перебора паролей (429 Lockout + Audit Log)
       -> Попытки 6-8 заблокированы с кодом 429, событие занесено в аудит
[PASS] Шаг 03 (9.81s): Сетевая изоляция DMZ и Management (MASK-3)
       -> backend:8000, db:5432, mgmt:80 изолированы; DNS mgmt имен не резолвятся; static-edge отдаёт stock Nginx 404 без JSON
[PASS] Шаг 04 (2.24s): Атака на SSH и задержка телеметрии (< 5s)
       -> Lure rejection -> успешный вход -> команды выполнены -> событие в API за 0.54s
[PASS] Шаг 05 (1.05s): TCP-сканирование портов Low-Trap
       -> Сканирование портов 2121, 2323, 6379 сгенерировало события телеметрии
[PASS] Шаг 06 (17.05s): Срабатывание правил корреляции (Alert)
       -> Выключение правила предотвратило алерт; включение правила сгенерировало '>=5 попыток входа за минуту' (severity=high)
[PASS] Шаг 07 (1.07s): Срабатывание токена-приманки (Honeytoken)
       -> Canary token 'ht-c203d547' вызвал Critical Alert: 'КРИТИЧЕСКИЙ: Зафиксировано срабатывание токена-приманки 'Canary E2E Product...'
[PASS] Шаг 08 (9.84s): Надёжная доставка телеметрии (FR-A4 Store & Forward)
       -> 3 события сохранены в SQLite-буфер, пережили перезапуск rsyslogd-med при мертвом edge и доставлены без потерь
       /proc/1/cmdline: rsyslogd
       Masked /proc/1/environ (0 vars):
       Zero-marker scan in rsyslogd-med: PASS (0 marker occurrences across filesystem)
       Zero-marker scan in systemd-resolved-low: PASS (0 marker occurrences across filesystem)
[PASS] Шаг 09 (4.30s): Аудит маркеров в контейнерах ловушек (MASK-4)
       -> PID 1 маскирован, /proc/1/environ и cmdline чистые, файловая система (0 маркеров во всех контейнерах) и docker inspect без маркеров
[PASS] Шаг 10 (4.11s): Проверка сетевого периметра хоста (MASK-1 / MASK-3)
       -> Порты 8000 и 5432 надёжно закрыты наружу; открыты только порты edge и ловушек
[PASS] Шаг 11 (0.36s): Проверка TLS Pinning и сертификатов (FR-C7 / MASK-7)
       -> Чужой CA сертификат надёжно отклонён (ConnectError), пиннингованный CA принят
[PASS] Шаг 12 (4.14s): PostgreSQL 15.19, фильтры телеметрии и персистентность (FR-C4)
       -> PostgreSQL 15.19 подтвержден динамически (SELECT version()), фильтры trap_id/period/пагинация работают, данные сохранены после рестарта backend
[PASS] Шаг 13 (0.11s): Статистическое подтверждение джиттера и энтропии пакетов (MASK-5)
       -> Собрано 242 маяка от узла 172.28.0.20: dt=[min=1.0s, max=12.0s, mean=5.01s, stddev=2.28s, CV=0.4545 >= 0.10]. Размеров пакетов: 115 уникальных ([983, 984, 985, 988, 989]... байт)
================================================================================
  ИТОГ ЖИВОГО ТЕСТИРОВАНИЯ E2E: 13/13 шагов успешно пройдены.
================================================================================
```

---

## 4. Доказательства чувствительности тестов (Fault Injection Evidence)

### 4.1. Доказательство чувствительности проверки 404 (Пункт 9 selfcheck_realism.py)
При внесении искусственного сбоя (возврат 204 вместо 404):
```text
[FAIL] Пункт 09: 404-идентичность скрытого эндпоинта - POST /cdn-cgi/rum without sig returned 204 (expected 404 identical to non-existent route)
================================================================================
  ИТОГ САМОПРОВЕРКИ: 10/11 проверок успешно пройдены.
[FAIL] Обнаружены несоответствия критериям реализма и скрытности!
```
Скрипт завершается с ненулевым кодом выхода `1`.

### 4.2. Доказательство динамического обнаружения незащищенного эндпоинта (test_auth_coverage.py)
При регистрации незащищенного маршрута `@app.get("/api/v1/fault_injection_leak_route")`:
```text
tests\test_auth_coverage.py F                                            [100%]
================================== FAILURES ===================================
_________________ test_07_fastapi_route_walker_auth_coverage __________________
>       assert len(unprotected_routes) == 0, f"Unprotected routes detected by crawler: {unprotected_routes}"
E       AssertionError: Unprotected routes detected by crawler: [('/api/v1/fault_injection_leak_route', ['fault_injection_unprotected'])]
E       assert 1 == 0
E        +  where 1 = len([('/api/v1/fault_injection_leak_route', ['fault_injection_unprotected'])])
```
Динамический краулер дерева зависимостей `app.routes` мгновенно обнаруживает неавторизованный маршрут и валит тест с `AssertionError`.

---

## 5. Аудит маркеров и сканирование контейнеров (MASK-4 Zero-Marker Audit)

В ходе реализации задачи были устранены исключения целых директорий (`/usr/bin`, `/usr/sbin`, `/usr/share`, `/usr/local/lib/python3.11` и др.). Сканирование выполняется инструментом `/usr/local/bin/scan_container_markers.py`:
- Сканируются **все имена файлов и директорий** от корня `/`.
- Сканируется **содержимое всех текстовых файлов и байткода `.pyc`** (с извлечением строковых констант).
- Пропускаются только заведомо двоичные исполняемые файлы ELF (`\x7fELF`).

### Результаты сканирования работающих контейнеров стенда:
1. **`rsyslogd-med` (Medium-interaction ловушка):**
   ```text
   SCAN METRICS & STATISTICS:
     Total paths checked by name:       3639
     Scanned text files:                1825
     Scanned .pyc bytecode files:          0
     Skipped binary ELF files:           815
     Total forbidden matches:              0
   [PASS] Exactly 0 marker occurrences detected across the filesystem!
   ```
2. **`systemd-resolved-low` (Low-interaction ловушка):**
   ```text
   SCAN METRICS & STATISTICS:
     Total paths checked by name:       3632
     Scanned text files:                1818
     Scanned .pyc bytecode files:          0
     Skipped binary ELF files:           815
     Total forbidden matches:              0
   [PASS] Exactly 0 marker occurrences detected across the filesystem!
   ```

---

## 6. Таблица переименования сервисов, эндпоинтов и сетевых портов

| Компонент / Назначение | Контейнер / Имя | Адрес и Порт | Протокол | Назначение и изоляция |
|:---|:---|:---|:---:|:---|
| Центральный бэкенд C2 | `app-backend` | `172.29.0.3:8000` | HTTP/API | Изолирован в `internal_mgmt`. Внешние порты **не публикуются**. |
| База данных СУБД | `db-store` | `172.29.0.2:5432` | PostgreSQL | Изолирована в `internal_mgmt`. Внешние порты **не публикуются**. |
| Внешний агентский шлюз | `static-edge` | `172.28.0.3:443`, `127.0.0.1:8443` | HTTPS | Мост между `edge_dmz` и `internal_mgmt`. Публикует порт 8443 только на loopback (127.0.0.1) для проверок TLS/404. |
| Операторский шлюз SOC | `mgmt-gateway` | `172.29.0.4`, хост `80/443` | HTTPS / HTTP | Доступ операторов к Web UI и API. Находится строго в `internal_mgmt`. |
| Medium-interaction ловушка | `rsyslogd-med` | `172.28.0.20`, хост `2222, 8088` | SSH, HTTP | Находится строго в `edge_dmz`. Нет доступа к бэкенду и СУБД. |
| Low-interaction ловушка | `systemd-resolved-low` | `172.28.0.10`, хост `2121, 2323, 6379, 50000..50050` | FTP, Telnet, Redis | Находится строго в `edge_dmz`. Полная сетевая изоляция периметра. |
