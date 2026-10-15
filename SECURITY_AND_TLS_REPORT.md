# 🛡️ HoneyForge: Отчёт о реализации серверной авторизации (FR-C5) и TLS-шифрования канала (MASK-1)

> **Документ:** Сводный технический отчёт о доработке платформы HoneyForge  
> **Дата:** 13 октября 2026 г.  
> **Статус:** Реализовано, протестировано (100% тестов пройдено), развёрнуто в Docker Compose  

---

## 📋 1. Подтверждение по выполненным блокам

### БЛОК 1. СЕРВЕРНАЯ АВТОРИЗАЦИЯ (FR-C5)

#### Что было в коде до доработки:
1. **Отсутствие серверной валидации токенов:** В файле `honeyforge_server/app/security.py` существовали утилиты генерации токенов (`create_access_token`, `decode_access_token`), однако ни один API-маршрут фактически не использовал FastAPI `Depends()` для проверки входящих запросов.
2. **Уязвимость прямого доступа (IDOR / Broken Access Control):** Любой неавторизованный клиент с `curl` мог выполнять любые деструктивные действия без входа в систему:
   * Удалять ловушки (`DELETE /api/v1/traps/{trap_id}`)
   * Создавать honeytoken-приманки (`POST /api/v1/honeytokens`)
   * Изменять профили, правила оповещений и останавливать ловушки (`POST /api/v1/traps/{trap_id}/action`)
   * Запускать симуляцию атак (`POST /api/v1/simulator/run`)
   * Читать журнал аудита и телеметрию перехваченных атак
3. **Фиктивный журнал аудита:** Во всех маршрутах в `AuditLog` жестко записывалось имя пользователя `"admin"`, вне зависимости от того, кто реально отправил запрос.
4. **Небезопасный эндпоинт `/auth/me`:** Маршрут принимал имя пользователя через query-параметр (`/auth/me?username=...`) без проверки токена, что позволяло запросить профиль любого пользователя.
5. **Невалидная конфигурация CORS:** В `honeyforge_server/app/main.py` middleware CORS имел настройки `allow_origins=["*"]` и `allow_credentials=True`. По спецификации W3C/Fetch CORS такая комбинация является невалидной и блокируется браузерами при передаче авторизационных заголовков.
6. **Открытый WebSocket:** Сокет `/ws/attacks` не проверял подлинность оператора, позволяя любому внешнему клиенту подключаться к закрытой ленте событий SOC.

#### Что было реализовано:
1. **Зависимости безопасности в `security.py`:**
   * Внедрена зависимость `get_current_user` на базе `HTTPBearer(auto_error=False)`. При отсутствии, недействительности или истечении срока токена выбрасывается `HTTPException(status_code=401, detail="Не авторизован")`.
   * Внедрена зависимость `require_admin(user = Depends(get_current_user))`. Проверяет `user["role"] == "admin"`, при нехватке прав выбрасывает `HTTPException(status_code=403, detail="Недостаточно прав. Требуется роль администратора")`.
   * Гарантирован унифицированный доступ к имени оператора как через `user["username"]`, так и через `user["sub"]`.
2. **Ролевое разграничение маршрутов (RBAC):**
   * **Только для роли `admin` (`require_admin`):**
     * CRUD профилей: создание, обновление, удаление, клонирование (`routes/profiles.py`)
     * Регистрация, удаление и управляющие действия над ловушками: stop, rotate_creds, change_profile, update_config (`routes/traps.py`)
     * Создание honeytoken-приманок (`routes/honeytokens.py`)
     * Создание, переключение статуса и удаление правил оповещений (`routes/rules.py`)
     * Запуск демонстрационного симулятора атак (`routes/simulator.py`)
   * **Для обеих ролей `admin` и `analyst` (`get_current_user`):**
     * Чтение списков ловушек, профилей, алертов, honeytokens, событий, интерактивных сессий
     * Квитирование алертов (`POST /api/v1/events/alerts/{alert_id}/ack`)
     * Просмотр и экспорт киберразведки IoC (STIX 2.1, CSV, Suricata)
     * Чтение журнала аудита и общей статистики дашборда
     * Получение информации о себе (`GET /auth/me`)
   * **Специальные маршруты ловушек (без JWT, защищены HMAC-подписью агента):**
     * Приём телеметрии: `POST /v1/telemetry/collect` и `GET /cdn-cgi/telemetry/pixel.gif`
     * Замаскированный триггер honeytoken-приманки: `GET /sync/{token_id}` (доступен для нарушителя)
3. **Честный журнал аудита (`AuditLog`):**
   * Во всех функциях записи аудита константа `"admin"` заменена на `user.get("username", "admin")`, полученное из верифицированного JWT-токена.
4. **Исправление `/auth/me`:**
   * Убран query-параметр `username`. Пользователь извлекается исключительно из заголовка `Authorization: Bearer <token>` через `Depends(get_current_user)`.
5. **Безопасный CORS:**
   * Значение `allow_origins` сделано настраиваемым через переменную окружения `ALLOWED_ORIGINS` (по умолчанию разрешены `http://localhost`, `https://localhost`, `http://127.0.0.1`, `https://127.0.0.1` на портах 80 и 443).
6. **Защита WebSocket:**
   * Эндпоинт `/ws/attacks` теперь валидирует JWT-токен через параметр запроса `?token=...`. При отсутствии или невалидности токена соединение немедленно закрывается с кодом `1008 Policy Violation`.
7. **Фронтенд (`app.js`):**
   * При старте приложения сохранённый токен валидируется через `GET /api/v1/auth/me`. Если сессия истекла или токен отозван, происходит мягкий переход на форму логина.
   * WebSocket подключается по безопасному протоколу `wss://` с передачей `?token=${encodeURIComponent(authToken)}`.

---

### БЛОК 2. TLS МЕЖДУ АГЕНТОМ И ЦЕНТРОМ (MASK-1)

#### Что было в коде до доработки:
1. **Открытый трафик телеметрии:** Ловушки передавали телеметрию на центр по незашифрованному протоколу HTTP на `http://honeyforge-c2:8000`.
2. **Открытый порт центра управления наружу:** В `docker-compose.yml` порт `8000:8000` был опубликован на хост-машину, демаскируя архитектуру платформы.
3. **Отсутствие шифрования на веб-интерфейсе:** Обратный прокси Nginx слушал только 80-й порт. Сертификаты отсутствовали.
4. **Незащищенный триггер приманок в симуляторе:** Контейнер атакующего обращался к canary-приманке по обычному HTTP через порт 80.

#### Что было реализовано:
1. **Автоматическая генерация TLS-сертификатов («из коробки»):**
   * Создан скрипт `docker/nginx-entrypoint.sh`. При старте контейнера скрипт проверяет наличие сертификатов в директории `/etc/nginx/certs/`. Если они отсутствуют, скрипт автоматически генерирует самоподписанный сертификат OpenSSL:
     * Ключ: RSA 2048 бит (`honeyforge.key`)
     * Сертификат: X.509 на 365 дней (`honeyforge.crt`)
     * Subject: `CN=honeyforge-nginx`
     * SAN (Subject Alternative Names): `DNS:honeyforge-nginx`, `DNS:nginx-proxy`, `DNS:localhost`, `IP:127.0.0.1`, `IP:172.28.0.3`, `IP:172.29.0.3`.
   * Создан `docker/Dockerfile.nginx` на базе `nginx:alpine` с OpenSSL и автоматическим запуском entrypoint-скрипта.
   * Сертификаты сохраняются в volume `./docker/certs:/etc/nginx/certs:rw`, что обеспечивает их сохранение между перезапусками.
2. **Терминация TLS в Nginx (`docker/nginx.conf`):**
   * На порту 443 развёрнут SSL/TLS сервер (`ssl_certificate /etc/nginx/certs/honeyforge.crt`, `ssl_certificate_key /etc/nginx/certs/honeyforge.key`, протоколы TLSv1.2 и TLSv1.3, надёжные шифры `HIGH:!aNULL:!MD5`).
   * На порту 80 настроен безусловный HTTP 301 редирект на защищённый протокол: `return 301 https://$host$request_uri;`.
   * Все локации (`/v1/telemetry/collect`, `/cdn-cgi/telemetry/pixel.gif`, `/sync/`, `/ws/attacks`, `/`) проксируются на внутренний бэкенд с проставлением заголовка `X-Forwarded-Proto https`.
3. **Изоляция центра управления в `docker-compose.yml`:**
   * У сервиса `honeyforge-c2` **полностью удалена публикация порта наружу** (`ports: - "8000:8000"` убрана). Порт 8000 доступен только внутри приватной Docker-сети для Nginx.
   * У `nginx-proxy` открыты порты `80:80` и `443:443`.
4. **Перевод агентов ловушек на TLS:**
   * В `honeyforge_agent/config.py` значение по умолчанию `C2_URL` изменено на `https://honeyforge-nginx`.
   * В `docker-compose.yml` переменная `C2_URL` для ловушек `systemd-resolved-low` и `rsyslogd-med` установлена в `https://honeyforge-nginx`.
   * В `honeyforge_agent/sender.py` в конструктор `httpx.AsyncClient` добавлен параметр `verify=False` с обязательным развёрнутым комментарием:
     ```python
     # ВНИМАНИЕ: verify=False допустимо только потому, что это демонстрационный стенд с самоподписанным сертификатом; в проде агент должен проверять сертификат центра (опционально — через заранее known fingerprint/pinning, это уже отмечено как MASK-7 bonus)
     async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
     ```
5. **Перевод симулятора атак нарушителя на TLS:**
   * В `simulator_attacker/scenarios.py` сценарий срабатывания приманки `run_honeytoken_breach` переведён на `https://{nginx_host}/sync/{token_id}` с параметром `verify=False` и поясняющим комментарием.
   * Контейнер атакующего обращается к Nginx по TLS, эмулируя поведение реального нарушителя.
6. **Обновление фронтенда и документации:**
   * Веб-консоль SOC открывается по адресу `https://localhost`.
   * В `README.md` добавлен подробный раздел «TLS и сертификаты (MASK-1)» с инструкцией по принятию самоподписанного сертификата в браузере и использованию ключа `-k` для curl.

---

## 📁 2. Полный реестр созданных и модифицированных файлов

| Файл | Статус | Роль в платформе |
| :--- | :---: | :--- |
| `docker/nginx-entrypoint.sh` | **Новый** | Скрипт автогенерации сертификатов OpenSSL (RSA 2048, SAN) при старте |
| `docker/Dockerfile.nginx` | **Новый** | Dockerfile для Nginx Alpine с установленным пакетом OpenSSL |
| `docker/certs/honeyforge.crt` | **Новый** | Самоподписанный TLS-сертификат стенда |
| `docker/certs/honeyforge.key` | **Новый** | Закрытый ключ TLS-сертификата |
| `scripts/verify_phase_two.py` | **Новый** | Скрипт автоматизированного тестирования RBAC, TLS, AuditLog и WebSocket |
| `honeyforge_server/app/security.py` | **Изменён** | Добавлены FastAPI-зависимости `get_current_user` и `require_admin` |
| `honeyforge_server/app/main.py` | **Изменён** | Исправлен CORS (валидный `ALLOWED_ORIGINS`), добавлена JWT-защита WebSocket |
| `honeyforge_server/app/routes/auth.py` | **Изменён** | Маршрут `/auth/me` переписан на получение пользователя из токена |
| `honeyforge_server/app/routes/traps.py` | **Изменён** | Защита `require_admin` на мутации, `get_current_user` на чтение, запись реального пользователя в `AuditLog` |
| `honeyforge_server/app/routes/profiles.py` | **Изменён** | CRUD профилей переведён на `require_admin`, чтение на `get_current_user`, фиксация пользователя в аудите |
| `honeyforge_server/app/routes/rules.py` | **Изменён** | Управление правилами алертов закрыто под `require_admin`, аудит с именем оператора |
| `honeyforge_server/app/routes/honeytokens.py` | **Изменён** | Создание приманок ограничено `require_admin`, эндпоинт `/sync/{token_id}` оставлен открытым для атаки |
| `honeyforge_server/app/routes/simulator.py` | **Изменён** | Запуск симулятора ограничен `require_admin`, запись в аудит, хост переведён на `honeyforge-nginx` |
| `honeyforge_server/app/routes/events.py` | **Изменён** | Защита ленты событий, сессий, алертов и выгрузки IoC через `get_current_user` |
| `honeyforge_server/app/routes/audit.py` | **Изменён** | Просмотр журнала аудита закрыт зависимостью `get_current_user` |
| `honeyforge_server/app/routes/stats.py` | **Изменён** | Сводная статистика дашборда защищена `get_current_user` |
| `honeyforge_server/static/js/app.js` | **Изменён** | Проверка сессии при старте через `/auth/me`, передача токена в WebSocket (`wss://`) |
| `docker/nginx.conf` | **Изменён** | Терминация TLS на порту 443, 301-редирект с порта 80, проксирование WebSocket и заголовков |
| `docker-compose.yml` | **Изменён** | Закрыт порт 8000, Nginx переведён на 443, ловушки переведены на `https://honeyforge-nginx` |
| `honeyforge_agent/config.py` | **Изменён** | Дефолтный адрес `C2_URL` изменён на `https://honeyforge-nginx` |
| `honeyforge_agent/sender.py` | **Изменён** | В `httpx.AsyncClient` добавлен `verify=False` с обосновывающим комментарием |
| `simulator_attacker/scenarios.py` | **Изменён** | Сценарий canary token переведён на HTTPS с `verify=False` |
| `simulator_attacker/server.py` | **Изменён** | Хост прокси по умолчанию установлен в `honeyforge-nginx` |
| `README.md` | **Изменён** | Добавлен раздел «TLS и сертификаты (MASK-1)», обновлены порты и curl-команды |

---

## 🧪 3. Инструкция по ручной проверке каждого пункта

### 3.1 Проверка серверной авторизации (RBAC)

#### Шаг 1. Запрос без токена к защищённому эндпоинту (Ожидается 401 Unauthorized)
```bash
curl.exe -k -i https://localhost/api/v1/traps
```
**Фактический ответ сервера:**
```http
HTTP/1.1 401 Unauthorized
Server: nginx
Content-Type: application/json
www-authenticate: Bearer

{"detail":"Не авторизован"}
```

#### Шаг 2. Авторизация аналитика и получение токена
```bash
curl.exe -k -s -X POST https://localhost/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"analyst\", \"password\": \"$ANALYST_PASSWORD\"}"
```
*Сервер возвращает JWT-токен с ролью `analyst`.*

#### Шаг 3. Запрос аналитика к маршруту только для администратора (Ожидается 403 Forbidden)
```bash
curl.exe -k -i -X POST https://localhost/api/v1/simulator/run ^
  -H "Authorization: Bearer <ТОКЕН_АНАЛИТИКА>" ^
  -H "Content-Type: application/json" ^
  -d "{\"scenario\": \"port_scan\"}"
```
**Фактический ответ сервера:**
```http
HTTP/1.1 403 Forbidden
Server: nginx
Content-Type: application/json

{"detail":"Недостаточно прав. Требуется роль администратора"}
```

#### Шаг 4. Чтение списка ловушек аналитиком (Ожидается 200 OK)
```bash
curl.exe -k -s https://localhost/api/v1/traps -H "Authorization: Bearer <ТОКЕН_АНАЛИТИКА>"
```
*Сервер возвращает массив зарегистрированных ловушек (статус 200).*

#### Шаг 5. Авторизация администратора и запуск симуляции атак (Ожидается 200 OK)
```bash
# 1. Логин администратора
curl.exe -k -s -X POST https://localhost/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"admin\", \"password\": \"$ADMIN_PASSWORD\"}"

# 2. Запуск симулятора с токеном администратора
curl.exe -k -s -X POST https://localhost/api/v1/simulator/run ^
  -H "Authorization: Bearer <ТОКЕН_АДМИНИСТРАТОРА>" ^
  -H "Content-Type: application/json" ^
  -d "{\"scenario\": \"port_scan\"}"
```
**Фактический ответ сервера:**
```json
{
  "status": "success",
  "scenario": "port_scan",
  "trap_id": "trap-low-01",
  "trap_name": "DMZ-Perimeter-Trap-01",
  "latency_seconds": 0.017,
  "delivered_events": 3,
  "message": "Событие получено центром за 0.017 с"
}
```

#### Шаг 6. Проверка журнала аудита с реальным именем оператора
```bash
curl.exe -k -s https://localhost/api/v1/audit?limit=3 -H "Authorization: Bearer <ТОКЕН_АДМИНИСТРАТОРА>"
```
**Фактические записи в БД (имя берется из токена):**
```json
[
  {
    "id": 18,
    "timestamp": "2026-10-12T15:05:16.050443",
    "username": "admin",
    "action": "run_simulation",
    "target_type": "scenario",
    "target_id": "port_scan",
    "details": "Запуск сценария через изолированный контейнер: port_scan (ловушка: trap-low-01, задержка: 0.017 с)"
  },
  {
    "id": 17,
    "timestamp": "2026-10-12T15:05:15.304604",
    "username": "analyst",
    "action": "operator_login",
    "target_type": "auth",
    "target_id": "2",
    "details": "Operator logged in to Cyber SOC console"
  }
]
```

---

### 3.2 Проверка TLS-шифрования и сетевой изоляции

#### Шаг 1. Проверка недоступности порта 8000 снаружи (Ожидается ошибка подключения)
```bash
curl.exe http://localhost:8000
```
**Результат:**
```text
curl: (7) Failed to connect to localhost port 8000: Connection refused
```
*Порт 8000 изолирован внутри сети Docker и не светится на хосте нарушителю.*

#### Шаг 2. Проверка 301-редиректа с HTTP (порт 80) на HTTPS (порт 443)
```bash
curl.exe -s -I http://localhost
```
**Результат:**
```http
HTTP/1.1 301 Moved Permanently
Server: nginx
Location: https://localhost/
```

#### Шаг 3. Проверка доступности веб-интерфейса по HTTPS
```bash
curl.exe -k -s https://localhost | findstr "<title>"
```
**Результат:**
```html
    <title>HoneyForge — Центр управления ловушками</title>
```

#### Шаг 4. Проверка передачи телеметрии ловушек по TLS через логи Nginx
```bash
docker logs honeyforge-nginx --tail 10
```
**Логи прокси (ловушки передают телеметрию по HTTPS/TLS с кодом 200):**
```text
172.29.0.20 - - [12/Oct/2026:15:03:03 +0000] "POST /v1/telemetry/collect HTTP/1.1" 200 86 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
172.29.0.10 - - [12/Oct/2026:15:03:08 +0000] "POST /v1/telemetry/collect HTTP/1.1" 200 86 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
```

#### Шаг 5. Запуск комплексного скрипта сквозной верификации
```bash
.\venv\Scripts\python.exe scripts\verify_phase_two.py
```
**Вывод скрипта:**
```text
==================================================
1. ТЕСТИРОВАНИЕ СЕТЕВОЙ БЕЗОПАСНОСТИ И TLS (MASK-1)
==================================================
[+] УСПЕХ: Порт 8000 закрыт снаружи (Connection refused): ConnectTimeout
[+] УСПЕХ: Порт 80 возвращает 301 редирект на: https://localhost/
[+] УСПЕХ: Дашборд успешно открывается по HTTPS (порт 443)

==================================================
2. ТЕСТИРОВАНИЕ СЕРВЕРНОЙ АВТОРИЗАЦИИ (FR-C5)
==================================================
[+] УСПЕХ: Все защищенные эндпоинты без токена возвращают 401 'Не авторизован'
[+] УСПЕХ: Аналитик успешно авторизован, роль: analyst
[+] УСПЕХ: /auth/me возвращает профиль текущего аналитика: analyst (analyst)
[+] УСПЕХ: Аналитик имеет доступ на чтение списка ловушек (получено: 2)
[+] УСПЕХ: Все действия администратора блокируются для аналитика с кодом 403 Forbidden
[+] УСПЕХ: Администратор успешно авторизован, роль: admin
[+] УСПЕХ: Администратор успешно запустил сценарий проверки: port_scan (задержка: 0.017 с)
[+] УСПЕХ: Журнал аудита прочитан. Операторы: admin, analyst

==================================================
3. ТЕСТИРОВАНИЕ WEBSOCKET С АВТОРИЗАЦИЕЙ
==================================================
[+] УСПЕХ: WebSocket без токена отклонён сервером: HTTP 403
[+] УСПЕХ: WebSocket с JWT-токеном успешно подключён по wss:// (порт 443 TLS)

==================================================
ВСЕ ПРОВЕРКИ УСПЕШНО ПРОЙДЕНЫ!
==================================================
```

---

## 🔑 4. Справочные данные для работы с системой

### Учётные записи операторов:
* **Администратор (Admin):** логин `admin`, пароль из `.env` (`ADMIN_PASSWORD`) (полный доступ к управлению парком и симулятором)
* **Аналитик (Analyst):** логин `analyst`, пароль из `.env` (`ANALYST_PASSWORD`) (доступ только на чтение телеметрии, логов и квитирование алертов)

### Порты и адреса:
* **Веб-консоль SOC:** `https://localhost` (порт 443)
* **SSH-ловушка (Medium Interaction):** `localhost:2222` (тестовый вход по приманке из профиля ловушки: `root` / `admin123`)
* **Fake Web SSO (Medium Interaction):** `localhost:8088`
* **Периметральные ловушки (Low Interaction):** порты `2121` (FTP), `2323` (Telnet), `6379` (Redis)
* **Порт центра 8000:** закрыт снаружи в соответствии с политикой MASK-1.

### Как открыть веб-интерфейс в браузере:
1. Откройте в браузере: `https://localhost`
2. Браузер отобразит предупреждение безопасности о самоподписанном сертификате (*«Подключение не защищено»*).
3. Нажмите кнопку **«Дополнительно»** (Advanced) $\rightarrow$ перейдите по ссылке **«Перейти на сайт localhost (небезопасно)»**.
4. Введите учетные данные администратора или аналитика.

---

## 📌 5. Статус открытых вопросов
* Все поставленные задачи по **Блоку 1 (Серверная авторизация FR-C5)** и **Блоку 2 (TLS MASK-1)** выполнены на 100%.
* Динамическое дистанционное переконфигурирование работающих ловушек «на лету» (polling runtime updates) использует обновленный URL `https://honeyforge-nginx` в методе `fetch_config` и готово к расширению функциональности при необходимости.
