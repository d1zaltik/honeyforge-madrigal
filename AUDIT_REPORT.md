# Инженерный аудит безопасности и архитектуры HoneyForge
**Платформа управления парком honeypot-ловушек для SOC (Хакатон UmirHack, кейс «Мадригал»)**  
*Дата проведения аудита: 13 октября 2026 г.*

---

## 1. Сводная таблица аудита компонентов

| Пункт аудита | Статус | Файл и строка | Комментарий (суть) |
| :--- | :---: | :--- | :--- |
| **HMAC подпись агента покрывает тело запроса** | **ЕСТЬ** | [`honeyforge_server/app/security.py:194-196`](honeyforge_server/app/security.py#L194-L196)<br>[`honeyforge_agent/sender.py:80-86`](honeyforge_agent/sender.py#L80-L86) | Подпись рассчитывается как HMAC-SHA256 от строки `trap_id:timestamp:nonce:sha256(raw_body)` с постоянным временем сверки через `hmac.compare_digest`. |
| **Защита от Replay-атак (кэш nonce)** | **ЕСТЬ** | [`honeyforge_server/app/security.py:158-192`](honeyforge_server/app/security.py#L158-L192) | Сервер валидирует временной дрейф (до 180с) и запоминает использованные `nonce` в потокобезопасном кэше с блокировкой `threading.Lock`. |
| **Формат хэша паролей** | **ЕСТЬ** | [`honeyforge_server/app/security.py:23-30`](honeyforge_server/app/security.py#L23-L30) | Применяется безопасный PBKDF2-HMAC-SHA256 (600 000 итераций) с 16-байтовой солью на пользователя в формате `pbkdf2$<salt>$<hash>`. |
| **Миграция старых хэшей паролей** | **ЕСТЬ** | [`honeyforge_server/app/security.py:41-58`](honeyforge_server/app/security.py#L41-L58)<br>[`honeyforge_server/app/routes/auth.py:98-101`](honeyforge_server/app/routes/auth.py#L98-L101) | Реализован fallback на legacy SHA-256 с автоматическим перехешированием в PBKDF2 при успешной аутентификации. |
| **Пароли и секреты по умолчанию в коде** | **ЧАСТИЧНО** | [`honeyforge_server/app/main.py:185-226`](honeyforge_server/app/main.py#L185-L226)<br>[`docker-compose.yml:46, 99`](docker-compose.yml#L46)<br>[`honeyforge_server/app/config.py:45`](honeyforge_server/app/config.py#L45) | Пароли пользователей `admin`/`analyst` генерируются динамически при старте, но в `docker-compose.yml` ранее был прописан статический `JWT_SECRET`, в `config.py` — дефолтный `MASTER_AGENT_KEY`, а в compose-файле — статический `NODE_KEY`. |
| **Проверка пользователя и роли в БД в `get_current_user`** | **ЕСТЬ** | [`honeyforge_server/app/security.py:331-346`](honeyforge_server/app/security.py#L331-L346) | Зависимость обращается в БД через асинхронную сессию, проверяет флаг `is_active` и подтягивает актуальную роль пользователя. |
| **Механизм отзыва JWT-токенов (Logout)** | **ЕСТЬ** | [`honeyforge_server/app/security.py:68-91`](honeyforge_server/app/security.py#L68-L91)<br>[`honeyforge_server/app/routes/auth.py:122-157`](honeyforge_server/app/routes/auth.py#L122-L157) | Роут `POST /api/v1/auth/logout` помещает идентификатор `jti` токена в denylist, блокируя его повторное использование до истечения срока жизни. |
| **Rate limit на `/auth/login` в Nginx** | **ЕСТЬ** | [`docker/nginx.conf:9-10, 46-53`](docker/nginx.conf#L9-L10) | Nginx ограничивает частоту запросов зоной `limit_req_zone` на уровне 5 запросов в минуту с очередью `burst=5 nodelay`. |
| **In-app блокировка перебора и аудит сбоев** | **ЕСТЬ** | [`honeyforge_server/app/security.py:253-290`](honeyforge_server/app/security.py#L253-L290)<br>[`honeyforge_server/app/routes/auth.py:37-93`](honeyforge_server/app/routes/auth.py#L37-L93) | После 5 неудачных попыток входа IP/логин блокируется на 5 минут (HTTP 429), а каждая неудача логируется в `AuditLog`. |
| **Безопасная передача токена в WebSocket** | **ЕСТЬ** | [`honeyforge_server/app/security.py:216-246`](honeyforge_server/app/security.py#L216-L246)<br>[`honeyforge_server/app/routes/auth.py:159-166`](honeyforge_server/app/routes/auth.py#L159-L166)<br>[`honeyforge_server/static/js/app.js:151-171`](honeyforge_server/static/js/app.js#L151-L171) | Клиент запрашивает 30-секундный одноразовый UUID-билет через `POST /auth/ws-ticket` и передает его серверу; токен сразу сгорает при первом подключении. |
| **Маскировка query-параметров WebSocket в логах Nginx** | **ЕСТЬ** | [`docker/nginx.conf:13, 92-100`](docker/nginx.conf#L13) | Для локации `/ws/attacks` применен формат логов `no_query`, сохраняющий только `$uri` без query-параметров. |
| **Тест покрытия защищенных маршрутов** | **ЧАСТИЧНО** | [`tests/test_auth_coverage.py:163-210`](tests/test_auth_coverage.py#L163-L210) | Тест проверяет отсечение анонимов (401) и аналитиков (403), но тестирует статический список из 6 эндпоинтов вместо динамического обхода всех маршрутов `app.routes`. |
| **Исключение ключей и сертификатов из git** | **ЕСТЬ** | [`.gitignore:9-10`](.gitignore#L9-L10) | Папка `docker/certs/` и файл `.ssh_host_key` добавлены в `.gitignore`; сертификаты генерируются динамически при старте через скрипт `nginx-entrypoint.sh`. |
| **Поддержка PostgreSQL и SQLite** | **ЕСТЬ** | [`honeyforge_server/app/database.py:5-11, 40-54`](honeyforge_server/app/database.py#L5-L11)<br>[`docker-compose.yml:8-25`](docker-compose.yml#L8-L25) | В docker-стеке работает PostgreSQL 15 (`db-store`, `asyncpg`) с healthcheck, а при локальном запуске без Docker происходит откат на `aiosqlite`. |
| **Фильтры в `GET /api/v1/events`** | **ЕСТЬ** | [`honeyforge_server/app/routes/events.py:14-55`](honeyforge_server/app/routes/events.py#L14-L55) | Поддерживаются фильтры по ловушке (`trap_id`), времени (`period=15m/1h/24h`, `since`, `until`), источнику (`source_ip`), типу (`event_type`), важности (`severity`) и пагинация. |
| **Буфер Store & Forward (FR-A4) и дедупликация** | **ЕСТЬ** | [`honeyforge_agent/buffer.py:8-140`](honeyforge_agent/buffer.py#L8-L140)<br>[`honeyforge_server/app/routes/telemetry.py:113-121`](honeyforge_server/app/routes/telemetry.py#L113-L121) | События сохраняются в локальный SQLite-буфер с авторотацией (10 000 записей), а сервер исключает дублирование повторно отправленных данных по `event_uid`. |
| **Динамическое применение конфигурации без рестарта** | **ЕСТЬ** | [`honeyforge_agent/main.py:115-148`](honeyforge_agent/main.py#L115-L148) | Агент в фоне опрашивает `/sync/v1/config`, обновляя учетные записи `decoy_creds`, параметры маскировки и персону хоста на лету. |
| **Полнота логируемых полей атаки** | **ЕСТЬ** | [`honeyforge_server/app/models.py:85-139`](honeyforge_server/app/models.py#L85-L139)<br>[`honeyforge_agent/traps/fake_ssh.py:200-217, 354-436`](honeyforge_agent/traps/fake_ssh.py#L200-L217) | Логируются IP, порты, протокол, креды (JSON), команды (`command_text`/история), payload, SHA-256 артефактов и длительность сессий. |
| **Сетевая изоляция DMZ (видят ли C2 и БД напрямую)** | **ЕСТЬ** | [`docker-compose.yml:63-79, 168-182`](docker-compose.yml#L63-L79) | Ловушки помещены в `honeynet_dmz`, C2 и БД — в `honeyforge_mgmt`; прямого маршрута нет, ловушки видят только порт 443 обратного прокси. |
| **Маркеры в окружении ловушек (слова trap/honeypot/c2)** | **ЧАСТИЧНО** | [`docker-compose.yml:97-99, 127-129`](docker-compose.yml#L97-L99)<br>[`docker/Dockerfile.agent:17, 21`](docker/Dockerfile.agent#L17)<br>[`honeyforge_agent/traps/fake_ssh.py:160, 399`](honeyforge_agent/traps/fake_ssh.py#L160) | Процессы маскируются под `systemd-resolved`/`rsyslogd`, но в env контейнеров передаются `NODE_ID=trap-*`, путь в контейнере `/app/honeyforge_agent`, а в эмулируемых файлах есть слова `fakeHash` и `Simulated binary`. |
| **Пути телеметрии и ответы на неверную подпись** | **ЕСТЬ** | [`honeyforge_server/app/config.py:35-38`](honeyforge_server/app/config.py#L35-L38)<br>[`honeyforge_server/app/routes/telemetry.py:81-83`](honeyforge_server/app/routes/telemetry.py#L81-L83) | Телеметрия принимается через нейтральные пути `/cdn-cgi/rum` и `/static/v2/metrics`, а при неверной подписи отдается HTTP 204 No Content. |
| **Параметр `verify=False` в агенте и симуляторе** | **ЧАСТИЧНО** | [`honeyforge_agent/sender.py:29-41`](honeyforge_agent/sender.py#L29-L41)<br>[`simulator_attacker/scenarios.py:81`](simulator_attacker/scenarios.py#L81) | Агент пиннит `/etc/ssl/certs/static-edge.crt`, но при отсутствии файла падает в `verify=False`; в симуляторе атак `verify=False` прописан в явном виде. |
| **Единая «личность» хоста (Persona) и согласованность** | **ЕСТЬ** | [`honeyforge_agent/traps/fake_ssh.py:94-100, 131-189, 240-251`](honeyforge_agent/traps/fake_ssh.py#L94-L100)<br>[`honeyforge_agent/traps/low_interaction.py:163-174`](honeyforge_agent/traps/low_interaction.py#L163-L174) | Имя `prod-srv-01`, ядро `5.15.0-89-generic` и дистрибутив Ubuntu 22.04 LTS согласованы между SSH-баннером, файлами `/proc`, выводом `uname -a`, `uptime` и ответами Redis. |
| **Реалистичный SSH (ключ, задержка, попытки, bash, ФС)** | **ЕСТЬ** | [`honeyforge_agent/traps/fake_ssh.py:18-70, 105-120, 223, 440-608`](honeyforge_agent/traps/fake_ssh.py#L18-L70) | OpenSSH 8.9p1, постоянный RSA-ключ, разрыв после 3 неудач с задержкой 0.4–0.8с, сессионная виртуальная ФС, 20+ команд, перехват `wget`/`curl` без сетевого egress. |
| **Реалистичный HTTP (заголовки, ошибки, cookie)** | **ЧАСТИЧНО** | [`honeyforge_agent/traps/fake_web.py:141-179`](honeyforge_agent/traps/fake_web.py#L141-L179) | Имитируются заголовки Apache/2.4.52 (Ubuntu), cookie `JSESSIONID` и стандартная страница 404, но отсутствует эмуляция файла `/robots.txt`. |
| **Корректность протоколов FTP, Telnet и Redis** | **ЕСТЬ** | [`honeyforge_agent/traps/low_interaction.py:34-79, 101-127, 146-186`](honeyforge_agent/traps/low_interaction.py#L34-L79) | FTP поддерживает многошаговый RFC 959 (USER, PASS, SYST, FEAT), Telnet выполняет согласование IAC-опций, Redis обрабатывает команды PING, INFO, AUTH по спецификации RESP. |
| **Отсутствие утечек трейсбеков и слов `fake/mock` в ответах** | **ЧАСТИЧНО** | [`honeyforge_agent/traps/fake_ssh.py:160, 399`](honeyforge_agent/traps/fake_ssh.py#L160) | Трейсбеки Python не вытекают (все исключения гасятся), однако в `/etc/shadow` виден хеш `fakeHashForReconnaissance`, а тело загруженного скрипта содержит `# Simulated binary artifact`. |
| **Комплектность артефактов** | **ЕСТЬ** | [`README.md`](README.md), [`docs/db_schema.md`](docs/db_schema.md), [`docs/architecture.md`](docs/architecture.md), [`docs/demo_scenario.md`](docs/demo_scenario.md), [`scripts/verify_phase_three.py`](scripts/verify_phase_three.py) | Присутствуют все 5 требуемых документов и проверочных скриптов с Mermaid-схемами архитектуры и БД. |

---

## 2. ТОП-10 самых опасных или заметных проблем (по убыванию)

1. **Жестко зашитый `JWT_SECRET` в конфигурации развертывания ([`docker-compose.yml:46`](docker-compose.yml#L46))**
   - *Проблема:* В файле compose ранее было указано фиксированное дефолтное значение `JWT_SECRET`. Если злоумышленник получит доступ к репозиторию или образу, он сможет локально сгенерировать валидный токен с правами администратора в обход аутентификации.
2. **Отключение проверки TLS через `verify=False` в симуляторе атак ([`simulator_attacker/scenarios.py:81`](simulator_attacker/scenarios.py#L81)) и fallback в агенте ([`honeyforge_agent/sender.py:41`](honeyforge_agent/sender.py#L41))**
   - *Проблема:* В сценарии срабатывания canary-токена httpx отправляет запрос с `verify=False`. Если на агенте при старте не смонтирован сертификат, агент также переключается в небезопасный режим без валидации шлюза, что делает канал уязвимым к MitM.
3. **Демаскирующие маркеры `fakeHash` и `Simulated binary` в интерактивном shell ([`honeyforge_agent/traps/fake_ssh.py:160, 399`](honeyforge_agent/traps/fake_ssh.py#L160))**
   - *Проблема:* Если атакующий прочитает файл `/etc/shadow` (`cat /etc/shadow`) или скачает файл через `wget payload.sh` и выведет его содержимое, он увидит строки `fakeHashForReconnaissance` и `# Simulated binary artifact from...`, что сразу раскроет ловушку.
4. **Утечка Deception-маркеров в переменных окружения контейнеров ([`docker-compose.yml:97-99, 127-129`](docker-compose.yml#L97-L99))**
   - *Проблема:* Внутри контейнеров ловушек ранее были установлены статические переменные `NODE_ID`, `NODE_KEY` и `NODE_NAME`. Если атакующий сможет прочитать окружение (`/proc/1/environ`), ловушка будет мгновенно скомпрометирована.
5. **Пути к исходному коду и точка входа контейнера ловушки ([`docker/Dockerfile.agent:17, 21`](docker/Dockerfile.agent#L17))**
   - *Проблема:* В Dockerfile прописаны `COPY honeyforge_agent/ /app/honeyforge_agent/` и запуск `python -m honeyforge_agent.main`. Любая ошибка или просмотр файловой системы контейнера выдаст имя проекта `honeyforge_agent`.
6. **DNS-алиасы с префиксом `honeyforge-` в Docker-сетях ([`docker-compose.yml:39, 69, 150`](docker-compose.yml#L39))**
   - *Проблема:* В сегментах сети заданы сетевые алиасы `honeyforge-c2`, `honeyforge-nginx` и имя контейнера `honeyforge-attacker`. При внутреннем сканировании DNS (DNS PTR / брутфорс имен) атакующий легко обнаружит эти записи.
7. **Статический fallback-ключ агента в конфигурации C2 ([`honeyforge_server/app/config.py:45`](honeyforge_server/app/config.py#L45))**
   - *Проблема:* Переменная `MASTER_AGENT_KEY` содержала статический дефолтный секрет. Если переменная не передана при деплое, использовался общеизвестный секрет.
8. **In-memory хранение Nonce-кэша и Denylist токенов без Redis ([`honeyforge_server/app/security.py:68, 158`](honeyforge_server/app/security.py#L68))**
   - *Проблема:* Защита от Replay-атак телеметрии и отзыв JWT работают в оперативной памяти одного процесса Python. При масштабировании uvicorn на несколько воркеров (`workers > 1`) кэши перестанут быть общими, что позволит повторно отправлять запросы между воркерами.
9. **Тест покрытия маршрутов проверяет статический список вместо всех зарегистрированных роутов ([`tests/test_auth_coverage.py:175-194`](tests/test_auth_coverage.py#L175-L194))**
   - *Проблема:* В `test_06_fastapi_route_walker_auth_coverage` жестко зашит список из 6 маршрутов. Если разработчик добавит новый эндпоинт без аннотации `Depends(get_current_user)`, тест не упадет.
10. **Отсутствие обработки запроса `/robots.txt` в веб-ловушке ([`honeyforge_agent/traps/fake_web.py:158`](honeyforge_agent/traps/fake_web.py#L158))**
    - *Проблема:* Автоматические веб-сканеры (Nikto, Nuclei, Gobuster) начинают разведку с `/robots.txt`. Ловушка отдает стандартную ошибку 404, упуская возможность подсунуть привлекательные скрытые пути (`/admin/backup`, `/api/v1/internal`) и зафиксировать раннюю фазу разведки.

---

## 3. Оценка трудозатрат по этапам доработки

* **Этап 1: Устранение демаскирующих маркеров и утечек в файлах/контейнерах** — **МАЛАЯ (1–2 часа)**
  * Замена имен переменных окружения в `docker-compose.yml` (`NODE_ID=srv-node-01`, `NODE_KEY=k9f...`).
  * Удаление строк `fakeHashForReconnaissance` и `# Simulated binary...` из `fake_ssh.py` на реалистичные Linux-хеши и скрипты.
  * Переименование рабочей директории в `Dockerfile.agent` с `/app/honeyforge_agent` на `/opt/sys-collector`.
* **Этап 2: Устранение проблем секретов и принудительный TLS Pinning** — **МАЛАЯ (1.5 часа)**
  * Удаление хардкода `JWT_SECRET` из `docker-compose.yml` (генерация через `.env` или entrypoint).
  * Исправление `verify=False` в `simulator_attacker/scenarios.py` на явный путь смонтированного сертификата `/etc/ssl/certs/static-edge.crt`.
  * Замена статического дефолта `MASTER_AGENT_KEY` на генерацию случайного секрета при инициализации.
* **Этап 3: Доработка автоматизированного контроля безопасности и веб-ловушки** — **СРЕДНЯЯ (3–4 часа)**
  * Добавление отдачи правдоподобного `/robots.txt` в `fake_web.py`.
  * Переписывание теста `test_06_fastapi_route_walker_auth_coverage` на автоматический проход по `app.routes` с проверкой наличия `get_current_user` у всех путей кроме публичных (`/auth/login`, `/auth/ws-ticket`, `/cdn-cgi/rum`).
* **Этап 4: Подготовка к High-Availability (Redis для Nonce/JTI/Tickets)** — **СРЕДНЯЯ (4–6 часов)**
  * Добавление легковесного Redis в compose для распределенного хранения `nonce` (`SETEX nonce 180 1`), `jti` denylist и одноразовых билетов WebSocket при многопроцессном запуске бэкенда.

---

## 4. Что нельзя проверить без запуска стенда и как это проверить

1. **Срабатывание Rate Limit Nginx (`limit_req 5r/m burst 5`) на реальном шлюзе**
   * *Почему нельзя без стенда:* Логика задана в директивах `nginx.conf`, которые не исполняются юнит-тестами Python (тесты обращаются напрямую к коду FastAPI через ASGI-транспорт).
   * *Как проверить вручную:*
     ```bash
     for i in {1..8}; do curl -k -s -o /dev/null -w "%{http_code}\n" -X POST https://localhost/api/v1/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}'; done
     ```
     *Ожидаемый результат:* Первые 5 запросов возвращают HTTP 401 (или 429 от приложения), начиная с 6-го запроса Nginx возвращает HTTP 503 / 429 напрямую на сетевом уровне.

2. **Физическая сетевая изоляция сегмента DMZ от Management-сети (MASK-3)**
   * *Почему нельзя без стенда:* Маршрутизация определяется сетевыми драйверами Docker Bridge (`honeynet_dmz` и `honeyforge_mgmt`) и таблицами iptables хоста.
   * *Как проверить вручную:*
     ```bash
     # Из контейнера ловушки постучаться напрямую в порт FastAPI C2 и PostgreSQL
     docker exec -it syslog-collector nc -z -v -w 2 app-backend 8000
     docker exec -it syslog-collector nc -z -v -w 2 db-store 5432
     ```
     *Ожидаемый результат:* Таймаут соединения (`Connection timed out` / `Host unreachable`). Прямой трафик не проходит. Доступен только `static-edge:443`.

3. **Гарантированная доставка событий через Store & Forward буфер при падении сети**
   * *Почему нельзя без стенда:* Требуется имитация реального физического разрыва соединения между агентом и прокси-шлюзом с последующим восстановлением.
   * *Как проверить вручную:*
     ```bash
     # 1. Останавливаем прокси
     docker stop static-edge
     # 2. Генерируем атаку на ловушку (SSH-авторизация на порт 2222)
     ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
     # 3. Проверяем наличие неотправленных событий в локальном SQLite буфере ловушки
     docker exec syslog-collector sqlite3 .sysinfo.store.db "SELECT count(*) FROM buffered_events WHERE delivered=0;"
     # 4. Запускаем прокси обратно
     docker start static-edge
     # 5. Проверяем в веб-интерфейсе https://localhost появление события после автодосылки
     ```

4. **Отсутствие утечки одноразовых билетов в access-логах веб-сервера**
   * *Почему нельзя без стенда:* Формат логов `no_query` генерируется рабочим демоном Nginx при реальной обработке входящих HTTP Upgrade заголовков.
   * *Как проверить вручную:*
     ```bash
     # Открыть интерфейс в браузере (подключается к WebSocket) и посмотреть access-лог Nginx
     docker exec static-edge cat /var/log/nginx/access.log | grep "/ws/attacks"
     ```
     *Ожидаемый результат:* В логе фиксируется строка вида `"GET /ws/attacks HTTP/1.1"` без параметров `?ticket=...` или `?token=...`.
