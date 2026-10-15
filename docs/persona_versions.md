# Спецификация согласованности версий ОС и сервисов (Persona Baseline)

В соответствии с требованиями кейса «Мадригал» (хакатон UmirHack) и требованиями MASK-5, MASK-6, MASK-7, платформа HoneyForge эмулирует целостное и согласованное окружение **Ubuntu 22.04.4 LTS**. Все сетевые сервисы, баннеры, ядро Linux, ошибки GNU coreutils и заголовки протоколов согласованы между собой и исключают деанонимизацию ловушек по расхождениям версионного стека.

---

## 1. Базовый дистрибутив и системное окружение

| Компонент | Точное значение | Обоснование / Референс |
|:---|:---|:---|
| **Дистрибутив** | `Ubuntu 22.04.4 LTS (Jammy Jellyfish)` | Официальный point-release Ubuntu 22.04 LTS |
| **Релиз ядра** | `5.15.0-105-generic` | Официальное LTS-ядро репозитория `jammy-updates` (#115-Ubuntu) |
| **Строка uname -a** | `Linux <hostname> 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux` | Стандартный формат GNU uname в Ubuntu x86_64 |
| **Компилятор** | `gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)` | Штатная версия GCC в Ubuntu 22.04.4 |
| **Формат /proc/version** | `Linux version 5.15.0-105-generic (buildd@lcy02-amd64-077) (gcc version 11.4.0) #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024` | Идентичен реальному файлу ядра Ubuntu |
| **Файлы /etc/os-release** | `NAME="Ubuntu"`, `VERSION="22.04.4 LTS (Jammy Jellyfish)"`, `VERSION_ID="22.04"`, `ID=ubuntu`, `ID_LIKE=debian`, `UBUNTU_CODENAME=jammy` | Стандартный systemd os-release |
| **Формат /etc/shadow** | Хеши Yescrypt: `$y$j9T$<salt>$<hash>` (разные соли и хеши для root, deploy, ubuntu) | Стандартный алгоритм PAM crypt в Ubuntu 22.04 |

---

## 2. Сетевые сервисы и протоколы

| Протокол | Сервис / Демон | Баннер / Сигнатура | Особенности эмуляции |
|:---|:---|:---|:---|
| **SSH (Port 22/2222)** | OpenSSH 8.9p1 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | KEX, шифры и MAC ограничены строгим подмножеством OpenSSH 8.9; постоянные host-keys (RSA 3072, ECDSA nistp256, Ed25519) |
| **HTTP (Port 80/8088)** | Apache 2.4.52 | `Server: Apache/2.4.52 (Ubuntu)` | Точные HTML-шаблоны ошибок Apache (400, 403, 404, 405, 414) с кодировкой `iso-8859-1`, ServerSignature и заголовком `Server` |
| **FTP (Port 21/2121)** | ProFTPD 1.3.7a | `220 ProFTPD 1.3.7a Server (Ubuntu) [<host_ip>]` | Поддержка динамического пассивного режима (PASV / EPSV) на портах 50000..50050, реальный TCP data listener, листинги `LIST`/`NLST` и чтение `RETR` |
| **Telnet (Port 23/2323)** | agetty / Ubuntu getty | `Ubuntu 22.04.4 LTS\r\n\r\n<hostname> login: ` | RFC 854 IAC handshake (`\xff\xfb\x01\xff\xfb\x03\xff\xfd\x22`), эмуляция логина с псевдотерминальным выводом |
| **Redis (Port 6379)** | Redis 7.0.15 | `redis_version:7.0.15`, `os:Linux 5.15.0-105-generic x86_64` | Поставляется через официальный APT PPA (`packages.redis.io`); аутентичный формат неизвестной команды `-ERR unknown command 'CMD', with args beginning with: 'arg'` |

---

## 3. Источники версий и доказательная база (Launchpad / Security Notices)

Все версии согласованы на временной срез **Q2 2024** (май 2024 года, актуальный апдейт Ubuntu 22.04.4 LTS):

1. **OpenSSH 8.9p1-3ubuntu0.10**
   - **Дата релиза пакета**: 15 мая 2024 г.
   - **Launchpad**: [https://launchpad.net/ubuntu/+source/openssh/1:8.9p1-3ubuntu0.10](https://launchpad.net/ubuntu/+source/openssh/1:8.9p1-3ubuntu0.10)
   - **Changelog**: [https://changelogs.ubuntu.com/changelogs/pool/main/o/openssh/openssh_8.9p1-3ubuntu0.10/changelog](https://changelogs.ubuntu.com/changelogs/pool/main/o/openssh/openssh_8.9p1-3ubuntu0.10/changelog)
   - **Контекст**: Плановое обновление безопасности USN-6856-1 для ветки `jammy-updates`.

2. **Linux Kernel 5.15.0-105-generic (#115-Ubuntu)**
   - **Дата сборки ядра**: 15 апреля 2024 г. (`Mon Apr 15 17:33:04 UTC 2024`)
   - **Launchpad**: [https://launchpad.net/ubuntu/+source/linux/5.15.0-105.115](https://launchpad.net/ubuntu/+source/linux/5.15.0-105.115)
   - **Changelog**: [https://changelogs.ubuntu.com/changelogs/pool/main/l/linux/linux_5.15.0-105.115/changelog](https://changelogs.ubuntu.com/changelogs/pool/main/l/linux/linux_5.15.0-105.115/changelog)
   - **Контекст**: Стабильное LTS ядро дистрибутива Ubuntu 22.04.4 LTS, бюллетень USN-6752-1.

3. **Apache 2.4.52-1ubuntu4.9**
   - **Дата релиза пакета**: 04 апреля 2024 г.
   - **Launchpad**: [https://launchpad.net/ubuntu/+source/apache2/2.4.52-1ubuntu4.9](https://launchpad.net/ubuntu/+source/apache2/2.4.52-1ubuntu4.9)
   - **Changelog**: [https://changelogs.ubuntu.com/changelogs/pool/main/a/apache2/apache2_2.4.52-1ubuntu4.9/changelog](https://changelogs.ubuntu.com/changelogs/pool/main/a/apache2/apache2_2.4.52-1ubuntu4.9/changelog)
   - **Контекст**: Обновление безопасности HTTP-сервера Apache 2.4.52 для ветки `jammy-updates`.

4. **ProFTPD 1.3.7a+dfsg-1build1**
   - **Дата релиза пакета**: Релиз дистрибутива Ubuntu 22.04 LTS (Jammy Jellyfish)
   - **Launchpad**: [https://launchpad.net/ubuntu/+source/proftpd-dfsg/1.3.7a+dfsg-1build1](https://launchpad.net/ubuntu/+source/proftpd-dfsg/1.3.7a+dfsg-1build1)
   - **Changelog**: [https://changelogs.ubuntu.com/changelogs/pool/universe/p/proftpd-dfsg/proftpd-dfsg_1.3.7a+dfsg-1build1/changelog](https://changelogs.ubuntu.com/changelogs/pool/universe/p/proftpd-dfsg/proftpd-dfsg_1.3.7a+dfsg-1build1/changelog)
   - **Контекст**: Официальный пакет FTP сервера ProFTPD 1.3.7a в репозитории Ubuntu Universe.

5. **Redis 7.0.15**
   - **Дата релиза**: 27 марта 2024 г.
   - **Upstream Release**: [https://github.com/redis/redis/releases/tag/7.0.15](https://github.com/redis/redis/releases/tag/7.0.15)
   - **Release Notes**: [https://raw.githubusercontent.com/redis/redis/7.0.15/00-RELEASENOTES](https://raw.githubusercontent.com/redis/redis/7.0.15/00-RELEASENOTES)
   - **Контекст**: Стабильный LTS выпуск Redis 7.0 на официальном APT-источнике `packages.redis.io` для Ubuntu 22.04 LTS.

---

## 4. Динамическая persona ловушек

Каждая ловушка получает конфигурацию `persona` из профиля ловушки:
```json
{
  "hostname": "edge-gw-01",
  "ip": "172.28.0.20",
  "mac": "02:42:0a:1c:00:14",
  "os": "Ubuntu 22.04.4 LTS",
  "kernel": "5.15.0-105-generic",
  "uptime_base": 172800,
  "users": ["root", "deploy", "ubuntu"]
}
```

Все компоненты агента (`fake_ssh.py`, `fake_web.py`, `low_interaction.py`) динамически подставляют параметры из словаря `persona`:
- `hostname`, `ip` и `kernel` никогда не хардкодятся в ответах протоколов;
- время непрерывной работы `uptime` монотонно возрастает между запросами с момента `boot_time` (сохраняемого на постоянном томе);
- ключи хоста (`ssh_host_*_key`) сохраняются в именованных томах `/etc/ssh` и не регенерируются при перезапусках.
