@echo off
chcp 65001 > nul
cd /d "%~dp0"

echo ===================================================
echo   Запуск платформы HoneyForge в Docker...
echo ===================================================

if not exist .env (
    if exist .env.example (
        echo [INFO] Файл .env не найден, создаю из .env.example...
        copy .env.example .env > nul
    )
)

set DOCKER_BUILDKIT=0
docker compose up -d

echo.
echo [OK] Все сервисы запущены!
echo Веб-интерфейс SOC доступен по адресу: https://localhost
echo.
start https://localhost

echo.
echo Для закрытия этого окна нажмите любую клавишу.
pause > nul
