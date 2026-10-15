@echo off
chcp 65001 > nul
cd /d "%~dp0"

echo ===================================================
echo   Остановка платформы HoneyForge...
echo ===================================================

docker compose down

echo.
echo [OK] Все контейнеры остановлены.
pause
