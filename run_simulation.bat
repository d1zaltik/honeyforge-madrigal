@echo off
chcp 65001 > nul
cd /d "%~dp0"

echo ===================================================
echo   Запуск симуляции атак HoneyForge...
echo ===================================================

if exist .\venv\Scripts\python.exe (
    .\venv\Scripts\python.exe -m simulator.attack_simulator --all
) else (
    python -m simulator.attack_simulator --all
)

echo.
pause
