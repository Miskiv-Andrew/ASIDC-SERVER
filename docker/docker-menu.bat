@echo off
setlocal EnableDelayedExpansion

REM ============================
REM CONFIG
REM ============================
set PROJECT_DIR=%~dp0..
set COMPOSE_FILE=docker-compose.yml
set SERVICE_DEBUG=server-debug

REM ============================
REM MENU LOOP
REM ============================
:MENU
cls
echo ==============================
echo   Guarder Docker Control
echo ==============================
echo.
echo [1] Build ALL images
echo [2] Run ALL (prod)
echo [3] Run DEBUG
echo [4] Stop ALL
echo [5] Attach GDB to debug server
echo [0] Exit
echo.
set /p choice=Select option: 

if "%choice%"=="1" goto BUILD
if "%choice%"=="2" goto RUN_PROD
if "%choice%"=="3" goto RUN_DEBUG
if "%choice%"=="4" goto STOP
if "%choice%"=="5" goto GDB
if "%choice%"=="0" goto END

echo Invalid option!
pause
goto MENU

REM ============================
REM ACTIONS
REM ============================

:BUILD
cls
echo Building all images...
cd /d "%PROJECT_DIR%\docker"
docker compose build
pause
goto MENU

:RUN_PROD
cls
echo Starting production containers...
cd /d "%PROJECT_DIR%\docker"
docker compose --profile prod up -d
pause
goto MENU

:RUN_DEBUG
cls
echo Starting debug containers...
cd /d "%PROJECT_DIR%\docker"
docker compose --profile debug up -d
pause
goto MENU

:STOP
cls
echo Stopping all containers...
cd /d "%PROJECT_DIR%\docker"
docker compose down
pause
goto MENU

:GDB
cls
echo Opening GDB connection in new window...
cd /d "%PROJECT_DIR%\docker"

start "GDB Guarder Server" cmd /k ^
"gdb -ex \"target remote localhost:2345\""

goto MENU

:END
endlocal
exit /b
