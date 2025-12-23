@echo off
setlocal

cd ..

set EXE=build\bin\Release\GuarderServerCLI.exe

if not exist %EXE% (
    echo Executable not found. Build first.
    pause
    exit /b 1
)

%EXE% 8443
pause