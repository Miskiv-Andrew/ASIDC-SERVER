@echo off
setlocal

docker run --rm -it guarder-server:latest bash

echo.
echo Container started.
pause