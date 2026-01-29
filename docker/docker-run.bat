@echo off
setlocal

docker run --rm -it docker-server:latest bash

echo.
echo Container started.
pause