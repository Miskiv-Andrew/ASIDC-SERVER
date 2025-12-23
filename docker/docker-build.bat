@echo off
setlocal

cd ..

docker compose -f docker/docker-compose.yml build

echo.
echo Build finished.
pause
