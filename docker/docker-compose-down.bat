@echo off
setlocal

cd ..

docker compose -f docker/docker-compose.yml down

pause