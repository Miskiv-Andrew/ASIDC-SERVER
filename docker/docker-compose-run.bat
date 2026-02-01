@echo off
setlocal

cd ..

docker compose -f docker/docker-compose.yml up -d

pause