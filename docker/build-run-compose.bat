# Находясь в ASIDC-SERVER/docker/
cd ..

# Теперь вы в ASIDC-SERVER/ (как ваш bat-файл)
docker compose -f docker/docker-compose.yml build --no-cache
docker compose -f docker/docker-compose.yml up -d

pause