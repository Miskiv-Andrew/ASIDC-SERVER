# ==========================================================================================================
# 1) BUILD STAGE
# ==========================================================================================================
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ca-certificates \
    unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY CMakeLists.txt ./

# Копируем исходный код
COPY apps ./apps/
COPY core ./core/

# Копируем зависимости (если есть)
COPY third_party ./third_party/ 

# ВАЖНО: Сборка с отладочными символами
RUN cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build

# Проверка линковки SSL (для отладки)
RUN echo "=== Checking SSL linking ===" && \
    ldd /build/build/bin/GuarderServerCLI | grep -E "ssl|crypto" || echo "WARNING: SSL libraries not found in binary!"

# ==========================================================================================================
# 2) RUNTIME STAGE
# ==========================================================================================================
FROM ubuntu:22.04 as runtime

# Установка необходимых пакетов включая MySQL ODBC драйвер И ОТЛАДЧИК
RUN apt-get update && apt-get install -y \
    libssl3 \
    libstdc++6 \
    unixodbc \
    libodbc2 \
    ca-certificates \
    odbc-mariadb \
    && rm -rf /var/lib/apt/lists/*

# Настройка ODBC Driver Manager (odbcinst.ini)
RUN echo "[MySQL ODBC 8.0 Driver]" > /etc/odbcinst.ini && \
    echo "Description = MariaDB ODBC Connector" >> /etc/odbcinst.ini && \
    echo "Driver = /usr/lib/x86_64-linux-gnu/odbc/libmaodbc.so" >> /etc/odbcinst.ini && \
    echo "Setup = /usr/lib/x86_64-linux-gnu/odbc/libmaodbc.so" >> /etc/odbcinst.ini && \
    echo "FileUsage = 1" >> /etc/odbcinst.ini

# КРИТИЧНО: Создание User DSN (odbc.ini) для приложения
RUN echo "[ODBC Data Sources]" > /etc/odbc.ini && \
    echo "guarder_db = MySQL ODBC 8.0 Driver" >> /etc/odbc.ini && \
    echo "" >> /etc/odbc.ini && \
    echo "[guarder_db]" >> /etc/odbc.ini && \
    echo "Description = Guarder Database Connection" >> /etc/odbc.ini && \
    echo "Driver = MySQL ODBC 8.0 Driver" >> /etc/odbc.ini && \
    echo "Server = mysql" >> /etc/odbc.ini && \
    echo "Port = 3306" >> /etc/odbc.ini && \
    echo "Database = guarder_base" >> /etc/odbc.ini && \
    echo "User = cvituser" >> /etc/odbc.ini && \
    echo "Password = cvitpass" >> /etc/odbc.ini && \
    echo "Option = 3" >> /etc/odbc.ini

WORKDIR /app
# Создаем директорию для SSL сертификатов
RUN mkdir -p /app/ssl_certs
COPY config/ssl_certs /app/ssl_certs

COPY --from=build /build/build/bin/GuarderServerCLI .
COPY db/init/001_init.sql ./db/init/

# Делаем файл исполняемым
RUN chmod +x ./GuarderServerCLI

# Переменные окружения для ODBC
ENV ODBCSYSINI=/etc
ENV ODBCINI=/etc/odbc.ini

# Обычный запуск
CMD ["./GuarderServerCLI"]

# ==========================================================================================================
# 3) DEBUG STAGE
# ==========================================================================================================
FROM runtime AS debug

RUN apt-get update && apt-get install -y \
    gdb \
    gdbserver \
    vim \
    procps \
 && rm -rf /var/lib/apt/lists/*

EXPOSE 2345
CMD ["gdbserver", "0.0.0.0:2345", "./GuarderServerCLI"]

# Для отладки: запускаем tail чтобы контейнер не останавливался
# Программу будем запускать вручную через gdb
# CMD ["tail", "-f", "/dev/null"]